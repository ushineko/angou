package store

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ushineko/angou/internal/envelope"
	"github.com/ushineko/angou/internal/keybundle"
	"github.com/ushineko/angou/internal/pgpcrypto"
	"github.com/ushineko/angou/lib/container"
)

// stagingDir is where a rekey assembles the new store before committing any of
// it. It is a directory, and Reindex skips directories, so its contents are
// invisible to a reader working on the store meanwhile.
const stagingDir = ".angou-rekey"

// RekeyResult reports what an identity rotation did.
type RekeyResult struct {
	OldFingerprint string
	NewFingerprint string
	Blobs          int
	OldBlobNames   []string
}

// RekeyIdentity generates a new keypair and a new naming key, re-encrypts every
// blob to the new identity under its new name, and writes a new key bundle
// (spec 001 R4.2, R4.2.1).
//
// The naming key rotates with the keypair deliberately. Leaving it in place
// would let an observer of the store keep tracking which logical paths exist and
// how often each changes — the deterministic names are a metadata channel that
// survives an identity rotation unless the naming key rotates too.
//
// The operation is staged and then committed (R4.3). Nothing in the live store
// is modified until every new blob has been written and verified, and the
// superseded key bundle is retained so a reader can still open the store if the
// process dies between the two files that have to change together.
func (s *Store) RekeyIdentity(recovery []byte) (*RekeyResult, error) {
	// Read every blob through the current identity first. A store that cannot
	// be fully read is a store that must not be rotated: re-encrypting what we
	// can and dropping the rest would silently lose secrets.
	existing, err := s.readAll()
	if err != nil {
		return nil, err
	}

	newIdentity, err := pgpcrypto.Generate("angou", "angou@localhost")
	if err != nil {
		return nil, err
	}
	newNameKey := make([]byte, NameKeyLen)
	if _, err := rand.Read(newNameKey); err != nil {
		return nil, fmt.Errorf("generate naming key: %w", err)
	}

	staged := &Store{
		root:         filepath.Join(s.root, stagingDir),
		identity:     newIdentity,
		meta:         Meta{NameKey: newNameKey, BootstrapSHA256: s.meta.BootstrapSHA256, VersionFloor: s.meta.VersionFloor},
		index:        Index{Entries: map[string]IndexEntry{}},
		IndexTrusted: true,
	}
	if err := os.MkdirAll(staged.root, 0o700); err != nil {
		return nil, fmt.Errorf("create staging directory: %w", err)
	}
	// Staging is removed on every exit path. On success its contents have
	// already been moved out; on failure it is the thing that must not linger.
	defer func() { _ = os.RemoveAll(staged.root) }()

	for _, env := range existing {
		if _, err := staged.Put(env.Path, env.Content, env.Mode, env.MTime, env.MIME, container.EncodingArmor); err != nil {
			return nil, fmt.Errorf("re-encrypt %s: %w", env.Path, err)
		}
	}
	if err := staged.writeMeta(); err != nil {
		return nil, err
	}

	exported, err := newIdentity.SerializePrivate()
	if err != nil {
		return nil, err
	}
	bundle, err := keybundle.Seal(exported, recovery)
	if err != nil {
		return nil, err
	}
	bundleBytes, err := keybundle.Marshal(bundle)
	if err != nil {
		return nil, err
	}

	// Verify the staged store opens with the new identity before touching the
	// live one. Everything above this line is discardable; everything below
	// changes the store.
	if err := verifyStaged(staged.root, exported, len(existing)); err != nil {
		return nil, fmt.Errorf("the rotated store did not verify, so nothing was changed: %w", err)
	}

	oldNames, err := s.blobFileNames()
	if err != nil {
		return nil, err
	}
	result := &RekeyResult{
		OldFingerprint: s.identity.Fingerprint(),
		NewFingerprint: newIdentity.Fingerprint(),
		Blobs:          len(existing),
		OldBlobNames:   oldNames,
	}

	if err := s.commitRekey(staged, bundleBytes, oldNames); err != nil {
		return nil, err
	}
	s.identity = newIdentity
	s.meta = staged.meta
	s.index = staged.index
	s.IndexTrusted = true
	return result, nil
}

// commitRekey moves the staged store into place.
//
// The order matters. New blobs land first: their names are HMACs under the new
// naming key, so they cannot collide with the old ones and their presence is
// invisible to a reader still using the old key. The key bundle and the metadata
// blob then change together — they are the pair that decides which key and which
// naming key are authoritative — and the superseded bundle is kept so that a
// crash between them leaves the store openable either way. Old blobs are deleted
// last, because until they are gone the previous store is still complete.
func (s *Store) commitRekey(staged *Store, bundleBytes []byte, oldNames []string) error {
	entries, err := os.ReadDir(staged.root)
	if err != nil {
		return fmt.Errorf("read staging directory: %w", err)
	}
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		from := filepath.Join(staged.root, de.Name())
		to := filepath.Join(s.root, de.Name())
		if de.Name() == MetaName || de.Name() == IndexName {
			continue // handled below, with the bundle
		}
		if err := os.Rename(from, to); err != nil {
			return fmt.Errorf("commit %s: %w", de.Name(), err)
		}
	}

	// Retain the superseded bundle under a name derived from its fingerprint,
	// so a reader interrupted mid-swap still finds a bundle that works.
	bundleDir := filepath.Join(s.root, BootstrapDir)
	current := filepath.Join(bundleDir, KeyBundleName)
	superseded := filepath.Join(bundleDir, KeyBundlePrefix+s.identity.Fingerprint()+".json")
	if _, err := os.Stat(current); err == nil {
		if err := os.Rename(current, superseded); err != nil {
			return fmt.Errorf("retain the superseded key bundle: %w", err)
		}
	}
	if err := writeFileAtomic(current, bundleBytes, 0o600); err != nil {
		return err
	}
	for _, name := range []string{MetaName, IndexName} {
		if err := os.Rename(filepath.Join(staged.root, name), filepath.Join(s.root, name)); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}

	for _, name := range oldNames {
		if err := os.Remove(filepath.Join(s.root, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove superseded blob %s: %w", name, err)
		}
	}
	return nil
}

// verifyStaged re-opens the staged store from disk with the new identity and
// confirms every blob is present and readable.
func verifyStaged(root string, exported []byte, want int) error {
	identity, err := pgpcrypto.ParsePrivate(exported)
	if err != nil {
		return err
	}
	check := &Store{root: root, identity: identity}
	if err := check.readMeta(); err != nil {
		return err
	}
	blobs, err := check.readAll()
	if err != nil {
		return err
	}
	if len(blobs) != want {
		return fmt.Errorf("staged %d blobs, expected %d", len(blobs), want)
	}
	return nil
}

// readAll decrypts every blob in the store. An unreadable blob is an error here,
// unlike in Reindex: a rotation that skipped one would drop a secret.
func (s *Store) readAll() ([]envelope.Envelope, error) {
	names, err := s.blobFileNames()
	if err != nil {
		return nil, err
	}
	out := make([]envelope.Envelope, 0, len(names))
	for _, name := range names {
		id := strings.TrimSuffix(name, container.Extension)
		env, err := s.readBlob(id)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		out = append(out, env)
	}
	return out, nil
}

// blobFileNames lists the blob-shaped files in the store root.
func (s *Store) blobFileNames() ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("scan store: %w", err)
	}
	var out []string
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if name == MetaName || name == IndexName || !strings.HasSuffix(name, container.Extension) {
			continue
		}
		if !LooksLikeBlobID(strings.TrimSuffix(name, container.Extension)) {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

// RewrapRecovery writes a new key bundle under a new recovery passphrase and
// retires the old one (R6.4.1 `passwd`). It changes what guards the key, not the
// key itself, so no blob changes.
func (s *Store) RewrapRecovery(newRecovery []byte) error {
	exported, err := s.identity.SerializePrivate()
	if err != nil {
		return err
	}
	bundle, err := keybundle.Seal(exported, newRecovery)
	if err != nil {
		return err
	}
	raw, err := keybundle.Marshal(bundle)
	if err != nil {
		return err
	}
	// The new bundle is written first and the old ones removed afterwards, so an
	// interruption leaves a store openable by the old passphrase rather than by
	// neither.
	if err := writeFileAtomic(filepath.Join(s.root, BootstrapDir, KeyBundleName), raw, 0o600); err != nil {
		return err
	}
	return s.PruneSupersededBundles()
}

// PruneSupersededBundles removes retained bundles, leaving only the current one.
//
// They are removed rather than kept indefinitely because each is an independent
// offline target for whichever recovery passphrase guarded it: a rotated-away
// passphrase that still opens a bundle in the store has not really been rotated
// away.
func (s *Store) PruneSupersededBundles() error {
	paths, err := bundlePaths(s.root)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if filepath.Base(path) == KeyBundleName {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

// PruneOrphans removes blob-shaped files this store's key cannot read, which is
// what an interrupted rotation leaves behind.
func (s *Store) PruneOrphans() ([]string, error) {
	names, err := s.blobFileNames()
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, name := range names {
		id := strings.TrimSuffix(name, container.Extension)
		if _, err := s.readBlob(id); err == nil {
			continue
		}
		if err := os.Remove(filepath.Join(s.root, name)); err != nil {
			return removed, fmt.Errorf("remove %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// OldKeyOpensAnything reports whether a superseded identity still decrypts
// anything in the store. It is the verification step after an identity rekey
// (R6.4.1 `doctor --old-key`): without it an operator has no way to tell a
// complete rotation from a partial one.
func OldKeyOpensAnything(root string, exported []byte) ([]string, error) {
	identity, err := pgpcrypto.ParsePrivate(exported)
	if err != nil {
		return nil, err
	}
	probe := &Store{root: root, identity: identity}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("scan store: %w", err)
	}
	var opened []string
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), container.Extension) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, de.Name()))
		if err != nil {
			continue
		}
		if _, err := probe.openContainer(raw); err == nil {
			opened = append(opened, de.Name())
		}
	}
	return opened, nil
}
