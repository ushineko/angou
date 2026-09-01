// Package store implements blob addressing, the store metadata blob, the
// rebuildable index, and safe extraction (spec 001 R3).
//
// The store is a plain directory of opaque blobs with no database, so that it
// survives rsync, Dropbox, and removable media (R3.1).
package store

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ushineko/angou/internal/envelope"
	"github.com/ushineko/angou/internal/keybundle"
	"github.com/ushineko/angou/internal/pgpcrypto"
	"github.com/ushineko/angou/lib/container"
)

const (
	// MetaName is the fixed-name blob holding K_name and store-wide records
	// (R3.3).
	MetaName = "store" + container.Extension
	// IndexName is the rebuildable listing cache (R3.6).
	IndexName = "index" + container.Extension
	// BootstrapDir holds the key bundle and, in a later pass, the release
	// binaries (R5.1).
	BootstrapDir = "bootstrap"
	// KeyBundleName is the symmetrically-encrypted identity export.
	KeyBundleName = "keybundle.json"
)

var (
	// ErrNotAStore reports a directory that does not hold an angou store.
	ErrNotAStore = errors.New("not an angou store")
	// ErrNoSuchPath reports a logical path absent from the store.
	ErrNoSuchPath = errors.New("no such path in store")
	// ErrNameBinding reports a blob whose filename does not match the HMAC of
	// its own envelope path (R1.8).
	ErrNameBinding = errors.New("blob filename does not match its envelope path")
	// ErrUnsafeExtract reports a destination that escapes the extraction root.
	ErrUnsafeExtract = errors.New("refusing to write outside the destination root")
)

// Meta is the plaintext of store.angou.
type Meta struct {
	NameKey []byte `json:"name_key"`
	// BootstrapSHA256 is the recorded digest of bootstrap.sh (R5.8). It is
	// written by a later pass; an empty value means no record exists yet.
	BootstrapSHA256 string `json:"bootstrap_sha256,omitempty"`
	// VersionFloor is the highest release version ever installed from this
	// store (R5.4.2), likewise populated by a later pass.
	VersionFloor string `json:"version_floor,omitempty"`
}

// IndexEntry is one row of the listing cache.
type IndexEntry struct {
	Path  string   `json:"path"`
	MIME  string   `json:"mime"`
	Size  int64    `json:"size"`
	MTime int64    `json:"mtime"`
	Mode  uint32   `json:"mode"`
	Tags  []string `json:"tags,omitempty"`
}

// Index maps blob_id to entry.
type Index struct {
	Entries map[string]IndexEntry `json:"entries"`
}

// Store is an opened store.
type Store struct {
	root     string
	identity *pgpcrypto.Identity
	meta     Meta
	index    Index
	// IndexTrusted is false when the on-disk index was absent, unreadable, or
	// failed verification and was rebuilt or emptied. Callers surface this;
	// it degrades browsing only, never retrieval, because retrieval addresses
	// blobs through R3.2 (R3.7).
	IndexTrusted bool
	// SkippedOnReindex lists files the last rebuild ignored because their names
	// are not blob names. They are usually sync-service debris and are worth
	// showing the user, who is the only one who can decide to delete them.
	SkippedOnReindex []string
	// UnreadableOnReindex lists blob-shaped files the last rebuild could not
	// decrypt. They belong to a different key — most often a superseded one
	// after an identity rekey — and are reported so the user can prune them.
	UnreadableOnReindex []string
}

// Root returns the store directory.
func (s *Store) Root() string { return s.root }

// Fingerprint returns the store identity fingerprint.
func (s *Store) Fingerprint() string { return s.identity.Fingerprint() }

// Init creates a new store: a fresh identity, a fresh K_name, a key bundle
// under the recovery passphrase, and an empty index.
func Init(root string, recovery []byte) (*Store, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}
	if _, err := os.Stat(filepath.Join(root, MetaName)); err == nil {
		return nil, fmt.Errorf("%s already holds a store", root)
	}

	identity, err := pgpcrypto.Generate("angou", "angou@localhost")
	if err != nil {
		return nil, err
	}
	exported, err := identity.SerializePrivate()
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
	if err := os.MkdirAll(filepath.Join(root, BootstrapDir), 0o700); err != nil {
		return nil, fmt.Errorf("create bootstrap namespace: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(root, BootstrapDir, KeyBundleName), bundleBytes, 0o600); err != nil {
		return nil, err
	}

	nameKey := make([]byte, NameKeyLen)
	if _, err := rand.Read(nameKey); err != nil {
		return nil, fmt.Errorf("generate naming key: %w", err)
	}

	s := &Store{
		root:         root,
		identity:     identity,
		meta:         Meta{NameKey: nameKey},
		index:        Index{Entries: map[string]IndexEntry{}},
		IndexTrusted: true,
	}
	if err := s.writeMeta(); err != nil {
		return nil, err
	}
	if err := s.writeIndex(); err != nil {
		return nil, err
	}
	return s, nil
}

// ExportIdentity returns the serialized identity from whichever key bundle opens
// this store. Bootstrap needs the bytes, not just a usable identity, because it
// re-wraps them under the unlock passphrase.
func ExportIdentity(root string, recovery []byte) ([]byte, error) {
	return openIdentityFor(root, recovery)
}

// parseIdentity is the seam bundles.go uses to test a candidate identity.
func parseIdentity(exported []byte) (*pgpcrypto.Identity, error) {
	return pgpcrypto.ParsePrivate(exported)
}

// Open unlocks a store with the recovery passphrase. This is the path taken
// before bootstrap, and the only path on a machine with no keyring backend
// (R2.5).
func Open(root string, recovery []byte) (*Store, error) {
	exported, err := ExportIdentity(root, recovery)
	if err != nil {
		return nil, err
	}
	return OpenWithExportedIdentity(root, exported)
}

// OpenWithExportedIdentity unlocks a store from an identity already recovered by
// other means — in practice the machine-local copy, unwrapped with the unlock
// passphrase from the keyring.
func OpenWithExportedIdentity(root string, exported []byte) (*Store, error) {
	identity, err := pgpcrypto.ParsePrivate(exported)
	if err != nil {
		return nil, err
	}

	s := &Store{root: root, identity: identity}
	if err := s.readMeta(); err != nil {
		return nil, err
	}
	s.readIndexBestEffort()
	return s, nil
}

func (s *Store) writeMeta() error {
	raw, err := json.Marshal(s.meta)
	if err != nil {
		return fmt.Errorf("encode store metadata: %w", err)
	}
	blob, err := s.sealContainer(raw, container.EncodingArmor)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.root, MetaName), blob, 0o600)
}

func (s *Store) readMeta() error {
	raw, err := os.ReadFile(filepath.Join(s.root, MetaName))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: no %s under %s", ErrNotAStore, MetaName, s.root)
		}
		return fmt.Errorf("read %s: %w", MetaName, err)
	}
	plaintext, err := s.openContainer(raw)
	if err != nil {
		return fmt.Errorf("open %s: %w", MetaName, err)
	}
	if err := json.Unmarshal(plaintext, &s.meta); err != nil {
		return fmt.Errorf("parse store metadata: %w", err)
	}
	if len(s.meta.NameKey) != NameKeyLen {
		return fmt.Errorf("%w: naming key is %d bytes", ErrNotAStore, len(s.meta.NameKey))
	}
	return nil
}

// ExportLocalIdentity serializes the unlocked identity, for re-wrapping under a
// fresh unlock passphrase.
func (s *Store) ExportLocalIdentity() ([]byte, error) {
	return s.identity.SerializePrivate()
}

// Meta returns a copy of the store metadata.
func (s *Store) Meta() Meta { return s.meta }

func (s *Store) sealContainer(plaintext []byte, enc container.Encoding) ([]byte, error) {
	payload, err := s.identity.Seal(plaintext, enc == container.EncodingArmor)
	if err != nil {
		return nil, err
	}
	return container.Marshal(container.Blob{Encoding: enc, Payload: payload})
}

func (s *Store) openContainer(raw []byte) ([]byte, error) {
	blob, err := container.Unmarshal(raw)
	if err != nil {
		return nil, err
	}
	// The encoding comes from the header; it is never sniffed (R1.2).
	return s.identity.Open(blob.Payload, blob.Encoding == container.EncodingArmor)
}

// BlobID returns the on-disk name for a logical path under this store.
func (s *Store) BlobID(logicalPath string) (string, error) {
	return BlobID(s.meta.NameKey, logicalPath)
}

func (s *Store) blobPath(id string) string {
	return filepath.Join(s.root, id+container.Extension)
}

// Put writes content at a logical path. Because blob_id is deterministic, a
// second write to the same path lands on the same file and leaves no orphan
// (R3.2).
func (s *Store) Put(logicalPath string, content []byte, mode uint32, mtime int64, mime string, enc container.Encoding) (string, error) {
	normalized, err := NormalizePath(logicalPath)
	if err != nil {
		return "", err
	}
	id, err := s.BlobID(normalized)
	if err != nil {
		return "", err
	}
	env := envelope.New(normalized, mime, mode, mtime, content)
	raw, err := envelope.Marshal(env)
	if err != nil {
		return "", err
	}
	blob, err := s.sealContainer(raw, enc)
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(s.blobPath(id), blob, 0o600); err != nil {
		return "", err
	}
	s.index.Entries[id] = entryFromEnvelope(env)
	return id, s.writeIndex()
}

// Get retrieves the envelope stored at a logical path. It addresses the blob
// through R3.2 and so is unaffected by a missing or corrupt index (R3.7).
func (s *Store) Get(logicalPath string) (envelope.Envelope, error) {
	normalized, err := NormalizePath(logicalPath)
	if err != nil {
		return envelope.Envelope{}, err
	}
	id, err := s.BlobID(normalized)
	if err != nil {
		return envelope.Envelope{}, err
	}
	return s.readBlob(id)
}

// readBlob decrypts, verifies, and checks the name binding of one blob.
func (s *Store) readBlob(id string) (envelope.Envelope, error) {
	raw, err := os.ReadFile(s.blobPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return envelope.Envelope{}, ErrNoSuchPath
		}
		return envelope.Envelope{}, fmt.Errorf("read blob: %w", err)
	}
	plaintext, err := s.openContainer(raw)
	if err != nil {
		return envelope.Envelope{}, err
	}
	env, err := envelope.Unmarshal(plaintext)
	if err != nil {
		return envelope.Envelope{}, err
	}
	// R1.8: the filename must equal the HMAC of the envelope path. Without this
	// an attacker who can rename files in the store serves one secret under the
	// name of another — every signature verifies and every digest matches, and
	// the wrong secret comes back with no error.
	want, err := s.BlobID(env.Path)
	if err != nil {
		return envelope.Envelope{}, err
	}
	if want != id {
		return envelope.Envelope{}, fmt.Errorf("%w: %s claims path %q which addresses %s", ErrNameBinding, id, env.Path, want)
	}
	return env, nil
}

// Remove deletes the blob at a logical path.
func (s *Store) Remove(logicalPath string) error {
	normalized, err := NormalizePath(logicalPath)
	if err != nil {
		return err
	}
	id, err := s.BlobID(normalized)
	if err != nil {
		return err
	}
	if err := os.Remove(s.blobPath(id)); err != nil {
		if os.IsNotExist(err) {
			return ErrNoSuchPath
		}
		return fmt.Errorf("remove blob: %w", err)
	}
	delete(s.index.Entries, id)
	return s.writeIndex()
}

// Move re-addresses a blob under a new logical path. The blob is rewritten
// rather than renamed, because the envelope path is part of the signed
// plaintext and must change with the name (R1.8).
func (s *Store) Move(from, to string) error {
	env, err := s.Get(from)
	if err != nil {
		return err
	}
	normalized, err := NormalizePath(to)
	if err != nil {
		return err
	}
	if _, err := s.Put(normalized, env.Content, env.Mode, env.MTime, env.MIME, container.EncodingArmor); err != nil {
		return err
	}
	return s.Remove(from)
}

// List returns the index entries, sorted by logical path.
func (s *Store) List() []IndexEntry {
	out := make([]IndexEntry, 0, len(s.index.Entries))
	for _, e := range s.index.Entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Reindex rebuilds the index from blob envelopes, which are authoritative
// (R3.7). A blob whose envelope path does not address its own filename is
// refused rather than indexed.
func (s *Store) Reindex() error {
	names, err := os.ReadDir(s.root)
	if err != nil {
		return fmt.Errorf("scan store: %w", err)
	}
	rebuilt := Index{Entries: map[string]IndexEntry{}}
	var skipped, unreadable []string
	for _, de := range names {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if name == MetaName || name == IndexName || !strings.HasSuffix(name, container.Extension) {
			continue
		}
		id := strings.TrimSuffix(name, container.Extension)
		if !LooksLikeBlobID(id) {
			// Not a blob: a sync service's conflicted copy, an editor backup, or
			// something a user dropped in. Report it and move on rather than
			// aborting the rebuild (R3.7).
			skipped = append(skipped, name)
			continue
		}
		env, err := s.readBlob(id)
		switch {
		case errors.Is(err, ErrNameBinding):
			// A blob this key can read, filed under a name its own envelope
			// does not address. That is the R1.8 substitution, and indexing it
			// would file one secret under another's name — so the rebuild stops
			// rather than recording it.
			return fmt.Errorf("reindex %s: %w", name, err)
		case err != nil:
			// A blob this key cannot read at all is not this store's blob: a
			// leftover from an interrupted identity rekey, another machine's
			// conflicted copy, or something a user dropped in. Report it and
			// carry on, or a rekey interrupted at the wrong moment would leave
			// the store unindexable (R4.3).
			unreadable = append(unreadable, name)
			continue
		}
		rebuilt.Entries[id] = entryFromEnvelope(env)
	}
	s.index = rebuilt
	s.IndexTrusted = true
	s.SkippedOnReindex = skipped
	s.UnreadableOnReindex = unreadable
	return s.writeIndex()
}

func entryFromEnvelope(e envelope.Envelope) IndexEntry {
	return IndexEntry{Path: e.Path, MIME: e.MIME, Size: e.Size, MTime: e.MTime, Mode: e.Mode}
}

func (s *Store) writeIndex() error {
	raw, err := json.Marshal(s.index)
	if err != nil {
		return fmt.Errorf("encode index: %w", err)
	}
	blob, err := s.sealContainer(raw, container.EncodingArmor)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.root, IndexName), blob, 0o600)
}

// readIndexBestEffort loads the index, treating every failure as a cache miss.
// An index that decrypts but does not verify is refused outright rather than
// trusted, per the acceptance criteria: it is attacker-controlled if anyone can
// write to the store.
func (s *Store) readIndexBestEffort() {
	s.index = Index{Entries: map[string]IndexEntry{}}
	s.IndexTrusted = false

	raw, err := os.ReadFile(filepath.Join(s.root, IndexName))
	if err != nil {
		return
	}
	plaintext, err := s.openContainer(raw)
	if err != nil {
		return
	}
	var idx Index
	if err := json.Unmarshal(plaintext, &idx); err != nil {
		return
	}
	if idx.Entries == nil {
		idx.Entries = map[string]IndexEntry{}
	}
	s.index = idx
	s.IndexTrusted = true
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".angou-tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()

	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("set mode: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit %s: %w", path, err)
	}
	return nil
}
