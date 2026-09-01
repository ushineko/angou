package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ushineko/angou/internal/keybundle"
)

// KeyBundlePrefix names a superseded bundle, retained until pruned.
//
// More than one bundle can be present at once, and that is what makes rotation
// survivable rather than a moment of risk. An identity rekey has to replace both
// the key bundle and store.angou, which cannot be done in one atomic step on a
// plain directory: whichever is written first, a crash in between would leave a
// store whose metadata the available key cannot read. Keeping the superseded
// bundle means the reader simply tries each one, so the window is recoverable
// instead of fatal (spec 001 R4.3, R6.4.1).
const KeyBundlePrefix = "keybundle-"

// ErrNoUsableBundle reports that no key bundle in the store opens it.
var ErrNoUsableBundle = errors.New("no key bundle opens this store")

// bundlePaths lists the current bundle first, then any superseded ones, newest
// name first for determinism.
func bundlePaths(root string) ([]string, error) {
	dir := filepath.Join(root, BootstrapDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: no %s directory under %s", ErrNotAStore, BootstrapDir, root)
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var superseded []string
	current := ""
	for _, de := range entries {
		name := de.Name()
		switch {
		case name == KeyBundleName:
			current = filepath.Join(dir, name)
		case strings.HasPrefix(name, KeyBundlePrefix) && strings.HasSuffix(name, ".json"):
			superseded = append(superseded, filepath.Join(dir, name))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(superseded)))

	var out []string
	if current != "" {
		out = append(out, current)
	}
	return append(out, superseded...), nil
}

// openIdentityFor returns the exported identity from whichever bundle actually
// opens this store's metadata blob.
//
// Trying each bundle rather than trusting the current one is what carries a
// reader through an interrupted rotation. It costs one Argon2id derivation per
// candidate, which is why superseded bundles are pruned rather than kept
// indefinitely.
func openIdentityFor(root string, recovery []byte) ([]byte, error) {
	paths, err := bundlePaths(root)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%w: no key bundle under %s", ErrNotAStore, root)
	}

	// When there is no metadata blob to test against — a store mid-init, or a
	// damaged one — the best available answer is the first bundle the
	// passphrase opens.
	metaRaw, err := os.ReadFile(filepath.Join(root, MetaName))
	requireMetaMatch := err == nil

	var lastErr error
	for _, path := range paths {
		exported, err := readBundle(path, recovery)
		if err != nil {
			lastErr = err
			continue
		}
		if !requireMetaMatch || identityOpens(exported, metaRaw) {
			return exported, nil
		}
		lastErr = fmt.Errorf("%w: %s does not open %s", ErrNoUsableBundle, filepath.Base(path), MetaName)
	}
	if lastErr == nil {
		lastErr = ErrNoUsableBundle
	}
	return nil, lastErr
}

// ExportIdentityByFingerprint recovers a specific identity from whichever
// retained bundle carries it, so a superseded key can be checked against the
// store after a rotation.
func ExportIdentityByFingerprint(root, fingerprint string, recovery []byte) ([]byte, error) {
	paths, err := bundlePaths(root)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		exported, err := readBundle(path, recovery)
		if err != nil {
			continue
		}
		id, err := parseIdentity(exported)
		if err != nil {
			continue
		}
		if id.Fingerprint() == fingerprint {
			return exported, nil
		}
	}
	return nil, fmt.Errorf("%w: no retained key bundle under %s carries the key %s",
		ErrNoUsableBundle, root, fingerprint)
}

func readBundle(path string, recovery []byte) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	bundle, err := keybundle.Unmarshal(raw)
	if err != nil {
		return nil, err
	}
	return bundle.Open(recovery)
}

// identityOpens reports whether an exported identity decrypts the metadata blob.
func identityOpens(exported, metaRaw []byte) bool {
	s := &Store{}
	id, err := parseIdentity(exported)
	if err != nil {
		return false
	}
	s.identity = id
	_, err = s.openContainer(metaRaw)
	return err == nil
}
