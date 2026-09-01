// Package keyring stores the unlock passphrase in the platform's secret store.
//
// The unlock passphrase is 32 bytes from a CSPRNG, generated at bootstrap, never
// displayed, and wrapping the local copy of the store identity (spec 001 R2.2).
// The keyring entry is its only copy (R2.4), which makes the local keyring
// disposable derived state: losing the entry is recovered by re-running
// bootstrap, not by any local means.
//
// Platform backends are split by build constraint so a new one is a new file
// rather than a refactor (R6.6).
package keyring

import "errors"

var (
	// ErrUnavailable reports that no keyring backend is reachable on this
	// machine — headless, non-KDE, or a platform without a backend yet. The
	// caller falls back to the recovery passphrase (R2.5).
	ErrUnavailable = errors.New("no keyring backend is available")
	// ErrNoEntry reports that the backend is reachable but holds no entry.
	// Distinct from ErrUnavailable: this is the "key present, wallet entry
	// absent" state R2.4 requires the tool to detect and explain.
	ErrNoEntry = errors.New("no keyring entry for this store")
)

// Keyring is a platform secret store.
type Keyring interface {
	// Get returns the unlock passphrase for a store, or ErrNoEntry.
	Get(storeID string) ([]byte, error)
	// Set writes the unlock passphrase for a store, replacing any existing one.
	Set(storeID string, secret []byte) error
	// Remove deletes the entry. Removing an absent entry is not an error.
	Remove(storeID string) error
	// Close releases the backend connection.
	Close() error
}

// Folder is the KWallet folder, and the equivalent grouping elsewhere, that
// angou confines itself to.
const Folder = "angou"

// EntryName builds the per-store entry key. A machine may hold several stores,
// so the identity fingerprint rather than a fixed name selects the entry.
func EntryName(storeID string) string { return "unlock-" + storeID }
