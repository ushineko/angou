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
	// ErrBadBackend reports a keyring backend selected by name that does not
	// exist. It is deliberately not ErrUnavailable: a user who pinned a backend
	// and mistyped it must be told, rather than have angou quietly decide the
	// machine has no keyring and fall back to asking for a passphrase forever.
	ErrBadBackend = errors.New("unknown keyring backend")
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

// WalletEnv names the wallet to use instead of the session's default one.
//
// It exists so the end-to-end suite can operate a wallet of its own and delete
// it afterwards, rather than writing into the wallet the user keeps their real
// secrets in. It selects a namespace and changes no protection, so it is also a
// reasonable thing for a user to set deliberately.
const WalletEnv = "ANGOU_KWALLET"

// EntryName builds the per-store entry key. A machine may hold several stores,
// so the identity fingerprint rather than a fixed name selects the entry.
func EntryName(storeID string) string { return "unlock-" + storeID }
