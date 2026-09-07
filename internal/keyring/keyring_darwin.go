//go:build darwin && cgo

// This backend talks to the macOS Keychain through Security.framework, which is
// a C API, so it is built with cgo. That is the reason the darwin CLI links
// libSystem's Security framework where the Linux CLI stays CGO-free: there is no
// pure-Go path to the Keychain, and the Keychain is what lets a Mac stop asking
// for the recovery passphrase on every command (spec 003 R1.3). The no-cgo
// darwin build (keyring_darwin_nocgo.go) keeps the old stub, so a darwin CLI
// cross-compiled from a Linux release box is still a recovery-capable artifact —
// it simply has no keyring, which is the state bootstrap exists to leave behind.

package keyring

import (
	"errors"
	"fmt"
	"os"

	gokeychain "github.com/keybase/go-keychain"
)

// keychainLabel is what the Keychain Access app shows a human browsing the
// login keychain. The service and account carry the addressing; this is only a
// description, and names no secret.
const keychainLabel = "angou store unlock passphrase"

// serviceName is the Keychain service angou's items are grouped under: Folder by
// default, or the value of KeychainServiceEnv when set. Every read and write
// goes through it so a caller that overrides the namespace overrides it wholly.
func serviceName() string {
	if s := os.Getenv(KeychainServiceEnv); s != "" {
		return s
	}
	return Folder
}

// keychain is the macOS Keychain backend. It holds no connection: SecItem calls
// address the login keychain directly, so there is nothing to keep open or to
// close. The type exists to satisfy the Keyring interface.
type keychain struct{}

// Open reports the Keychain backend, or ErrUnavailable when the login keychain
// cannot be reached.
//
// There is no persistent handle to acquire; Open exists to fail here, once, the
// way the Linux backend fails when no bus is reachable, rather than deferring
// the failure to the first Get. The probe in Available prompts for nothing.
func Open() (Keyring, error) {
	if !Available() {
		return nil, ErrUnavailable
	}
	return &keychain{}, nil
}

// Available reports whether the login keychain answers, without prompting.
//
// It queries for an item that does not exist: a reachable keychain returns
// errSecItemNotFound and raises no dialog, while a keychain that cannot be
// reached returns some other error — the case R1.5 degrades to the recovery
// passphrase rather than hanging on.
func Available() bool {
	if os.Getenv(BackendEnv) == BackendNone {
		return false
	}
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(serviceName())
	query.SetAccount("angou-availability-probe")
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnData(false)
	_, err := gokeychain.QueryItem(query)
	return err == nil || errors.Is(err, gokeychain.ErrorItemNotFound)
}

// ValidateBackend accepts anything: macOS has one backend, the Keychain, so the
// ANGOU_KEYRING selector — which exists for the Linux Secret Service / KWallet
// choice — has nothing to select between here.
func ValidateBackend() error { return nil }

// Get returns the unlock passphrase for a store, or ErrNoEntry.
func (k *keychain) Get(storeID string) ([]byte, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(serviceName())
	query.SetAccount(EntryName(storeID))
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := gokeychain.QueryItem(query)
	if err != nil {
		if errors.Is(err, gokeychain.ErrorItemNotFound) {
			return nil, ErrNoEntry
		}
		return nil, fmt.Errorf("read keychain item: %w", err)
	}
	if len(results) == 0 || len(results[0].Data) == 0 {
		return nil, ErrNoEntry
	}
	return results[0].Data, nil
}

// Set writes the unlock passphrase, replacing any existing entry.
//
// The Keychain refuses a second item with the same service and account
// (errSecDuplicateItem) rather than overwriting, so a replace is add-or-update:
// the caller does not know or care which store visits are first, and R2.2 makes
// the keyring entry the only copy, so a Set that silently failed to replace
// would leave the old secret wrapping a key it no longer matches.
func (k *keychain) Set(storeID string, secret []byte) error {
	item := gokeychain.NewGenericPassword(serviceName(), EntryName(storeID), keychainLabel, secret, "")
	item.SetSynchronizable(gokeychain.SynchronizableNo)
	item.SetAccessible(gokeychain.AccessibleWhenUnlocked)

	err := gokeychain.AddItem(item)
	if errors.Is(err, gokeychain.ErrorDuplicateItem) {
		query := gokeychain.NewItem()
		query.SetSecClass(gokeychain.SecClassGenericPassword)
		query.SetService(serviceName())
		query.SetAccount(EntryName(storeID))

		update := gokeychain.NewItem()
		update.SetData(secret)
		if err := gokeychain.UpdateItem(query, update); err != nil {
			return fmt.Errorf("update keychain item: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("write keychain item: %w", err)
	}
	return nil
}

// Remove deletes the entry. Removing an absent entry is not an error, but a
// removal that failed for any other reason must not be reported as success:
// the paths that call this claim to have cleared the unlock passphrase, and
// acting on a false claim leaves it in the keychain after the key it protects
// is gone.
func (k *keychain) Remove(storeID string) error {
	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(serviceName())
	item.SetAccount(EntryName(storeID))

	err := gokeychain.DeleteItem(item)
	if err == nil || errors.Is(err, gokeychain.ErrorItemNotFound) {
		return nil
	}
	return fmt.Errorf("remove keychain item: %w", err)
}

// Close releases nothing: the backend holds no connection.
func (k *keychain) Close() error { return nil }
