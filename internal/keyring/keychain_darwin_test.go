//go:build darwin && cgo

// These exercise the real macOS Keychain in-process. There is no mock: the claim
// is that angou can store and retrieve a secret through Security.framework, and a
// fake proves nothing about that. Isolation is a throwaway service namespace set
// per run via KeychainServiceEnv, so the tests never touch angou's own "angou"
// items, and each cleans up after itself. Because a single process both writes
// and reads, the Keychain raises no access dialog — unlike the cross-process e2e
// path, which cannot be isolated once the harness redirects HOME away from the
// login keychain (spec 003 R1.2 is covered here plus a documented manual check).
//
// A machine whose login keychain is locked or absent (headless CI) skips rather
// than fails: that is a property of the machine, not of the backend.

package keyring

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func throwawayKeychain(t *testing.T) Keyring {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	t.Setenv(KeychainServiceEnv, "angou-unit-"+hex.EncodeToString(b))

	if !Available() {
		t.Skip("the login keychain is not reachable here; this test needs it")
	}
	ring, err := Open()
	require.NoError(t, err)
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

// TestKeychainRoundTrip covers R1.1: a secret written through the backend comes
// back byte-identical, a second write replaces it, and removal is verifiable.
func TestKeychainRoundTrip(t *testing.T) {
	ring := throwawayKeychain(t)
	const storeID = "unit-store-fingerprint"
	t.Cleanup(func() { _ = ring.Remove(storeID) })

	secret := []byte("a-32-byte-unlock-secret-000000!!")
	require.NoError(t, ring.Set(storeID, secret))

	got, err := ring.Get(storeID)
	require.NoError(t, err)
	require.True(t, bytes.Equal(got, secret), "round-trip must return the secret unchanged")

	// Set replaces rather than duplicating.
	secret2 := []byte("a-different-unlock-secret-11111!!")
	require.NoError(t, ring.Set(storeID, secret2))
	got2, err := ring.Get(storeID)
	require.NoError(t, err)
	require.True(t, bytes.Equal(got2, secret2), "a second Set must replace the first")

	require.NoError(t, ring.Remove(storeID))
	_, err = ring.Get(storeID)
	require.ErrorIs(t, err, ErrNoEntry, "after Remove, Get must report ErrNoEntry")
}

// TestKeychainGetMissingIsErrNoEntry covers the "reachable backend, no entry"
// state that R2.4 requires the tool to detect and explain.
func TestKeychainGetMissingIsErrNoEntry(t *testing.T) {
	ring := throwawayKeychain(t)
	_, err := ring.Get("never-written-store")
	require.ErrorIs(t, err, ErrNoEntry)
}

// TestKeychainRemoveAbsentIsNoError covers that clearing an entry that is not
// there succeeds: the point of Remove is to leave nothing behind.
func TestKeychainRemoveAbsentIsNoError(t *testing.T) {
	ring := throwawayKeychain(t)
	require.NoError(t, ring.Remove("never-written-store"))
}

// TestBackendNoneForcesNoKeyring covers the cross-platform disable knob and the
// e2e no-keyring gate: with it set, the backend reports unavailable and Open
// fails the way a missing keyring does, so the caller falls back to the recovery
// passphrase.
func TestBackendNoneForcesNoKeyring(t *testing.T) {
	t.Setenv(BackendEnv, BackendNone)
	require.False(t, Available(), "BackendNone must report no keyring")
	_, err := Open()
	require.ErrorIs(t, err, ErrUnavailable, "BackendNone must make Open report ErrUnavailable")
}
