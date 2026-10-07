//go:build windows

// These exercise the real Windows Credential Manager in-process. There is no
// mock: the claim is that angou can store and retrieve a secret through
// advapi32, and a fake proves nothing about that. Isolation is a store ID drawn
// from crypto/rand per test, so every entry written has a target name no real
// store has, and each test removes what it wrote.
//
// A session with no credential vault (a network logon over ssh) skips rather
// than fails: that is a property of the session, not of the backend.

package keyring

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func throwawayCredManager(t *testing.T) (Keyring, string) {
	t.Helper()
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)
	storeID := "unit-" + hex.EncodeToString(b)

	if !Available() {
		t.Skip("the Credential Manager vault is not reachable in this logon session")
	}
	ring, err := Open()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = ring.Remove(storeID)
		_ = ring.Close()
	})
	return ring, storeID
}

func TestCredManagerRoundTrip(t *testing.T) {
	ring, storeID := throwawayCredManager(t)

	secret := []byte("a-32-byte-unlock-secret-000000!!")
	require.NoError(t, ring.Set(storeID, secret))
	got, err := ring.Get(storeID)
	require.NoError(t, err)
	require.True(t, bytes.Equal(got, secret), "round-trip must return the secret unchanged")

	secret2 := []byte("a-different-unlock-secret-11111!!")
	require.NoError(t, ring.Set(storeID, secret2))
	got2, err := ring.Get(storeID)
	require.NoError(t, err)
	require.True(t, bytes.Equal(got2, secret2), "a second Set must replace the first")

	require.NoError(t, ring.Remove(storeID))
	_, err = ring.Get(storeID)
	require.ErrorIs(t, err, ErrNoEntry, "after Remove, Get must report ErrNoEntry")
}

func TestCredManagerGetMissingIsErrNoEntry(t *testing.T) {
	ring, storeID := throwawayCredManager(t)
	_, err := ring.Get(storeID)
	require.ErrorIs(t, err, ErrNoEntry)
}

func TestCredManagerRemoveAbsentIsNoError(t *testing.T) {
	ring, storeID := throwawayCredManager(t)
	require.NoError(t, ring.Remove(storeID))
}

func TestCredManagerRejectsOversizedSecret(t *testing.T) {
	ring, storeID := throwawayCredManager(t)
	require.Error(t, ring.Set(storeID, make([]byte, credMaxBlobSize+1)))
	require.Error(t, ring.Set(storeID, nil))
}

func TestBackendNoneForcesNoKeyring(t *testing.T) {
	t.Setenv(BackendEnv, BackendNone)
	require.False(t, Available(), "BackendNone must report no keyring")
	_, err := Open()
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestValidateBackendRejectsLinuxNames(t *testing.T) {
	t.Setenv(BackendEnv, BackendKWallet)
	require.ErrorIs(t, ValidateBackend(), ErrBadBackend)
	t.Setenv(BackendEnv, BackendNone)
	require.NoError(t, ValidateBackend())
}
