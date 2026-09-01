//go:build e2e

package e2e

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
)

// keyringEnv builds an environment whose child can reach the real kwalletd6, and
// registers cleanup that removes whatever entry the run created.
//
// The entry name carries the store's identity fingerprint, which is freshly
// generated per run, so a test can never collide with — or overwrite — an entry
// belonging to the developer's own store (spec 001 R8.5).
func keyringEnv(t *testing.T) *env {
	t.Helper()
	requireKeyring(t)

	e := newEnv(t)
	e.withKeyring = true

	// localkey resolves its directory from XDG_DATA_HOME at call time, so point
	// this process at the child's tree. Without it the helpers below would look
	// for the child's local key under the developer's own data directory — and
	// find nothing.
	t.Setenv("XDG_DATA_HOME", filepath.Join(e.home, ".local", "share"))

	t.Cleanup(func() { removeTestEntry(t, e) })
	return e
}

// requireKeyring skips when no session bus is reachable. This is a skip rather
// than a failure because a keyring is a property of the machine running the
// suite, unlike the HOME guard, which is a property of the suite itself.
func requireKeyring(t *testing.T) {
	t.Helper()
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("no session bus: this test needs a live kwalletd6")
	}
	ring, err := keyring.Open()
	if err != nil {
		t.Skipf("no reachable keyring backend: %v", err)
	}
	_ = ring.Close()
}

// removeTestEntry deletes the run's wallet entry, so the suite leaves the
// developer's wallet as it found it.
func removeTestEntry(t *testing.T, e *env) {
	t.Helper()
	if !localkey.Exists(e.store) {
		return
	}
	fingerprint, err := localkey.Fingerprint(e.store)
	if err != nil {
		return
	}
	ring, err := keyring.Open()
	if err != nil {
		return
	}
	defer func() { _ = ring.Close() }()
	if err := ring.Remove(fingerprint); err != nil {
		t.Errorf("could not remove the test keyring entry for %s: %v", fingerprint, err)
		return
	}
	// Verify rather than assume. A removal that silently failed would leave an
	// entry in the developer's own wallet, which is the isolation failure R8.5
	// exists to prevent.
	if _, err := ring.Get(fingerprint); !errors.Is(err, keyring.ErrNoEntry) {
		t.Errorf("the test keyring entry for %s survived cleanup (Get returned %v)", fingerprint, err)
	}
}

// TestBootstrapRemovesTheNeedForTheRecoveryPassphrase is the point of the
// keyring: after bootstrap, the machine opens the store on its own.
func TestBootstrapRemovesTheNeedForTheRecoveryPassphrase(t *testing.T) {
	e := keyringEnv(t)
	e.initStore()
	e.mustRun("bootstrap")

	// Every command below runs with no passphrase source at all. If any of them
	// still needed one it would fail rather than silently prompt, because the
	// harness gives the child no terminal.
	src := e.writePlaintext("k.env", []byte("FIELD=value\n"), 0o600)
	e.mustRunNoPassphrase("enc", "--as", "k.env", src)
	require.Contains(t, e.mustRunNoPassphrase("ls").stdout, "k.env")
	require.Equal(t, "FIELD=value\n", e.mustRunNoPassphrase("dec", "k.env").stdout)
}

// TestBootstrapIsIdempotentlyGuarded checks that a second bootstrap does not
// quietly replace working local state.
func TestBootstrapIsIdempotentlyGuarded(t *testing.T) {
	e := keyringEnv(t)
	e.initStore()
	e.mustRun("bootstrap")

	r := e.run("bootstrap")
	require.NotZero(t, r.code, "a second bootstrap must not silently replace local state")
	require.Contains(t, r.stderr, "--force")

	e.mustRun("bootstrap", "--force")
	require.Contains(t, e.mustRunNoPassphrase("ls").stderr, "")
}

// TestTwoBootstrapsProduceDifferentUnlockPassphrases covers R2.2: the unlock
// passphrase is drawn per machine, not derived from the store or the host.
func TestTwoBootstrapsProduceDifferentUnlockPassphrases(t *testing.T) {
	e := keyringEnv(t)
	e.initStore()

	e.mustRun("bootstrap")
	first := readLocalKeyFile(t, e)

	e.mustRun("bootstrap", "--force")
	second := readLocalKeyFile(t, e)

	require.NotEqual(t, first, second,
		"re-bootstrapping must re-wrap the identity under a fresh unlock passphrase")
}

// TestUnlockPassphraseIsNeverDisclosed covers the acceptance criterion that the
// unlock passphrase appears in no output and no file but the keyring entry.
func TestUnlockPassphraseIsNeverDisclosed(t *testing.T) {
	e := keyringEnv(t)
	e.initStore()
	r := e.mustRun("bootstrap")

	fingerprint, err := localkey.Fingerprint(e.store)
	require.NoError(t, err)

	ring, err := keyring.Open()
	require.NoError(t, err)
	defer func() { _ = ring.Close() }()
	secret, err := ring.Get(fingerprint)
	require.NoError(t, err)
	require.Len(t, secret, localkey.UnlockPassphraseLen)

	// The passphrase is raw random bytes; look for it in every encoding a leak
	// would plausibly take.
	for _, form := range encodings(secret) {
		require.NotContains(t, r.stdout, form, "the unlock passphrase must not reach stdout")
		require.NotContains(t, r.stderr, form, "the unlock passphrase must not reach stderr")
		for _, path := range filesUnder(t, e.home) {
			require.NotContains(t, string(readFile(t, path)), form,
				"the unlock passphrase must not appear in %s", path)
		}
		for _, path := range filesUnder(t, e.store) {
			require.NotContains(t, string(readFile(t, path)), form,
				"the unlock passphrase must not appear in the store at %s", path)
		}
	}
}

// TestMissingKeyringEntryIsExplained covers R2.4. The keyring entry is the only
// copy of the unlock passphrase, so losing it is unrecoverable locally — and the
// tool must say that rather than prompt for something the user was never told.
func TestMissingKeyringEntryIsExplained(t *testing.T) {
	e := keyringEnv(t)
	e.initStore()
	e.mustRun("bootstrap")

	fingerprint, err := localkey.Fingerprint(e.store)
	require.NoError(t, err)
	ring, err := keyring.Open()
	require.NoError(t, err)
	require.NoError(t, ring.Remove(fingerprint))
	require.NoError(t, ring.Close())

	r := e.runNoPassphrase("ls")
	require.NotZero(t, r.code, "the tool must not proceed with an unopenable local key")
	require.Contains(t, r.stderr, "bootstrap --force",
		"the user must be told how to recover")
	require.NotContains(t, strings.ToLower(r.stderr), "recovery passphrase:",
		"the tool must not issue a passphrase prompt the user cannot answer")

	// doctor reports the same state without being asked to do anything else.
	d := e.runNoPassphrase("doctor")
	require.Contains(t, d.stdout, "MISSING")
}

// TestBootstrapWithoutAKeyringChangesNothing covers R2.5: where no backend is
// reachable, bootstrap reports that and leaves the store on the recovery
// passphrase rather than half-configuring the machine.
func TestBootstrapWithoutAKeyringChangesNothing(t *testing.T) {
	e := newEnv(t) // withKeyring stays false: the child gets no session bus.
	e.initStore()

	r := e.mustRun("bootstrap")
	require.Contains(t, r.stderr, "No keyring is available")
	require.Contains(t, r.stderr, "recovery passphrase")
	require.False(t, localkey.Exists(e.store), "no local key may be written without a keyring")

	// And the store is still fully usable by the recovery route.
	src := e.writePlaintext("n.env", []byte("FIELD=value\n"), 0o600)
	e.mustRun("enc", "--as", "n.env", src)
	require.Equal(t, "FIELD=value\n", e.mustRun("dec", "n.env").stdout)
}

// TestForgetReturnsTheMachineToTheRecoveryPassphrase covers the reverse
// operation, which is what a user runs before handing a machine on.
func TestForgetReturnsTheMachineToTheRecoveryPassphrase(t *testing.T) {
	e := keyringEnv(t)
	e.initStore()
	e.mustRun("bootstrap")
	require.True(t, localkey.Exists(e.store))

	e.mustRunNoPassphrase("bootstrap", "--forget")
	require.False(t, localkey.Exists(e.store), "the local key must be gone")

	// Without a passphrase source the store is now unreachable again...
	require.NotZero(t, e.runNoPassphrase("ls").code)
	// ... and with one it opens as before.
	require.Zero(t, e.run("ls").code)
}

func readLocalKeyFile(t *testing.T, e *env) []byte {
	t.Helper()
	dir, err := localkey.Dir(e.store)
	require.NoError(t, err)
	return readFile(t, filepath.Join(dir, "identity.local"))
}

// encodings returns the byte forms a secret might leak as.
func encodings(secret []byte) []string {
	return []string{
		string(secret),
		hexOf(secret),
		base64Of(secret),
	}
}

func filesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable entry is not this test's concern
		}
		if info.IsDir() {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}
