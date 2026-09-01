//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ushineko/angou/internal/localkey"
)

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

// TestInitWithoutAKeyringSaysSo covers the other half of R2.5 at the point a
// store is created. init sets the machine up itself; where it cannot, it must
// say so rather than leaving the user to discover it one passphrase prompt at a
// time.
func TestInitWithoutAKeyringSaysSo(t *testing.T) {
	e := newEnv(t) // the harness gives the child no reachable session bus

	r := e.mustRun("init")
	require.Contains(t, r.stderr, "No keyring is available")
	require.Contains(t, r.stderr, "recovery passphrase")
	require.Contains(t, r.stderr, "Round-trip self-test passed",
		"init should confirm the store it just made actually works")
	require.False(t, localkey.Exists(e.store))

	// And the store is usable by the recovery route.
	src := e.writePlaintext("n.env", []byte("FIELD=value\n"), 0o600)
	e.mustRun("enc", "--as", "n.env", src)
	require.Equal(t, "FIELD=value\n", e.mustRun("dec", "n.env").stdout)
}

// TestInitNoBootstrapOptsOut checks the escape hatch, for a machine the user
// does not want holding a copy of the key.
func TestInitNoBootstrapOptsOut(t *testing.T) {
	e := newEnv(t)

	r := e.mustRun("init", "--no-bootstrap")
	require.Contains(t, r.stderr, "was not set up")
	require.Contains(t, r.stderr, "angou bootstrap --store")
	require.NotContains(t, r.stderr, "No keyring is available",
		"opting out should not report a keyring problem it never looked for")
	require.False(t, localkey.Exists(e.store))
}

// TestInitRefusesAnExistingStoreWithoutAsking covers the ordering, not just the
// refusal.
//
// init used to prompt for a "new recovery passphrase" and only then report that
// the store already existed. Asking that question of someone who already has a
// store reads as though the store is about to be replaced, which is alarming and
// is not what would have happened. The check belongs before the prompt.
func TestInitRefusesAnExistingStoreWithoutAsking(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	before := blobDigests(t, e)

	// No passphrase source at all: if init prompted, it would fail complaining
	// about that rather than about the store, and this would catch it.
	r := e.runNoPassphrase("init")
	require.NotZero(t, r.code)
	require.Contains(t, r.stderr, "already holds a store")
	require.Contains(t, r.stderr, "angou bootstrap")
	require.NotContains(t, strings.ToLower(r.stderr), "passphrase source",
		"init must decide before asking for anything")
	require.NotContains(t, strings.ToLower(r.stderr), "new recovery passphrase")

	require.Equal(t, before, blobDigests(t, e), "nothing may change")
}
