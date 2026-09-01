//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The order of the --verbose lines is a contract, not an accident.
//
// These exist because of a regression the rest of the suite did not catch. When
// the unlock routes moved into internal/core (spec 002 pass 2), the store
// identity and index lines ended up after the bootstrap suggestion rather than
// before it, because the step that emits them had moved out of the recovery
// route and up into its caller. Every other test passed. Only a byte comparison
// against a binary built before the refactor showed it.
//
// The lines are what tells a user which route the store was opened by, and the
// order is what makes them read as a sequence rather than a heap.
//
// What these tests can and cannot reach is worth being exact about. They pin the
// route sequence, the route naming, and the no-secrets rule. They do NOT catch
// the specific regression described above: the bootstrap suggestion is only
// emitted where a keyring is available to bootstrap into, and this suite runs
// without a session bus on purpose, so that line never appears here. Putting the
// bug back and running these tests leaves them green -- which was checked, rather
// than assumed.
//
// The net for that one is tools/regress.sh, which diffs the current binary
// against a previous commit's on a real desktop session where the suggestion is
// emitted. Run it when moving an operation into internal/core.
//
// These assert relative order and the exact wording of each line, not the whole
// stream: an unrelated new line appearing between them is a change worth making
// freely, and a test that forbids it would be a test nobody thanks you for.

// requireOrder fails unless every needle appears in the haystack, in order.
func requireOrder(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	at := 0
	for _, needle := range needles {
		i := strings.Index(haystack[at:], needle)
		require.GreaterOrEqualf(t, i, 0,
			"missing from the --verbose output, or out of order: %q\nfull output:\n%s", needle, haystack)
		at += i + len(needle)
	}
}

// TestVerboseOrderOnTheRecoveryRoute pins the sequence a machine with no local
// key sees. The bootstrap suggestion comes last: it is advice about the route
// just taken, and printing it before the route has finished reporting itself
// puts the advice ahead of the fact it is advising about.
func TestVerboseOrderOnTheRecoveryRoute(t *testing.T) {
	e := newEnv(t)
	e.initStoreUnbootstrapped()
	path := e.writePlaintext("secret.txt", []byte("contents"), 0o600)
	e.mustRun("enc", path, "--as", "secret.txt")

	out := e.mustRun("-v", "ls").stderr

	requireOrder(t, out,
		"angou: opening store ",
		"angou: no local key on this machine; using the recovery passphrase",
		"angou: opened the key bundle with the recovery passphrase",
		"angou: store identity ",
		"angou: index ",
	)

	// The suggestion is only made where it can be followed. Under `make e2e`
	// there is no session bus, so this branch does not run; it is here for a
	// run that does have one, and tools/regress.sh is what actually guards it.
	if i := strings.Index(out, "this machine asks for the recovery passphrase every time"); i >= 0 {
		identity := strings.Index(out, "angou: store identity ")
		require.Greaterf(t, i, identity,
			"the bootstrap suggestion must come after the route has reported itself\nfull output:\n%s", out)
	}
}

// TestVerboseNamesTheRouteItTook is the property underneath the ordering: the
// verbose stream says which of the three routes opened the store. A user
// running -v is usually asking exactly that.
func TestVerboseNamesTheRouteItTook(t *testing.T) {
	e := newEnv(t)
	e.initStoreUnbootstrapped()

	out := e.mustRun("-v", "ls").stderr
	require.Contains(t, out, "using the recovery passphrase",
		"a machine with no local key must say so; without this line the user cannot tell "+
			"a slow route from a fast one")
	require.NotContains(t, out, "using the running agent")
	require.NotContains(t, out, "using the machine-local key")
}

// TestVerboseDisclosesNoSecret is the rule the logging exists under, asserted
// against the artifact rather than trusted to call-site discipline. Spec 001
// forbids a passphrase or plaintext reaching any log path at any verbosity, and
// internal/core is now a boundary those values cross.
func TestVerboseDisclosesNoSecret(t *testing.T) {
	e := newEnv(t)
	e.initStoreUnbootstrapped()
	const plaintext = "the-quick-brown-fox-plaintext-marker"
	path := e.writePlaintext("secret.txt", []byte(plaintext), 0o600)

	streams := []string{
		e.mustRun("-v", "enc", path, "--as", "secret.txt").stderr,
		e.mustRun("-v", "ls").stderr,
		e.mustRun("-v", "doctor").stderr,
		e.mustRun("-v", "dec", "secret.txt", "--stdout").stderr,
	}
	for _, out := range streams {
		require.NotContains(t, out, e.recovery, "the recovery passphrase reached a log path")
		require.NotContains(t, out, plaintext, "blob plaintext reached a log path")
	}
}
