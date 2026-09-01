//go:build e2e

package e2e

import (
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
