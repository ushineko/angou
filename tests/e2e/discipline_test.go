//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSuiteRunsAgainstABuiltBinary covers R8.1: the suite drives an artifact it
// built, never internal packages, and says so plainly when that artifact is
// missing.
func TestSuiteRunsAgainstABuiltBinary(t *testing.T) {
	bin := os.Getenv(BinEnv)
	require.NotEmpty(t, bin, "%s must be set; `make e2e` sets it", BinEnv)

	info, err := os.Stat(bin)
	require.NoError(t, err, "the binary under test must exist")
	require.False(t, info.IsDir())
	require.NotZero(t, info.Mode()&0o111, "the binary under test must be executable")

	e := newEnv(t)
	require.Contains(t, e.mustRun("--version").stdout, "angou")
}

// TestHomeGuardIsFatal covers R8.4. A suite that silently writes to a
// developer's real store, keyring, or wallet is worse than one that fails, so
// this is a t.Fatal and never a skip.
//
// The guard is exercised through a nested test whose failure is expected: the
// assertion is that it fails, and that its message names the hazard.
func TestHomeGuardIsFatal(t *testing.T) {
	realHome, err := os.UserHomeDir()
	require.NoError(t, err)

	// Drive the guard against a path inside the real home and require that it
	// reports rather than proceeds.
	fake := &guardRecorder{}
	assertHomeIsDisposableFor(fake, filepath.Join(realHome, ".cache", "angou-e2e-should-never-exist"))
	require.True(t, fake.failed, "the guard must reject a HOME inside the real home directory")
	require.Contains(t, fake.message, realHome)
	require.Contains(t, strings.ToLower(fake.message), "refusing to run")

	// And that it accepts a disposable one.
	ok := &guardRecorder{}
	assertHomeIsDisposableFor(ok, t.TempDir())
	require.False(t, ok.failed, "a temporary directory must be accepted")
}

// TestEachRunUsesAFreshPassphrase covers R8.3: no credential-shaped constant is
// committed, and two runs never share a recovery passphrase.
func TestEachRunUsesAFreshPassphrase(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		p := freshPassphrase(t)
		require.False(t, seen[p], "recovery passphrases must not repeat between runs")
		require.NotEmpty(t, p)
		seen[p] = true
	}

	a, b := newEnv(t), newEnv(t)
	require.NotEqual(t, a.recovery, b.recovery)
}

// TestSuiteTouchesNothingOutsideItsSandbox covers the isolation criterion: after
// a full exercise of the tool, the developer's own angou state is exactly as it
// was.
func TestSuiteTouchesNothingOutsideItsSandbox(t *testing.T) {
	realHome, err := os.UserHomeDir()
	require.NoError(t, err)
	realState := filepath.Join(realHome, ".local", "share", "angou")

	before := snapshot(t, realState)

	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("s.env", []byte("S=1\n"), 0o600)
	e.mustRun("enc", "--as", "s.env", src)
	e.mustRun("ls")
	e.mustRun("dec", "s.env")
	e.mustRun("get", "--dest", filepath.Join(e.work, "out"), "s.env")
	e.mustRun("reindex")
	e.mustRun("rm", "s.env")

	require.Equal(t, before, snapshot(t, realState),
		"the suite must not create or modify anything under %s", realState)

	// Everything the run produced lives under the test's own temporary tree.
	require.DirExists(t, e.store)
	require.True(t, strings.HasPrefix(e.store, os.TempDir()) || !strings.HasPrefix(e.store, realHome),
		"the throwaway store must not be inside the real home directory")
}

// snapshot records the names and modification times under a directory, or nil
// when it does not exist.
func snapshot(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read %s: %v", dir, err)
	}
	out := map[string]int64{}
	for _, de := range entries {
		info, err := de.Info()
		if err != nil {
			t.Fatalf("stat %s: %v", de.Name(), err)
		}
		out[de.Name()] = info.ModTime().UnixNano()
	}
	return out
}

// guardRecorder captures what the home guard would have reported, so the guard
// itself can be tested without failing the suite that runs it.
type guardRecorder struct {
	failed  bool
	message string
}

func (g *guardRecorder) Fatalf(format string, args ...any) {
	g.failed = true
	g.message = fmt.Sprintf(format, args...)
}
