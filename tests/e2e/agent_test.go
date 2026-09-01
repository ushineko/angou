//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// startAgent launches an agent in the background and waits for its socket.
func startAgent(t *testing.T, e *env, ttl string) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	go func() {
		defer func() { _ = w.Close() }()
		_, _ = w.WriteString(e.recovery + "\n")
	}()

	cmd := exec.Command(e.bin, "--passphrase-fd", "3", "agent", "start", "--ttl", ttl)
	cmd.ExtraFiles = []*os.File{r}
	cmd.Dir = e.work
	cmd.Env = e.childEnv()
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	_ = r.Close()

	socketDir := filepath.Join(e.runtimeDir, "angou")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(socketDir)
		if err == nil && len(entries) > 0 {
			return filepath.Join(socketDir, entries[0].Name())
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the agent did not create its socket")
	return ""
}

// TestAgentServesCommandsWithoutAPassphrase is what the agent is for: without
// gpg-agent, every command otherwise unlocks the store from scratch.
func TestAgentServesCommandsWithoutAPassphrase(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("a.env", []byte("FIELD=value\n"), 0o600)
	e.mustRun("enc", "--as", "a.env", src)

	startAgent(t, e, "60s")

	// No passphrase source at all, and no keyring on this machine either.
	require.Equal(t, "FIELD=value\n", e.mustRunNoPassphrase("dec", "a.env").stdout)
	require.Contains(t, e.mustRunNoPassphrase("ls").stdout, "a.env")
	require.Contains(t, e.mustRunNoPassphrase("-v", "ls").stderr, "using the running agent")
}

// TestAgentSocketExcludesOtherUsers covers the only access control the agent
// actually has. The mode keeps out other users; it is not, and must not be
// described as, a boundary against other processes of this user (R-10).
func TestAgentSocketExcludesOtherUsers(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	socket := startAgent(t, e, "60s")

	info, err := os.Lstat(socket)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"the socket must be readable and writable only by its owner")

	// The containing directory is equally restricted, or the mode above would
	// be the only thing standing between the socket and another user.
	dirInfo, err := os.Stat(filepath.Dir(socket))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
}

// TestAgentStatusAndStop covers the operator-facing half, including the release
// that compromise recovery depends on (R6.4.1).
func TestAgentStatusAndStop(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	socket := startAgent(t, e, "120s")

	status := e.mustRunNoPassphrase("agent", "status")
	require.Contains(t, status.stdout, "Holding")
	require.Contains(t, status.stdout, socket)

	e.mustRunNoPassphrase("agent", "stop")

	// The socket is gone, and so is the cached material.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); os.IsNotExist(err) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NoFileExists(t, socket, "stopping the agent must remove its socket")
	require.Contains(t, e.mustRunNoPassphrase("agent", "status").stdout, "No agent is running")

	// And commands need a passphrase again.
	require.NotZero(t, e.runNoPassphrase("ls").code)
}

// TestAgentReleasesKeyMaterialAtTTL covers the bounded lifetime, which is the
// design's actual mitigation for the exposure R-10 accepts.
func TestAgentReleasesKeyMaterialAtTTL(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	socket := startAgent(t, e, "2s")

	require.Zero(t, e.runNoPassphrase("ls").code, "the agent should serve while it is alive")

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); os.IsNotExist(err) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NoFileExists(t, socket, "the agent must release and clean up at its TTL")
	require.NotZero(t, e.runNoPassphrase("ls").code,
		"once the lifetime is over, a passphrase is needed again")
}

// TestAgentHelpDoesNotOverstateItsProtection guards the wording. R-10 requires
// the agent not be described as a boundary it is not, and help text is where
// that claim would most plausibly creep in.
func TestAgentHelpDoesNotOverstateItsProtection(t *testing.T) {
	e := newEnv(t)
	help := e.mustRunNoPassphrase("agent", "--help").stdout

	// The help text is wrapped, so collapse whitespace before matching phrases
	// that span a line break.
	lower := strings.Join(strings.Fields(strings.ToLower(help)), " ")
	require.Contains(t, lower, "does not keep out anything else running as you")
	require.Contains(t, lower, "the short lifetime is the real mitigation")
	require.NotContains(t, lower, "secure against")
	require.NotContains(t, lower, "protects you from malware")
}

// TestAgentRefusesASecondInstance keeps two agents from racing over one socket.
func TestAgentRefusesASecondInstance(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	startAgent(t, e, "60s")

	r := e.run("agent", "start", "--ttl", "60s")
	require.NotZero(t, r.code)
	require.Contains(t, r.stderr, "already holding this store")
}
