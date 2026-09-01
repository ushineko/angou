//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNoSecretsAtDebugVerbosity covers the security criterion. Verbose output is
// the most likely place for a passphrase or a plaintext to escape, because it is
// the one place the tool deliberately narrates what it is doing.
func TestNoSecretsAtDebugVerbosity(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	secret := "FIELD=" + freshPassphrase(t) + "\n"
	src := e.writePlaintext("v.env", []byte(secret), 0o600)

	var combined strings.Builder
	for _, args := range [][]string{
		{"-v", "enc", "--as", "v.env", src},
		{"-v", "ls", "--long"},
		{"-v", "dec", "v.env"},
		{"-v", "reindex"},
		{"-v", "doctor"},
	} {
		r := e.mustRun(args...)
		// dec writes the plaintext to stdout on purpose; only stderr is a log
		// path, and that is what must stay clean.
		combined.WriteString(r.stderr)
	}
	logged := combined.String()

	require.NotContains(t, logged, e.recovery, "the recovery passphrase must never be logged")
	require.NotContains(t, logged, strings.TrimSpace(secret), "the plaintext must never be logged")
	require.NotContains(t, logged, "FIELD=", "no fragment of the plaintext may be logged")

	// The plaintext digest is not logged either. For a low-entropy secret it is
	// a reusable oracle: anyone holding the log can test guesses against it,
	// which makes it as disclosing as a fragment of the plaintext.
	sum := sha256.Sum256([]byte(secret))
	require.NotContains(t, logged, hex.EncodeToString(sum[:]),
		"the plaintext digest must not appear in a log path")
	require.Contains(t, logged, "angou:", "verbose output should actually say something")
	require.Contains(t, logged, "opened the key bundle", "so the test is exercising the log path")
}

// TestStaticBinaryHasNoDynamicDependencies covers R6.2: the bootstrap artifact
// has to run on a machine with nothing installed, so it must not be linked
// against anything.
func TestStaticBinaryHasNoDynamicDependencies(t *testing.T) {
	bin := os.Getenv(BinEnv)
	require.NotEmpty(t, bin)

	if _, err := exec.LookPath("ldd"); err == nil {
		out, _ := exec.Command("ldd", bin).CombinedOutput()
		require.Contains(t, strings.ToLower(string(out)), "not a dynamic executable",
			"the bootstrap binary must not be dynamically linked; ldd said: %s", out)
	}
	if _, err := exec.LookPath("file"); err == nil {
		out, err := exec.Command("file", bin).CombinedOutput()
		require.NoError(t, err)
		require.Contains(t, string(out), "statically linked")
	}
}

// TestGPGCannotReadTheKeyBundle pins the incompatibility R5.2.1 records.
//
// The key bundle is deliberately not an OpenPGP message: stock gpg implements
// S2K modes 0, 1 and 3, and Argon2 is mode 4. An earlier revision protected the
// bootstrap binaries the same way and did not work at all. This asserts the
// bundle stays unreadable to gpg, so a future change cannot quietly reintroduce
// a design that depends on gpg reading it.
func TestGPGCannotReadTheKeyBundle(t *testing.T) {
	requireGPG(t)

	e := newEnv(t)
	e.initStore()

	bundle := e.storePath("bootstrap", "keybundle.json")
	gnupgHome := filepath.Join(e.work, "gnupg-bundle")
	mkdirAll(t, gnupgHome)
	require.NoError(t, os.Chmod(gnupgHome, 0o700))

	cmd := exec.Command("gpg", "--batch", "--quiet", "--passphrase", e.recovery,
		"--pinentry-mode", "loopback", "--decrypt", bundle)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	out, err := cmd.CombinedOutput()

	require.Error(t, err, "gpg must not be able to read the key bundle; it produced:\n%s", out)
	require.NotContains(t, string(out), "PGP PRIVATE KEY")
}

// TestOlderBinaryIsRefusedOnceNewerIsInstalled covers R5.4.2. Signature validity
// is not freshness: bootstrap/ retains several versions and a sync service keeps
// its own history, so without a floor an attacker with write access can replay
// an older, validly signed, known-vulnerable binary.
func TestOlderBinaryIsRefusedOnceNewerIsInstalled(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	// A build claiming a much newer version, standing in for a later release.
	newer := buildVersioned(t, e, "9.9.9")

	key := filepath.Join(e.work, "signing.asc")
	e.mustRunNoPassphrase("release", "--new-signing-key", key)
	dist := filepath.Join(e.work, "dist")
	mkdirAll(t, dist)
	writeFakeBinary(t, filepath.Join(dist, "angou-linux-amd64"))

	// Releasing with the newer build raises the store's floor to 9.9.9.
	runBinary(t, e, newer, []string{e.recovery}, "release", "--dist", dist, "--signing-key", key)
	// doctor still works below the floor and says why, rather than refusing for
	// the very reason someone would be running it.
	d := e.mustRun("doctor").stdout
	require.Contains(t, d, "9.9.9")
	require.Contains(t, d, "THIS BINARY IS OLDER AND WILL BE REFUSED")

	// The ordinary build is older, and bootstrap must refuse it.
	r := e.run("bootstrap")
	require.NotZero(t, r.code, "an older binary must be refused once a newer one has been installed")
	require.Contains(t, r.stderr, "9.9.9")
	require.Contains(t, r.stderr, "Refusing to bootstrap with an older binary")
}

// buildVersioned compiles the tool with a different reported version, so the
// version floor can be exercised against a real artifact rather than a stub.
func buildVersioned(t *testing.T, e *env, version string) string {
	t.Helper()
	out := filepath.Join(e.work, "angou-"+version)
	cmd := exec.Command("go", "build",
		"-ldflags", "-X github.com/ushineko/angou/lib/container.Version="+version,
		"-trimpath", "-o", out, "./cmd/angou")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building a %s binary: %v\n%s", version, err, combined)
	}
	return out
}

// runBinary drives a specific binary rather than the one under test.
func runBinary(t *testing.T, e *env, bin string, lines []string, args ...string) result {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	go func() {
		defer func() { _ = w.Close() }()
		for _, line := range lines {
			_, _ = w.WriteString(line + "\n")
		}
	}()
	defer func() { _ = r.Close() }()

	cmd := exec.Command(bin, append([]string{"--passphrase-fd", "3"}, args...)...)
	cmd.ExtraFiles = []*os.File{r}
	cmd.Dir = e.work
	cmd.Env = e.childEnv()
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); !ok {
			t.Fatalf("running %s %v: %v\n%s", bin, args, err, stderr.String())
		}
		code = exitErr.ExitCode()
	}
	if code != 0 {
		t.Fatalf("%s %v exited %d\n%s", bin, args, code, stderr.String())
	}
	return result{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	bin, err := filepath.Abs(os.Getenv(BinEnv))
	require.NoError(t, err)
	return filepath.Dir(bin)
}
