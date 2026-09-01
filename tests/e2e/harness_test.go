//go:build e2e

// Package e2e drives the real angou binary as a subprocess against throwaway
// stores (spec 001 R8).
//
// The suite deliberately does not import angou's internal packages. Most of what
// spec 001 claims is a property of the artifact rather than of a function — that
// the container header leaks nothing, that the static binary has no runtime
// prerequisites, that a renamed blob is refused — and none of those can be
// falsified against a substitute, because the substitute is not the thing
// carrying the property (R8.2).
package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// BinEnv names the environment variable holding the binary under test. `make
// e2e` builds it with the build-static flags and sets this.
const BinEnv = "ANGOU_E2E_BIN"

// env is one hermetic test environment: a built binary, a throwaway store, a
// per-run recovery passphrase, and a redirected HOME.
type env struct {
	t        *testing.T
	bin      string
	home     string
	store    string
	work     string
	recovery string
	// fingerprint is the store identity reported by init, kept so a test can
	// name the superseded key after a rotation.
	fingerprint string
	// withKeyring lets the child reach the session bus, and so the real
	// kwalletd6. Off by default: a test that does not exercise the keyring must
	// not be able to touch the developer's wallet even by accident.
	withKeyring bool
	// runtimeDir stands in for XDG_RUNTIME_DIR and is kept short on purpose.
	runtimeDir string
	// cachedVersion is the version the binary under test reports.
	cachedVersion string
}

// version asks the binary what version it is.
//
// Tests that name a stashed artifact have to agree with the binary about the
// version in its filename, and hardcoding one means every release breaks the
// suite. Asking is also the more honest test: it checks what the artifact
// actually claims rather than what the suite assumes.
func (e *env) version(t *testing.T) string {
	t.Helper()
	if e.cachedVersion != "" {
		return e.cachedVersion
	}
	out := e.mustRunNoPassphrase("--version").stdout
	// cobra prints "angou version <version> (<commit>)".
	fields := strings.Fields(out)
	if len(fields) < 3 {
		t.Fatalf("cannot read a version out of %q", out)
	}
	e.cachedVersion = fields[2]
	return e.cachedVersion
}

// binaryName is the stashed filename for a platform at the version under test.
func (e *env) binaryName(t *testing.T, platform string) string {
	t.Helper()
	return "angou-" + platform + "-" + e.version(t)
}

// newEnv builds the environment for one test.
func newEnv(t *testing.T) *env {
	t.Helper()

	bin := os.Getenv(BinEnv)
	if bin == "" {
		t.Fatalf("%s is not set: the e2e suite runs against a binary it built, never against "+
			"internal packages. Run `make e2e`.", BinEnv)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("%s=%s is not present: %v. Run `make e2e`.", BinEnv, bin, err)
	}

	base := t.TempDir()
	home := filepath.Join(base, "home")
	mkdirAll(t, home)

	// R8.4: a suite that silently writes to a developer's real store, keyring,
	// or wallet is worse than one that fails. This is a fatal error and never a
	// skip.
	assertHomeIsDisposable(t, home)

	e := &env{
		t:     t,
		bin:   bin,
		home:  home,
		store: filepath.Join(base, "store"),
		work:  filepath.Join(base, "work"),
	}
	mkdirAll(t, e.work)
	e.recovery = freshPassphrase(t)

	// A short runtime directory, deliberately not under t.TempDir(). A unix
	// socket path is bounded by sockaddr_un.sun_path, and the temporary
	// directory names Go generates are long enough on their own to exceed it
	// once a subdirectory and a filename are added.
	runtime, err := os.MkdirTemp("", "angou-rt-")
	if err != nil {
		t.Fatalf("create runtime directory: %v", err)
	}
	e.runtimeDir = runtime
	t.Cleanup(func() { _ = os.RemoveAll(runtime) })

	return e
}

// fataler is the part of *testing.T the home guard uses. The guard is written
// against it so the guard itself can be tested without failing the suite that
// runs it.
type fataler interface {
	Fatalf(format string, args ...any)
}

// assertHomeIsDisposable fails when the redirected HOME is, or lies within, the
// real home directory.
func assertHomeIsDisposable(t *testing.T, home string) {
	t.Helper()
	assertHomeIsDisposableFor(t, home)
}

func assertHomeIsDisposableFor(t fataler, home string) {
	real, err := os.UserHomeDir()
	if err != nil {
		// No discoverable home is fine: there is nothing to protect.
		return
	}
	realAbs, err := filepath.Abs(real)
	if err != nil {
		t.Fatalf("cannot resolve the real home directory %q: %v", real, err)
	}
	homeAbs, err := filepath.Abs(home)
	if err != nil {
		t.Fatalf("cannot resolve the test home directory %q: %v", home, err)
	}
	if homeAbs == realAbs || strings.HasPrefix(homeAbs, realAbs+string(os.PathSeparator)) {
		t.Fatalf("refusing to run: the test HOME %q is inside the real home directory %q. "+
			"The suite would operate on your own store, keyring, and wallet.", homeAbs, realAbs)
	}
}

// freshPassphrase draws a recovery passphrase from crypto/rand for this run
// (R8.3). No credential-shaped constant is committed, even a fake one, and two
// runs never share a passphrase.
func freshPassphrase(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("draw recovery passphrase: %v", err)
	}
	return hex.EncodeToString(raw)
}

type result struct {
	stdout string
	stderr string
	code   int
}

// run invokes the binary with the recovery passphrase on file descriptor 3.
// The passphrase never reaches the command line or the environment, both of
// which any process running as the same user can read.
func (e *env) run(args ...string) result {
	e.t.Helper()
	return e.runWithPassphrase(e.recovery, args...)
}

func (e *env) runWithPassphrase(passphrase string, args ...string) result {
	e.t.Helper()
	return e.runWithLines([]string{passphrase}, args...)
}

// runWithLines supplies several passphrases, one per line. Some commands need
// more than one — rekey --identity opens the store and then seals a new bundle
// — and the descriptor is a stream rather than a single value.
func (e *env) runWithLines(lines []string, args ...string) result {
	e.t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		e.t.Fatalf("pipe: %v", err)
	}
	go func() {
		defer func() { _ = w.Close() }()
		for _, line := range lines {
			_, _ = fmt.Fprintln(w, line)
		}
	}()
	defer func() { _ = r.Close() }()

	cmd := exec.Command(e.bin, append([]string{"--passphrase-fd", "3"}, args...)...)
	cmd.ExtraFiles = []*os.File{r} // becomes fd 3 in the child
	cmd.Dir = e.work
	cmd.Env = e.childEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); !ok {
			e.t.Fatalf("running %v: %v\nstderr:\n%s", args, err, stderr.String())
		}
		code = exitErr.ExitCode()
	}
	return result{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func asExitError(err error, out **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*out = e
		return true
	}
	return false
}

// childEnv redirects HOME and every XDG variable into the throwaway tree, so a
// test cannot reach the developer's real store, keyring, or wallet even if the
// tool grows a new state directory.
func (e *env) childEnv() []string {
	base := filepath.Dir(e.home)
	xdg := map[string]string{
		"HOME":            e.home,
		"XDG_DATA_HOME":   filepath.Join(e.home, ".local", "share"),
		"XDG_CONFIG_HOME": filepath.Join(e.home, ".config"),
		"XDG_CACHE_HOME":  filepath.Join(e.home, ".cache"),
		"XDG_STATE_HOME":  filepath.Join(e.home, ".local", "state"),
		"XDG_RUNTIME_DIR": e.runtimeDir,
		"ANGOU_STORE":     e.store,
	}
	for _, dir := range xdg {
		if strings.HasPrefix(dir, base) {
			mkdirAll(e.t, dir)
		}
	}
	out := []string{"PATH=" + os.Getenv("PATH")}
	// The session bus address is pinned in both directions, never left unset.
	// Unsetting it does not mean "no bus": the D-Bus client library falls back
	// to autolaunch and finds the developer's real session, and with it their
	// real wallet. A test that means to have no keyring must be given an address
	// that cannot resolve.
	if e.withKeyring {
		addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
		if addr == "" {
			e.t.Fatal("withKeyring was set but DBUS_SESSION_BUS_ADDRESS is not available")
		}
		out = append(out, "DBUS_SESSION_BUS_ADDRESS="+addr)
	} else {
		out = append(out, "DBUS_SESSION_BUS_ADDRESS=unix:path="+
			filepath.Join(base, "no-such-bus"))
	}
	for k, v := range xdg {
		out = append(out, k+"="+v)
	}
	return out
}

// runNoPassphrase invokes the binary with no passphrase source at all. A command
// that still needs one fails rather than prompting, because the child has no
// terminal — which is exactly the assertion the keyring tests want.
func (e *env) runNoPassphrase(args ...string) result {
	e.t.Helper()

	cmd := exec.Command(e.bin, args...)
	cmd.Dir = e.work
	cmd.Env = e.childEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); !ok {
			e.t.Fatalf("running %v: %v\nstderr:\n%s", args, err, stderr.String())
		}
		code = exitErr.ExitCode()
	}
	return result{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

// mustRunNoPassphrase is runNoPassphrase with a non-zero exit treated as fatal.
func (e *env) mustRunNoPassphrase(args ...string) result {
	e.t.Helper()
	r := e.runNoPassphrase(args...)
	if r.code != 0 {
		e.t.Fatalf("angou %v exited %d without a passphrase source\nstdout:\n%s\nstderr:\n%s",
			args, r.code, r.stdout, r.stderr)
	}
	return r
}

// mustRunWithLines is runWithLines with a non-zero exit treated as fatal.
func (e *env) mustRunWithLines(lines []string, args ...string) result {
	e.t.Helper()
	r := e.runWithLines(lines, args...)
	if r.code != 0 {
		e.t.Fatalf("angou %v exited %d\nstdout:\n%s\nstderr:\n%s", args, r.code, r.stdout, r.stderr)
	}
	return r
}

// mustRunLines repeats this run's recovery passphrase n times, for commands that
// ask for it more than once.
func (e *env) mustRunLines(n int, args ...string) result {
	e.t.Helper()
	lines := make([]string, n)
	for i := range lines {
		lines[i] = e.recovery
	}
	return e.mustRunWithLines(lines, args...)
}

// mustRun runs a command and fails the test if it exits non-zero.
func (e *env) mustRun(args ...string) result {
	e.t.Helper()
	r := e.run(args...)
	if r.code != 0 {
		e.t.Fatalf("angou %v exited %d\nstdout:\n%s\nstderr:\n%s", args, r.code, r.stdout, r.stderr)
	}
	return r
}

// initStore creates the throwaway store and records its identity fingerprint.
func (e *env) initStore() {
	e.t.Helper()
	e.fingerprint = extractFingerprint(e.t, e.mustRun("init").stdout)
}

// writePlaintext creates an input file in the work directory.
func (e *env) writePlaintext(name string, content []byte, mode os.FileMode) string {
	e.t.Helper()
	path := filepath.Join(e.work, name)
	mkdirAll(e.t, filepath.Dir(path))
	if err := os.WriteFile(path, content, mode); err != nil {
		e.t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		e.t.Fatalf("chmod %s: %v", path, err)
	}
	return path
}

// blobNames lists the blob filenames in the store, excluding the metadata blob
// and the index.
func (e *env) blobNames() []string {
	e.t.Helper()
	entries, err := os.ReadDir(e.store)
	if err != nil {
		e.t.Fatalf("read store: %v", err)
	}
	var out []string
	for _, de := range entries {
		n := de.Name()
		if de.IsDir() || n == "store.angou" || n == "index.angou" || !strings.HasSuffix(n, ".angou") {
			continue
		}
		out = append(out, n)
	}
	return out
}

func (e *env) storePath(parts ...string) string {
	return filepath.Join(append([]string{e.store}, parts...)...)
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
