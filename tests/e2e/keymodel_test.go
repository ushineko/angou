//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestKDFParametersAreRecordedAndFloored covers R2.2.1. The recovery passphrase
// is the one artifact an attacker can grind offline without limit and without
// being noticed, so the parameters are recorded in the clear beside the
// ciphertext and validated on every read. A bundle presenting weaker parameters
// than the floor is refused, which is what stops an attacker from editing the
// header to make the target cheap.
func TestKDFParametersAreRecordedAndFloored(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	path := e.storePath("bootstrap", "keybundle.json")
	var bundle map[string]any
	require.NoError(t, json.Unmarshal(readFile(t, path), &bundle))

	kdf, ok := bundle["kdf"].(map[string]any)
	require.True(t, ok, "the bundle must record its KDF parameters in the clear")
	require.Equal(t, "argon2id", kdf["algorithm"])
	require.NotEmpty(t, kdf["salt"])
	for _, field := range []string{"memory_kib", "time", "parallelism"} {
		require.NotZero(t, kdf[field], "%s must be recorded", field)
	}
	require.EqualValues(t, 64<<10, kdf["memory_kib"], "the pinned floor is 64 MiB")
	require.EqualValues(t, 24, kdf["time"])
	require.EqualValues(t, 4, kdf["parallelism"])

	t.Run("downgraded parameters are refused", func(t *testing.T) {
		kdf["memory_kib"] = 1
		kdf["time"] = 1
		kdf["parallelism"] = 1
		raw, err := json.Marshal(bundle)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, raw, 0o600))

		r := e.run("ls")
		require.NotZero(t, r.code, "a downgraded KDF header must be refused")
		require.Contains(t, strings.ToLower(r.stderr), "floor")
	})
}

// TestInitRefusesWeakPassphrase covers the R2.2.1 requirement that a low-entropy
// recovery passphrase is refused outright rather than warned about.
func TestInitRefusesWeakPassphrase(t *testing.T) {
	for _, weak := range []string{
		"abc123",
		"correct horse battery staple",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"letmein1",
	} {
		t.Run(weak, func(t *testing.T) {
			e := newEnv(t)
			r := e.runWithPassphrase(weak, "init")
			require.NotZero(t, r.code, "a weak recovery passphrase must be refused")
			require.Contains(t, strings.ToLower(r.stderr), "too weak")
			require.NoFileExists(t, e.storePath("store.angou"), "no store may be created")
		})
	}
}

// TestGeneratedPassphraseIsUsable covers the --generate path: the phrase is shown
// once, carries at least the required entropy, and actually opens the store.
func TestGeneratedPassphraseIsUsable(t *testing.T) {
	e := newEnv(t)
	// --generate ignores the passphrase source and chooses its own.
	r := e.mustRun("init", "--generate")

	phrase := extractGeneratedPhrase(t, r.stderr)
	require.GreaterOrEqual(t, len(strings.Fields(phrase)), 9,
		"a 512-word list needs at least nine words to clear 77 bits")
	require.Contains(t, r.stderr, "shown exactly once")

	src := e.writePlaintext("g.env", []byte("G=1\n"), 0o600)
	require.Zero(t, e.runWithPassphrase(phrase, "enc", "--as", "g.env", src).code,
		"the generated phrase must open the store it created")
	require.NotZero(t, e.runWithPassphrase(phrase+" extra", "dec", "g.env").code,
		"a different phrase must not")
}

// TestWrongPassphraseIsRefused checks the ordinary failure: a wrong recovery
// passphrase yields a non-zero exit and no plaintext.
func TestWrongPassphraseIsRefused(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("w.env", []byte("W=1\n"), 0o600)
	e.mustRun("enc", "--as", "w.env", src)

	r := e.runWithPassphrase(freshPassphrase(t), "dec", "w.env")
	require.NotZero(t, r.code)
	require.Empty(t, r.stdout)
}

func extractGeneratedPhrase(t *testing.T, stderr string) string {
	t.Helper()
	lines := strings.Split(stderr, "\n")
	for i, line := range lines {
		if strings.Contains(line, "Your recovery passphrase") && i+2 < len(lines) {
			return strings.TrimSpace(lines[i+2])
		}
	}
	t.Fatalf("init --generate did not display a phrase:\n%s", stderr)
	return ""
}

// TestFailedInitShowsNoPassphrase covers the ordering of R2.2.1's "displayed
// exactly once". A phrase printed before the store is committed is worse than no
// phrase at all: the user writes down something that opens nothing, and nothing
// tells them it is void.
func TestFailedInitShowsNoPassphrase(t *testing.T) {
	e := newEnv(t)

	// An unwritable parent stands in for the ways store creation fails in the
	// field — a full disk, a read-only mount, a directory the user cannot write.
	locked := filepath.Join(e.work, "locked")
	mkdirAll(t, locked)
	require.NoError(t, os.Chmod(locked, 0o500))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	target := filepath.Join(locked, "store")
	r := e.run("init", "--generate", "--store", target)
	require.NotZero(t, r.code, "init must fail when the store cannot be created")
	require.NotContains(t, r.stderr, "shown exactly once",
		"no recovery passphrase may be displayed for a store that was never created")
	require.NotContains(t, r.stderr, "bits of entropy")
	require.NoDirExists(t, target)
}
