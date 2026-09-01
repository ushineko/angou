//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ushineko/angou/internal/keybundle"
)

// TestGPGDecryptsABlobBody covers R1.5, which is a recovery guarantee rather
// than an interoperability nicety: if angou is unavailable or unusable, the
// payload must still be readable with the tool every Linux machine already has.
//
// The test imports the store identity into a throwaway GNUPGHOME and drives the
// real gpg binary. A Go OpenPGP implementation reading its own output would
// establish nothing — the claim is about gpg, so gpg has to be the thing that
// reads it.
func TestGPGDecryptsABlobBody(t *testing.T) {
	requireGPG(t)

	e := newEnv(t)
	e.initStore()

	content := []byte("FIELD=recoverable-without-angou\n")
	src := e.writePlaintext("r.env", content, 0o600)
	e.mustRun("enc", "--as", "recover/r.env", src)

	// Recover the identity the way an operator holding the recovery passphrase
	// would, and hand it to gpg.
	bundle, err := keybundle.Unmarshal(readFile(t, e.storePath("bootstrap", "keybundle.json")))
	require.NoError(t, err)
	exported, err := bundle.Open([]byte(e.recovery))
	require.NoError(t, err)

	gnupgHome := filepath.Join(e.work, "gnupg")
	mkdirAll(t, gnupgHome)
	require.NoError(t, os.Chmod(gnupgHome, 0o700))

	keyPath := filepath.Join(e.work, "identity.gpg")
	require.NoError(t, os.WriteFile(keyPath, exported, 0o600))
	runGPG(t, gnupgHome, nil, "--batch", "--quiet", "--import", keyPath)

	// The payload is the container's body: everything between the blank line
	// after the header and the closing delimiter.
	blob := readFile(t, e.storePath(e.blobNames()[0]))
	_, payload, ok := bytes.Cut(blob, []byte("\n\n"))
	require.True(t, ok)
	payload = bytes.TrimSuffix(payload, []byte("-----END ANGOU1 BLOB-----\n"))

	out := runGPG(t, gnupgHome, payload, "--batch", "--quiet", "--decrypt")

	// What gpg yields is the envelope, and it is parseable without angou.
	var envelope struct {
		Path    string `json:"path"`
		Content []byte `json:"content"`
	}
	require.NoError(t, json.Unmarshal(out, &envelope),
		"gpg should yield a parseable envelope, got:\n%s", string(out))
	require.Equal(t, "recover/r.env", envelope.Path)
	require.Equal(t, content, envelope.Content)
}

// TestFileMagicIdentifiesABlob covers the R1.6 detection entry. The magic file
// is checked as shipped, because file(1) is the consumer and a Go constant is
// not something it can read.
func TestFileMagicIdentifiesABlob(t *testing.T) {
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file(1) is not installed")
	}
	magic := repoFile(t, "packaging/magic")

	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("m.env", []byte("FIELD=value\n"), 0o600)
	e.mustRun("enc", "--as", "m.env", src)

	for _, name := range []string{e.blobNames()[0], "store.angou", "index.angou"} {
		out, err := exec.Command("file", "-m", magic, e.storePath(name)).CombinedOutput()
		require.NoError(t, err, string(out))
		require.Contains(t, string(out), "angou encrypted blob",
			"file(1) should identify %s", name)
	}

	// And the MIME type the desktop integration relies on.
	out, err := exec.Command("file", "-m", magic, "--mime-type", e.storePath("store.angou")).CombinedOutput()
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "application/x-angou-blob")
}

func runGPG(t *testing.T, gnupgHome string, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("gpg", args...)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg %v: %v\nstderr:\n%s", args, err, stderr.String())
	}
	return stdout.Bytes()
}

// repoFile resolves a path inside the repository, which the suite reaches via
// the binary's location rather than by assuming a working directory.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	bin, err := filepath.Abs(os.Getenv(BinEnv))
	require.NoError(t, err)
	path := filepath.Join(filepath.Dir(bin), rel)
	require.FileExists(t, path)
	return path
}
