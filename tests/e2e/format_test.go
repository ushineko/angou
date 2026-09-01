//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRoundTripArmoredAndBinary covers the format acceptance criterion: content,
// mode, and mtime survive a round trip for both a text and a binary input, in
// both payload encodings.
func TestRoundTripArmoredAndBinary(t *testing.T) {
	textInput := []byte("FIELD_ONE=value-one\nFIELD_TWO=value-two\n")
	binaryInput := make([]byte, 4096)
	_, err := rand.Read(binaryInput)
	require.NoError(t, err)

	cases := []struct {
		name    string
		content []byte
		mode    os.FileMode
		binary  bool
	}{
		{"text/armored", textInput, 0o600, false},
		{"text/binary-payload", textInput, 0o640, true},
		{"random/armored", binaryInput, 0o600, false},
		{"random/binary-payload", binaryInput, 0o644, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.initStore()

			src := e.writePlaintext("input.bin", tc.content, tc.mode)
			before, err := os.Stat(src)
			require.NoError(t, err)

			args := []string{"enc", "--as", "secrets/input.bin", src}
			if tc.binary {
				args = append(args, "--binary")
			}
			e.mustRun(args...)

			dec := e.mustRun("dec", "secrets/input.bin")
			require.Equal(t, tc.content, []byte(dec.stdout), "content must round-trip byte-identically")

			dest := filepath.Join(e.work, "out")
			e.mustRun("get", "--dest", dest, "secrets/input.bin")

			extracted := filepath.Join(dest, "secrets", "input.bin")
			after, err := os.Stat(extracted)
			require.NoError(t, err)
			require.Equal(t, tc.content, readFile(t, extracted))
			require.Equal(t, before.Mode().Perm(), after.Mode().Perm(), "POSIX mode must be restored")
			require.Equal(t, before.ModTime().Unix(), after.ModTime().Unix(), "mtime must be restored")
		})
	}
}

// TestHeaderCarriesNoMetadata asserts R1.3 against the raw bytes on disk: the
// plaintext header is dispatch data only. A filename, a plaintext hash, or a key
// fingerprint in the clear would each be a correlation handle available to
// anyone holding the store.
func TestHeaderCarriesNoMetadata(t *testing.T) {
	e := newEnv(t)
	initOut := e.mustRun("init")

	fingerprint := extractFingerprint(t, initOut.stdout)
	require.Len(t, fingerprint, 40, "init should report a full fingerprint")

	content := []byte("FIELD_ONE=value-one\n")
	src := e.writePlaintext("aws-credentials", content, 0o600)
	e.mustRun("enc", "--as", "cloud/aws-credentials", src)

	names := e.blobNames()
	require.Len(t, names, 1)
	raw := readFile(t, e.storePath(names[0]))

	header, _, ok := bytes.Cut(raw, []byte("\n\n"))
	require.True(t, ok, "container must separate header from payload with a blank line")

	// The header carries exactly the delimiter, the format, and the encoding.
	require.Equal(t,
		[]string{"-----BEGIN ANGOU1 BLOB-----", "Format: ANGOU1", "Encoding: armor"},
		strings.Split(string(header), "\n"))

	sum := sha256.Sum256(content)
	for label, needle := range map[string]string{
		"original filename": "aws-credentials",
		"logical path":      "cloud/aws-credentials",
		"plaintext SHA-256": hex.EncodeToString(sum[:]),
		"key fingerprint":   fingerprint,
		"lowercase key fpr": strings.ToLower(fingerprint),
	} {
		require.NotContains(t, string(raw), needle,
			"the %s must not appear anywhere in the blob on disk", label)
	}
}

// TestReaderHonoursDeclaredEncoding covers R1.2: the header declares the payload
// encoding and the reader never sniffs it. Flipping the declaration must break
// the read rather than being silently corrected.
func TestReaderHonoursDeclaredEncoding(t *testing.T) {
	for _, tc := range []struct{ name, wrote, claims string }{
		{"armored blob claiming binary", "armor", "binary"},
		{"binary blob claiming armor", "binary", "armor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.initStore()

			src := e.writePlaintext("f.txt", []byte("payload\n"), 0o600)
			args := []string{"enc", "--as", "f.txt", src}
			if tc.wrote == "binary" {
				args = append(args, "--binary")
			}
			e.mustRun(args...)

			name := e.blobNames()[0]
			path := e.storePath(name)
			raw := readFile(t, path)
			tampered := bytes.Replace(raw,
				[]byte("Encoding: "+tc.wrote), []byte("Encoding: "+tc.claims), 1)
			require.NotEqual(t, raw, tampered, "the encoding header should have been rewritten")
			require.NoError(t, os.WriteFile(path, tampered, 0o600))

			r := e.run("dec", "f.txt")
			require.NotZero(t, r.code, "a mis-declared encoding must not be sniffed around")
			require.Empty(t, r.stdout, "no plaintext may be emitted")
		})
	}
}

func extractFingerprint(t *testing.T, stdout string) string {
	t.Helper()
	for _, line := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(line, "Identity fingerprint: "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("init did not report a fingerprint:\n%s", stdout)
	return ""
}
