package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExtractRefusesBadPaths covers the extraction half of R3.4.1.
//
// This is exercised here rather than through the binary because a blob cannot
// carry such a path to that point: the name binding of R1.8 rejects it first,
// since the blob's filename is an HMAC over a path that would have to normalize
// successfully to exist at all. The guard is still required — it is the second
// of the two independent controls R3.4.2 asks for, and a change to the naming
// scheme must not silently become the only thing standing between an envelope
// and an arbitrary file write.
func TestExtractRefusesBadPaths(t *testing.T) {
	root := t.TempDir()

	bad := map[string]string{
		"parent traversal":  "../../.ssh/authorized_keys",
		"absolute":          "/etc/shadow",
		"NUL byte":          "a\x00b",
		"embedded parent":   "a/../../b",
		"current directory": "./a",
		"drive letter":      `C:/secrets`,
		"backslash":         `..\..\secrets`,
		"empty":             "",
	}
	for name, path := range bad {
		t.Run(name, func(t *testing.T) {
			written, err := Extract(root, path, []byte("payload"), 0o600, 0)
			require.Error(t, err, "%q must be refused", path)
			require.Empty(t, written)
		})
	}

	// Nothing was created anywhere near the root.
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Empty(t, entries, "a refused extraction must write nothing")
	require.NoFileExists(t, filepath.Join(filepath.Dir(root), "b"))
}

func TestExtractWritesUnderTheRoot(t *testing.T) {
	root := t.TempDir()

	written, err := Extract(root, "a/b/c.env", []byte("FIELD=value\n"), 0o640, 1756684800)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "a", "b", "c.env"), written)

	info, err := os.Stat(written)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
	require.Equal(t, int64(1756684800), info.ModTime().Unix())
	require.Equal(t, "FIELD=value\n", string(mustRead(t, written)))
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return raw
}
