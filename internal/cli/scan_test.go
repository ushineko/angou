package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLooksSecret pins the judgement the scanner makes, which is the whole of
// its value. Table-driven because the interesting cases are the near misses.
func TestLooksSecret(t *testing.T) {
	cases := []struct {
		path string
		want bool
		why  string
	}{
		{"/home/u/.ssh/id_ed25519", true, "an SSH private key"},
		{"/home/u/.ssh/id_rsa", true, "an SSH private key"},
		{"/home/u/.ssh/id_ed25519.pub", false, "the public half is not secret"},
		{"/home/u/.aws/credentials", true, "AWS credentials"},
		{"/home/u/.kube/config", true, "kube config carries tokens"},
		{"/home/u/proj/config", false, "an ordinary config file is not a credential"},
		{"/home/u/proj/.env", true, "an environment file"},
		{"/home/u/proj/.env.production", true, "an environment file"},
		{"/home/u/proj/staging.env", true, "an environment file"},
		{"/home/u/.netrc", true, "netrc credentials"},
		{"/home/u/.pgpass", true, "a password file"},
		{"/home/u/certs/server.pem", true, "a key or certificate"},
		{"/home/u/certs/server.pub", false, "public material"},
		{"/home/u/app/db-password.txt", true, "the name says so"},
		{"/home/u/docs/README.md", false, "an ordinary document"},
		{"/home/u/src/main.go", false, "source code"},
		{"/home/u/.docker/config.json", true, "registry credentials"},
		{"/home/u/other/config.json", false, "only credentials when it is docker's"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			_, got := looksSecret(tc.path, filepath.Base(tc.path))
			require.Equal(t, tc.want, got, tc.why)
		})
	}
}

// TestScanSkipsNoiseAndBulk covers the exclusions. A scanner that walked
// node_modules would drown a real finding in vendored copies, and one that
// offered a hundred-megabyte match would be a slow surprise.
func TestScanSkipsNoiseAndBulk(t *testing.T) {
	root := t.TempDir()
	write := func(rel string, size int) {
		path := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, make([]byte, size), 0o600))
	}
	write(".env", 10)
	write("node_modules/pkg/.env", 10)
	write(".git/config", 10)
	write(".cache/x/.env", 10)
	write("huge.pem", maxScanSize+1)
	write("empty.pem", 0)
	write("deep/one/two/three/four/five/.env", 10)

	found, err := scanForSecrets(root)
	require.NoError(t, err)

	var names []string
	for _, c := range found {
		rel, err := filepath.Rel(root, c.Path)
		require.NoError(t, err)
		names = append(names, rel)
	}
	require.Equal(t, []string{".env"}, names,
		"only the real candidate should be offered; got %v", names)
}

// TestScanIgnoresSymlinks covers the one that matters for a store: a symlink is
// a pointer to a file somewhere else, and following it would encrypt something
// the user never pointed the scan at.
func TestScanIgnoresSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.pem")
	require.NoError(t, os.WriteFile(outside, []byte("PRIVATE\n"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link.pem")))

	found, err := scanForSecrets(root)
	require.NoError(t, err)
	require.Empty(t, found, "a symlink is not a file to encrypt")
}

func TestHumanSize(t *testing.T) {
	require.Equal(t, "0B", humanSize(0))
	require.Equal(t, "512B", humanSize(512))
	require.Equal(t, "1.0K", humanSize(1024))
	require.Equal(t, "1.5M", humanSize(1024*1024*3/2))
}

func TestFormatMode(t *testing.T) {
	require.Equal(t, "rw-------", formatMode(0o600))
	require.Equal(t, "rw-r--r--", formatMode(0o644))
	require.Equal(t, "rwxr-xr-x", formatMode(0o755))
	require.Equal(t, "---------", formatMode(0))
}
