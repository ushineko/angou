package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLooksSecretByName pins the judgement made on names alone, for the rules
// precise enough not to need a look at the contents.
func TestLooksSecretByName(t *testing.T) {
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
		{"/home/u/certs/server.pub", false, "public material"},
		{"/home/u/docs/README.md", false, "an ordinary document"},
		{"/home/u/src/main.go", false, "source code"},
		{"/home/u/.docker/config.json", true, "registry credentials"},
		{"/home/u/other/config.json", false, "only credentials when it is docker's"},
		{"/home/u/keys/bundle.p12", true, "a key store"},

		// Templates advertise themselves as placeholders. On a developer's
		// machine these are the most common file that looks exactly like a
		// credential and holds nothing but example values.
		{"/home/u/proj/.env.example", false, "a template, not a credential"},
		{"/home/u/proj/.env.template", false, "a template"},
		{"/home/u/proj/.env.local.template", false, "a template"},
		{"/home/u/proj/.env.sample", false, "a template"},
		{"/home/u/proj/.env.local", true, "a real local environment file"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			_, got := looksSecret(tc.path, filepath.Base(tc.path))
			require.Equal(t, tc.want, got, tc.why)
		})
	}
}

// TestWeakRulesRequireContent covers the rules a name alone cannot settle.
//
// Every case here comes from running the scan against a real home directory. An
// earlier version offered eighteen session-state files ending in .key, Python's
// own secrets.py, libssh2 man pages and a pkg-config file — which is why these
// rules look at the file before speaking.
func TestWeakRulesRequireContent(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) string {
		path := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}

	cases := []struct {
		name string
		path string
		want bool
		why  string
	}{
		{"real private key",
			write("server.key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n"),
			true, "the PEM header is the evidence"},
		{"session handle with a .key name",
			write("sessions/34671.abc.key", `{"id":"34671","pid":9182}`+"\n"),
			false, "a .key extension is not a private key"},
		{"certificate without a private half",
			write("server.crt", "-----BEGIN CERTIFICATE-----\nMIIC\n"),
			false, "a certificate is not a secret"},
		{"credentials mentioning a secret",
			write("db-password.txt", "DB_PASSWORD=hunter2\nDB_USER=app\n"),
			true, "the name and the contents agree"},
		{"a note about passwords",
			write("password-policy.txt", "Passwords must be rotated every 90 days.\nSee the handbook.\n"),
			false, "prose about secrets is not a secret"},
		{"a binary that mentions a token",
			write("token-report.bin", "\x00\x01\x02binary: data\x00\x03"),
			false, "binary content must not match by accident"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := looksSecret(tc.path, filepath.Base(tc.path))
			require.Equal(t, tc.want, got, tc.why)
		})
	}
}

// TestProseAndProgramsAreNotCredentials covers the exclusion that turned the
// weakest rule from noise into signal. Every name here was actually offered by
// an earlier version of the scan.
func TestProseAndProgramsAreNotCredentials(t *testing.T) {
	for _, name := range []string{
		"secrets.py", "token.py", "secret.py",
		"libssh2_userauth_password.3", "libssh2_userauth_password_ex.3",
		"absl_cordz_sample_token.pc",
		"Invoke-ImpersonateByProcessToken.ps1",
		"KDB4_PasswordsOnly.xsl",
		"secret-report.yml",
		"feedback_passwordless_sudo_ask_first.md",
		"1Password Emergency Kit.pdf",
	} {
		t.Run(name, func(t *testing.T) {
			require.True(t, isProseOrProgram(name),
				"%s talks about secrets for a living; it does not hold one", name)
		})
	}

	// And the things that are not prose still reach the rules.
	for _, name := range []string{"credentials", ".env", "id_rsa", "msal_token_cache.json", "secrets.env.txt"} {
		require.False(t, isProseOrProgram(name), "%s must not be excluded", name)
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
	write(".claude/sessions/a.key", 10)
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
	require.NoError(t, os.WriteFile(outside, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600))
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
