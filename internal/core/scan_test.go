package core

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

	found, err := Scan(root)
	require.NoError(t, err)

	var names []string
	for _, c := range found {
		rel, err := filepath.Rel(root, c.Path)
		require.NoError(t, err)
		names = append(names, rel)
	}
	require.Equal(t, []string{".env"}, names,
		"only the real Candidate should be offered; got %v", names)
}

// TestScanIgnoresSymlinks covers the one that matters for a store: a symlink is
// a pointer to a file somewhere else, and following it would encrypt something
// the user never pointed the scan at.
func TestScanIgnoresSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.pem")
	require.NoError(t, os.WriteFile(outside, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link.pem")))

	found, err := Scan(root)
	require.NoError(t, err)
	require.Empty(t, found, "a symlink is not a file to encrypt")
}

func TestHumanSize(t *testing.T) {
	require.Equal(t, "0B", HumanSize(0))
	require.Equal(t, "512B", HumanSize(512))
	require.Equal(t, "1.0K", HumanSize(1024))
	require.Equal(t, "1.5M", HumanSize(1024*1024*3/2))
}

// A private key is a private key whatever it is called.
//
// Every name-based rule missed ~/njv_ssh_key: outside .ssh, no id_ prefix, and
// "key" without a dot in front of it is not the ".key" extension the PEM rule
// looks for. The file's own first line identified it beyond doubt, and the
// scanner was not looking at it unless a name had already matched.
func TestPrivateKeyHeaderBeatsTheName(t *testing.T) {
	root := t.TempDir()

	keys := map[string]string{
		// The reported case: a key named however its owner felt like naming it.
		"njv_ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n",
		// No hint in the name at all.
		"backup-2019": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n",
		// An encrypted key is still a key.
		"work.bak": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBABgkq\n",
		// A misleading extension must not save it either.
		"notes.txt": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA\n",
	}
	for name, content := range keys {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o600))
	}

	found, err := Scan(root)
	require.NoError(t, err)

	got := map[string]string{}
	for _, c := range found {
		got[filepath.Base(c.Path)] = c.Reason
	}
	for name := range keys {
		require.Containsf(t, got, name, "a file whose header says PRIVATE KEY must be found "+
			"whatever it is named; %q was missed", name)
	}
}

// The header rule must not undo the exclusions that stop the scan being noise.
func TestPrivateKeyHeaderDoesNotOverrideTheExclusions(t *testing.T) {
	root := t.TempDir()

	// A public key mentions the armour but is never secret.
	require.NoError(t, os.WriteFile(filepath.Join(root, "id_ed25519.pub"),
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 someone@host\n"), 0o644))
	// Prose about keys is not a key.
	require.NoError(t, os.WriteFile(filepath.Join(root, "howto.md"),
		[]byte("# Keys\n\nRun ssh-keygen to make one. The file starts with a BEGIN line.\n"), 0o644))
	// A certificate is not a private key, whatever it sits beside.
	require.NoError(t, os.WriteFile(filepath.Join(root, "server.crt"),
		[]byte("-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgI\n"), 0o644))

	found, err := Scan(root)
	require.NoError(t, err)
	require.Empty(t, found, "none of these hold a private key")
}

// A shell expands ~ before angou sees an argument, but only when it is
// unquoted. `--store '~/store'` arrives literally and creates a directory
// actually named "~", and the GUI — which has no shell at all — always passes
// typed paths through this way. One turned up inside the repository: a real
// store at ./~/Dropbox/angou, created by a path someone typed with a tilde.
func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	require.Equal(t, home, ExpandPath("~"))
	require.Equal(t, filepath.Join(home, "Dropbox", "angou"), ExpandPath("~/Dropbox/angou"))

	// Left alone: absolute and relative paths mean what they say.
	require.Equal(t, "/tmp/store", ExpandPath("/tmp/store"))
	require.Equal(t, "store", ExpandPath("store"))
	require.Equal(t, "", ExpandPath(""))

	// A tilde that is not a home reference is a legitimate filename.
	require.Equal(t, "~store", ExpandPath("~store"))
	require.Equal(t, "backup~", ExpandPath("backup~"))
	require.Equal(t, "dir/~/file", ExpandPath("dir/~/file"))

	// "~user" is another user's home. Resolving it means consulting the password
	// database, and silently landing in someone else's home directory is worse
	// than not resolving at all.
	require.Equal(t, "~other/store", ExpandPath("~other/store"))
}

// A directory named "~" is a trap, not a mess. From its parent the obvious way
// to remove it is `rm -rf ~`, which the shell expands to the user's home
// directory before rm runs — so the tool must not create one, and the person who
// found the one angou made was right to delete it from a file manager.
func TestCheckCreatablePathRefusesABareTilde(t *testing.T) {
	for _, bad := range []string{
		"~/Dropbox/angou",         // only reachable unexpanded; refused anyway
		"/home/someone/git/x/~",   // the exact shape angou created
		"/home/someone/~/Dropbox", // a tilde in the middle
		"./~/store",               // relative, as a shell would leave it
	} {
		require.ErrorIsf(t, CheckCreatablePath(bad), ErrTildeComponent,
			"%q contains a bare tilde component and must be refused", bad)
	}

	// Ordinary paths, including filenames that merely contain a tilde. Backup
	// files end in one, and refusing those would be a different bug.
	for _, ok := range []string{
		"/home/someone/Dropbox/angou",
		"store",
		"/tmp/backup~",
		"/tmp/~store",
		"/tmp/a~b/store",
	} {
		require.NoErrorf(t, CheckCreatablePath(ok), "%q is an ordinary path", ok)
	}
}
