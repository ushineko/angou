//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// --- enc --all --------------------------------------------------------------

// seedHome builds a home directory with the shapes a scan should and should not
// find, so the test says something about judgement rather than only about
// walking a tree.
func seedHome(t *testing.T, e *env) {
	t.Helper()
	for _, dir := range []string{".ssh", ".aws", ".kube", "proj/app", ".cache/junk", "node_modules/pkg", "docs"} {
		mkdirAll(t, filepath.Join(e.home, dir))
	}
	write := func(rel, content string, mode os.FileMode) {
		path := filepath.Join(e.home, rel)
		require.NoError(t, os.WriteFile(path, []byte(content), mode))
		require.NoError(t, os.Chmod(path, mode))
	}
	// Should be found.
	write(".ssh/id_ed25519", "PRIVATE KEY MATERIAL\n", 0o600)
	write(".aws/credentials", "[default]\naws_access_key_id=AKIA\n", 0o600)
	write(".kube/config", "apiVersion: v1\n", 0o600)
	write("proj/app/.env", "DB_URL=postgres://x\n", 0o600)
	write("proj/app/service.pem", "-----BEGIN PRIVATE KEY-----\n", 0o600)

	// Should not be.
	write(".ssh/id_ed25519.pub", "ssh-ed25519 AAAA\n", 0o644) // public half
	write("docs/README.md", "nothing sensitive\n", 0o644)     // ordinary file
	write(".cache/junk/.env", "cached copy\n", 0o644)         // skipped directory
	write("node_modules/pkg/.env", "vendored copy\n", 0o644)  // skipped directory
}

// TestEncAllFindsCredentialsAndSkipsTheRest covers the scan's judgement. The
// value of --all is entirely in what it declines to offer: a scanner that
// suggested every file would be no better than the user doing it by hand.
func TestEncAllFindsCredentialsAndSkipsTheRest(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	seedHome(t, e)

	r := e.mustRun("enc", "--all", "--auto", e.home)
	listing := e.mustRun("ls", "--names").stdout

	for _, want := range []string{
		".ssh/id_ed25519", ".aws/credentials", ".kube/config",
		"proj/app/.env", "proj/app/service.pem",
	} {
		require.Contains(t, listing, want, "the scan should have found %s", want)
	}
	for _, unwanted := range []string{
		"id_ed25519.pub", "README.md", ".cache", "node_modules",
		".env.example", "secrets.py",
	} {
		require.NotContains(t, listing, unwanted, "the scan should not have offered %s", unwanted)
	}

	require.Contains(t, r.stderr, "Encrypted 5")
	require.Contains(t, r.stderr, "originals are untouched")

	// The originals really are untouched, including their permissions.
	info, err := os.Stat(filepath.Join(e.home, ".ssh", "id_ed25519"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.Equal(t, "PRIVATE KEY MATERIAL\n",
		string(readFile(t, filepath.Join(e.home, ".ssh", "id_ed25519"))))
}

// TestEncAllAsksWithoutAuto covers the default. The scan is a guess, and a guess
// is worth checking before it sweeps files into a store.
func TestEncAllAsksWithoutAuto(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	seedHome(t, e)

	// The suite never gives the child a terminal, which is exactly the case
	// that must not default to yes: a sweep of a home directory into a store is
	// not something to do because nobody was there to object.
	r := e.run("enc", "--all", e.home)
	require.NotZero(t, r.code, "without --auto and without a terminal, nothing may be swept up")
	require.Contains(t, r.stderr, "no terminal to ask")
	require.Contains(t, r.stderr, "--auto", "the refusal should say how to proceed")
	require.Contains(t, r.stderr, "candidate(s)", "and how many it found")

	require.Empty(t, strings.TrimSpace(e.mustRun("ls", "--names").stdout),
		"nothing may be stored")
}

// TestEncAllDryRunStoresNothing covers the flag that makes the scan usable: the
// only way to find out whether the guess is any good on a particular machine is
// to see what it picked and why, before it acts.
func TestEncAllDryRunStoresNothing(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	seedHome(t, e)

	r := e.mustRun("enc", "--all", "--dry-run", e.home)

	// It reports what it found, and why for each one.
	require.Contains(t, r.stdout, "SIZE")
	require.Contains(t, r.stdout, "WHY")
	require.Contains(t, r.stdout, "id_ed25519")
	require.Contains(t, r.stdout, "SSH private key")
	require.Contains(t, r.stdout, "AWS credentials")
	require.Contains(t, r.stdout, ".env")

	// And it declines what it should, in the same listing.
	require.NotContains(t, r.stdout, "id_ed25519.pub")
	require.NotContains(t, r.stdout, "README.md")

	require.Contains(t, r.stderr, "Nothing was stored")
	require.Contains(t, r.stderr, "not an assurance")

	// Nothing was stored, which is the whole contract.
	require.Empty(t, strings.TrimSpace(e.mustRun("ls", "--names").stdout))
}

// TestDryRunNeedsAll checks the flag is refused where it would mean nothing,
// rather than silently ignored.
func TestDryRunNeedsAll(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("one.env", []byte("FIELD=value\n"), 0o600)

	r := e.run("enc", "--dry-run", src)
	require.NotZero(t, r.code)
	require.Contains(t, r.stderr, "--all")
}

// TestEncAllOnAnEmptyTreeSaysWhatItMeans covers the wording of the empty result,
// which is the one most likely to be misread as a clean bill of health.
func TestEncAllOnAnEmptyTreeSaysWhatItMeans(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	mkdirAll(t, filepath.Join(e.home, "boring"))
	require.NoError(t, os.WriteFile(filepath.Join(e.home, "boring", "notes.txt"), []byte("hi\n"), 0o644))

	r := e.mustRun("enc", "--all", "--auto", e.home)
	require.Contains(t, r.stdout, "Nothing that looks like a credential")
	require.Contains(t, r.stderr, "not the same as there being nothing sensitive",
		"an empty result must not be presented as an assurance")
}

// --- dec restoring to the recorded location ---------------------------------

// TestDecRestoresToTheRecordedLocation is the point of recording an origin: a
// key encrypted on one machine goes back to ~/.ssh on the next one, not into
// whatever directory you happened to be standing in.
func TestDecRestoresToTheRecordedLocation(t *testing.T) {
	machineA := newEnv(t)
	machineB := newEnv(t)

	machineA.initStore()
	mkdirAll(t, filepath.Join(machineA.home, ".ssh"))
	origin := filepath.Join(machineA.home, ".ssh", "id_ed25519")
	require.NoError(t, os.WriteFile(origin, []byte("PRIVATE\n"), 0o600))
	machineA.mustRun("enc", origin)

	syncStore(t, machineA.store, machineB.store)

	// The origin is machine A's absolute path, which is what a second machine
	// actually receives. Remove the file so the restore has somewhere to land.
	require.NoError(t, os.Remove(origin))

	r := machineB.runWithPassphrase(machineA.recovery, "dec", "--restore", ".ssh/id_ed25519")
	require.Zero(t, r.code, "restore should succeed:\n%s", r.stderr)
	require.Contains(t, r.stdout, origin, "the destination must be reported")

	require.Equal(t, "PRIVATE\n", string(readFile(t, origin)))
	info, err := os.Stat(origin)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"a restored private key must come back with its own permissions")
}

// TestRestoreWillNotReplaceWithoutBeingTold covers the guard. With nothing to
// answer a question, the destructive default must be the safe one.
func TestRestoreWillNotReplaceWithoutBeingTold(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	mkdirAll(t, filepath.Join(e.home, ".ssh"))
	origin := filepath.Join(e.home, ".ssh", "id_ed25519")
	require.NoError(t, os.WriteFile(origin, []byte("ORIGINAL\n"), 0o600))
	e.mustRun("enc", origin)

	require.NoError(t, os.WriteFile(origin, []byte("CHANGED SINCE\n"), 0o600))

	r := e.run("dec", "--restore", ".ssh/id_ed25519")
	require.NotZero(t, r.code, "an existing file must not be replaced silently")
	require.Equal(t, "CHANGED SINCE\n", string(readFile(t, origin)),
		"the file on disk must be untouched")

	// And with --overwrite it goes ahead.
	e.mustRun("dec", "--restore", "--overwrite", ".ssh/id_ed25519")
	require.Equal(t, "ORIGINAL\n", string(readFile(t, origin)))
}

// TestRestoreRefusesASymlink covers the destination check. A symlink at the
// recorded location would otherwise be written through, to somewhere the store
// never named.
func TestRestoreRefusesASymlink(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	mkdirAll(t, filepath.Join(e.home, ".ssh"))
	origin := filepath.Join(e.home, ".ssh", "id_ed25519")
	require.NoError(t, os.WriteFile(origin, []byte("PRIVATE\n"), 0o600))
	e.mustRun("enc", origin)

	elsewhere := filepath.Join(e.work, "elsewhere")
	require.NoError(t, os.WriteFile(elsewhere, []byte("NOT THIS\n"), 0o600))
	require.NoError(t, os.Remove(origin))
	require.NoError(t, os.Symlink(elsewhere, origin))

	r := e.run("dec", "--restore", "--overwrite", ".ssh/id_ed25519")
	require.NotZero(t, r.code)
	require.Contains(t, r.stderr, "symlink")
	require.Equal(t, "NOT THIS\n", string(readFile(t, elsewhere)),
		"nothing may be written through the link")
}

// TestDecWritesToStdoutWhenPiped guards the habit `angou dec x > file`. Changing
// what a command does when its output is redirected would break scripts silently.
func TestDecWritesToStdoutWhenPiped(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	mkdirAll(t, filepath.Join(e.home, ".ssh"))
	origin := filepath.Join(e.home, ".ssh", "id_ed25519")
	require.NoError(t, os.WriteFile(origin, []byte("PRIVATE\n"), 0o600))
	e.mustRun("enc", origin)

	// The harness never gives the child a terminal, so this is the piped case.
	require.Equal(t, "PRIVATE\n", e.mustRun("dec", ".ssh/id_ed25519").stdout)

	// And nothing was written anywhere as a side effect.
	require.NoFileExists(t, filepath.Join(e.work, "id_ed25519"))
}

// TestDecOutFlagStillWins covers the explicit destination taking precedence over
// the recorded one.
func TestDecOutFlagStillWins(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("thing.env", []byte("FIELD=value\n"), 0o600)
	e.mustRun("enc", src)

	dest := filepath.Join(e.work, "elsewhere.env")
	e.mustRun("dec", "--out", dest, strings.TrimPrefix(filepath.ToSlash(src), "/"))
	require.Equal(t, "FIELD=value\n", string(readFile(t, dest)))
}

// TestEncRecordsTheOrigin checks the metadata itself, since everything above
// depends on it being carried.
func TestEncRecordsTheOrigin(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("recorded.env", []byte("FIELD=value\n"), 0o600)
	e.mustRun("enc", src)

	listing := e.mustRun("ls").stdout
	require.Contains(t, listing, "ORIGIN")
	require.Contains(t, listing, "recorded.env")
}

// --- ls ---------------------------------------------------------------------

// TestLsShowsDetail covers the default listing.
func TestLsShowsDetail(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("app/.secrets.env", []byte("DB=1\n"), 0o600)
	e.mustRun("enc", "--as", "app/.secrets.env", src)

	r := e.mustRun("ls")
	for _, want := range []string{"MODE", "SIZE", "MODIFIED", "PATH", "ORIGIN", "rw-------", "app/.secrets.env", "1 files"} {
		require.Contains(t, r.stdout, want)
	}
}

// TestLsIsPlainWhenPiped covers the colour rule. A listing being read by another
// program should not have to be stripped of escapes first.
func TestLsIsPlainWhenPiped(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("c.env", []byte("x\n"), 0o600)
	e.mustRun("enc", "--as", "c.env", src)

	r := e.mustRun("ls")
	require.NotContains(t, r.stdout, "\033[", "no escape sequences when stdout is not a terminal")
	require.NotContains(t, e.mustRun("ls", "--names").stdout, "\033[")
}

// TestLsNamesIsScriptable covers the form a script consumes.
func TestLsNamesIsScriptable(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	for _, p := range []string{"a/one.env", "b/two.env"} {
		src := e.writePlaintext(filepath.Base(p), []byte("x\n"), 0o600)
		e.mustRun("enc", "--as", p, src)
	}
	lines := strings.Fields(strings.TrimSpace(e.mustRun("ls", "--names").stdout))
	require.Equal(t, []string{"a/one.env", "b/two.env"}, lines,
		"--names should print paths and nothing else")
}

// TestLsRawShowsTheStoreAsItIs covers the raw listing, which exists to show
// honestly what the keyed naming does and does not hide.
func TestLsRawShowsTheStoreAsItIs(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("secret.env", []byte("DB_PASSWORD=x\n"), 0o600)
	e.mustRun("enc", "--as", "very/secret/name.env", src)

	// --raw needs no passphrase: these are the names anyone holding the store
	// already sees.
	r := e.mustRunNoPassphrase("ls", "--raw")

	require.Contains(t, r.stdout, "store.angou")
	require.Contains(t, r.stdout, "index.angou")
	require.Contains(t, r.stdout, "encrypted file")
	require.Contains(t, r.stdout, "1 encrypted files")

	// The whole point: the logical name is nowhere in it.
	require.NotContains(t, r.stdout, "very/secret/name.env")
	require.NotContains(t, r.stdout, "secret.env")

	// And it says what is and is not hidden.
	require.Contains(t, r.stderr, "give up no")
	require.Contains(t, r.stderr, "sizes are visible")
}
