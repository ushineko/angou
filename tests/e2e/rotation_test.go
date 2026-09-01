//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// seedStore fills a store with a handful of files and returns their contents by
// logical path.
func seedStore(t *testing.T, e *env, n int) map[string]string {
	t.Helper()
	want := map[string]string{}
	for i := 0; i < n; i++ {
		path := "proj/" + string(rune('a'+i)) + ".env"
		content := "FIELD=value-" + string(rune('a'+i)) + "\n"
		src := e.writePlaintext("seed", []byte(content), 0o600)
		e.mustRun("enc", "--as", path, src)
		want[path] = content
	}
	return want
}

// blobDigests records each blob's name and its bytes, for a byte-identity check.
func blobDigests(t *testing.T, e *env) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range e.blobNames() {
		out[name] = string(readFile(t, e.storePath(name)))
	}
	return out
}

// TestRekeyLocalChangesNothingInTheStore covers R4.1: rotating the machine
// password is a local operation, and a user reaching for it after losing a
// laptop needs to know it did not touch the shared store.
func TestRekeyLocalChangesNothingInTheStore(t *testing.T) {
	e := keyringEnv(t)
	e.initStore()
	want := seedStore(t, e, 3)
	e.mustRun("bootstrap")

	before := blobDigests(t, e)
	beforeLocal := readLocalKeyFile(t, e)

	e.mustRunNoPassphrase("rekey", "--local")

	require.Equal(t, before, blobDigests(t, e),
		"rekey --local must leave every blob name and every blob body byte-identical")
	require.NotEqual(t, beforeLocal, readLocalKeyFile(t, e),
		"the local key must be re-wrapped under a fresh machine password")

	for path, content := range want {
		require.Equal(t, content, e.mustRunNoPassphrase("dec", path).stdout)
	}
}

// TestRekeyIdentityRotatesKeyAndNames covers R4.2 and R4.2.1. Rotating the
// keypair without rotating the naming key would leave the deterministic names in
// place, and with them an observer's ability to follow each file across
// snapshots — a metadata channel that survives the rotation it was supposed to
// end.
func TestRekeyIdentityRotatesKeyAndNames(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	want := seedStore(t, e, 4)

	before := e.blobNames()
	sort.Strings(before)
	require.Len(t, before, 4)

	fingerprints := e.mustRunLines(2, "rekey", "--identity")
	require.Contains(t, fingerprints.stdout, "blobs re-encrypted and renamed: 4")

	after := e.blobNames()
	sort.Strings(after)
	require.Len(t, after, 4, "every blob must survive the rotation")

	for _, name := range after {
		require.NotContains(t, before, name,
			"no filename in the rotated store may appear in the old one (R4.2.1)")
	}

	// Every blob still decrypts, under the new key, with its content intact.
	for path, content := range want {
		require.Equal(t, content, e.mustRun("dec", path).stdout)
	}
	require.Len(t, strings.Fields(strings.TrimSpace(e.mustRun("ls").stdout)), 4)
}

// TestOldKeyOpensNothingAfterRekey covers the verification step of R6.4.1.
// Without it an operator cannot tell a complete rotation from a partial one.
func TestOldKeyOpensNothingAfterRekey(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	seedStore(t, e, 3)

	oldFingerprint := e.fingerprint
	require.NotEmpty(t, oldFingerprint)

	e.mustRunLines(2, "rekey", "--identity")

	r := e.mustRun("doctor", "--old-key", oldFingerprint)
	require.Contains(t, r.stdout, "opens nothing")

	// And once the superseded bundle is pruned, the check reports that it cannot
	// be performed rather than reporting a clean result it did not establish.
	e.mustRun("prune", "--bundles")
	after := e.run("doctor", "--old-key", oldFingerprint)
	require.NotZero(t, after.code)
	require.Contains(t, after.stderr, "must not be assumed")
}

// TestInterruptedRekeyLeavesTheStoreReadable covers R4.3. A rotation that dies
// part-way must not take the store with it.
func TestInterruptedRekeyLeavesTheStoreReadable(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	// Enough blobs that the staging phase lasts long enough to be interrupted.
	want := seedStore(t, e, 12)
	before := blobDigests(t, e)

	killed := e.startAndKill(t, 60*time.Millisecond, "rekey", "--identity")
	require.NotZero(t, killed, "the rekey should have been killed rather than completing")

	// The staging directory must not survive as store content.
	require.NoDirExists(t, e.storePath(".angou-rekey"),
		"an interrupted rekey must not leave its staging directory behind")

	// Every original blob is still present, byte-identical, and readable.
	require.Equal(t, before, blobDigests(t, e),
		"an interrupted rekey must leave the previous store byte-identical")
	for path, content := range want {
		require.Equal(t, content, e.mustRun("dec", path).stdout,
			"%s must still be readable after an interrupted rekey", path)
	}
	e.mustRun("reindex")
}

// TestPasswdChangesTheGuardNotTheKey covers R6.4.1: passwd rewrites what
// protects the key bundle and leaves every blob alone.
func TestPasswdChangesTheGuardNotTheKey(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	want := seedStore(t, e, 3)
	before := blobDigests(t, e)

	fresh := freshPassphrase(t)
	e.mustRunWithLines([]string{e.recovery, fresh}, "passwd")

	require.Equal(t, before, blobDigests(t, e), "passwd must not change any blob")

	// The old passphrase no longer opens the store...
	require.NotZero(t, e.runWithPassphrase(e.recovery, "ls").code,
		"the previous recovery passphrase must stop working")
	// ... and the new one does.
	for path, content := range want {
		require.Equal(t, content, e.runWithPassphrase(fresh, "dec", path).stdout)
	}
}

// TestPruneOrphansRemovesUnreadableLeftovers covers the cleanup path an
// interrupted rotation needs.
func TestPruneOrphansRemovesUnreadableLeftovers(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	seedStore(t, e, 2)

	// A blob-shaped file this store's key cannot read, which is exactly what a
	// half-finished rotation leaves.
	orphan := e.storePath("aaaaaaaaaaaaaaaaaaaaaaaaaa.angou")
	require.NoError(t, os.WriteFile(orphan,
		[]byte("-----BEGIN ANGOU1 BLOB-----\nFormat: ANGOU1\nEncoding: armor\n\nnot a real payload\n-----END ANGOU1 BLOB-----\n"), 0o600))

	// reindex reports it and carries on rather than aborting.
	r := e.mustRun("reindex")
	require.Contains(t, r.stderr, "does not decrypt")
	require.Contains(t, e.mustRun("ls").stdout, "proj/a.env")

	e.mustRun("prune", "--orphans")
	require.NoFileExists(t, orphan)
}

// startAndKill runs a command and kills it after d, returning the signal-derived
// exit code.
func (e *env) startAndKill(t *testing.T, d time.Duration, args ...string) int {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	go func() {
		defer func() { _ = w.Close() }()
		_, _ = w.WriteString(e.recovery + "\n" + e.recovery + "\n")
	}()
	defer func() { _ = r.Close() }()

	cmd := exec.Command(e.bin, append([]string{"--passphrase-fd", "3"}, args...)...)
	cmd.ExtraFiles = []*os.File{r}
	cmd.Dir = e.work
	cmd.Env = e.childEnv()
	require.NoError(t, cmd.Start())

	time.AfterFunc(d, func() { _ = cmd.Process.Kill() })
	err = cmd.Wait()
	if err == nil {
		return 0
	}
	return 1
}
