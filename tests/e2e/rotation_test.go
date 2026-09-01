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
	// --names, because the default listing is now a table rather than one path
	// per line.
	require.Len(t, strings.Fields(strings.TrimSpace(e.mustRun("ls", "--names").stdout)), 4)
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
	// prune --bundles asks for the recovery passphrase a second time: it decides
	// which bundle to keep by testing each against the store rather than by
	// trusting the filename.
	e.mustRunLines(2, "prune", "--bundles")
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

// TestPruneKeepsTheBundleThatOpensTheStore covers the failure mode that makes
// prune dangerous rather than tidy.
//
// An identity rekey has to replace both the key bundle and store.angou, and
// those cannot change in one step. Interrupted in between, the file named
// keybundle.json is the one that does *not* open the store, and the retained
// bundle is the one that does. A prune that kept the current bundle by its
// filename would delete the only usable one and finish the damage the
// interruption started.
func TestPruneKeepsTheBundleThatOpensTheStore(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	want := seedStore(t, e, 3)
	e.mustRunLines(2, "rekey", "--identity")

	// Reproduce the interrupted state by exchanging the two bundle names, so
	// the current name holds the bundle that no longer opens the store.
	current := e.storePath("bootstrap", "keybundle.json")
	superseded := supersededBundlePath(t, e)
	swapFiles(t, current, superseded)

	// The store still opens, because the reader tries every bundle.
	require.Contains(t, e.mustRun("ls").stdout, "proj/a.env")

	e.mustRunLines(2, "prune", "--bundles")

	// And it still opens afterwards, which is the whole point.
	for path, content := range want {
		require.Equal(t, content, e.mustRun("dec", path).stdout,
			"%s must survive a prune performed in the interrupted state", path)
	}
	require.NoFileExists(t, superseded, "the unusable bundle should be gone")
	require.FileExists(t, current, "the working bundle should have been promoted")
}

// TestPruneOrphansRefusesMisnamedBlobs covers the other prune hazard. A blob that
// decrypts with the current key but sits under a name its envelope does not
// address is not rotation debris — it is the R1.8 substitution — and deleting it
// would destroy both a live secret and the evidence of the tampering.
func TestPruneOrphansRefusesMisnamedBlobs(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	seedStore(t, e, 2)

	names := e.blobNames()
	require.Len(t, names, 2)
	// Serve one blob's ciphertext under the other's name.
	require.NoError(t, os.WriteFile(e.storePath(names[0]), readFile(t, e.storePath(names[1])), 0o600))

	r := e.run("prune", "--orphans")
	require.NotZero(t, r.code, "a name-binding failure must not be pruned away quietly")
	require.Contains(t, r.stderr, "Refused to remove")
	require.FileExists(t, e.storePath(names[0]),
		"the misnamed blob must be left in place as evidence")
}

func supersededBundlePath(t *testing.T, e *env) string {
	t.Helper()
	entries, err := os.ReadDir(e.storePath("bootstrap"))
	require.NoError(t, err)
	for _, de := range entries {
		if strings.HasPrefix(de.Name(), "keybundle-") {
			return e.storePath("bootstrap", de.Name())
		}
	}
	t.Fatal("no superseded key bundle was retained by the rotation")
	return ""
}

func swapFiles(t *testing.T, a, b string) {
	t.Helper()
	aBytes, bBytes := readFile(t, a), readFile(t, b)
	require.NoError(t, os.WriteFile(a, bBytes, 0o600))
	require.NoError(t, os.WriteFile(b, aBytes, 0o600))
}
