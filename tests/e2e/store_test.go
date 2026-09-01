//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSamePathUpdatesInPlace covers the determinism of R3.2: because the blob
// name is a function of the logical path, a second write lands on the same file
// and leaves no orphan behind.
func TestSamePathUpdatesInPlace(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	src := e.writePlaintext("v.env", []byte("V=1\n"), 0o600)
	e.mustRun("enc", "--as", "app/v.env", src)
	first := e.blobNames()
	require.Len(t, first, 1)

	require.NoError(t, os.WriteFile(src, []byte("V=2\n"), 0o600))
	e.mustRun("enc", "--as", "app/v.env", src)

	require.Equal(t, first, e.blobNames(), "the second write must land on the same blob")
	require.Equal(t, "V=2\n", e.mustRun("dec", "app/v.env").stdout)
}

// TestDistinctStoresProduceDistinctBlobIDs covers R3.3 and R3.4: the blob name is
// keyed, so the same logical path in two stores has nothing in common. An
// unkeyed hash would let anyone holding either store confirm which well-known
// filenames it contains.
func TestDistinctStoresProduceDistinctBlobIDs(t *testing.T) {
	a := newEnv(t)
	b := newEnv(t)
	a.initStore()
	b.initStore()

	content := []byte("SAME=content\n")
	e1 := a.writePlaintext("x.env", content, 0o600)
	e2 := b.writePlaintext("x.env", content, 0o600)
	a.mustRun("enc", "--as", "same/path.env", e1)
	b.mustRun("enc", "--as", "same/path.env", e2)

	require.NotEqual(t, a.blobNames(), b.blobNames(),
		"identical paths in different stores must not share a blob name")
}

// TestRetrievalDoesNotNeedTheIndex covers R3.7: the index is a cache, and lookup
// by logical path goes through R3.2 instead.
func TestRetrievalDoesNotNeedTheIndex(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	src := e.writePlaintext("n.env", []byte("N=1\n"), 0o600)
	e.mustRun("enc", "--as", "deep/nested/n.env", src)
	require.NoError(t, os.Remove(e.storePath("index.angou")))

	r := e.mustRun("dec", "deep/nested/n.env")
	require.Equal(t, "N=1\n", r.stdout)
	require.Contains(t, r.stderr, "reindex", "the user should be told the index needs rebuilding")
}

// TestReindexRebuildsFromEnvelopes covers R3.7 for both the deleted index and the
// conflicted copy a sync service leaves behind.
func TestReindexRebuildsFromEnvelopes(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	for _, p := range []string{"a/one.env", "b/two.env", "b/c/three.env"} {
		src := e.writePlaintext(filepath.Base(p), []byte(p+"\n"), 0o600)
		e.mustRun("enc", "--as", p, src)
	}
	original := e.mustRun("ls", "--long").stdout
	require.NotEmpty(t, original)

	t.Run("after deletion", func(t *testing.T) {
		require.NoError(t, os.Remove(e.storePath("index.angou")))
		e.mustRun("reindex")
		require.Equal(t, original, e.mustRun("ls", "--long").stdout)
	})

	t.Run("after a conflicted copy", func(t *testing.T) {
		// Dropbox's shape: the original is replaced with one machine's copy and
		// the other is written alongside it under a decorated name.
		conflicted := e.storePath("index (nverenin's conflicted copy 2026-08-31).angou")
		require.NoError(t, os.WriteFile(conflicted, readFile(t, e.storePath("index.angou")), 0o600))
		require.NoError(t, os.WriteFile(e.storePath("index.angou"), []byte("garbage\n"), 0o600))

		r := e.mustRun("reindex")
		require.Contains(t, r.stderr, "conflicted copy",
			"the rebuild should name the debris it ignored rather than aborting on it")
		require.Equal(t, original, e.mustRun("ls", "--long").stdout)
	})
}

// TestIdenticalBasenamesCoexist covers R3.5: the store is keyed by
// store-relative path, so the same filename from two projects does not collide.
func TestIdenticalBasenamesCoexist(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	one := e.writePlaintext("one.env", []byte("PROJECT=one\n"), 0o600)
	two := e.writePlaintext("two.env", []byte("PROJECT=two\n"), 0o600)
	e.mustRun("enc", "--as", "projects/one/.secrets.env", one)
	e.mustRun("enc", "--as", "projects/two/.secrets.env", two)

	require.Len(t, e.blobNames(), 2)
	require.Equal(t, "PROJECT=one\n", e.mustRun("dec", "projects/one/.secrets.env").stdout)
	require.Equal(t, "PROJECT=two\n", e.mustRun("dec", "projects/two/.secrets.env").stdout)
}

// TestMoveReAddressesAndLeavesNoOrphan covers mv: the logical path is inside the
// signed envelope and bound to the filename, so both change together.
func TestMoveReAddressesAndLeavesNoOrphan(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	src := e.writePlaintext("m.env", []byte("M=1\n"), 0o600)
	e.mustRun("enc", "--as", "old/m.env", src)
	before := e.blobNames()
	require.Len(t, before, 1)

	e.mustRun("mv", "old/m.env", "new/m.env")

	after := e.blobNames()
	require.Len(t, after, 1, "mv must leave no orphan")
	require.NotEqual(t, before, after, "the blob name must follow the logical path")
	require.Equal(t, "M=1\n", e.mustRun("dec", "new/m.env").stdout)
	require.NotZero(t, e.run("dec", "old/m.env").code, "the old path must be gone")
}

// TestRemove deletes a blob and its index entry.
func TestRemove(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	src := e.writePlaintext("r.env", []byte("R=1\n"), 0o600)
	e.mustRun("enc", "--as", "r.env", src)
	e.mustRun("rm", "r.env")

	require.Empty(t, e.blobNames())
	require.Empty(t, e.mustRun("ls").stdout)
	require.NotZero(t, e.run("dec", "r.env").code)
}
