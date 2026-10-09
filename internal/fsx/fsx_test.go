package fsx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRefuseSymlink(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	require.NoError(t, os.WriteFile(regular, []byte("x"), 0o600))

	require.NoError(t, RefuseSymlink(os.Lstat, regular), "a regular file is accepted")
	require.NoError(t, RefuseSymlink(os.Lstat, filepath.Join(dir, "absent")), "a missing file is accepted")

	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Skipf("cannot create a symlink here (Windows without Developer Mode): %v", err)
	}
	require.ErrorIs(t, RefuseSymlink(os.Lstat, link), ErrSymlink)
}
