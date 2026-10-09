//go:build windows

package fsx

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// holdOpen opens path without FILE_SHARE_DELETE, the way a sync client or
// scanner holds a file it is reading, which makes Windows refuse to replace it.
func holdOpen(t *testing.T, path string) windows.Handle {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	h, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	require.NoError(t, err)
	return h
}

func staged(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "index")
	tmp := filepath.Join(dir, "tmp")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))
	require.NoError(t, os.WriteFile(tmp, []byte("new"), 0o600))
	return target, tmp
}

func TestRenameWaitsOutABriefHold(t *testing.T) {
	target, tmp := staged(t)
	h := holdOpen(t, target)
	require.Error(t, os.Rename(tmp, target), "the hold must make a plain rename fail, or this test proves nothing")

	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = windows.CloseHandle(h)
	}()
	require.NoError(t, Rename(tmp, target))
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "new", string(got))
}

func TestRenameGivesUpOnAHoldThatOutlastsTheTimeout(t *testing.T) {
	old := renameTimeout
	renameTimeout = 100 * time.Millisecond
	t.Cleanup(func() { renameTimeout = old })

	target, tmp := staged(t)
	h := holdOpen(t, target)
	t.Cleanup(func() { _ = windows.CloseHandle(h) })

	err := Rename(tmp, target)
	require.ErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
}

func TestRenameDoesNotRetryOtherErrors(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()
	err := Rename(filepath.Join(dir, "absent"), filepath.Join(dir, "target"))
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Less(t, time.Since(start), renameTimeout/2, "a missing source is not worth waiting on")
}
