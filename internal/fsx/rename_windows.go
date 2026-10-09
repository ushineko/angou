//go:build windows

package fsx

import (
	"errors"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// renameTimeout bounds how long Rename keeps retrying. It is the bound Go's
// own toolchain uses for the same problem (cmd/go/internal/robustio). A
// variable so the test can shorten it.
var renameTimeout = 2 * time.Second

// Rename is os.Rename, retried for up to renameTimeout while the target is
// briefly held by another process.
//
// Windows refuses to replace a file that another process has open without
// FILE_SHARE_DELETE, and sync clients, indexers and antivirus all open files
// they have just seen change. Measured on a Dropbox folder: replacing a file
// moments after writing it failed seven times over 359 ms before succeeding,
// and angou's bootstrap self-test failed on exactly that, committing the index
// just after writing a blob beside it. Only the errors such a hold produces are
// retried; anything else is returned at once.
func Rename(oldpath, newpath string) error {
	start := time.Now()
	delay := 5 * time.Millisecond
	for {
		err := os.Rename(oldpath, newpath)
		if err == nil || !transient(err) || time.Since(start) >= renameTimeout {
			return err //nolint:wrapcheck // a drop-in for os.Rename; callers wrap
		}
		time.Sleep(delay)
		delay = min(2*delay, 100*time.Millisecond)
	}
}

func transient(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION:
		return true
	}
	return false
}
