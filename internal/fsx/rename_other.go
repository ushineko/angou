//go:build !windows

package fsx

import "os"

// Rename is os.Rename. Replacing a file by rename does not depend on who else
// has it open here, so there is nothing to wait out.
func Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath) //nolint:wrapcheck // a drop-in for os.Rename; callers wrap
}
