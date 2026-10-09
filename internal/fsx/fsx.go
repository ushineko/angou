// Package fsx holds the small filesystem differences between platforms that
// more than one package has to agree on.
package fsx

import (
	"errors"
	"fmt"
	"io/fs"
)

// ErrSymlink reports a path whose final component is a symbolic link where a
// regular file is required.
var ErrSymlink = errors.New("refusing to write through a symbolic link")

// RefuseSymlink fails when lstat reports name as a symbolic link. A missing
// file is not an error: the caller is about to create it.
//
// On Unix this duplicates what NoFollow already enforces atomically; it exists
// for Windows, where NoFollow is zero and this check is the only one.
func RefuseSymlink(lstat func(string) (fs.FileInfo, error), name string) error {
	fi, err := lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, name)
	}
	return nil
}
