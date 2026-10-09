//go:build !windows

package core

import "io/fs"

// recordedMode is the permission recorded for a file encrypted on this machine:
// the file's own mode bits.
func recordedMode(fi fs.FileInfo) uint32 { return uint32(fi.Mode().Perm()) }
