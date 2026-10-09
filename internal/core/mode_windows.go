//go:build windows

package core

import "io/fs"

// recordedMode is the permission recorded for a file encrypted on this machine.
//
// Windows has no Unix mode bits: Go reports 0666 for every writable file and
// 0444 for a read-only one, and what actually guards the file is its ACL, which
// does not travel. Recording 0666 would hand the next Unix machine to decrypt
// the file a world-readable private key, so a Windows file is recorded as
// private to its owner — 0600, or 0400 where it was read-only.
func recordedMode(fi fs.FileInfo) uint32 {
	if fi.Mode().Perm()&0o200 == 0 {
		return 0o400
	}
	return 0o600
}
