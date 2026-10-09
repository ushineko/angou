//go:build windows

package fsx

// NoFollow is zero on Windows, which has no O_NOFOLLOW open flag. Callers that
// need the leaf to be a regular file check it with Lstat first (see
// RefuseSymlink). That check and the open are two steps, so a symlink planted
// between them is not caught; creating one on Windows needs Developer Mode or
// the SeCreateSymbolicLinkPrivilege, which narrows who can win that race but
// does not close it.
const NoFollow = 0
