//go:build !windows

package fsx

import "syscall"

// NoFollow makes an open refuse a symlink at the final path component.
const NoFollow = syscall.O_NOFOLLOW
