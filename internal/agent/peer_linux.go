//go:build linux

package agent

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkPeer refuses a connection from another user.
//
// SO_PEERCRED reports the credentials the kernel recorded at connect time, so it
// cannot be spoofed by the peer. It establishes only that the peer runs as this
// user; it says nothing about which program it is, and there is no portable way
// to ask that question meaningfully.
func checkPeer(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("%w: not a unix socket", ErrDenied)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("%w: cannot read peer credentials: %w", ErrDenied, err)
	}

	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("%w: cannot read peer credentials: %w", ErrDenied, err)
	}
	if credErr != nil {
		return fmt.Errorf("%w: cannot read peer credentials: %w", ErrDenied, credErr)
	}
	if int(cred.Uid) != os.Getuid() {
		return fmt.Errorf("%w: connection from uid %d, this agent serves uid %d",
			ErrDenied, cred.Uid, os.Getuid())
	}
	return nil
}

// LockMemory asks the kernel not to page this process out.
//
// Best-effort by design: it commonly fails without privileges or against a low
// RLIMIT_MEMLOCK, and failing to lock memory is not a reason to refuse to run.
// It reduces the chance of key material reaching swap; it does not prevent it,
// and the garbage collector may relocate a secret before any of this applies
// (R-2).
func LockMemory() error {
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("mlockall: %w", err)
	}
	return nil
}

func setUmask(mask int) int { return unix.Umask(mask) }
