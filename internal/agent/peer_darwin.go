//go:build darwin

package agent

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkPeer refuses a connection from another user.
//
// macOS has no SO_PEERCRED. LOCAL_PEERCRED is the equivalent: the kernel records
// the peer's credentials at connect time and this side reads them back, so the
// peer cannot spoof them. Like the Linux check it establishes only that the peer
// runs as this user — not which program it is, a question there is no portable
// way to ask meaningfully.
func checkPeer(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("%w: not a unix socket", ErrDenied)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("%w: cannot read peer credentials: %w", ErrDenied, err)
	}

	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
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
// Best-effort by design, exactly as on Linux: mlockall commonly fails without
// privileges or against a low memory-lock limit, and that is not a reason to
// refuse to run. It reduces the chance of key material reaching swap; it does
// not prevent it, and the garbage collector may relocate a secret before any of
// this applies (R-2).
func LockMemory() error {
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("mlockall: %w", err)
	}
	return nil
}

func setUmask(mask int) int { return unix.Umask(mask) }
