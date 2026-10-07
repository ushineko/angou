//go:build e2e && windows

package e2e

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// passphraseCommand builds a command that reads its passphrase from r.
//
// Windows has no numbered descriptors to hand down, so ExtraFiles is
// unsupported there. The pipe's handle is inherited instead, and its value is
// what --passphrase-fd names: an inherited handle keeps its value in the child,
// and os.NewFile takes a handle on Windows where it takes a descriptor
// elsewhere. The passphrase still never reaches the command line or the
// environment.
func passphraseCommand(bin string, r *os.File, args ...string) *exec.Cmd {
	handle := r.Fd()
	cmd := exec.Command(bin, append([]string{"--passphrase-fd", strconv.FormatUint(uint64(handle), 10)}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(handle)}}
	return cmd
}
