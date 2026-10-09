//go:build e2e && !windows

package e2e

import (
	"os"
	"os/exec"
)

// passphraseCommand builds a command that reads its passphrase from r, passed
// as file descriptor 3. The passphrase never reaches the command line or the
// environment, both of which any process running as the same user can read.
func passphraseCommand(bin string, r *os.File, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, append([]string{"--passphrase-fd", "3"}, args...)...)
	cmd.ExtraFiles = []*os.File{r} // becomes fd 3 in the child
	return cmd
}
