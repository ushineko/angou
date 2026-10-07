//go:build !linux && !darwin

package agent

import (
	"errors"
	"net"
)

// checkPeer has no implementation on platforms without one yet. It refuses
// rather than waving connections through: an agent that cannot identify its
// peers should not hand out key material. Linux and macOS have real
// implementations (peer_linux.go, peer_darwin.go); this covers the rest.
func checkPeer(_ net.Conn) error {
	return errors.New("peer credential checks are not implemented on this platform")
}

// LockMemory reports that memory locking is not implemented here. The agent
// never gets as far as calling it: Supported refuses first.
func LockMemory() error { return errors.New("mlockall is not implemented on this platform") }

// setUmask is a no-op where there is no umask. It is a variable rather than a
// function so staticcheck does not flag server.go's call, which matters on the
// platforms where it does change the umask, as a pure call whose result is unused.
var setUmask = func(_ int) int { return 0 }

// Supported reports why the agent cannot run here. An agent that refuses every
// connection is worse than none: it starts, prints a socket, and then leaves
// every command falling back to the passphrase with no explanation at the
// point the user chose it. Windows lands here; there the Credential Manager
// already spares the passphrase, which is what the agent is for elsewhere.
func Supported() error {
	return errors.New("the agent is not available on this platform: it cannot check which user is " +
		"connecting to it, and it will not hand the key to a connection it cannot identify")
}
