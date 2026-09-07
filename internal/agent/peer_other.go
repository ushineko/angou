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

func LockMemory() error { return errors.New("mlockall is not implemented on this platform") }

func setUmask(_ int) int { return 0 }
