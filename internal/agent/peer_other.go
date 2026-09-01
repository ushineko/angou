//go:build !linux

package agent

import (
	"errors"
	"net"
)

// checkPeer has no implementation outside Linux yet. It refuses rather than
// waving connections through: an agent that cannot identify its peers should not
// hand out key material.
func checkPeer(_ net.Conn) error {
	return errors.New("peer credential checks are not implemented on this platform")
}

func LockMemory() error { return errors.New("mlockall is not implemented on this platform") }

func setUmask(_ int) int { return 0 }
