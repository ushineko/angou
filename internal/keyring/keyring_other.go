//go:build !linux && !darwin

package keyring

// Open reports no backend on platforms without one.
func Open() (Keyring, error) { return nil, ErrUnavailable }

// Available reports no backend on platforms without one.
func Available() bool { return false }
