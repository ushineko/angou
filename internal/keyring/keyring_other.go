//go:build !linux && !darwin

package keyring

// Open reports no backend on platforms without one.
func Open() (Keyring, error) { return nil, ErrUnavailable }

// ValidateBackend accepts anything: there is no backend to select between.
func ValidateBackend() error { return nil }

// Available reports no backend on platforms without one.
func Available() bool { return false }
