//go:build darwin

package keyring

// Open reports no backend on macOS. The Keychain backend is deferred; until it
// lands, bootstrap on macOS does not re-protect the key and it remains under the
// recovery passphrase on that machine (spec 001 R2.5).
func Open() (Keyring, error) { return nil, ErrUnavailable }

// ValidateBackend accepts anything: there is no backend to select between.
func ValidateBackend() error { return nil }

// Available reports no backend on macOS.
func Available() bool { return false }
