//go:build darwin && !cgo

package keyring

// This is the darwin build with cgo disabled. The Keychain backend needs
// Security.framework through cgo (keyring_darwin.go), so with cgo off there is
// no keyring — the same state as a headless Linux box with no bus.
//
// It exists so a darwin CLI cross-compiled from a Linux release box (where there
// is no macOS SDK to link against) still builds and still bootstraps: recovery
// never needs a keyring, only the recovery passphrase. The supported darwin
// build is CGO_ENABLED=1 and gets the real backend.

// Open reports no backend when the darwin build has cgo disabled.
func Open() (Keyring, error) { return nil, ErrUnavailable }

// ValidateBackend accepts anything: there is no backend to select between.
func ValidateBackend() error { return nil }

// Available reports no backend when the darwin build has cgo disabled.
func Available() bool { return false }
