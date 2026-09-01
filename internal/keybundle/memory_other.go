//go:build !linux

package keybundle

// availableMemory has no implementation outside Linux yet, so the check is
// skipped rather than guessed at. macOS support arrives with the Keychain
// keyring backend, which is the pass that makes the platform a target.
func availableMemory() memoryReport { return memoryReport{} }
