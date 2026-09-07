//go:build !linux && !darwin

package keybundle

// availableMemory has no implementation on platforms without one, so the check
// is skipped rather than guessed at. Linux reads MemAvailable and the cgroup
// cap; macOS documents the check as deliberately absent (memory_darwin.go). This
// covers the rest.
func availableMemory() memoryReport { return memoryReport{} }
