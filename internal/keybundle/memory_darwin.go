//go:build darwin

package keybundle

// availableMemory reports "unknown" on macOS, so the pre-derivation headroom
// check is skipped rather than run against a misleading figure.
//
// The Linux check compares Argon2id's demand against MemAvailable and the
// process's cgroup cap — the two ways a derivation gets OOM-killed there. macOS
// has neither: there is no cheap MemAvailable equivalent (a true figure needs a
// mach host_statistics64 call for free/inactive/purgeable pages), and no cgroup
// cap to read. Reporting total physical memory instead would make the check pass
// under real pressure, which is worse than not checking; so the check is
// deliberately absent here, not guessed at. A macOS process under memory
// pressure is far less likely to be OOM-killed mid-derivation than a capped
// Linux container is, which is the case the Linux check exists for (spec 003
// R4.2).
func availableMemory() memoryReport { return memoryReport{} }
