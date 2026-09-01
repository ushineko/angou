//go:build linux

package keybundle

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// availableMemory reports the smaller of what the kernel says is available to
// the machine and what the process's cgroup will let it use. Both matter: a
// container with a 200 MiB limit on a 64 GiB host is killed at 200 MiB, and
// MemAvailable alone would happily report the host's figure.
func availableMemory() memoryReport {
	host, hostOK := hostAvailableKiB()
	limit, used, limitOK := cgroupMemoryKiB()

	switch {
	case hostOK && limitOK:
		headroom := uint64(0)
		if limit > used {
			headroom = limit - used
		}
		if headroom < host {
			return memoryReport{
				availableKiB: headroom,
				known:        true,
				limitNote:    fmt.Sprintf(" (this process is capped at %d MiB by its cgroup)", limit/1024),
			}
		}
		return memoryReport{availableKiB: host, known: true}
	case hostOK:
		return memoryReport{availableKiB: host, known: true}
	case limitOK:
		headroom := uint64(0)
		if limit > used {
			headroom = limit - used
		}
		return memoryReport{
			availableKiB: headroom,
			known:        true,
			limitNote:    fmt.Sprintf(" (this process is capped at %d MiB by its cgroup)", limit/1024),
		}
	default:
		return memoryReport{}
	}
}

// hostAvailableKiB reads MemAvailable, the kernel's own estimate of what can be
// allocated without swapping.
func hostAvailableKiB() (uint64, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rest, ok := strings.CutPrefix(scanner.Text(), "MemAvailable:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 1 {
			return 0, false
		}
		kib, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return kib, true
	}
	return 0, false
}

// cgroupMemoryKiB reads this process's memory limit and current usage. It
// handles cgroup v2 first, then falls back to v1.
func cgroupMemoryKiB() (limitKiB, usedKiB uint64, ok bool) {
	if dir, found := cgroupV2Dir(); found {
		limit, limitOK := readBytesFile(filepath.Join(dir, "memory.max"))
		used, usedOK := readBytesFile(filepath.Join(dir, "memory.current"))
		if limitOK && usedOK {
			return limit / 1024, used / 1024, true
		}
	}
	limit, limitOK := readBytesFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
	used, usedOK := readBytesFile("/sys/fs/cgroup/memory/memory.usage_in_bytes")
	if limitOK && usedOK {
		return limit / 1024, used / 1024, true
	}
	return 0, 0, false
}

// cgroupV2Dir resolves this process's unified-hierarchy cgroup directory.
func cgroupV2Dir() (string, bool) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		// The unified hierarchy is the entry with an empty controller list.
		rel, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		dir := filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+strings.TrimSpace(rel)))
		if _, err := os.Stat(dir); err != nil {
			return "", false
		}
		return dir, true
	}
	return "", false
}

// readBytesFile reads a cgroup file holding a byte count. "max" means no limit,
// as does v1's sentinel of a value near the word size, and both are reported as
// unknown rather than as an enormous allowance.
func readBytesFile(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	text := strings.TrimSpace(string(raw))
	if text == "max" {
		return 0, false
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, false
	}
	// cgroup v1 signals "unlimited" with a value at the top of the range.
	if value >= 1<<62 {
		return 0, false
	}
	return value, true
}
