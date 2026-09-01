package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// SocketPath returns the socket for a store.
//
// It lives under XDG_RUNTIME_DIR, which is a per-user directory the system
// clears at logout. That placement is doing real work: a socket in /tmp would
// outlive the session it belongs to.
func SocketPath(storeDir string) (string, error) {
	abs, err := filepath.Abs(storeDir)
	if err != nil {
		return "", fmt.Errorf("resolve store directory: %w", err)
	}
	sum := sha256.Sum256([]byte(abs))

	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		// No runtime directory: fall back to a private directory under the
		// user's home rather than to a world-writable one.
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("no XDG_RUNTIME_DIR and no home directory: %w", err)
		}
		base = filepath.Join(home, ".cache")
	}
	// The directory name is built from a fixed literal and a hex digest, so it
	// carries no caller-supplied path components.
	dir := filepath.Join(filepath.Clean(base), "angou")
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G703: see above
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	socket := filepath.Join(dir, hex.EncodeToString(sum[:6])+".sock")

	// A unix socket path is bounded by the size of sockaddr_un.sun_path, which
	// is 108 bytes on Linux and 104 on macOS. Exceeding it fails at bind with
	// "invalid argument", which says nothing useful, so the limit is checked
	// here where the path can still be explained. The name is kept short for
	// the same reason.
	if len(socket) >= maxSocketPath {
		return "", fmt.Errorf("the agent socket path would be %d bytes, and the system limit is %d:\n    %s\n"+
			"Set XDG_RUNTIME_DIR to a shorter directory, or run without the agent",
			len(socket), maxSocketPath, socket)
	}
	return socket, nil
}

// maxSocketPath is the smaller of the Linux and macOS limits, so a path that
// works here works on both.
const maxSocketPath = 104
