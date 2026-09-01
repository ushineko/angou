package store

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"time"
)

// Extract writes an envelope's content beneath destRoot, restoring mode and
// mtime.
//
// The envelope path is attacker-controlled input under the write-access threat
// model (R-9), so every write is confined beneath an explicit root and refuses
// to leave it by symlink (R3.4.2). Without both halves, an envelope naming
// ../../.ssh/authorized_keys — or a symlink planted at an intermediate
// component — turns a decrypt into an arbitrary file write.
//
// The confinement is delegated to os.Root, which holds an open descriptor on the
// root directory and resolves every component against it. That matters for more
// than tidiness: checking each parent for a symlink and then opening it leaves a
// window in which the parent can be replaced between the check and the open, and
// O_NOFOLLOW closes that window only for the final component. A textual prefix
// check cannot see through a symlink at all, including one that destRoot itself
// resolves through.
func Extract(destRoot, logicalPath string, content []byte, mode uint32, mtime int64) (string, error) {
	normalized, err := NormalizePath(logicalPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(destRoot, 0o700); err != nil {
		return "", fmt.Errorf("create destination root: %w", err)
	}
	root, err := os.OpenRoot(destRoot)
	if err != nil {
		return "", fmt.Errorf("open destination root: %w", err)
	}
	defer func() { _ = root.Close() }()

	// The path grammar guarantees forward slashes and no traversal components,
	// so the slash-separated form is the right one to hand to os.Root.
	if dir := path.Dir(normalized); dir != "." {
		if err := root.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("%w: create %s: %w", ErrUnsafeExtract, dir, err)
		}
	}

	perm := os.FileMode(mode).Perm()
	// O_NOFOLLOW additionally refuses a symlink at the leaf, including one that
	// stays inside the root: the extracted file must be a regular file.
	f, err := root.OpenFile(normalized, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return "", fmt.Errorf("%w: open %s: %w", ErrUnsafeExtract, normalized, err)
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write %s: %w", normalized, err)
	}
	// Chmod through the descriptor rather than the name, so the mode lands on
	// the file that was just written and not on whatever the name resolves to
	// by the time this runs.
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("set mode on %s: %w", normalized, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", normalized, err)
	}

	// os.Root.Chtimes carries a documented race on Unix: it resolves the name
	// again rather than acting on the descriptor. Restoring the timestamp is a
	// convenience rather than a security control, and the file's contents and
	// mode are already committed above, so the residual exposure is a wrong
	// mtime on a file an attacker had to win a race to substitute.
	when := time.Unix(mtime, 0)
	if err := root.Chtimes(normalized, when, when); err != nil {
		return "", fmt.Errorf("set mtime on %s: %w", normalized, err)
	}
	return filepath.Join(destRoot, filepath.FromSlash(normalized)), nil
}
