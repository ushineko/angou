package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ushineko/angou/internal/release"
	"github.com/ushineko/angou/internal/store"
)

// CopyStore copies a store to another directory, optionally leaving the
// platform binaries behind (spec 001 R5.10).
func CopyStore(from, to string, noBinaries bool) (int, error) {
	count := 0
	// Lstat semantics: Walk reports symlinks without following them, which is
	// what lets the callback refuse them.
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return fmt.Errorf("resolve %s relative to %s: %w", path, from, err)
		}
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o700)
		}
		// A symlink in the store is not store content. Following one would let
		// anyone who can write to a synced store name a local file — an SSH key,
		// say — and have its contents copied into a directory they may be able
		// to read (R-9). They are refused rather than skipped, because their
		// presence means something put them there.
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to copy it, because following it "+
				"would read a file outside the store", rel)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file; refusing to copy it", rel)
		}
		if noBinaries && isReleaseBinary(rel) {
			return nil
		}
		if err := copyFile(path, filepath.Join(to, rel), info.Mode()); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil {
		return count, fmt.Errorf("copy store: %w", err)
	}
	return count, nil
}

// isReleaseBinary reports whether a store-relative path is a stashed binary or
// one of its companions.
func isReleaseBinary(rel string) bool {
	dir, name := filepath.Split(filepath.ToSlash(rel))
	if strings.TrimSuffix(dir, "/") != store.BootstrapDir {
		return false
	}
	base := strings.TrimSuffix(strings.TrimSuffix(name, release.SignatureSuffix), release.MetadataSuffix)
	_, _, _, _, ok := release.ParseBinaryName(base)
	return ok
}

// IsInside reports whether child lies beneath parent, after resolving both. A
// clone into a subdirectory of its own source would copy itself.
func IsInside(parent, child string) (bool, error) {
	parentAbs, err := filepath.Abs(parent)
	if err != nil {
		return false, fmt.Errorf("resolve %s: %w", parent, err)
	}
	childAbs, err := filepath.Abs(child)
	if err != nil {
		return false, fmt.Errorf("resolve %s: %w", child, err)
	}
	rel, err := filepath.Rel(parentAbs, childAbs)
	if err != nil {
		return false, nil //nolint:nilerr // unrelated paths are simply not inside
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(dst), err)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode.Perm())
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}
