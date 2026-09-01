package core

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultLogicalPath works out the name to store a file under when the user did
// not give one, and reports whether it had to derive it.
//
// A relative argument is used exactly as typed. That keeps the common case
// predictable and keeps the refusal of R3.4.1 intact: a relative path with a
// ".." in it is still refused rather than quietly rewritten, because the user
// typed something the store cannot represent and should see that.
//
// An absolute argument is a different matter. `angou enc ~/.secrets.env` is the
// natural way to reach for the tool, and the shell has already turned it into an
// absolute path by the time angou sees it — so refusing absolute paths means
// refusing the most obvious invocation there is. Absolute paths are mapped into
// the store's namespace instead: relative to the home directory where the file
// is under it, and otherwise with the leading separator removed. Both keep the
// directory structure, which is what stops two files called .secrets.env from
// different projects landing on the same name (R3.5).
func DefaultLogicalPath(src string) (string, bool) {
	if !filepath.IsAbs(src) {
		return filepath.ToSlash(src), false
	}

	// filepath.Abs also cleans, which is wanted here: the input is a filesystem
	// path being translated into a logical one, not a logical path being
	// silently repaired.
	abs, err := filepath.Abs(src)
	if err != nil {
		abs = src
	}
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(home, abs); err == nil &&
			rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel), true
		}
	}
	// Outside the home directory: keep the whole path, minus its root, so
	// /etc/ssl/private/key becomes etc/ssl/private/key.
	trimmed := strings.TrimPrefix(filepath.ToSlash(abs), filepath.ToSlash(filepath.VolumeName(abs)))
	return strings.TrimPrefix(trimmed, "/"), true
}

// encryptAll scans a directory and encrypts what it finds.
