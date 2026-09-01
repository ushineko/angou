package store

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// ErrBadPath reports a logical path that does not satisfy the grammar.
var ErrBadPath = errors.New("invalid store path")

// NormalizePath applies the strict path grammar of spec 001 R3.4.1. The grammar
// is a security control, not a convenience: blob_id is an HMAC over the result
// (R3.2), and an envelope path is attacker-controlled input under the
// write-access threat model (R-9). Non-conforming paths are refused rather than
// silently repaired, so that writers and readers cannot disagree about what a
// given input means.
func NormalizePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: empty path", ErrBadPath)
	}
	// NFC first: the grammar checks below must run against the same bytes the
	// HMAC will see, or a path could pass validation and hash differently.
	p = norm.NFC.String(p)

	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: path contains a NUL byte", ErrBadPath)
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: path contains a control character", ErrBadPath)
		}
	}
	if strings.Contains(p, `\`) {
		return "", fmt.Errorf("%w: path must use %q separators", ErrBadPath, "/")
	}
	if strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%w: path must be relative, got %q", ErrBadPath, p)
	}
	if isDriveOrUNC(p) {
		return "", fmt.Errorf("%w: path carries a drive letter or UNC prefix", ErrBadPath)
	}
	if strings.HasSuffix(p, "/") {
		return "", fmt.Errorf("%w: path has a trailing separator", ErrBadPath)
	}

	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "":
			return "", fmt.Errorf("%w: path has an empty component", ErrBadPath)
		case ".", "..":
			return "", fmt.Errorf("%w: path has a %q component", ErrBadPath, seg)
		}
	}
	return p, nil
}

func isDriveOrUNC(p string) bool {
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	// A Windows drive letter: exactly one ASCII letter, then a colon.
	if len(p) >= 2 && p[1] == ':' {
		c := p[0]
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return false
}
