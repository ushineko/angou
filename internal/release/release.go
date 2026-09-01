// Package release manages the bootstrap/ namespace: the platform binaries, their
// detached signatures, and the metadata records that describe them (spec 001
// R5.1, R5.3, R5.10).
//
// The binaries are stored in plaintext. They are published software, so
// encrypting them protects nothing, and an earlier revision that did encrypt
// them was withdrawn for two independent reasons recorded in R5.2.1: stock gpg
// cannot decrypt an Argon2-protected message at all, and guarding the binaries
// with the same passphrase as the key bundle would have capped the whole system
// at whichever KDF was cheaper. Their protection is the signature and the
// version floor, never secrecy.
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	// KeyName holds the public half of the release-signing key.
	//
	// Its presence here does not make it trusted. Trust comes from the
	// fingerprint compiled into the binary and written into bootstrap.sh, which
	// live outside the store precisely so that store contents cannot decide what
	// counts as a genuine release (R5.4.1).
	KeyName = "release-key.asc"
	// SignatureSuffix names a detached signature beside its binary.
	SignatureSuffix = ".sig"
	// MetadataSuffix names a metadata record beside its binary.
	MetadataSuffix = ".json"
	// DefaultKeep is how many versions per platform are retained (R5.10).
	DefaultKeep = 3
)

// ErrNoBinary reports that the namespace holds nothing for a platform.
var ErrNoBinary = errors.New("no binary for this platform")

// Metadata describes one stashed binary (R5.3). Combined with a pinned Go
// toolchain and -trimpath, it is what makes the artifact reproducible enough for
// the record to mean something.
type Metadata struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	Toolchain  string `json:"toolchain"`
	BuildFlags string `json:"build_flags"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
}

// Artifact is one stashed binary and its companions.
type Artifact struct {
	Name     string
	Kind     Kind
	Version  string
	GOOS     string
	GOARCH   string
	Metadata Metadata
}

// Platform is the GOOS/GOARCH pair a binary targets.
func (a Artifact) Platform() string { return a.GOOS + "/" + a.GOARCH }

// Kind distinguishes the two artifacts a store can carry.
//
// They are not interchangeable and only one of them is part of recovery: the
// CLI is static and needs nothing, while the GUI needs CGO, OpenGL and a
// display server. bootstrap.sh installs the CLI and ignores the rest, which is
// what keeps spec 002 R2.2 true — the GUI may live in the namespace, but
// nothing about getting a bare machine open depends on it.
type Kind string

const (
	// KindCLI is the static command-line binary, the one bootstrap installs.
	KindCLI Kind = "angou"
	// KindGUI is the desktop front end. It cannot be cross-compiled, so a store
	// carries it only for the platforms someone has actually built it on.
	KindGUI Kind = "angou-gui"
)

// BinaryName builds the stashed filename for a kind, platform and version.
//
// KindGUI is spelled "angou-gui", so the two prefixes overlap and the longer
// one has to be tested first when parsing. That is the price of a filename that
// reads correctly; the alternative was a separator no one would guess.
func BinaryName(kind Kind, goos, goarch, version string) string {
	return fmt.Sprintf("%s-%s-%s-%s", kind, goos, goarch, version)
}

// ParseBinaryName recovers the platform and version from a stashed filename.
func ParseBinaryName(name string) (kind Kind, goos, goarch, version string, ok bool) {
	// Longest prefix first: "angou-gui-..." also starts with "angou-".
	kind = KindGUI
	rest, found := strings.CutPrefix(name, string(KindGUI)+"-")
	if !found {
		kind = KindCLI
		rest, found = strings.CutPrefix(name, string(KindCLI)+"-")
	}
	if !found {
		return "", "", "", "", false
	}
	parts := strings.SplitN(rest, "-", 3)
	if len(parts) != 3 {
		return "", "", "", "", false
	}
	return kind, parts[0], parts[1], parts[2], true
}

// Digest returns the hex SHA-256 of a file.
func Digest(path string) (string, int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, fmt.Errorf("read %s: %w", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), int64(len(raw)), nil
}

// List enumerates the artifacts in a bootstrap namespace.
func List(dir string) ([]Artifact, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var out []Artifact
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || strings.HasSuffix(name, SignatureSuffix) || strings.HasSuffix(name, MetadataSuffix) {
			continue
		}
		kind, goos, goarch, version, ok := ParseBinaryName(name)
		if !ok {
			continue
		}
		a := Artifact{Name: name, Kind: kind, Version: version, GOOS: goos, GOARCH: goarch}
		if raw, err := os.ReadFile(filepath.Join(dir, name+MetadataSuffix)); err == nil {
			_ = json.Unmarshal(raw, &a.Metadata)
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Platform() != out[j].Platform() {
			return out[i].Platform() < out[j].Platform()
		}
		return CompareVersions(out[i].Version, out[j].Version) > 0
	})
	return out, nil
}

// Prune keeps at most keep versions per platform and removes the rest, together
// with their signatures and metadata (R5.10).
//
// Retention is bounded because a static Go binary is tens of megabytes and the
// store is usually synced. A version withdrawn for a vulnerability should be
// removed outright rather than left signed and available, which is what makes
// this a security operation and not only a housekeeping one.
func Prune(dir string, keep int) ([]string, error) {
	if keep < 1 {
		return nil, errors.New("retention must keep at least one version per platform")
	}
	artifacts, err := List(dir)
	if err != nil {
		return nil, err
	}
	// Retention is per kind as well as per platform. Counting them together
	// would let a GUI build evict the CLI for the same platform, and the CLI is
	// the one a bare machine needs.
	seen := map[string]int{}
	var removed []string
	for _, a := range artifacts {
		key := string(a.Kind) + " " + a.Platform()
		seen[key]++
		if seen[key] <= keep {
			continue
		}
		for _, suffix := range []string{"", SignatureSuffix, MetadataSuffix} {
			path := filepath.Join(dir, a.Name+suffix)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return removed, fmt.Errorf("remove %s: %w", filepath.Base(path), err)
			}
		}
		removed = append(removed, a.Name)
	}
	return removed, nil
}

// Find returns the newest artifact for a platform.
func Find(dir, goos, goarch string) (Artifact, error) {
	artifacts, err := List(dir)
	if err != nil {
		return Artifact{}, err
	}
	for _, a := range artifacts {
		// The CLI only: this is what bootstrap installs, and installing a GUI
		// on a machine being recovered would be the wrong binary even where it
		// happened to run.
		if a.Kind == KindCLI && a.GOOS == goos && a.GOARCH == goarch {
			return a, nil
		}
	}
	return Artifact{}, fmt.Errorf("%w: %s/%s", ErrNoBinary, goos, goarch)
}

// Platforms lists the platforms the namespace can serve, for an error message
// that tells the user what is actually available.
func Platforms(dir string) []string {
	artifacts, _ := List(dir)
	seen := map[string]bool{}
	var out []string
	for _, a := range artifacts {
		if a.Kind != KindCLI {
			continue // the question is which platforms can be bootstrapped
		}
		if !seen[a.Platform()] {
			seen[a.Platform()] = true
			out = append(out, a.Platform())
		}
	}
	sort.Strings(out)
	return out
}

// CompareVersions orders two versions, returning -1, 0, or 1.
//
// Numeric components are compared as numbers so that 0.10.0 sorts above 0.9.0,
// which a string comparison gets backwards. A version carrying a pre-release
// suffix sorts below the same version without one, following the usual
// convention that 1.0.0-dev precedes 1.0.0.
func CompareVersions(a, b string) int {
	aNum, aPre := splitVersion(a)
	bNum, bPre := splitVersion(b)

	for i := 0; i < len(aNum) || i < len(bNum); i++ {
		av, bv := 0, 0
		if i < len(aNum) {
			av = aNum[i]
		}
		if i < len(bNum) {
			bv = bNum[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	switch {
	case aPre == bPre:
		return 0
	case aPre == "":
		return 1 // a release outranks the same version's pre-release
	case bPre == "":
		return -1
	case aPre < bPre:
		return -1
	default:
		return 1
	}
}

func splitVersion(v string) ([]int, string) {
	v = strings.TrimPrefix(v, "v")
	numeric, pre, _ := strings.Cut(v, "-")
	var out []int
	for _, part := range strings.Split(numeric, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out, pre
}
