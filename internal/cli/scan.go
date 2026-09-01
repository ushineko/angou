package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxScanSize bounds what the scanner will offer. Credentials are small; a
// hundred-megabyte match is a false positive, and encrypting it would be a slow
// surprise rather than a helpful one.
const maxScanSize = 1 << 20 // 1 MiB

// scanDepth bounds how far down the scanner looks. Deep enough for the places
// credentials actually live, shallow enough not to walk a whole home directory
// of source checkouts and caches.
const scanDepth = 4

// candidate is a file the scanner thinks is worth encrypting.
type candidate struct {
	Path   string
	Reason string
	Size   int64
}

// secretPatterns describes what the scanner looks for.
//
// This is a convenience for finding the obvious things, not a security control,
// and it should not be read as one: it will miss credentials in files it has
// never heard of, and it will occasionally offer something harmless. That is why
// the default is to ask about each file rather than to sweep them up.
var secretPatterns = []struct {
	// dir, when set, requires the file to sit directly in a directory of that
	// name. It keeps "config" from matching every config file on the machine.
	dir    string
	match  func(name string) bool
	reason string
}{
	{dir: ".ssh", match: func(n string) bool {
		return strings.HasPrefix(n, "id_") && !strings.HasSuffix(n, ".pub")
	}, reason: "SSH private key"},
	{dir: ".aws", match: func(n string) bool { return n == "credentials" || n == "config" }, reason: "AWS credentials"},
	{dir: ".kube", match: func(n string) bool { return n == "config" }, reason: "Kubernetes credentials"},
	{dir: ".docker", match: func(n string) bool { return n == "config.json" }, reason: "Docker registry credentials"},
	{dir: ".gnupg", match: func(n string) bool { return strings.HasSuffix(n, ".key") }, reason: "GnuPG private key"},

	{match: func(n string) bool { return n == ".env" || strings.HasPrefix(n, ".env.") }, reason: "environment file"},
	{match: func(n string) bool { return strings.HasSuffix(n, ".env") }, reason: "environment file"},
	{match: func(n string) bool { return n == ".netrc" || n == "_netrc" }, reason: "netrc credentials"},
	{match: func(n string) bool { return n == ".pgpass" }, reason: "PostgreSQL password file"},
	{match: func(n string) bool { return n == ".npmrc" || n == ".pypirc" }, reason: "package registry token"},
	{match: func(n string) bool { return n == "credentials" || n == "credentials.json" }, reason: "credentials file"},
	{match: func(n string) bool {
		for _, ext := range []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"} {
			if strings.HasSuffix(n, ext) {
				return true
			}
		}
		return false
	}, reason: "key or certificate"},
	{match: func(n string) bool {
		lower := strings.ToLower(n)
		return strings.Contains(lower, "secret") || strings.Contains(lower, "password")
	}, reason: "name mentions a secret"},
}

// skipDirs are never descended into. They are large, uninteresting, and full of
// files whose names would match by accident.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".cache": true, ".venv": true,
	"venv": true, "vendor": true, "target": true, "build": true,
	".gradle": true, ".cargo": true, ".rustup": true, ".npm": true,
	".local": true, ".mozilla": true, "Downloads": true, "snap": true,
}

// scanForSecrets walks a directory and returns what looks worth encrypting.
func scanForSecrets(root string) ([]candidate, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", root, err)
	}

	var found []candidate
	err = filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, walkErr error) error {
		// An unreadable directory is not a reason to abandon a scan whose whole
		// purpose is to look around and report what it can see. Returning the
		// error here would stop the walk on the first permission denial, which
		// on a home directory is close to guaranteed.
		if walkErr != nil {
			return nil //nolint:nilerr // tolerating unreadable entries is the point
		}
		rel, ok := relativeTo(rootAbs, path)
		if !ok {
			return nil
		}
		depth := len(strings.Split(filepath.ToSlash(rel), "/"))

		if d.IsDir() {
			switch {
			case path == rootAbs:
				return nil
			case skipDirs[d.Name()]:
				return filepath.SkipDir
			case depth > scanDepth:
				return filepath.SkipDir
			}
			return nil
		}
		// Symlinks are reported by WalkDir without being followed; a symlink is
		// not a file to encrypt, it is a pointer to one somewhere else.
		if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}

		info, ok := entryInfo(d)
		if !ok || info.Size() == 0 || info.Size() > maxScanSize {
			return nil
		}
		if reason, ok := looksSecret(path, d.Name()); ok {
			found = append(found, candidate{Path: path, Reason: reason, Size: info.Size()})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", rootAbs, err)
	}
	return found, nil
}

// relativeTo is filepath.Rel with the error folded into a boolean, so the walk
// callback stays a single tolerant path.
func relativeTo(base, path string) (string, bool) {
	rel, err := filepath.Rel(base, path)
	return rel, err == nil
}

// entryInfo is DirEntry.Info with the error folded into a boolean.
func entryInfo(d fs.DirEntry) (fs.FileInfo, bool) {
	info, err := d.Info()
	return info, err == nil
}

// looksSecret reports whether a file matches, and why.
func looksSecret(path, name string) (string, bool) {
	// Public keys are the most common false positive and are never secret.
	if strings.HasSuffix(name, ".pub") {
		return "", false
	}
	parent := filepath.Base(filepath.Dir(path))
	for _, p := range secretPatterns {
		if p.dir != "" && parent != p.dir {
			continue
		}
		if p.match(name) {
			return p.reason, true
		}
	}
	return "", false
}
