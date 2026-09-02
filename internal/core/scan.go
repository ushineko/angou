package core

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

// Candidate is a file the scan flagged, with the reason it did.
//
// The reason is the point. The scan is a guess, and the only way to find out
// whether it is a good one on a particular machine is to look at what it picked
// and why -- a rule that is right about SSH keys can still be wrong about a
// directory full of session files whose names end in .key.
type Candidate struct {
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
	// verify, when set, must also agree after looking at the start of the file.
	// The rules that rest on a name alone are the ones that misfire: a `.key`
	// extension means a private key in some tools and a cache entry in others —
	// one real home directory held eighteen session files ending in `.key` and
	// not a secret among them — and a filename mentioning "password" is as
	// likely to be a note about passwords as a file containing one.
	verify func(head []byte) bool
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
	// Text key formats: the extension is a hint, the PEM header is the evidence.
	{match: func(n string) bool {
		for _, ext := range []string{".pem", ".key", ".crt", ".cer"} {
			if strings.HasSuffix(n, ext) {
				return true
			}
		}
		return false
	}, reason: "private key", verify: looksLikePrivateKey},

	// Binary key stores have no header this can read, and the extensions are
	// specific enough that they are rarely anything else.
	{match: func(n string) bool {
		for _, ext := range []string{".p12", ".pfx", ".jks", ".keystore"} {
			if strings.HasSuffix(n, ext) {
				return true
			}
		}
		return false
	}, reason: "key store"},

	// The weakest signal there is, so it carries the most conditions: the name
	// must mention a secret, the file must not be something that obviously
	// discusses secrets rather than holding one, and the contents must look
	// like assignments.
	//
	// Without the middle condition this rule is worse than useless. Run against
	// a real home directory it offered Python's own secrets.py and token.py,
	// libssh2 man pages, a pkg-config file, and every source file with "token"
	// in its name — because source code assigns values, which is exactly what
	// the content check looks for.
	{match: func(n string) bool {
		if isProseOrProgram(n) {
			return false
		}
		lower := strings.ToLower(n)
		return strings.Contains(lower, "secret") || strings.Contains(lower, "password") ||
			strings.Contains(lower, "token")
	}, reason: "name mentions a secret and the contents look like one", verify: looksLikeAssignment},
}

// proseOrProgramExtensions are files that talk about secrets for a living.
// Source, documentation, manual pages, and build metadata all mention
// credentials constantly and hold none.
var proseOrProgramExtensions = map[string]bool{
	".py": true, ".go": true, ".js": true, ".ts": true, ".tsx": true, ".jsx": true,
	".rs": true, ".c": true, ".h": true, ".cpp": true, ".hpp": true, ".java": true,
	".rb": true, ".php": true, ".pl": true, ".sh": true, ".bash": true, ".zsh": true,
	".md": true, ".rst": true, ".adoc": true, ".html": true, ".css": true,
	".pc": true, ".cmake": true, ".mk": true, ".gradle": true, ".lock": true,
	".po": true, ".mo": true, ".pyc": true, ".pyi": true, ".map": true,
	".ps1": true, ".psm1": true, ".bat": true, ".cmd": true, ".vbs": true,
	".xsl": true, ".xslt": true, ".xml": true, ".yml": true, ".yaml": true,
	".pdf": true, ".doc": true, ".docx": true, ".odt": true, ".rtf": true,
}

// isProseOrProgram reports whether a filename is something that discusses
// secrets rather than holding one.
func isProseOrProgram(name string) bool {
	if proseOrProgramExtensions[strings.ToLower(filepath.Ext(name))] {
		return true
	}
	// Manual pages: a single-digit or digit-plus-letter section suffix.
	if ext := strings.TrimPrefix(filepath.Ext(name), "."); len(ext) <= 2 && ext != "" {
		if ext[0] >= '1' && ext[0] <= '9' {
			return true
		}
	}
	return false
}

// looksLikeText reports whether a byte sample reads as text rather than as a
// binary format.
func looksLikeText(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	printable := 0
	for _, b := range head {
		if b == 0 {
			return false // a NUL byte settles it
		}
		if b >= 0x20 && b < 0x7f || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return printable*10 >= len(head)*9
}

// looksLikePrivateKey reports whether a file begins with a PEM private-key
// header. A certificate is not a secret, so a plain "BEGIN CERTIFICATE" does not
// qualify.
// looksLikePrivateKey reports whether a file begins with a private-key header.
//
// PEM spells it "-----BEGIN RSA PRIVATE KEY-----" and friends; OpenSSH's own
// format spells it "-----BEGIN OPENSSH PRIVATE KEY-----". Both are matched by
// looking for the armour opening and the words together, which also covers
// "ENCRYPTED PRIVATE KEY" — an encrypted key is still a key, and still
// something its owner would want in the store.
func looksLikePrivateKey(head []byte) bool {
	text := string(head)
	if !strings.Contains(text, "-----BEGIN") {
		return false
	}
	return strings.Contains(text, "PRIVATE KEY")
}

// looksLikeAssignment reports whether the start of a file looks like it assigns
// a value to something, which is what a credential file does and what a note
// about credentials does not.
//
// Binary files are excluded first. Without that, any large binary whose name
// mentions a secret matches by accident — a PDF happens to contain bytes that
// read as "key: value" — and the scanner ends up asserting a reason it cannot
// actually support.
func looksLikeAssignment(head []byte) bool {
	if !looksLikeText(head) {
		return false
	}
	for _, line := range strings.Split(string(head), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			key, value, ok = strings.Cut(line, ":")
		}
		if ok && strings.TrimSpace(key) != "" && len(strings.TrimSpace(value)) > 3 {
			return true
		}
	}
	return false
}

// skipDirs are never descended into. They are large, uninteresting, and full of
// files whose names would match by accident.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".cache": true, ".venv": true,
	"venv": true, "vendor": true, "target": true, "build": true,
	".gradle": true, ".cargo": true, ".rustup": true, ".npm": true,
	".local": true, ".mozilla": true, "Downloads": true, "snap": true,
	// Tool state directories. They are full of files whose names look like
	// credentials and are not: session handles, cache entries, plugin sources.
	".claude": true, ".vscode": true, ".idea": true, ".pki": true,
	"__pycache__": true, ".pytest_cache": true, ".terraform": true,
	// Installed software. Its files are not this user's secrets, and a language
	// runtime ships plenty of names that read like credentials.
	"site-packages": true, "dist-packages": true, "pkgconfig": true,
	"man": true, "share": true, "miniforge3": true, "miniconda3": true,
	".pyenv": true, ".nvm": true, ".sdkman": true, ".goenv": true,
}

// Scan walks a directory and returns what looks worth encrypting.
// Scan walks a directory for files that look like credentials.
//
// An empty or short result is not an assurance: it knows the usual names and
// places, not every way a secret can be written down.
func Scan(root string) ([]Candidate, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", root, err)
	}

	var found []Candidate
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
			found = append(found, Candidate{Path: path, Reason: reason, Size: info.Size()})
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

// headBytes is how much of a file the content checks look at. A PEM header and
// the first assignment in a credentials file are both near the top, and reading
// more would mean reading whole files during what is meant to be a survey.
const headBytes = 512

// templateMarkers name a file that shows the shape of a credential rather than
// holding one. `.env.example` is the most common file on any developer's machine
// that looks exactly like a secret and contains nothing but placeholders.
var templateMarkers = []string{"example", "template", "sample", "dist", "tmpl", "default"}

// isTemplate reports whether a filename advertises itself as a placeholder.
func isTemplate(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range templateMarkers {
		if strings.HasSuffix(lower, "."+marker) || strings.Contains(lower, "."+marker+".") {
			return true
		}
	}
	return false
}

// looksSecret reports whether a file matches, and why.
func looksSecret(path, name string) (string, bool) {
	// Public keys are the most common false positive and are never secret.
	if strings.HasSuffix(name, ".pub") {
		return "", false
	}
	// Nor is a file whose whole purpose is to show what a credential file looks
	// like without being one.
	if isTemplate(name) {
		return "", false
	}
	// The header first, before any question about the name.
	//
	// A private key is a private key whatever it is called, and the file says so
	// itself: "-----BEGIN ... PRIVATE KEY-----" is not a guess the way an
	// extension is. Every name-based rule below missed ~/njv_ssh_key -- outside
	// .ssh, no id_ prefix, and "key" without a dot in front of it is not the
	// ".key" extension the PEM rule looks for -- while the first line of the
	// file identified it beyond doubt.
	//
	// This costs a 512-byte read per candidate file. That is the price of
	// finding keys their owner did not name conventionally, which are exactly
	// the ones a name-based scan is worst at and the ones most worth finding.
	if looksLikePrivateKey(readHead(path)) {
		return "private key header", true
	}

	parent := filepath.Base(filepath.Dir(path))
	for _, p := range secretPatterns {
		if p.dir != "" && parent != p.dir {
			continue
		}
		if !p.match(name) {
			continue
		}
		if p.verify != nil && !p.verify(readHead(path)) {
			continue
		}
		return p.reason, true
	}
	return "", false
}

// readHead returns the first bytes of a file, or nothing if it cannot be read.
func readHead(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	head := make([]byte, headBytes)
	n, err := f.Read(head)
	if err != nil && n == 0 {
		return nil
	}
	return head[:n]
}
