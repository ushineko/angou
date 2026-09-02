package core

import (
	"crypto/sha256"
	gobuildinfo "debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ushineko/angou/internal/buildinfo"
	"github.com/ushineko/angou/internal/pgpcrypto"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/release"
	"github.com/ushineko/angou/internal/store"
)

// GenerateSigningKey writes a new release-signing key.
//
// The key decides which binaries every future bootstrap accepts as genuine. Left
// on a machine that publishes from, it is one compromise away from letting
// someone plant a binary the other machines install and run, which is why the
// command that writes it also says to move it offline.
func GenerateSigningKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a signing key", path)
	}
	identity, err := pgpcrypto.Generate("angou release signing", "release@angou.invalid")
	if err != nil {
		return err
	}
	armored, err := identity.ExportArmoredPrivate()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, armored, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("Wrote a release-signing key to %s\n", path)
	fmt.Printf("Fingerprint: %s\n", identity.Fingerprint())
	fmt.Fprintln(os.Stderr, "\nBuild releases with this fingerprint pinned into the binary:")
	fmt.Fprintf(os.Stderr, "    make build-all RELEASE_KEY=%s\n", identity.Fingerprint())
	fmt.Fprintln(os.Stderr, "\nThen move this file to offline storage and delete it from this machine.\n"+
		"It is not protected by a passphrase, and it is the key that decides which binaries\n"+
		"every future bootstrap will accept as genuine.")
	return nil
}

// DefaultSigningKeyPath is where install.sh puts a generated release-signing
// key, and so where one is likely to be found.
//
// Knowing the path is not the same as using it. Nothing here signs with a key
// the user did not name: a release-signing key decides which binaries every
// future bootstrap accepts as genuine, and picking one up off disk because it
// happened to be there is not a decision a tool should make on someone's
// behalf. What this enables is telling them where it is.
func DefaultSigningKeyPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "angou", "release-signing.asc")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "angou", "release-signing.asc")
}

// SigningKeyPresent reports whether a key is sitting at the conventional path.
//
// A true answer is worth showing the user for two reasons, and only one of them
// is convenience: it is also the answer to "is my signing key still on this
// machine", which install.sh tells them to fix and which is easy to forget
// having done.
func SigningKeyPresent() bool {
	path := DefaultSigningKeyPath()
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// StashedBinaries lists what the store's bootstrap namespace currently holds.
func (s *Session) StashedBinaries() ([]release.Artifact, error) {
	return release.List(filepath.Join(s.Root(), store.BootstrapDir))
}

// StashRelease signs the built binaries and puts them in the store's bootstrap
// namespace, so a machine with no angou can install one from the store
// (spec 001 R5.3).
func StashRelease(s *Session, dist, signingKeyPath string, keep int, secrets Secrets) error {
	// Checked before anything is opened. Without this an empty field reaches
	// os.ReadFile and comes back as `open : no such file or directory`, an
	// error with a hole where the path should be, which tells the user nothing
	// about which field they left blank.
	if signingKeyPath == "" {
		if SigningKeyPresent() {
			return fmt.Errorf("a release-signing key is required.\n"+
				"There is one at %s; pass it explicitly:\n"+
				"    --signing-key %s\n"+
				"It is not picked up automatically: which key signs a release decides which "+
				"binaries every future bootstrap trusts, and that is not a choice to make by "+
				"finding a file", DefaultSigningKeyPath(), DefaultSigningKeyPath())
		}
		return errors.New("a release-signing key is required.\n" +
			"Create one with `angou release --new-signing-key <path>`, and keep it offline")
	}
	if dist == "" {
		return errors.New("a directory of built binaries is required")
	}

	raw, err := os.ReadFile(signingKeyPath) //nolint:gosec // the path is the user's own argument
	if err != nil {
		return fmt.Errorf("read signing key: %w", err)
	}
	signer, err := pgpcrypto.ParseArmoredPrivate(raw)
	if err != nil {
		return err
	}
	// A key exported from gpg is normally passphrase protected. Ask before doing
	// any work, rather than failing at the first signature.
	if signer.IsLocked() {
		secret, err := secrets.Recovery("Passphrase for the release-signing key: ")
		if err != nil {
			return fmt.Errorf("%s is protected by a passphrase: %w", signingKeyPath, err)
		}
		defer prompt.Zero(secret)
		if err := signer.Unlock(secret); err != nil {
			return err
		}
	}
	if release.Trusted() && signer.Fingerprint() != release.SigningKeyFingerprint {
		return fmt.Errorf("this binary trusts release key %s, but %s holds %s.\n"+
			"Stashing binaries signed by a key this build will not accept would produce a "+
			"store no bootstrap could install from",
			release.SigningKeyFingerprint, signingKeyPath, signer.Fingerprint())
	}

	entries, err := os.ReadDir(dist)
	if err != nil {
		return fmt.Errorf("read %s: %w", dist, err)
	}
	bootstrapDir := filepath.Join(s.Root(), store.BootstrapDir)
	if err := os.MkdirAll(bootstrapDir, 0o700); err != nil {
		return fmt.Errorf("create bootstrap namespace: %w", err)
	}

	stashed := 0
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		kind, goos, goarch, ok := platformOf(de.Name())
		if !ok {
			continue
		}
		if err := stashOne(filepath.Join(dist, de.Name()), bootstrapDir, kind, goos, goarch, signer, s.ev); err != nil {
			return err
		}
		stashed++
	}
	if stashed == 0 {
		return fmt.Errorf("no binaries named angou-<goos>-<goarch> found in %s", dist)
	}

	pub, err := signer.ExportPublic()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(bootstrapDir, release.KeyName), pub, 0o644); err != nil { //nolint:gosec // the public key is not secret
		return fmt.Errorf("write %s: %w", release.KeyName, err)
	}

	raised, err := s.RaiseVersionFloor(buildinfo.Version, release.CompareVersions)
	if err != nil {
		return err
	}
	removed, err := release.Prune(bootstrapDir, keep)
	if err != nil {
		return err
	}
	// Write the installer alongside the binaries it installs, with this key's
	// fingerprint baked in, then record its digest so drift is detectable.
	if err := writeBootstrapScript(s.Root(), signer.Fingerprint()); err != nil {
		return err
	}
	// Sign the installer with the same offline key. That is what lets the
	// installer check itself without a passphrase, and it means altering it
	// requires the key rather than merely write access to the store.
	if err := signBootstrapScript(s.Root(), signer); err != nil {
		return err
	}
	if err := recordBootstrapScript(s); err != nil {
		return err
	}

	fmt.Printf("Stashed %d binaries at version %s into %s\n", stashed, buildinfo.Version, bootstrapDir)
	fmt.Printf("Signed by %s\n", signer.Fingerprint())
	if raised {
		fmt.Printf("Version floor raised to %s: older binaries will now be refused.\n", buildinfo.Version)
	}
	if len(removed) > 0 {
		fmt.Printf("Pruned %d superseded binaries beyond --keep %d.\n", len(removed), keep)
	}
	return nil
}

// verifyArtifactIsThisBuild refuses a binary that was not built from the commit
// doing the stashing.
//
// The metadata beside a stashed artifact is signed, and it records a version and
// a commit. Those came from the running tool, not from the artifact — so a stale
// dist/ directory produced signed metadata attesting to a version the bytes did
// not have: a store holding "angou-linux-amd64-0.2.0" whose binary reported
// 0.1.4, which the store's own version floor then refused. The signature was
// valid the whole time. It signs the bytes; it cannot notice that the
// description beside them is wrong.
//
// Go records the revision in the binary itself, so this can be checked without
// running it — which matters, because running a binary to ask its version means
// executing an artifact before deciding whether to trust it.
func verifyArtifactIsThisBuild(src string, ev Events) error {
	// A build with no commit stamped cannot assert that anything matches it.
	// That is an unstamped development build, and the honest response is to say
	// the check did not happen rather than to refuse every artifact or, worse,
	// to compare against the placeholder and appear to have checked.
	if currentCommit() == "" || currentCommit() == "unknown" {
		ev.noticef("angou: this build carries no commit, so %s cannot be checked against it.",
			filepath.Base(src))
		return nil
	}

	info, err := gobuildinfo.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read build information from %s: %w\n"+
			"Every stashed artifact must identify the build it came from", filepath.Base(src), err)
	}

	var revision string
	var dirty bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if revision == "" {
		return fmt.Errorf("%s carries no VCS revision, so there is no way to tell which build "+
			"it is.\nBuild it in the repository, without -buildvcs=false", filepath.Base(src))
	}
	if !strings.HasPrefix(revision, currentCommit()) {
		return fmt.Errorf("%s was built from commit %s, but this angou is %s.\n"+
			"Refusing to stash it: the metadata beside a stashed binary records the version and "+
			"commit of the tool doing the stashing, so a stale build would be signed under a "+
			"version it does not have — which is how a store ends up serving a binary its own "+
			"version floor refuses.\nRebuild first: make build-all",
			filepath.Base(src), revision[:len(currentCommit())], currentCommit())
	}
	if dirty {
		// Reported, not refused. A commit that does not identify the bytes is
		// worth knowing about, and it is also the normal state of a working
		// tree someone is publishing a test release from.
		ev.noticef("angou: %s was built from a modified working tree, so its recorded commit "+
			"does not identify it exactly.", filepath.Base(src))
	}
	return nil
}

// currentCommit is the revision this binary was built from, as the Makefile
// stamped it.
func currentCommit() string { return buildinfo.Commit }

func stashOne(src, bootstrapDir string, kind release.Kind, goos, goarch string, signer *pgpcrypto.Identity, ev Events) error {
	if err := verifyArtifactIsThisBuild(src, ev); err != nil {
		return err
	}
	binary, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	name := release.BinaryName(kind, goos, goarch, buildinfo.Version)
	target := filepath.Join(bootstrapDir, name)

	if err := os.WriteFile(target, binary, 0o755); err != nil { //nolint:gosec // an executable must be executable
		return fmt.Errorf("write %s: %w", name, err)
	}
	signature, err := signer.SignDetached(binary)
	if err != nil {
		return err
	}
	if err := os.WriteFile(target+release.SignatureSuffix, signature, 0o644); err != nil { //nolint:gosec // a signature is not secret
		return fmt.Errorf("write %s: %w", name+release.SignatureSuffix, err)
	}

	sum := sha256.Sum256(binary)
	meta := release.Metadata{
		Version:    buildinfo.Version,
		Commit:     buildinfo.Commit,
		Toolchain:  runtime.Version(),
		BuildFlags: buildFlagsFor(kind),
		GOOS:       goos,
		GOARCH:     goarch,
		SHA256:     hex.EncodeToString(sum[:]),
		Size:       int64(len(binary)),
	}
	encoded, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}
	if err := os.WriteFile(target+release.MetadataSuffix, encoded, 0o644); err != nil { //nolint:gosec // metadata is not secret
		return fmt.Errorf("write %s: %w", name+release.MetadataSuffix, err)
	}
	return nil
}

// platformOf reads the GOOS and GOARCH out of a built binary's filename, which
// build-all writes as angou-<goos>-<goarch>.
// platformOf reads a built binary's filename in dist/.
//
// Longest prefix first, for the same reason as ParseBinaryName: "angou-gui-..."
// also starts with "angou-", and testing the short one first would file every
// GUI build under the platform "gui".
func platformOf(name string) (kind release.Kind, goos, goarch string, ok bool) {
	kind = release.KindGUI
	rest, found := strings.CutPrefix(name, string(release.KindGUI)+"-")
	if !found {
		kind = release.KindCLI
		rest, found = strings.CutPrefix(name, string(release.KindCLI)+"-")
	}
	if !found {
		return "", "", "", false
	}
	parts := strings.Split(rest, "-")
	if len(parts) != 2 {
		return "", "", "", false
	}
	return kind, parts[0], parts[1], true
}

// buildFlagsFor records how each artifact was built. They differ in the one way
// that matters to someone deciding whether to trust a binary on a bare machine:
// the CLI is built without CGO and links statically, the GUI is not and cannot.
func buildFlagsFor(kind release.Kind) string {
	if kind == release.KindGUI {
		return "-ldflags='-w -s' -trimpath CGO_ENABLED=1"
	}
	return "-ldflags='-w -s' -trimpath CGO_ENABLED=0"
}

// signBootstrapScript writes a detached signature beside the installer.
func signBootstrapScript(root string, signer *pgpcrypto.Identity) error {
	path := filepath.Join(root, BootstrapScriptName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", BootstrapScriptName, err)
	}
	signature, err := signer.SignDetached(raw)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+release.SignatureSuffix, signature, 0o644); err != nil { //nolint:gosec // a signature is not secret
		return fmt.Errorf("write %s: %w", BootstrapScriptName+release.SignatureSuffix, err)
	}
	return nil
}

// recordBootstrapScript stores the digest of the script at the store root, if
// one is present (R5.8).
func recordBootstrapScript(s *Session) error {
	path := filepath.Join(s.Root(), BootstrapScriptName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", BootstrapScriptName, err)
	}
	sum := sha256.Sum256(raw)
	return s.SetBootstrapSHA256(hex.EncodeToString(sum[:]))
}
