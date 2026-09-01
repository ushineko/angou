package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/pgpcrypto"
	"github.com/ushineko/angou/internal/release"
	"github.com/ushineko/angou/internal/store"
	"github.com/ushineko/angou/lib/container"
)

func newReleaseCmd() *cobra.Command {
	var (
		dist       string
		signingKey string
		newKey     string
		keep       int
	)

	cmd := &cobra.Command{
		Use:   "release",
		Short: "Stash built binaries into the store so a bare machine can install one",
		Long: "release copies the binaries you have built into the store's bootstrap namespace,\n" +
			"signs each one with the offline release-signing key, and records what it was\n" +
			"built from.\n\n" +
			"The binaries are stored in the clear. They are public software and encrypting\n" +
			"them would protect nothing; what protects them is the signature and the version\n" +
			"floor. Anyone who can read your store learns which platforms you use and which\n" +
			"versions you have run, and that is accepted deliberately in exchange for the\n" +
			"bootstrap working with nothing but stock gpg.\n\n" +
			"The signing key is not the store's key and must not be. Keep it offline; it is\n" +
			"needed only here. If it were reachable from the store, anyone who obtained the\n" +
			"recovery passphrase could sign a binary that every future bootstrap would trust.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if newKey != "" {
				return generateSigningKey(newKey)
			}
			if dist == "" || signingKey == "" {
				return fmt.Errorf("release needs --dist and --signing-key\n" +
					"To create a signing key first: angou release --new-signing-key <path>")
			}
			return stashRelease(dist, signingKey, keep)
		},
	}
	cmd.Flags().StringVar(&dist, "dist", "", "directory holding the built binaries")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "armored private release-signing key")
	cmd.Flags().StringVar(&newKey, "new-signing-key", "", "generate a release-signing key at this path and exit")
	cmd.Flags().IntVar(&keep, "keep", release.DefaultKeep, "versions to retain per platform")
	return cmd
}

// generateSigningKey creates a release-signing key. It is written unencrypted
// because it is meant to leave this machine immediately; the instruction to move
// it offline is the control, and pretending a passphrase substitutes for that
// would be worse than saying so.
func generateSigningKey(path string) error {
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

func stashRelease(dist, signingKeyPath string, keep int) error {
	s, err := unlock()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(signingKeyPath)
	if err != nil {
		return fmt.Errorf("read signing key: %w", err)
	}
	signer, err := pgpcrypto.ParseArmoredPrivate(raw)
	if err != nil {
		return err
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
		goos, goarch, ok := platformOf(de.Name())
		if !ok {
			continue
		}
		if err := stashOne(filepath.Join(dist, de.Name()), bootstrapDir, goos, goarch, signer); err != nil {
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

	raised, err := s.RaiseVersionFloor(container.Version, release.CompareVersions)
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

	fmt.Printf("Stashed %d binaries at version %s into %s\n", stashed, container.Version, bootstrapDir)
	fmt.Printf("Signed by %s\n", signer.Fingerprint())
	if raised {
		fmt.Printf("Version floor raised to %s: older binaries will now be refused.\n", container.Version)
	}
	if len(removed) > 0 {
		fmt.Printf("Pruned %d superseded binaries beyond --keep %d.\n", len(removed), keep)
	}
	return nil
}

func stashOne(src, bootstrapDir, goos, goarch string, signer *pgpcrypto.Identity) error {
	binary, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	name := release.BinaryName(goos, goarch, container.Version)
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
		Version:    container.Version,
		Commit:     container.Commit,
		Toolchain:  runtime.Version(),
		BuildFlags: "-ldflags='-w -s' -trimpath CGO_ENABLED=0",
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
func platformOf(name string) (goos, goarch string, ok bool) {
	rest, found := strings.CutPrefix(name, "angou-")
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, "-")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
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
func recordBootstrapScript(s *store.Store) error {
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
