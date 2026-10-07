package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "embed"

	"github.com/ushineko/angou/internal/pgpcrypto"
	"github.com/ushineko/angou/internal/release"
	"github.com/ushineko/angou/internal/store"
)

//go:embed assets/bootstrap.sh
var bootstrapTemplate string

//go:embed assets/bootstrap.ps1
var bootstrapPS1Template string

// BootstrapPS1Name is the Windows installer kept beside bootstrap.sh. It does
// the same job for a machine with PowerShell and no POSIX shell.
const BootstrapPS1Name = "bootstrap.ps1"

// fingerprintPlaceholder is substituted when the script is written into a store.
const fingerprintPlaceholder = "__RELEASE_KEY_FINGERPRINT__"

// iconPlaceholder is substituted with the application icon, so the installer can
// give a bootstrapped GUI a real taskbar icon rather than a generic one.
//
// Substituted rather than carried as a separate file in the store: the script is
// signed and verified before it runs, so anything inside it is covered by that
// signature. A companion file beside it would be one more artifact to verify,
// for an icon.
const iconPlaceholder = "__ANGOU_ICON_SVG__"

//go:embed assets/angou.svg
var iconSVG []byte

// IconSVG is the application icon. The GUI draws its window and taskbar icon
// from this, and `angou release` writes it into the installer, so there is one
// embedded copy rather than one per consumer.
func IconSVG() []byte { return iconSVG }

// installer is one plaintext installer a store carries, and where its digest
// lives in the store metadata.
type installer struct {
	name     string
	template string
	recorded func(store.Meta) string
	record   func(*store.Store, string) error
}

// installers are every script `angou release` writes beside a store. Each is
// signed by the release key and has its digest recorded, so each is covered by
// the same drift detection.
var installers = []installer{
	{
		name:     BootstrapScriptName,
		template: bootstrapTemplate,
		recorded: func(m store.Meta) string { return m.BootstrapSHA256 },
		record:   (*store.Store).SetBootstrapSHA256,
	},
	{
		name:     BootstrapPS1Name,
		template: bootstrapPS1Template,
		recorded: func(m store.Meta) string { return m.BootstrapPS1SHA256 },
		record:   (*store.Store).SetBootstrapPS1SHA256,
	},
}

// IsInstallerName reports whether name is one of the plaintext installers at a
// store's root.
func IsInstallerName(name string) bool {
	for _, in := range installers {
		if in.name == name {
			return true
		}
	}
	return false
}

// HostInstaller is the installer this machine would run, and how to run it.
func HostInstaller(root string) (name, command string) {
	if runtime.GOOS == "windows" {
		path := filepath.Join(root, BootstrapPS1Name)
		return BootstrapPS1Name, "powershell -NoProfile -ExecutionPolicy Bypass -File \"" + path + "\""
	}
	path := filepath.Join(root, BootstrapScriptName)
	return BootstrapScriptName, "sh " + path
}

// writeBootstrapScripts renders every installer into the store root with the
// release-signing fingerprint baked in.
//
// The fingerprint is written into the script rather than read from the store at
// run time, which is the point of R5.4.1: if the installer took its idea of a
// trustworthy key from the same directory as the binaries it verifies, verifying
// them would establish nothing.
func writeBootstrapScripts(root, fingerprint string) error {
	if fingerprint == "" {
		return fmt.Errorf("refusing to write %s with no release key pinned: an installer that "+
			"trusts any signature is worse than none.\nBuild with RELEASE_KEY=<fingerprint>, "+
			"or create a key with `angou release --new-signing-key <path>`", BootstrapScriptName)
	}
	for _, in := range installers {
		rendered := strings.ReplaceAll(in.template, fingerprintPlaceholder, fingerprint)
		rendered = strings.ReplaceAll(rendered, iconPlaceholder, strings.TrimRight(string(iconSVG), "\n"))
		path := filepath.Join(root, in.name)
		if err := os.WriteFile(path, []byte(rendered), 0o755); err != nil { //nolint:gosec // an installer must be executable
			return fmt.Errorf("write %s: %w", in.name, err)
		}
	}
	return nil
}

// signBootstrapScripts writes a detached signature beside each installer.
//
// That is what lets an installer check itself without a passphrase, and it
// means altering one requires the offline key rather than merely write access
// to the store.
func signBootstrapScripts(root string, signer *pgpcrypto.Identity) error {
	for _, in := range installers {
		path := filepath.Join(root, in.name)
		raw, err := os.ReadFile(path) //nolint:gosec // a fixed name inside the store directory
		if err != nil {
			return fmt.Errorf("read %s: %w", in.name, err)
		}
		signature, err := signer.SignDetached(raw)
		if err != nil {
			return err
		}
		if err := os.WriteFile(path+release.SignatureSuffix, signature, 0o644); err != nil { //nolint:gosec // a signature is not secret
			return fmt.Errorf("write %s: %w", in.name+release.SignatureSuffix, err)
		}
	}
	return nil
}

// BootstrapCheck reports how one installer beside the store compares to the
// digest recorded inside it.
//
// What this catches and what it does not: run from a machine that already has a
// trusted angou, it detects alteration of the script that other machines will go
// on to run. It is not a guarantee that a script which already ran was genuine —
// a deliberately subverted script would simply not call this — and it cannot
// protect the first machine to run one.
type BootstrapCheck struct {
	// Name is the installer's filename.
	Name string
	// Recorded is the digest held inside the store, empty when none is.
	Recorded string
	// Actual is the digest of the script on disk.
	Actual string
	// Matches is false when the script has drifted from what was recorded.
	Matches bool
}

// ErrNoInstaller reports a store with no installer beside it.
var ErrNoInstaller = errors.New("no installer beside the store")

// VerifyBootstraps compares each installer present beside the store against its
// recorded digest. Installers that are absent are left out; a store with none
// at all is ErrNoInstaller.
func (s *Session) VerifyBootstraps() ([]BootstrapCheck, error) {
	return checkInstallers(s.st)
}

// RecordBootstraps writes the digest of each installer present beside the
// store as the expected one, and reports what it recorded. Only do this for
// scripts the user put there themselves.
func (s *Session) RecordBootstraps() ([]BootstrapCheck, error) {
	checks, err := checkInstallers(s.st)
	if err != nil {
		return nil, err
	}
	for i, c := range checks {
		if err := installerNamed(c.Name).record(s.st, c.Actual); err != nil {
			return nil, err
		}
		checks[i].Recorded, checks[i].Matches = c.Actual, true
	}
	return checks, nil
}

func checkInstallers(st *store.Store) ([]BootstrapCheck, error) {
	var out []BootstrapCheck
	for _, in := range installers {
		raw, err := os.ReadFile(filepath.Join(st.Root(), in.name)) //nolint:gosec // a fixed name inside the store directory
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", in.name, err)
		}
		recorded, actual := in.recorded(st.Meta()), digest(raw)
		out = append(out, BootstrapCheck{Name: in.name, Recorded: recorded, Actual: actual, Matches: recorded == actual})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: neither %s nor %s is in %s", ErrNoInstaller, BootstrapScriptName, BootstrapPS1Name, st.Root())
	}
	return out, nil
}

// recordBootstrapScripts stores the digest of each installer at the store root
// (R5.8).
func recordBootstrapScripts(s *Session) error {
	_, err := s.RecordBootstraps()
	if errors.Is(err, ErrNoInstaller) {
		return nil
	}
	return err
}

func installerNamed(name string) installer {
	for _, in := range installers {
		if in.name == name {
			return in
		}
	}
	panic("unknown installer " + name)
}
