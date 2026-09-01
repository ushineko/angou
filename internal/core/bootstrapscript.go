package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "embed"
)

//go:embed assets/bootstrap.sh
var bootstrapTemplate string

// fingerprintPlaceholder is substituted when the script is written into a store.
const fingerprintPlaceholder = "__RELEASE_KEY_FINGERPRINT__"

// writeBootstrapScript renders the installer into the store root with the
// release-signing fingerprint baked in.
//
// The fingerprint is written into the script rather than read from the store at
// run time, which is the point of R5.4.1: if the installer took its idea of a
// trustworthy key from the same directory as the binaries it verifies, verifying
// them would establish nothing.
func writeBootstrapScript(root, fingerprint string) error {
	if fingerprint == "" {
		return fmt.Errorf("refusing to write %s with no release key pinned: an installer that "+
			"trusts any signature is worse than none.\nBuild with RELEASE_KEY=<fingerprint>, "+
			"or create a key with `angou release --new-signing-key <path>`", BootstrapScriptName)
	}
	rendered := strings.ReplaceAll(bootstrapTemplate, fingerprintPlaceholder, fingerprint)
	path := filepath.Join(root, BootstrapScriptName)
	if err := os.WriteFile(path, []byte(rendered), 0o755); err != nil { //nolint:gosec // an installer must be executable
		return fmt.Errorf("write %s: %w", BootstrapScriptName, err)
	}
	return nil
}

// BootstrapCheck reports how the installer beside the store compares to the
// digest recorded inside it.
//
// What this catches and what it does not: run from a machine that already has a
// trusted angou, it detects alteration of the script that other machines will go
// on to run. It is not a guarantee that a script which already ran was genuine —
// a deliberately subverted script would simply not call this — and it cannot
// protect the first machine to run one.
type BootstrapCheck struct {
	// Recorded is the digest held inside the store, empty when none is.
	Recorded string
	// Actual is the digest of the script on disk.
	Actual string
	// Matches is false when the script has drifted from what was recorded.
	Matches bool
}

// VerifyBootstrap compares the store's bootstrap.sh against the recorded digest.
func (s *Session) VerifyBootstrap() (BootstrapCheck, error) {
	path := filepath.Join(s.Root(), BootstrapScriptName)
	raw, err := os.ReadFile(path) //nolint:gosec // a fixed name inside the store directory
	if err != nil {
		if os.IsNotExist(err) {
			return BootstrapCheck{}, fmt.Errorf("no %s in %s", BootstrapScriptName, s.Root())
		}
		return BootstrapCheck{}, fmt.Errorf("read %s: %w", BootstrapScriptName, err)
	}
	recorded := s.Meta().BootstrapSHA256
	actual := digest(raw)
	return BootstrapCheck{Recorded: recorded, Actual: actual, Matches: recorded == actual}, nil
}
