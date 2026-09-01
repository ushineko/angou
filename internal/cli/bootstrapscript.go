package cli

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
