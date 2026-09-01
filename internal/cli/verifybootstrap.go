package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/store"
)

// BootstrapScriptName is the plaintext entrypoint at the store root (R5.5).
const BootstrapScriptName = "bootstrap.sh"

func newVerifyBootstrapCmd() *cobra.Command {
	var record bool

	cmd := &cobra.Command{
		Use:   "verify-bootstrap",
		Short: "Check the store's bootstrap.sh against the digest recorded inside the store",
		Long: "verify-bootstrap compares the bootstrap.sh sitting in your store against the\n" +
			"digest recorded inside the encrypted store metadata.\n\n" +
			"What this catches and what it does not: run from a machine that already has a\n" +
			"trusted angou, it detects alteration of the script that your other machines will\n" +
			"go on to run. That is its purpose. It is not a guarantee that any script which\n" +
			"already ran was genuine — a deliberately subverted script would simply not call\n" +
			"this — and it cannot protect the first machine to run one. That machine is\n" +
			"unprotected by anything, which is inherent to a plaintext installer and is why\n" +
			"the published repository, not the store, is the place to check a first-run\n" +
			"script against.\n\n" +
			"--record writes the current script's digest into the store. Only do that when\n" +
			"you put the script there yourself.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := unlock()
			if err != nil {
				return err
			}
			path := filepath.Join(s.Root(), BootstrapScriptName)
			raw, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("no %s in %s", BootstrapScriptName, s.Root())
				}
				return fmt.Errorf("read %s: %w", BootstrapScriptName, err)
			}
			sum := sha256.Sum256(raw)
			digest := hex.EncodeToString(sum[:])

			if record {
				if err := s.SetBootstrapSHA256(digest); err != nil {
					return err
				}
				fmt.Printf("Recorded %s as the expected digest for %s.\n", digest, BootstrapScriptName)
				return nil
			}

			recorded := s.Meta().BootstrapSHA256
			switch {
			case recorded == "":
				return fmt.Errorf("no digest is recorded for %s in this store, so there is nothing "+
					"to compare against.\nIf you put that script there, record it with "+
					"`angou verify-bootstrap --record`", BootstrapScriptName)
			case recorded != digest:
				fmt.Fprintf(os.Stderr, "MISMATCH: %s does not match the digest recorded in this store.\n", BootstrapScriptName)
				fmt.Fprintf(os.Stderr, "  recorded: %s\n  on disk:  %s\n", recorded, digest)
				fmt.Fprintln(os.Stderr, "\nThe script has changed since it was recorded. Read it before any machine runs it.")
				return fmt.Errorf("%s does not match its recorded digest", BootstrapScriptName)
			default:
				fmt.Printf("%s matches the digest recorded in the store.\n", BootstrapScriptName)
				return nil
			}
		},
	}
	cmd.Flags().BoolVar(&record, "record", false,
		"record the current script's digest as the expected one")
	return cmd
}

// warnIfBootstrapDrifted runs the same comparison opportunistically on unlock
// and reports a mismatch as a warning (R5.8.1). It never fails the command it
// was called from: an altered installer does not make the store unreadable, and
// refusing to read a store because of it would help nobody.
func warnIfBootstrapDrifted(s *store.Store) {
	recorded := s.Meta().BootstrapSHA256
	if recorded == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(s.Root(), BootstrapScriptName))
	if err != nil {
		return
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != recorded {
		fmt.Fprintf(os.Stderr, "angou: WARNING — %s does not match the digest recorded in this store.\n"+
			"angou: Read it before any machine runs it; see `angou verify-bootstrap`.\n", BootstrapScriptName)
	}
}
