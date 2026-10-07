package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/core"
)

// BootstrapScriptName is the plaintext entrypoint at the store root (R5.5).
// The name lives in internal/core; this alias keeps the call sites here short.
const BootstrapScriptName = core.BootstrapScriptName

func newVerifyBootstrapCmd() *cobra.Command {
	var record bool

	cmd := &cobra.Command{
		Use:   "verify-bootstrap",
		Short: "Check the store's installers against the digests recorded inside the store",
		Long: "verify-bootstrap compares the installers sitting in your store -- bootstrap.sh,\n" +
			"and bootstrap.ps1 for Windows -- against the digests recorded inside the\n" +
			"encrypted store metadata.\n\n" +
			"What this catches and what it does not: run from a machine that already has a\n" +
			"trusted angou, it detects alteration of the scripts that your other machines will\n" +
			"go on to run. That is its purpose. It is not a guarantee that any script which\n" +
			"already ran was genuine — a deliberately subverted script would simply not call\n" +
			"this — and it cannot protect the first machine to run one. That machine is\n" +
			"unprotected by anything, which is inherent to a plaintext installer and is why\n" +
			"the published repository, not the store, is the place to check a first-run\n" +
			"script against.\n\n" +
			"--record writes the current scripts' digests into the store. Only do that when\n" +
			"you put the scripts there yourself.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := unlock()
			if err != nil {
				return err
			}

			if record {
				checks, err := s.RecordBootstraps()
				if err != nil {
					return err
				}
				for _, c := range checks {
					fmt.Printf("Recorded %s as the expected digest for %s.\n", c.Actual, c.Name)
				}
				return nil
			}

			checks, err := s.VerifyBootstraps()
			if err != nil {
				return err
			}
			var failed []error
			for _, c := range checks {
				switch {
				case c.Recorded == "":
					failed = append(failed, fmt.Errorf("no digest is recorded for %s in this store, so "+
						"there is nothing to compare against.\nIf you put that script there, record it "+
						"with `angou verify-bootstrap --record`", c.Name))
				case !c.Matches:
					fmt.Fprintf(os.Stderr, "MISMATCH: %s does not match the digest recorded in this store.\n", c.Name)
					fmt.Fprintf(os.Stderr, "  recorded: %s\n  on disk:  %s\n", c.Recorded, c.Actual)
					fmt.Fprintln(os.Stderr, "\nThe script has changed since it was recorded. Read it before any machine runs it.")
					failed = append(failed, fmt.Errorf("%s does not match its recorded digest", c.Name))
				default:
					fmt.Printf("%s matches the digest recorded in the store.\n", c.Name)
				}
			}
			return errors.Join(failed...)
		},
	}
	cmd.Flags().BoolVar(&record, "record", false,
		"record the current scripts' digests as the expected ones")
	return cmd
}
