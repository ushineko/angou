package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/core"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/store"
)

func newDoctorCmd() *cobra.Command {
	var oldKey string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Report what this machine can and cannot do with the store",
		Long: "doctor inspects the store and this machine's local state and reports what it\n" +
			"finds. It changes nothing.\n\n" +
			"Run it when a command fails in a way you do not understand, or after moving a\n" +
			"store between machines. It is also what tells you whether this machine still\n" +
			"needs the recovery passphrase.\n\n" +
			"--old-key asserts that a named superseded key opens nothing in the store. Run it\n" +
			"after `angou rekey --identity`: without it you have no way to tell a complete\n" +
			"rotation from a partial one, and a partial one leaves secrets readable by the key\n" +
			"you were rotating away from.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			dir, err := storeDir()
			if err != nil {
				return err
			}
			if oldKey != "" {
				return assertOldKeyIsDead(dir, oldKey)
			}
			renderReport(os.Stdout, core.Doctor(dir, quietSecrets{}, events()))
			return nil
		},
	}
	cmd.Flags().StringVar(&oldKey, "old-key", "",
		"assert that this superseded key fingerprint opens nothing in the store")
	return cmd
}

// assertOldKeyIsDead is the verification step after an identity rotation
// (R6.4.1). It exits non-zero if the named key still opens anything.
func assertOldKeyIsDead(dir, fingerprint string) error {
	fingerprint = strings.ToUpper(strings.ReplaceAll(fingerprint, " ", ""))

	// The superseded identity is recovered from a retained bundle. If no bundle
	// carries it, the check cannot be performed and says so rather than
	// reporting a clean result it did not establish.
	secret, err := prompt.Passphrase(global.passphraseFD, "Recovery passphrase for the superseded key bundle: ")
	if err != nil {
		return err
	}
	defer prompt.Zero(secret)

	exported, err := store.ExportIdentityByFingerprint(dir, fingerprint, secret)
	if err != nil {
		return fmt.Errorf("%w\nWithout the superseded key this check cannot be performed, and a clean "+
			"result must not be assumed", err)
	}
	defer prompt.Zero(exported)

	opened, err := store.OldKeyOpensAnything(dir, exported)
	if err != nil {
		return err
	}
	if len(opened) > 0 {
		fmt.Fprintf(os.Stderr, "The superseded key %s still opens %d file(s) in this store:\n", fingerprint, len(opened))
		for _, name := range opened {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		return fmt.Errorf("the rotation is incomplete: %s still opens %d file(s)", fingerprint, len(opened))
	}
	fmt.Printf("The superseded key %s opens nothing in %s.\n", fingerprint, dir)
	return nil
}

// renderReport prints a core report as the flat, tab-aligned list this command
// has always printed. The section titles and severities core attaches are not
// used here: the CLI's output is unchanged by the move, which is what the e2e
// suite asserts. They exist for the GUI.
func renderReport(out io.Writer, r core.Report) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	defer func() { _ = w.Flush() }()
	for _, f := range r.Findings() {
		_, _ = fmt.Fprintf(w, "%s%s:\t%s\n", strings.Repeat("  ", f.Indent), f.Label, f.Value)
	}
}

// quietSecrets refuses to prompt, except where the caller has already handed a
// passphrase in on a file descriptor. doctor is what a user runs when something
// is already confusing, and a diagnostic that stops to ask for a passphrase is
// a worse diagnostic.
type quietSecrets struct{}

func (quietSecrets) Recovery(p string) ([]byte, error) {
	if global.passphraseFD < 0 {
		return nil, core.ErrNoSecret
	}
	return prompt.Passphrase(global.passphraseFD, p)
}
