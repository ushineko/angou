package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/buildinfo"
	"github.com/ushineko/angou/internal/core"
	"github.com/ushineko/angou/internal/prompt"
)

func newBootstrapCmd() *cobra.Command {
	var (
		force  bool
		forget bool
	)

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Set this machine up to open the store without the recovery passphrase",
		Long: "bootstrap recovers the identity from the store's key bundle, re-wraps it under a\n" +
			"fresh machine password, and stores that password in the keyring. Afterwards every\n" +
			"command opens the store from the keyring, and you are not asked for the recovery\n" +
			"passphrase again on this machine.\n\n" +
			"The machine password is 32 random bytes. You are never shown it and never need it:\n" +
			"the keyring entry is its only copy. Deleting that entry does not lock you out of\n" +
			"the store — the store is still openable with the recovery passphrase — but it does\n" +
			"mean this machine has to be bootstrapped again.\n\n" +
			"Where no keyring is available, bootstrap tells you so and changes nothing. The\n" +
			"store stays reachable with the recovery passphrase on such a machine.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			dir, err := storeDir()
			if err != nil {
				return err
			}

			if forget {
				return forgetLocal(dir)
			}
			if core.HasLocalKey(dir) && !force {
				return fmt.Errorf("this machine is already bootstrapped for %s.\n"+
					"Pass --force to replace the local key, or --forget to remove it", dir)
			}

			secret, err := prompt.Passphrase(global.passphraseFD, "Recovery passphrase: ")
			if err != nil {
				return err
			}
			defer prompt.Zero(secret)

			exported, err := core.ExportIdentity(dir, secret)
			if err != nil {
				return err
			}
			defer prompt.Zero(exported)

			// Confirm the recovered identity actually opens this store before
			// committing any local state, so a failure leaves the machine as it
			// was rather than half-configured.
			s, err := core.OpenWithExportedIdentity(dir, exported, events())
			if err != nil {
				return err
			}
			// The real version floor is applied here, where the store can
			// actually be read (R5.4.2).
			if err := core.CheckVersionFloor(s.Meta().VersionFloor, s.Root(), buildinfo.Version); err != nil {
				return err
			}
			fingerprint := s.Fingerprint()

			done, err := setUpMachine(dir, fingerprint, exported, s)
			if err != nil {
				return err
			}
			if !done {
				fmt.Printf("Store %s is usable with the recovery passphrase.\n", dir)
				fmt.Printf("Identity fingerprint: %s\n", fingerprint)
				return nil
			}

			fmt.Printf("Bootstrapped %s on this machine.\n", dir)
			fmt.Printf("Identity fingerprint: %s\n", fingerprint)
			fmt.Fprintln(os.Stderr, "The recovery passphrase is no longer needed on this machine. Keep it anyway:\n"+
				"it is the only thing that opens the store on a machine that has not been bootstrapped.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false,
		"replace local key state that already exists, for a machine holding a superseded key")
	cmd.Flags().BoolVar(&forget, "forget", false,
		"remove this machine's local key and keyring entry, returning it to the recovery passphrase")
	return cmd
}

// setUpMachine wraps the identity under a fresh machine password held in the
// keyring, so this machine can open the store without the recovery passphrase.
//
// It reports whether it did anything. Where no keyring backend is reachable it
// writes nothing and says so, leaving the store on the recovery passphrase
// (R2.5) — a machine that silently kept prompting would look broken.
// setUpMachine stores the local key and reports how it went. The operation is
// core's; what stays here is saying so on stderr.
func setUpMachine(dir, fingerprint string, exported []byte, s *core.Session) (bool, error) {
	_, _ = dir, fingerprint
	r, err := s.SetUpMachine(exported)
	if err != nil {
		return false, err
	}
	if !r.UsedKeyring {
		fmt.Fprintf(os.Stderr, "No keyring is available on this machine, so the identity was not\n"+
			"re-protected here. The store remains reachable with the recovery passphrase.\n"+
			"Underlying cause: %v\n", r.Cause)
	}
	fmt.Fprintln(os.Stderr, "Round-trip self-test passed.")
	return r.UsedKeyring, nil
}

func forgetLocal(dir string) error {
	r, err := core.ForgetMachine(dir)
	if err != nil {
		return err
	}
	if !r.HadKey {
		fmt.Printf("This machine holds no local key for %s.\n", dir)
		return nil
	}
	fmt.Printf("Removed this machine's local key for %s.\n", dir)
	fmt.Fprintln(os.Stderr, "Commands will ask for the recovery passphrase again until you re-run bootstrap.")
	return nil
}
