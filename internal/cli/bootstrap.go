package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/store"
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
			if localkey.Exists(dir) && !force {
				return fmt.Errorf("this machine is already bootstrapped for %s.\n"+
					"Pass --force to replace the local key, or --forget to remove it", dir)
			}

			secret, err := prompt.Passphrase(global.passphraseFD, "Recovery passphrase: ")
			if err != nil {
				return err
			}
			defer prompt.Zero(secret)

			exported, err := store.ExportIdentity(dir, secret)
			if err != nil {
				return err
			}
			defer prompt.Zero(exported)

			// Confirm the recovered identity actually opens this store before
			// committing any local state, so a failure leaves the machine as it
			// was rather than half-configured.
			s, err := store.OpenWithExportedIdentity(dir, exported)
			if err != nil {
				return err
			}
			fingerprint := s.Fingerprint()

			ring, err := keyring.Open()
			if err != nil {
				if errors.Is(err, keyring.ErrUnavailable) {
					// R2.5: no backend, so the key is not re-protected here and
					// no local state is written. Report it plainly — a machine
					// that silently kept prompting would look broken.
					fmt.Fprintf(os.Stderr, "No keyring is available on this machine, so the identity was not\n"+
						"re-protected here. The store remains reachable with the recovery passphrase.\n"+
						"Underlying cause: %v\n", err)
					fmt.Printf("Store %s is usable with the recovery passphrase.\n", dir)
					fmt.Printf("Identity fingerprint: %s\n", fingerprint)
					return nil
				}
				return err
			}
			defer func() { _ = ring.Close() }()

			unlockSecret, err := localkey.GenerateUnlockPassphrase()
			if err != nil {
				return err
			}
			defer prompt.Zero(unlockSecret)

			// Keyring first: a local key whose passphrase never reached the
			// keyring is unopenable, whereas a keyring entry with no local key
			// is merely unused and is overwritten by the next bootstrap.
			if err := ring.Set(fingerprint, unlockSecret); err != nil {
				return err
			}
			if err := localkey.Write(dir, fingerprint, exported, unlockSecret); err != nil {
				return err
			}

			if err := selfTest(dir); err != nil {
				return fmt.Errorf("bootstrap wrote local state but its self-test failed: %w", err)
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

// selfTest confirms the machine can now open the store by the keyring route,
// so a broken bootstrap is reported by bootstrap rather than by the next
// command the user runs (R5.9).
func selfTest(dir string) error {
	s, err := unlockLocal(dir)
	if err != nil {
		return err
	}
	_ = s.List()
	return nil
}

func forgetLocal(dir string) error {
	if !localkey.Exists(dir) {
		fmt.Printf("This machine holds no local key for %s.\n", dir)
		return nil
	}
	fingerprint, err := localkey.Fingerprint(dir)
	if err != nil {
		return err
	}
	if ring, err := keyring.Open(); err == nil {
		defer func() { _ = ring.Close() }()
		if err := ring.Remove(fingerprint); err != nil {
			return err
		}
	} else if !errors.Is(err, keyring.ErrUnavailable) {
		return err
	}
	if err := localkey.Remove(dir); err != nil {
		return err
	}
	fmt.Printf("Removed this machine's local key for %s.\n", dir)
	fmt.Fprintln(os.Stderr, "Commands will ask for the recovery passphrase again until you re-run bootstrap.")
	return nil
}
