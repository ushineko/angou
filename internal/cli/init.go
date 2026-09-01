package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/passphrase"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/store"
)

func newInitCmd() *cobra.Command {
	var (
		generate    bool
		noBootstrap bool
	)

	cmd := &cobra.Command{
		Use:   "init [store-directory]",
		Short: "Create a store and its identity keypair",
		Long: "init generates the store's OpenPGP keypair and its blob-naming key, and writes\n" +
			"the key bundle under a recovery passphrase.\n\n" +
			"The recovery passphrase is the one secret you must remember. Anyone who can read\n" +
			"the store can copy the key bundle and guess against it offline, without limit and\n" +
			"without you being able to detect it, so a weak passphrase is refused rather than\n" +
			"warned about. There is no recovery path if you forget it: the store's contents are\n" +
			"lost.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 {
				global.storeDir = args[0]
			}
			dir, err := storeDir()
			if err != nil {
				return err
			}
			// Checked before anything is asked. Prompting for a "new recovery
			// passphrase" and only then reporting that the store already exists
			// reads as though the store is about to be replaced, which is
			// alarming and wrong.
			if store.Exists(dir) {
				return fmt.Errorf("%s already holds a store, so there is nothing to initialize.\n"+
					"To set this machine up to open it:   angou bootstrap --store %s\n"+
					"To see what this machine can do:     angou doctor --store %s", dir, dir, dir)
			}

			var (
				secret    []byte
				bits      float64
				generated bool
			)
			if generate {
				phrase, b, err := passphrase.Generate()
				if err != nil {
					return err
				}
				secret, bits, generated = []byte(phrase), b, true
			} else {
				secret, err = prompt.Confirm(global.passphraseFD,
					"New recovery passphrase: ", "Repeat recovery passphrase: ")
				if err != nil {
					return err
				}
				bits, err = passphrase.Check(string(secret))
				if err != nil {
					prompt.Zero(secret)
					return fmt.Errorf("%w\nRerun with --generate to have angou choose one for you", err)
				}
			}
			defer prompt.Zero(secret)

			// The store is created before a generated phrase is shown. Printing
			// it first tells the user to write down a phrase that opens nothing
			// if this fails — and it does fail, on a full disk, an unwritable
			// directory, or a machine without the memory for the derivation.
			s, err := store.Init(dir, secret)
			if err != nil {
				return err
			}

			if generated {
				fmt.Fprintf(os.Stderr, "\nYour recovery passphrase (%.0f bits of entropy):\n\n    %s\n\n", bits, secret)
				fmt.Fprintln(os.Stderr, "This is shown exactly once. Write it down now, somewhere that is not this machine.")
			} else {
				fmt.Fprintf(os.Stderr, "Recovery passphrase accepted (about %.0f bits).\n", bits)
			}
			fmt.Printf("Initialized store at %s\n", s.Root())
			fmt.Printf("Identity fingerprint: %s\n", s.Fingerprint())

			if noBootstrap {
				fmt.Fprintf(os.Stderr, "\nThis machine was not set up, so every command will ask for the recovery\n"+
					"passphrase. To change that later:\n    angou bootstrap --store %s\n", s.Root())
				return nil
			}

			// Set this machine up straight away. Requiring a second command
			// would be asking for the same passphrase that was just used, to do
			// something with no separate decision in it — and until it is run,
			// every command asks for that passphrase, which is the fallback for
			// machines without a keyring rather than how the tool is meant to
			// work.
			exported, err := s.ExportLocalIdentity()
			if err != nil {
				return err
			}
			defer prompt.Zero(exported)

			done, err := setUpMachine(dir, s.Fingerprint(), exported, s)
			if err != nil {
				return err
			}
			if done {
				fmt.Fprintln(os.Stderr, "\nThis machine is set up: commands will not ask for the recovery passphrase\n"+
					"here. Keep it anyway — it is the only thing that opens the store on a machine\n"+
					"that has not been set up.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&generate, "generate", false,
		"generate the recovery passphrase and display it once, instead of prompting")
	cmd.Flags().BoolVar(&noBootstrap, "no-bootstrap", false,
		"do not set this machine up; every command will ask for the recovery passphrase")
	return cmd
}
