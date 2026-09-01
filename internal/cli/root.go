// Package cli assembles the angou command tree (spec 001 R6.4).
//
// This is the first implementation pass: it covers the container format, the
// key model's recovery-passphrase path, store addressing, and the index. The
// keyring, agent, rekey, bootstrap, and release commands land in later passes,
// and are absent here rather than present as stubs that would misreport what
// the tool can do.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/store"
	"github.com/ushineko/angou/lib/container"
)

// StoreEnv names the environment variable holding the default store directory.
// It carries a path, never a secret.
const StoreEnv = "ANGOU_STORE"

type globalFlags struct {
	storeDir     string
	passphraseFD int
}

var global globalFlags

// Root builds the command tree.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "angou",
		Short: "Encrypt sensitive files into a portable, syncable store",
		Long: "angou converts sensitive files to and from encrypted blobs held in a plain\n" +
			"directory. The store is portable: rsync, a sync service, or removable media\n" +
			"carries it without any further state.",
		Version: fmt.Sprintf("%s (%s)", container.Version, container.Commit),
		// Errors are reported once, by main, with the program name. Leaving
		// cobra's own reporting on prints every failure twice.
		// Checked once, before any command does work, so a misspelt keyring
		// backend is reported rather than discovered halfway through.
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return keyring.ValidateBackend()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&global.storeDir, "store", os.Getenv(StoreEnv),
		"store directory (default $"+StoreEnv+")")
	pf.BoolVarP(&verbose, "verbose", "v", false,
		"report what angou is doing on stderr; never discloses secrets or file contents")
	pf.IntVar(&global.passphraseFD, "passphrase-fd", -1,
		"read the recovery passphrase from this already-open file descriptor instead of prompting")

	root.AddCommand(
		newInitCmd(),
		newBootstrapCmd(),
		newDoctorCmd(),
		newEncCmd(),
		newDecCmd(),
		newGetCmd(),
		newLsCmd(),
		newRmCmd(),
		newMvCmd(),
		newReindexCmd(),
		newRekeyCmd(),
		newPasswdCmd(),
		newPruneCmd(),
		newReleaseCmd(),
		newVerifyBootstrapCmd(),
		newCloneCmd(),
		newAgentCmd(),
	)
	return root
}

func storeDir() (string, error) {
	if global.storeDir == "" {
		return "", fmt.Errorf("no store directory: pass --store or set $%s", StoreEnv)
	}
	return global.storeDir, nil
}

// openStore unlocks the store by whichever route the machine supports. See
// unlock() for the two routes and why a failing local key never falls back.
func openStore() (*store.Store, error) { return unlock() }

func encodingFor(binary bool) container.Encoding {
	if binary {
		return container.EncodingBinary
	}
	return container.EncodingArmor
}
