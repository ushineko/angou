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

	"github.com/ushineko/angou/internal/buildinfo"
	"github.com/ushineko/angou/internal/container"
	"github.com/ushineko/angou/internal/core"
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
		Version: fmt.Sprintf("%s (%s)", buildinfo.Version, buildinfo.Commit),
		// Errors are reported once, by main, with the program name. Leaving
		// cobra's own reporting on prints every failure twice.
		// Checked once, before any command does work, so a misspelt keyring
		// backend is reported rather than discovered halfway through.
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return core.ValidateKeyringBackend()
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
		newUseCmd(),
		newAgentCmd(),
	)
	return root
}

// storeDir resolves which store to work with.
//
// --store wins, then $ANGOU_STORE (which is the flag's default, so both arrive
// in the same field), then the store this machine remembered when it was set up.
// The remembered one comes last on purpose: a --store on one command is a
// one-off against another store and must not become the new default, or a single
// command run against a backup copy would quietly repoint every later one.
func storeDir() (string, error) {
	if global.storeDir != "" {
		return global.storeDir, nil
	}
	if dir := core.RememberedStore(); dir != "" {
		return dir, nil
	}
	return "", fmt.Errorf("no store directory: pass --store, set $%s, or run `angou use <dir>`", StoreEnv)
}

// openStore unlocks the store by whichever route the machine supports. See
// unlock() for the two routes and why a failing local key never falls back.
func openStore() (*core.Session, error) { return unlock() }

func encodingFor(binary bool) container.Encoding {
	if binary {
		return container.EncodingBinary
	}
	return container.EncodingArmor
}

// rememberStore records the store a machine has just set up, so later commands
// find it without --store.
//
// Failing to write it is reported and then dropped. The store exists and the
// machine is set up; refusing to return success because a convenience file could
// not be written would misreport what actually happened.
func rememberStore(dir string) {
	if err := core.RememberStore(dir); err != nil {
		fmt.Fprintf(os.Stderr, "angou: could not remember %s as this machine's store: %v\n"+
			"Later commands will need --store or $%s.\n", dir, err, StoreEnv)
	}
}
