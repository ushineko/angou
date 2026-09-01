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

	"github.com/ushineko/angou/internal/prompt"
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
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&global.storeDir, "store", os.Getenv(StoreEnv),
		"store directory (default $"+StoreEnv+")")
	pf.IntVar(&global.passphraseFD, "passphrase-fd", -1,
		"read the recovery passphrase from this already-open file descriptor instead of prompting")

	root.AddCommand(
		newInitCmd(),
		newEncCmd(),
		newDecCmd(),
		newGetCmd(),
		newLsCmd(),
		newRmCmd(),
		newMvCmd(),
		newReindexCmd(),
	)
	return root
}

func storeDir() (string, error) {
	if global.storeDir == "" {
		return "", fmt.Errorf("no store directory: pass --store or set $%s", StoreEnv)
	}
	return global.storeDir, nil
}

// openStore unlocks the store with the recovery passphrase. Pass 1 has no
// keyring backend, so this is the R2.5 path: the identity stays under the
// recovery passphrase and every command pays for one derivation.
func openStore() (*store.Store, error) {
	dir, err := storeDir()
	if err != nil {
		return nil, err
	}
	secret, err := prompt.Passphrase(global.passphraseFD, "Recovery passphrase: ")
	if err != nil {
		return nil, err
	}
	defer prompt.Zero(secret)

	s, err := store.Open(dir, secret)
	if err != nil {
		return nil, err
	}
	if !s.IndexTrusted {
		// R3.7: the index is a cache, never authoritative. Degrade browsing and
		// say so, rather than failing an operation that does not need it.
		fmt.Fprintln(os.Stderr, "angou: the index is missing or did not verify; run `angou reindex` to rebuild it.")
	}
	return s, nil
}

func encodingFor(binary bool) container.Encoding {
	if binary {
		return container.EncodingBinary
	}
	return container.EncodingArmor
}
