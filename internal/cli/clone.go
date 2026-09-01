package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/core"

	"github.com/ushineko/angou/internal/store"
)

func newCloneCmd() *cobra.Command {
	var (
		to         string
		noBinaries bool
	)

	cmd := &cobra.Command{
		Use:   "clone",
		Short: "Copy a store to another directory",
		Long: "clone copies a store verbatim, so the copy opens with the same recovery\n" +
			"passphrase and holds the same secrets. Treat it exactly as you treat the\n" +
			"original.\n\n" +
			"--no-binaries omits the platform binaries, which are usually most of the size. A\n" +
			"store copied that way still holds every secret and still opens; it just cannot\n" +
			"bootstrap a bare machine on its own.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if to == "" {
				return fmt.Errorf("clone needs --to")
			}
			from, err := storeDir()
			if err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(from, store.MetaName)); err != nil {
				return fmt.Errorf("%w: %s", store.ErrNotAStore, from)
			}
			if _, err := os.Stat(to); err == nil {
				return fmt.Errorf("%s already exists; clone will not write into it", to)
			}
			// A destination inside the source would be created by the walk and
			// then walked into, copying the clone into itself until the disk
			// filled.
			inside, err := core.IsInside(from, to)
			if err != nil {
				return err
			}
			if inside {
				return fmt.Errorf("%s is inside %s; clone would copy the store into itself", to, from)
			}
			n, err := core.CopyStore(from, to, noBinaries)
			if err != nil {
				return err
			}
			fmt.Printf("Cloned %s to %s (%d files).\n", from, to, n)
			if noBinaries {
				fmt.Fprintln(os.Stderr, "The platform binaries were omitted. This copy cannot bootstrap a bare\n"+
					"machine; it still holds every secret the original does.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "destination directory, which must not already exist")
	cmd.Flags().BoolVar(&noBinaries, "no-binaries", false,
		"omit the platform binaries from the copy (R5.10)")
	return cmd
}
