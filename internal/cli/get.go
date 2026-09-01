package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newGetCmd() *cobra.Command {
	var dest string

	cmd := &cobra.Command{
		Use:   "get <path>",
		Short: "Extract a stored file under a destination root, restoring mode and mtime",
		Long: "get writes a stored file beneath --dest, recreating its directories and\n" +
			"restoring its POSIX mode and modification time.\n\n" +
			"Extraction is confined to the destination root and will not traverse a symlink\n" +
			"to leave it. A stored path is treated as untrusted input, because anyone who can\n" +
			"write to the store chooses it.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			written, err := s.Extract(args[0], dest)
			if err != nil {
				return err
			}
			fmt.Println(written)
			return nil
		},
	}
	cmd.Flags().StringVar(&dest, "dest", "", "destination root; every write is confined beneath it")
	return cmd
}
