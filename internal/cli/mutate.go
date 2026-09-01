package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <path>",
		Short: "Remove a stored file",
		Long: "rm deletes one blob from the store. The deletion propagates to every machine\n" +
			"the store syncs to, and angou keeps no copy of its own.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			return s.Remove(args[0])
		},
	}
}

func newMvCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mv <from> <to>",
		Short: "Re-address a stored file under a new logical path",
		Long: "mv rewrites the blob under the new path rather than renaming the file on disk:\n" +
			"the logical path is part of the signed, encrypted envelope and is bound to the\n" +
			"blob's filename, so the two must change together.",
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			return s.Move(args[0], args[1])
		},
	}
}

func newReindexCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reindex",
		Short: "Rebuild the index from the blobs themselves",
		Long: "reindex discards the index and reconstructs it by decrypting every blob and\n" +
			"reading its envelope, which is the authoritative record. Use it after a sync\n" +
			"service leaves a conflicted copy, or whenever ls reports the index as untrusted.\n\n" +
			"A blob whose envelope path does not address its own filename aborts the rebuild\n" +
			"rather than being indexed under the wrong name.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			r, err := s.Reindex()
			if err != nil {
				return err
			}
			fmt.Printf("Reindexed %d entries.\n", r.Entries)
			for _, name := range r.Unreadable {
				fmt.Fprintf(os.Stderr, "angou: ignored %q — it does not decrypt with this store's key. "+
					"This is usually a leftover from an interrupted rekey; `angou prune --orphans` removes them.\n", name)
			}
			for _, name := range r.Skipped {
				fmt.Fprintf(os.Stderr, "angou: ignored %q — not a blob name. "+
					"This is usually a sync-service conflicted copy; delete it once you are sure.\n", name)
			}
			return nil
		},
	}
}
