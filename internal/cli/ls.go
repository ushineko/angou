package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func newLsCmd() *cobra.Command {
	var long bool

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List the logical paths held in the store",
		Long: "ls reads the index, which is a rebuildable cache. If it is missing or does not\n" +
			"verify, the listing is empty and `angou reindex` rebuilds it from the blobs\n" +
			"themselves. Retrieval by path never depends on the index.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			entries := s.List()
			if !long {
				for _, e := range entries {
					fmt.Println(e.Path)
				}
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "MODE\tSIZE\tMODIFIED\tMIME\tPATH")
			for _, e := range entries {
				_, _ = fmt.Fprintf(w, "%04o\t%d\t%s\t%s\t%s\n",
					e.Mode, e.Size, time.Unix(e.MTime, 0).Format(time.RFC3339), e.MIME, e.Path)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&long, "long", false, "render envelope metadata for every entry")
	return cmd
}
