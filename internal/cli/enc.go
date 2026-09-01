package cli

import (
	"fmt"
	"mime"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/store"
)

func newEncCmd() *cobra.Command {
	var (
		logicalPath string
		binary      bool
	)

	cmd := &cobra.Command{
		Use:   "enc <file>",
		Short: "Encrypt a file into the store",
		Long: "enc reads a file and writes it into the store at a logical path. The same\n" +
			"logical path always resolves to the same blob, so encrypting again updates in\n" +
			"place and leaves no orphan.\n\n" +
			"The plaintext file is left where it is. Deleting it is your call, and on a\n" +
			"copy-on-write filesystem or flash storage deletion is not a secure erase.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			src := args[0]
			content, err := os.ReadFile(src)
			if err != nil {
				return fmt.Errorf("read %s: %w", src, err)
			}
			fi, err := os.Stat(src)
			if err != nil {
				return fmt.Errorf("stat %s: %w", src, err)
			}

			target := logicalPath
			if target == "" {
				// Deliberately not cleaned. R3.4.1 refuses a non-conforming path
				// rather than repairing it, and cleaning here would quietly turn
				// "a/../a/secret" into "a/secret" — storing the file under a name
				// the user did not ask for and did not see.
				target = filepath.ToSlash(src)
			}
			// The grammar is applied to whatever the user actually gave, so a
			// path the tool cannot represent is refused at the point the user
			// can still fix it (R3.4.1).
			normalized, err := store.NormalizePath(target)
			if err != nil {
				return fmt.Errorf("%w\nPass --as to give the file an explicit store-relative path", err)
			}

			s, err := openStore()
			if err != nil {
				return err
			}
			logf("encrypting %d bytes from %s as %s", len(content), src, normalized)
			id, err := s.Put(normalized, content,
				uint32(fi.Mode().Perm()), fi.ModTime().Unix(),
				mimeFor(src), encodingFor(binary))
			if err != nil {
				return err
			}
			fmt.Printf("%s -> %s\n", normalized, id)
			return nil
		},
	}
	cmd.Flags().StringVar(&logicalPath, "as", "",
		"store-relative logical path (default: the input path, normalized)")
	cmd.Flags().BoolVar(&binary, "binary", false,
		"emit raw OpenPGP packets instead of ASCII armor")
	return cmd
}

func mimeFor(name string) string {
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}
