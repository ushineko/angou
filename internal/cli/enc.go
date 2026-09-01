package cli

import (
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"

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
			derived := false
			if target == "" {
				target, derived = defaultLogicalPath(src)
			}
			// The grammar is applied to whatever will actually be stored, so a
			// path the tool cannot represent is refused at the point the user
			// can still fix it (R3.4.1).
			normalized, err := store.NormalizePath(target)
			if err != nil {
				return fmt.Errorf("%w\nPass --as to give the file an explicit store-relative path", err)
			}
			if derived {
				// The name was worked out rather than given, so say what it is.
				// The store is addressed by these names and the user has to know
				// which one to ask for later.
				fmt.Fprintf(os.Stderr, "angou: storing %s as %q\n", src, normalized)
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

// defaultLogicalPath works out the name to store a file under when the user did
// not give one, and reports whether it had to derive it.
//
// A relative argument is used exactly as typed. That keeps the common case
// predictable and keeps the refusal of R3.4.1 intact: a relative path with a
// ".." in it is still refused rather than quietly rewritten, because the user
// typed something the store cannot represent and should see that.
//
// An absolute argument is a different matter. `angou enc ~/.secrets.env` is the
// natural way to reach for the tool, and the shell has already turned it into an
// absolute path by the time angou sees it — so refusing absolute paths means
// refusing the most obvious invocation there is. Absolute paths are mapped into
// the store's namespace instead: relative to the home directory where the file
// is under it, and otherwise with the leading separator removed. Both keep the
// directory structure, which is what stops two files called .secrets.env from
// different projects landing on the same name (R3.5).
func defaultLogicalPath(src string) (string, bool) {
	if !filepath.IsAbs(src) {
		return filepath.ToSlash(src), false
	}

	// filepath.Abs also cleans, which is wanted here: the input is a filesystem
	// path being translated into a logical one, not a logical path being
	// silently repaired.
	abs, err := filepath.Abs(src)
	if err != nil {
		abs = src
	}
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(home, abs); err == nil &&
			rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel), true
		}
	}
	// Outside the home directory: keep the whole path, minus its root, so
	// /etc/ssl/private/key becomes etc/ssl/private/key.
	trimmed := strings.TrimPrefix(filepath.ToSlash(abs), filepath.ToSlash(filepath.VolumeName(abs)))
	return strings.TrimPrefix(trimmed, "/"), true
}

func mimeFor(name string) string {
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}
