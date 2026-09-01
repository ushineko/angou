package cli

import (
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ushineko/angou/internal/store"
	"github.com/ushineko/angou/lib/container"
)

func newEncCmd() *cobra.Command {
	var (
		logicalPath string
		binary      bool
		all         bool
		auto        bool
	)

	cmd := &cobra.Command{
		Use:   "enc <file>",
		Short: "Encrypt a file into the store",
		Long: "enc reads a file and writes it into the store at a logical path. The same\n" +
			"logical path always resolves to the same blob, so encrypting again updates in\n" +
			"place and leaves no orphan.\n\n" +
			"The plaintext file is left where it is. Deleting it is your call, and on a\n" +
			"copy-on-write filesystem or flash storage deletion is not a secure erase.\n\n" +
			"--all treats the argument as a directory and looks through it for the kinds of\n" +
			"file credentials usually live in: SSH private keys, cloud credentials, .env\n" +
			"files, and so on. It asks about each one it finds, because the list is a guess\n" +
			"and a guess is worth checking. --auto takes them all without asking.\n\n" +
			"The scan is a convenience, not a guarantee. It will miss secrets in files it has\n" +
			"never heard of, and it will occasionally offer you something harmless. Do not\n" +
			"read an empty result as \"there is nothing sensitive here\".",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if all {
				return encryptAll(args[0], auto, encodingFor(binary))
			}
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
			// Record where the file actually is, so it can be put back there on
			// another machine. Best effort: a path that cannot be resolved is
			// not a reason to refuse to encrypt.
			origin, err := filepath.Abs(src)
			if err != nil {
				origin = ""
			}

			id, err := s.PutWithOrigin(normalized, content,
				uint32(fi.Mode().Perm()), fi.ModTime().Unix(),
				mimeFor(src), origin, encodingFor(binary))
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
	cmd.Flags().BoolVar(&all, "all", false,
		"treat the argument as a directory to scan for credentials")
	cmd.Flags().BoolVar(&auto, "auto", false,
		"with --all, encrypt everything found without asking about each file")
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

// encryptAll scans a directory and encrypts what it finds.
func encryptAll(root string, auto bool, enc container.Encoding) error {
	found, err := scanForSecrets(root)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		fmt.Printf("Nothing that looks like a credential under %s.\n", root)
		fmt.Fprintln(os.Stderr, "That is not the same as there being nothing sensitive there: the scan only\n"+
			"knows the usual names and places.")
		return nil
	}

	// Without a terminal there is nobody to ask, and the default answer to
	// "encrypt this?" must not become yes by omission. A sweep of a home
	// directory into a store is not something to do because nobody objected.
	if !auto && !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("--all asks about each file, and there is no terminal to ask.\n"+
			"Found %d candidate(s) under %s. Re-run with --auto to take them all without "+
			"being asked, or run it where you can answer", len(found), root)
	}

	fmt.Fprintf(os.Stderr, "Found %d file(s) under %s that look like credentials.\n\n", len(found), root)

	s, err := openStore()
	if err != nil {
		return err
	}

	home, _ := os.UserHomeDir()
	stored, skipped := 0, 0
	for _, c := range found {
		logical, err := logicalPathFor(c.Path, home)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skipping %s: %v\n", c.Path, err)
			skipped++
			continue
		}
		if !auto && !confirm(fmt.Sprintf("  %s (%s, %s) -> %s. Encrypt?",
			c.Path, c.Reason, humanSize(c.Size), logical), true) {
			skipped++
			continue
		}

		content, err := os.ReadFile(c.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skipping %s: %v\n", c.Path, err)
			skipped++
			continue
		}
		fi, err := os.Stat(c.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skipping %s: %v\n", c.Path, err)
			skipped++
			continue
		}
		if _, err := s.PutWithOrigin(logical, content, uint32(fi.Mode().Perm()),
			fi.ModTime().Unix(), mimeFor(c.Path), c.Path, enc); err != nil {
			return fmt.Errorf("encrypt %s: %w", c.Path, err)
		}
		fmt.Printf("%s -> %s\n", c.Path, logical)
		stored++
	}

	fmt.Fprintf(os.Stderr, "\nEncrypted %d, skipped %d. The originals are untouched.\n", stored, skipped)
	return nil
}

// logicalPathFor derives the store name for a scanned file, the same way enc
// does for a single absolute path.
func logicalPathFor(path, home string) (string, error) {
	target, _ := defaultLogicalPath(path)
	normalized, err := store.NormalizePath(target)
	if err != nil {
		return "", err
	}
	_ = home
	return normalized, nil
}

// humanSize renders a byte count the way a listing would.
func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func mimeFor(name string) string {
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}
