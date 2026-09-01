package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ushineko/angou/internal/store"
	"github.com/ushineko/angou/lib/container"
)

func newLsCmd() *cobra.Command {
	var (
		long  bool
		raw   bool
		plain bool
	)

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List what the store holds",
		Long: "ls shows the logical paths in the store, with their size, permissions, and when\n" +
			"they were last changed, and where each one came from if that is recorded.\n\n" +
			"It reads the index, which is a rebuildable cache. If the index is missing or does\n" +
			"not verify, the listing is empty and `angou reindex` rebuilds it from the blobs\n" +
			"themselves. Retrieval by path never depends on the index.\n\n" +
			"--raw lists the files as they actually sit on disk: the keyed hashes that are the\n" +
			"blob names, plus the store's own files. That is what anyone holding your store\n" +
			"sees, and it is worth looking at once to understand what the naming does and does\n" +
			"not hide.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if raw {
				return listRaw()
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			entries := s.List()
			colour := useColour(plain)

			if long {
				return listNames(entries, colour)
			}
			return listDetailed(entries, colour)
		},
	}
	cmd.Flags().BoolVar(&long, "names", false, "print only the logical paths, one per line")
	cmd.Flags().BoolVar(&raw, "raw", false, "list the store as it sits on disk, not as you named it")
	cmd.Flags().BoolVar(&plain, "no-color", false, "never colourize, even on a terminal")
	// --long was the detailed listing before it became the default. Keep it
	// working rather than breaking anyone's habit or script.
	cmd.Flags().Bool("long", false, "deprecated: the detailed listing is now the default")
	_ = cmd.Flags().MarkHidden("long")
	return cmd
}

// ANSI attributes, used only when the output is a terminal that wants them.
const (
	cReset = "\033[0m"
	cDim   = "\033[2m"
	cBold  = "\033[1m"
	cBlue  = "\033[34m"
	cCyan  = "\033[36m"
	cGreen = "\033[32m"
	cRed   = "\033[31m"
	cYell  = "\033[33m"
)

// useColour decides whether to emit escapes.
//
// Piped output gets none, because a listing that is being read by another
// program should not have to be stripped first; NO_COLOR is honoured because it
// is the convention for exactly this.
func useColour(disabled bool) bool {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func paint(on bool, colour, text string) string {
	if !on {
		return text
	}
	return colour + text + cReset
}

// listNames prints just the paths, for scripts and for piping.
func listNames(entries []store.IndexEntry, colour bool) error {
	for _, e := range entries {
		fmt.Println(paint(colour, colourFor(e.Path), e.Path))
	}
	return nil
}

// listDetailed prints the listing a person reads.
func listDetailed(entries []store.IndexEntry, colour bool) error {
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "The store is empty, or the index needs rebuilding: try `angou reindex`.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() { _ = w.Flush() }()

	header := "MODE\tSIZE\tMODIFIED\tPATH\tORIGIN"
	if colour {
		header = cDim + strings.ReplaceAll(header, "\t", cReset+"\t"+cDim) + cReset
	}
	_, _ = fmt.Fprintln(w, header)

	var total int64
	for _, e := range entries {
		total += e.Size
		origin := e.Origin
		if origin == "" {
			origin = "—"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			paint(colour, modeColour(e.Mode), formatMode(e.Mode)),
			paint(colour, cGreen, humanSize(e.Size)),
			paint(colour, cDim, formatAge(e.MTime)),
			paint(colour, colourFor(e.Path), e.Path),
			paint(colour, cDim, shortenHome(origin)),
		)
	}
	_, _ = fmt.Fprintf(w, "\n%s\t%s\t\t\t\n",
		paint(colour, cBold, fmt.Sprintf("%d files", len(entries))),
		paint(colour, cBold, humanSize(total)))
	return nil
}

// listRaw shows the store as the filesystem holds it.
//
// It needs no key: these are the names anyone holding the store already sees.
// Showing them is the honest way to explain what the keyed naming hides — the
// count, the sizes, and the shape of the store are all visible here — and it is
// also what you look at when something is wrong with the store itself.
func listRaw() error {
	dir, err := storeDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	colour := useColour(false)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() { _ = w.Flush() }()
	_, _ = fmt.Fprintln(w, paint(colour, cDim, "SIZE\tMODIFIED\tNAME\tWHAT IT IS"))

	names := make([]os.DirEntry, 0, len(entries))
	names = append(names, entries...)
	sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })

	var blobs int
	for _, de := range names {
		info, err := de.Info()
		if err != nil {
			continue
		}
		kind, colourOf := describeRawEntry(de)
		if kind == "encrypted file" {
			blobs++
		}
		size := humanSize(info.Size())
		if de.IsDir() {
			size = "—"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			paint(colour, cGreen, size),
			paint(colour, cDim, formatAge(info.ModTime().Unix())),
			paint(colour, colourOf, de.Name()),
			paint(colour, cDim, kind))
	}
	_, _ = fmt.Fprintf(w, "\n%s\t\t\t\n",
		paint(colour, cBold, fmt.Sprintf("%d encrypted files", blobs)))
	fmt.Fprintln(os.Stderr, "\nThese names are keyed hashes of the paths you chose, so they give up no\n"+
		"filenames. The number of files and their sizes are visible to anyone holding\n"+
		"the store, and so is the fact that each one changed when it did.")
	return nil
}

func describeRawEntry(de os.DirEntry) (kind, colour string) {
	name := de.Name()
	switch {
	case de.IsDir() && name == store.BootstrapDir:
		return "key bundle and platform binaries", cBlue
	case de.IsDir():
		return "directory", cBlue
	case name == store.MetaName:
		return "store metadata, holds the naming key", cYell
	case name == store.IndexName:
		return "listing cache, rebuildable", cYell
	case name == BootstrapScriptName:
		return "plaintext installer", cRed
	case strings.HasSuffix(name, ".sig"):
		return "signature", cDim
	case store.LooksLikeBlobID(strings.TrimSuffix(name, container.Extension)):
		return "encrypted file", cCyan
	default:
		return "not an angou file", cDim
	}
}

// formatMode renders permissions the way ls does.
func formatMode(mode uint32) string {
	const rwx = "rwxrwxrwx"
	out := []byte("---------")
	for i := 0; i < 9; i++ {
		if mode&(1<<uint(8-i)) != 0 {
			out[i] = rwx[i]
		}
	}
	return string(out)
}

// modeColour flags a file that is readable by anyone but its owner, which for a
// stored credential is worth noticing on the way past.
func modeColour(mode uint32) string {
	if mode&0o077 != 0 {
		return cYell
	}
	return cDim
}

// colourFor tints a path by what it looks like, the way a file manager would.
func colourFor(path string) string {
	name := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasPrefix(name, "id_") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key"):
		return cRed
	case strings.Contains(name, "env") || strings.Contains(name, "secret") || strings.Contains(name, "credential"):
		return cYell
	default:
		return cCyan
	}
}

// formatAge renders a timestamp as a person reads it: recent things relatively,
// older things by date.
func formatAge(unix int64) string {
	if unix == 0 {
		return "—"
	}
	t := time.Unix(unix, 0)
	switch age := time.Since(t); {
	case age < time.Minute:
		return "just now"
	case age < time.Hour:
		return fmt.Sprintf("%dm ago", int(age.Minutes()))
	case age < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(age.Hours()))
	case age < 365*24*time.Hour:
		return t.Format("2 Jan 15:04")
	default:
		return t.Format("2 Jan 2006")
	}
}

// shortenHome renders a path under the home directory with a tilde.
func shortenHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !strings.HasPrefix(path, home) {
		return path
	}
	return "~" + strings.TrimPrefix(path, home)
}
