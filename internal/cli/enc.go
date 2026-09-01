package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ushineko/angou/internal/container"
	"github.com/ushineko/angou/internal/core"
)

func newEncCmd() *cobra.Command {
	var (
		logicalPath string
		binary      bool
		all         bool
		auto        bool
		dryRun      bool
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
			"read an empty result as \"there is nothing sensitive here\".\n\n" +
			"--dry-run prints what the scan found and why it thinks so, and stores nothing.\n" +
			"Run that first: it is how you find out whether the guess is any good on your\n" +
			"machine before you act on it.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if all {
				return encryptAll(args[0], auto, dryRun, encodingFor(binary))
			}
			if dryRun {
				return fmt.Errorf("--dry-run only means something with --all")
			}
			src := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			res, err := s.EncryptFile(src, logicalPath, encodingFor(binary))
			if err != nil {
				return err
			}
			if res.Derived {
				// The name was worked out rather than given, so say what it is.
				// The store is addressed by these names and the user has to know
				// which one to ask for later.
				fmt.Fprintf(os.Stderr, "angou: storing %s as %q\n", src, res.LogicalPath)
			}
			fmt.Printf("%s -> %s\n", res.LogicalPath, res.BlobID)
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
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"with --all, print what the scan found and why, and encrypt nothing")
	return cmd
}

func encryptAll(root string, auto, dryRun bool, enc container.Encoding) error {
	found, err := core.Scan(root)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		fmt.Printf("Nothing that looks like a credential under %s.\n", root)
		fmt.Fprintln(os.Stderr, "That is not the same as there being nothing sensitive there: the scan only\n"+
			"knows the usual names and places.")
		return nil
	}

	if dryRun {
		return reportScan(root, found)
	}

	// Without a terminal there is nobody to ask, and the default answer to
	// "encrypt this?" must not become yes by omission. A sweep of a home
	// directory into a store is not something to do because nobody objected.
	//
	// This check stays in the front end rather than moving into core: "is there
	// a terminal" is a question only this front end can ask, and the GUI's
	// answer to the same concern is a checkbox list that is empty until the
	// user ticks something.
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

	// --auto is the decider that says yes to everything. The GUI's checkbox
	// list is the same operation with a different one behind it.
	decider := core.Decider(cliDecider{})
	if auto {
		decider = core.DeciderFunc(func(core.Decision) bool { return true })
	}

	r, err := s.EncryptCandidates(cmdContext(), found, enc, decider, core.EncryptProgress{
		Stored: func(src string, res core.EncryptResult) {
			fmt.Printf("%s -> %s\n", src, res.LogicalPath)
		},
		Skipped: func(src string, err error) {
			if err != nil {
				fmt.Fprintf(os.Stderr, "  skipping %s: %v\n", src, err)
			}
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nEncrypted %d, skipped %d. The originals are untouched.\n", r.Stored, r.Skipped)
	return nil
}

// reportScan prints what the scan found without touching the store.
//
// This is the command to run first. The scan is a guess, and the only way to
// find out whether it is a good one on a particular machine is to look at what
// it picked and why — a rule that is right about SSH keys can still be wrong
// about a directory full of session files whose names end in .key.
func reportScan(root string, found []core.Candidate) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() { _ = w.Flush() }()

	colour := useColour(false)
	_, _ = fmt.Fprintln(w, paint(colour, cDim, "SIZE\tFILE\tWHY"))

	for _, c := range found {
		if _, err := core.StoredAs(c.Path); err != nil {
			// A file the store cannot name is not a candidate; say so here
			// rather than failing later.
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n",
				paint(colour, cGreen, core.HumanSize(c.Size)),
				paint(colour, cDim, shortenHome(c.Path)),
				paint(colour, cRed, "cannot be stored: "+err.Error()))
			continue
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n",
			paint(colour, cGreen, core.HumanSize(c.Size)),
			paint(colour, colourFor(c.Path), shortenHome(c.Path)),
			paint(colour, cYell, c.Reason))
	}
	_ = w.Flush()

	fmt.Fprintf(os.Stderr, "\n%d file(s) under %s. Nothing was stored.\n", len(found), root)
	fmt.Fprintln(os.Stderr, "Run again with --all to be asked about each, or --all --auto to take them all.")
	fmt.Fprintln(os.Stderr, "\nAn empty or short list is not an assurance: the scan knows the usual names and\n"+
		"places, not every way a secret can be written down.")
	return nil
}
