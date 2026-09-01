package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ushineko/angou/internal/core"
	"github.com/ushineko/angou/internal/envelope"
)

func newDecCmd() *cobra.Command {
	var (
		out       string
		overwrite bool
		stdout    bool
		restore   bool
	)

	cmd := &cobra.Command{
		Use:   "dec <path>",
		Short: "Decrypt a stored file, back to where it came from by default",
		Long: "dec decrypts one stored file.\n\n" +
			"If angou knows where the file came from — it records that when you encrypt —\n" +
			"it offers to put it back there, which is usually what you want on a second\n" +
			"machine: an SSH key belongs in ~/.ssh, not in whatever directory you happen to\n" +
			"be standing in. You are shown the destination and asked before anything is\n" +
			"written, and asked again before an existing file is replaced.\n\n" +
			"--overwrite skips the second question, not the first. -o writes somewhere you\n" +
			"choose instead, and --stdout writes the plaintext to stdout. When stdout is not\n" +
			"a terminal — piped or redirected — the plaintext goes there and nothing is\n" +
			"written to disk, so `angou dec x > file` keeps working. --restore asks for the\n" +
			"file to be put back regardless, which is what a script wants; with nothing to\n" +
			"answer a question, it will restore but will not replace an existing file unless\n" +
			"you also pass --overwrite.\n\n" +
			"The blob's signature is verified before anything is written. A blob that\n" +
			"decrypts but does not verify produces no output at all.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			env, err := s.Get(args[0])
			if err != nil {
				return err
			}

			switch {
			case out != "" && out != "-":
				return core.WriteTo(out, env)
			case stdout || out == "-":
				return writeStdout(env)
			case restore:
				return restoreToOrigin(env, overwrite)
			case env.Origin == "" || !term.IsTerminal(int(os.Stdout.Fd())):
				// No recorded origin, or nobody to ask: stdout is the only
				// answer that cannot surprise anyone.
				return writeStdout(env)
			default:
				return restoreToOrigin(env, overwrite)
			}
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "write the plaintext to this path instead")
	cmd.Flags().BoolVar(&stdout, "stdout", false, "write the plaintext to stdout, even if an origin is recorded")
	cmd.Flags().BoolVar(&restore, "restore", false,
		"put the file back at its recorded location, even when the output is piped")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false,
		"replace an existing file at the recorded location without asking")
	return cmd
}

// restoreToOrigin puts the file back and reports where, or reports that the
// user declined. The decision points and the write live in internal/core; what
// stays here is asking on a terminal and printing the outcome.
func restoreToOrigin(env envelope.Envelope, overwrite bool) error {
	target, err := core.RestoreToOrigin(env, overwrite, cliDecider{})
	if errors.Is(err, core.ErrDeclined) {
		fmt.Fprintln(os.Stderr, "Nothing written.")
		return errors.New("declined")
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s -> %s\n", env.Path, target)
	return nil
}

func writeStdout(env envelope.Envelope) error {
	if _, err := os.Stdout.Write(env.Content); err != nil {
		return fmt.Errorf("write plaintext to stdout: %w", err)
	}
	return nil
}

// confirm asks a yes/no question on the terminal.
//
// With no terminal to ask, it takes the default rather than reading from a
// stdin that may be a file, a pipe, or nothing. That keeps the safe answer safe:
// the questions whose default is "no" are the destructive ones, so a
// non-interactive run declines them unless a flag said otherwise.
func confirm(question string, defaultYes bool) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return defaultYes
	}

	suffix := " [y/N] "
	if defaultYes {
		suffix = " [Y/n] "
	}
	fmt.Fprint(os.Stderr, question+suffix)

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "":
		return defaultYes
	default:
		return false
	}
}
