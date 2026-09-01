package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newDecCmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "dec <path>",
		Short: "Decrypt a stored file to stdout",
		Long: "dec writes the plaintext of one stored file to stdout, or to --out.\n\n" +
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
			if out == "" || out == "-" {
				if _, err := os.Stdout.Write(env.Content); err != nil {
					return fmt.Errorf("write plaintext to stdout: %w", err)
				}
				return nil
			}
			if err := os.WriteFile(out, env.Content, os.FileMode(env.Mode).Perm()); err != nil {
				return fmt.Errorf("write %s: %w", out, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "write plaintext here instead of stdout")
	return cmd
}
