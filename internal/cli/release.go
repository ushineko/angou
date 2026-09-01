package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/core"
	"github.com/ushineko/angou/internal/release"
)

func newReleaseCmd() *cobra.Command {
	var (
		dist       string
		signingKey string
		newKey     string
		keep       int
	)

	cmd := &cobra.Command{
		Use:   "release",
		Short: "Stash built binaries into the store so a bare machine can install one",
		Long: "release copies the binaries you have built into the store's bootstrap namespace,\n" +
			"signs each one with the offline release-signing key, and records what it was\n" +
			"built from.\n\n" +
			"The binaries are stored in the clear. They are public software and encrypting\n" +
			"them would protect nothing; what protects them is the signature and the version\n" +
			"floor. Anyone who can read your store learns which platforms you use and which\n" +
			"versions you have run, and that is accepted deliberately in exchange for the\n" +
			"bootstrap working with nothing but stock gpg.\n\n" +
			"The signing key is not the store's key and must not be. Keep it offline; it is\n" +
			"needed only here. If it were reachable from the store, anyone who obtained the\n" +
			"recovery passphrase could sign a binary that every future bootstrap would trust.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if newKey != "" {
				return core.GenerateSigningKey(newKey)
			}
			if dist == "" || signingKey == "" {
				return fmt.Errorf("release needs --dist and --signing-key\n" +
					"To create a signing key first: angou release --new-signing-key <path>")
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			return core.StashRelease(s, dist, signingKey, keep, cliSecrets{})
		},
	}
	cmd.Flags().StringVar(&dist, "dist", "", "directory holding the built binaries")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "armored private release-signing key")
	cmd.Flags().StringVar(&newKey, "new-signing-key", "", "generate a release-signing key at this path and exit")
	cmd.Flags().IntVar(&keep, "keep", release.DefaultKeep, "versions to retain per platform")
	return cmd
}

// generateSigningKey creates a release-signing key. It is written unencrypted
// because it is meant to leave this machine immediately; the instruction to move
// it offline is the control, and pretending a passphrase substitutes for that
// would be worse than saying so.
