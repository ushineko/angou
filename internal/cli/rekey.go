package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
	"github.com/ushineko/angou/internal/passphrase"
	"github.com/ushineko/angou/internal/prompt"
)

func newRekeyCmd() *cobra.Command {
	var (
		local    bool
		identity bool
	)

	cmd := &cobra.Command{
		Use:   "rekey",
		Short: "Rotate the machine password, or the store's identity keypair",
		Long: "rekey does one of two very different things, and you have to say which.\n\n" +
			"--local generates a new machine password and re-wraps this machine's copy of the\n" +
			"key under it. Nothing in the store changes and no other machine is affected. Use\n" +
			"it when you want to invalidate a machine password without disturbing anything\n" +
			"else.\n\n" +
			"--identity generates a new keypair and a new naming key, then re-encrypts every\n" +
			"blob to the new key under a new name. This is the response to a machine you\n" +
			"believe is compromised, where the attacker holds the old keypair and --local\n" +
			"protects nothing. Every machine that used this store must be bootstrapped again\n" +
			"afterwards, and every secret the store held should be treated as known to the\n" +
			"attacker and rotated at its source. Rotating the store does not un-leak them.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			switch {
			case local == identity:
				return errors.New("say which rotation you mean: --local or --identity")
			case local:
				return rekeyLocal()
			default:
				return rekeyIdentity()
			}
		},
	}
	cmd.Flags().BoolVar(&local, "local", false, "rotate this machine's password only; the store is untouched")
	cmd.Flags().BoolVar(&identity, "identity", false, "rotate the store's keypair and naming key, re-encrypting every blob")
	return cmd
}

// rekeyLocal implements R4.1: a fresh unlock passphrase, a re-wrapped local key,
// and an overwritten keyring entry. No blob and no remote state changes.
func rekeyLocal() error {
	dir, err := storeDir()
	if err != nil {
		return err
	}
	if !localkey.Exists(dir) {
		return fmt.Errorf("this machine holds no local key for %s, so there is no machine "+
			"password to rotate.\nRun `angou bootstrap` first", dir)
	}

	s, err := unlock()
	if err != nil {
		return err
	}
	exported, err := s.ExportLocalIdentity()
	if err != nil {
		return err
	}
	defer prompt.Zero(exported)

	ring, err := keyring.Open()
	if err != nil {
		return err
	}
	defer func() { _ = ring.Close() }()

	fresh, err := localkey.GenerateUnlockPassphrase()
	if err != nil {
		return err
	}
	defer prompt.Zero(fresh)

	fingerprint := s.Fingerprint()
	if err := ring.Set(fingerprint, fresh); err != nil {
		return err
	}
	if err := localkey.Write(dir, fingerprint, exported, fresh); err != nil {
		return err
	}
	if err := selfTest(dir); err != nil {
		return fmt.Errorf("rekey --local wrote local state but its self-test failed: %w", err)
	}
	fmt.Printf("Rotated the machine password for %s.\n", dir)
	fmt.Fprintln(os.Stderr, "No blob changed and no other machine is affected.")
	return nil
}

// rekeyIdentity implements R4.2 and R4.2.1.
func rekeyIdentity() error {
	dir, err := storeDir()
	if err != nil {
		return err
	}
	s, err := unlock()
	if err != nil {
		return err
	}

	// The new key bundle has to be sealed under a recovery passphrase, and the
	// keyring route never learns it, so ask regardless of how the store opened.
	fmt.Fprintln(os.Stderr, "The new key bundle needs a recovery passphrase. This may be the one you already\n"+
		"use; pass it again to keep it, or use `angou passwd` afterwards to change it.")
	recovery, err := prompt.Passphrase(global.passphraseFD, "Recovery passphrase for the new key bundle: ")
	if err != nil {
		return err
	}
	defer prompt.Zero(recovery)
	if _, err := passphrase.Check(string(recovery)); err != nil {
		return err
	}

	result, err := s.RekeyIdentity(recovery)
	if err != nil {
		return err
	}

	fmt.Printf("Rotated the store identity for %s.\n", dir)
	fmt.Printf("  old fingerprint: %s\n", result.OldFingerprint)
	fmt.Printf("  new fingerprint: %s\n", result.NewFingerprint)
	fmt.Printf("  blobs re-encrypted and renamed: %d\n", result.Blobs)

	// The local key still wraps the old identity, so this machine must be
	// bootstrapped again before it can open the rotated store.
	if localkey.Exists(dir) {
		if err := forgetLocal(dir); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "\nEvery machine that used this store must run `angou bootstrap` again.\n"+
		"Verify the rotation was complete with `angou doctor --old-key "+result.OldFingerprint+"`.\n"+
		"Rotating the store does not un-leak the secrets it held: change them at their source.")
	return nil
}

func newPasswdCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "passwd",
		Short: "Change the recovery passphrase",
		Long: "passwd rewrites the key bundle under a new recovery passphrase and removes the\n" +
			"bundles the old one opened. It changes what guards the key, not the key itself,\n" +
			"so no blob changes and no other machine needs anything done to it.\n\n" +
			"Use this when the recovery passphrase may have been observed. If the key itself\n" +
			"may be compromised, this is not enough — use `angou rekey --identity`.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := unlock()
			if err != nil {
				return err
			}
			fresh, err := prompt.Confirm(global.passphraseFD,
				"New recovery passphrase: ", "Repeat new recovery passphrase: ")
			if err != nil {
				return err
			}
			defer prompt.Zero(fresh)
			bits, err := passphrase.Check(string(fresh))
			if err != nil {
				return err
			}
			if err := s.RewrapRecovery(fresh); err != nil {
				return err
			}
			fmt.Printf("Recovery passphrase changed (about %.0f bits).\n", bits)
			fmt.Fprintln(os.Stderr, "The previous passphrase no longer opens this store. No blob changed.")
			return nil
		},
	}
	return cmd
}

func newPruneCmd() *cobra.Command {
	var (
		bundles bool
		orphans bool
	)
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Remove superseded key bundles and unreadable leftovers from the store",
		Long: "prune removes things a rotation leaves behind.\n\n" +
			"--bundles removes retained key bundles, leaving only the current one. Each\n" +
			"retained bundle is an independent offline target for whichever recovery\n" +
			"passphrase guarded it, so a passphrase you rotated away is not really gone until\n" +
			"its bundle is.\n\n" +
			"--orphans removes blob-shaped files this store's key cannot read, which is what\n" +
			"an interrupted identity rekey leaves. They are unreadable, not recoverable: if\n" +
			"you are not certain the rekey finished, run `angou reindex` first and read what\n" +
			"it reports.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !bundles && !orphans {
				return errors.New("say what to prune: --bundles, --orphans, or both")
			}
			s, err := unlock()
			if err != nil {
				return err
			}
			if bundles {
				if err := s.PruneSupersededBundles(); err != nil {
					return err
				}
				fmt.Println("Removed superseded key bundles.")
			}
			if orphans {
				removed, err := s.PruneOrphans()
				if err != nil {
					return err
				}
				fmt.Printf("Removed %d unreadable file(s).\n", len(removed))
				for _, name := range removed {
					fmt.Printf("  %s\n", name)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&bundles, "bundles", false, "remove retained key bundles, leaving only the current one")
	cmd.Flags().BoolVar(&orphans, "orphans", false, "remove blob-shaped files this store's key cannot read")
	return cmd
}
