package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/buildinfo"
	"github.com/ushineko/angou/internal/keybundle"
	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/release"
	"github.com/ushineko/angou/internal/store"
)

func newDoctorCmd() *cobra.Command {
	var oldKey string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Report what this machine can and cannot do with the store",
		Long: "doctor inspects the store and this machine's local state and reports what it\n" +
			"finds. It changes nothing.\n\n" +
			"Run it when a command fails in a way you do not understand, or after moving a\n" +
			"store between machines. It is also what tells you whether this machine still\n" +
			"needs the recovery passphrase.\n\n" +
			"--old-key asserts that a named superseded key opens nothing in the store. Run it\n" +
			"after `angou rekey --identity`: without it you have no way to tell a complete\n" +
			"rotation from a partial one, and a partial one leaves secrets readable by the key\n" +
			"you were rotating away from.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			dir, err := storeDir()
			if err != nil {
				return err
			}
			if oldKey != "" {
				return assertOldKeyIsDead(dir, oldKey)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			defer func() { _ = w.Flush() }()

			report(w, "store directory", dir)
			reportStore(w, dir)
			reportKeyBundle(w, dir)
			if s, err := tryUnlockQuietly(); err == nil {
				reportBootstrapNamespace(w, dir, s)
			}
			reportLocal(w, dir)
			reportKeyring(w, dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&oldKey, "old-key", "",
		"assert that this superseded key fingerprint opens nothing in the store")
	return cmd
}

// tryUnlockQuietly opens the store by whichever route needs no interaction, so
// doctor can report store-level facts when it can and stay silent when it
// cannot. It never prompts: doctor is what a user runs when something is already
// confusing, and a diagnostic that stops to ask for a passphrase is a worse
// diagnostic.
func tryUnlockQuietly() (*store.Store, error) {
	dir, err := storeDir()
	if err != nil {
		return nil, err
	}
	if localkey.Exists(dir) {
		return unlockLocal(dir)
	}
	if global.passphraseFD >= 0 {
		secret, err := prompt.Passphrase(global.passphraseFD, "")
		if err != nil {
			return nil, err
		}
		defer prompt.Zero(secret)
		s, err := store.Open(dir, secret)
		if err != nil {
			return nil, err
		}
		return finishUnlockDiagnostic(s)
	}
	return nil, errors.New("no non-interactive route into the store")
}

// assertOldKeyIsDead is the verification step after an identity rotation
// (R6.4.1). It exits non-zero if the named key still opens anything.
func assertOldKeyIsDead(dir, fingerprint string) error {
	fingerprint = strings.ToUpper(strings.ReplaceAll(fingerprint, " ", ""))

	// The superseded identity is recovered from a retained bundle. If no bundle
	// carries it, the check cannot be performed and says so rather than
	// reporting a clean result it did not establish.
	secret, err := prompt.Passphrase(global.passphraseFD, "Recovery passphrase for the superseded key bundle: ")
	if err != nil {
		return err
	}
	defer prompt.Zero(secret)

	exported, err := store.ExportIdentityByFingerprint(dir, fingerprint, secret)
	if err != nil {
		return fmt.Errorf("%w\nWithout the superseded key this check cannot be performed, and a clean "+
			"result must not be assumed", err)
	}
	defer prompt.Zero(exported)

	opened, err := store.OldKeyOpensAnything(dir, exported)
	if err != nil {
		return err
	}
	if len(opened) > 0 {
		fmt.Fprintf(os.Stderr, "The superseded key %s still opens %d file(s) in this store:\n", fingerprint, len(opened))
		for _, name := range opened {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		return fmt.Errorf("the rotation is incomplete: %s still opens %d file(s)", fingerprint, len(opened))
	}
	fmt.Printf("The superseded key %s opens nothing in %s.\n", fingerprint, dir)
	return nil
}

func report(w *tabwriter.Writer, label, value string) {
	_, _ = fmt.Fprintf(w, "%s:\t%s\n", label, value)
}

func reportStore(w *tabwriter.Writer, dir string) {
	if _, err := os.Stat(filepath.Join(dir, store.MetaName)); err != nil {
		report(w, "store", "absent — run `angou init` to create one")
		return
	}
	report(w, "store", "present")
}

func reportKeyBundle(w *tabwriter.Writer, dir string) {
	raw, err := os.ReadFile(filepath.Join(dir, store.BootstrapDir, store.KeyBundleName))
	if err != nil {
		report(w, "key bundle", "absent — the store cannot be opened on a new machine")
		return
	}
	bundle, err := keybundle.Unmarshal(raw)
	if err != nil {
		report(w, "key bundle", "unreadable: "+err.Error())
		return
	}
	report(w, "key bundle", fmt.Sprintf("argon2id m=%d MiB t=%d p=%d",
		bundle.KDF.MemoryKiB/1024, bundle.KDF.Time, bundle.KDF.Parallelism))
	if err := bundle.KDF.Validate(); err != nil {
		report(w, "  parameters", "REFUSED — "+err.Error())
	} else {
		report(w, "  parameters", "meet the pinned floor")
	}
	if err := bundle.KDF.CheckMemory(); err != nil {
		report(w, "  memory", "INSUFFICIENT — "+err.Error())
	} else {
		report(w, "  memory", "sufficient on this machine")
	}
}

func reportBootstrapNamespace(w *tabwriter.Writer, dir string, s *store.Store) {
	if s == nil {
		return
	}
	if floor := s.Meta().VersionFloor; floor != "" {
		if err := checkVersionFloor(s, buildinfo.Version); err != nil {
			report(w, "version floor", floor+" — THIS BINARY IS OLDER AND WILL BE REFUSED")
			report(w, "  this binary", buildinfo.Version)
			report(w, "  to fix", "install the current release; a signed old release is still an old release")
		} else {
			report(w, "version floor", floor+" (older binaries are refused)")
		}
	} else {
		report(w, "version floor", "none recorded")
	}
	artifacts, err := release.List(filepath.Join(dir, store.BootstrapDir))
	if err != nil || len(artifacts) == 0 {
		report(w, "platform binaries", "none — this store cannot install angou on a machine that lacks it")
		report(w, "  to change that", "run `angou release` (optional; see the README)")
		return
	}
	report(w, "platform binaries", fmt.Sprintf("%d across %s", len(artifacts), strings.Join(release.Platforms(filepath.Join(dir, store.BootstrapDir)), ", ")))
}

func reportLocal(w *tabwriter.Writer, dir string) {
	if !localkey.Exists(dir) {
		report(w, "local key", "absent — this machine asks for the recovery passphrase")
		report(w, "  to change that", "run `angou bootstrap`")
		return
	}
	fingerprint, err := localkey.Fingerprint(dir)
	if err != nil {
		report(w, "local key", "unusable: "+err.Error())
		return
	}
	report(w, "local key", "present for "+fingerprint)
	localDir, err := localkey.Dir(dir)
	if err == nil {
		report(w, "  stored at", localDir)
	}
}

func reportKeyring(w *tabwriter.Writer, dir string) {
	ring, err := keyring.Open()
	if err != nil {
		if errors.Is(err, keyring.ErrUnavailable) {
			report(w, "keyring", "unavailable — "+trimCause(err))
			if localkey.Exists(dir) {
				report(w, "  consequence", "the local key cannot be unlocked; start the keyring or run `angou bootstrap --forget`")
			} else {
				report(w, "  consequence", "none; this machine uses the recovery passphrase anyway")
			}
			return
		}
		report(w, "keyring", "error: "+err.Error())
		return
	}
	defer func() { _ = ring.Close() }()
	report(w, "keyring", "reachable")

	if !localkey.Exists(dir) {
		report(w, "  entry", "not applicable until this machine is bootstrapped")
		return
	}
	fingerprint, err := localkey.Fingerprint(dir)
	if err != nil {
		return
	}
	secret, err := ring.Get(fingerprint)
	switch {
	case errors.Is(err, keyring.ErrNoEntry):
		// The state R2.4 exists to make legible.
		report(w, "  entry", "MISSING for "+fingerprint)
		report(w, "  consequence", "the local key is unopenable and nothing local can recover it; run `angou bootstrap --force`")
	case err != nil:
		report(w, "  entry", "error: "+err.Error())
	default:
		for i := range secret {
			secret[i] = 0
		}
		report(w, "  entry", "present for "+fingerprint)
		report(w, "  consequence", "this machine opens the store without the recovery passphrase")
	}
}

// trimCause shortens the wrapped D-Bus detail to the part a user can act on.
func trimCause(err error) string {
	msg := err.Error()
	if _, rest, ok := strings.Cut(msg, ": "); ok {
		return rest
	}
	return msg
}
