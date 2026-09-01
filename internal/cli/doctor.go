package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/keybundle"
	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
	"github.com/ushineko/angou/internal/store"
)

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Report what this machine can and cannot do with the store",
		Long: "doctor inspects the store and this machine's local state and reports what it\n" +
			"finds. It changes nothing.\n\n" +
			"Run it when a command fails in a way you do not understand, or after moving a\n" +
			"store between machines. It is also what tells you whether this machine still\n" +
			"needs the recovery passphrase.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			dir, err := storeDir()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			defer func() { _ = w.Flush() }()

			report(w, "store directory", dir)
			reportStore(w, dir)
			reportKeyBundle(w, dir)
			reportLocal(w, dir)
			reportKeyring(w, dir)
			return nil
		},
	}
	return cmd
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
