package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ushineko/angou/internal/buildinfo"
	"github.com/ushineko/angou/internal/keybundle"
	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
	"github.com/ushineko/angou/internal/release"
	"github.com/ushineko/angou/internal/store"
)

// Doctor inspects the store and this machine's local state and reports what it
// finds. It changes nothing.
//
// The findings are returned in the order the CLI has always printed them, so
// rendering the flattened list reproduces the previous output exactly. The
// section titles and severities are additional structure the GUI uses; the CLI
// ignores both.
//
// secrets is consulted only for the quiet unlock, and only to learn store-level
// facts. Passing NoSecrets is correct and normal: the report is smaller, not
// wrong.
func Doctor(dir string, secrets Secrets, ev Events) Report {
	var r Report

	r.add("Store", Finding{Label: "store directory", Value: dir})
	doctorStore(&r, dir)
	doctorKeyBundle(&r, dir)
	if s, err := OpenQuietly(dir, secrets, ev); err == nil {
		doctorBootstrapNamespace(&r, dir, s)
	}
	doctorLocal(&r, dir)
	doctorKeyring(&r, dir)
	return r
}

func doctorStore(r *Report, dir string) {
	if _, err := os.Stat(filepath.Join(dir, store.MetaName)); err != nil {
		r.add("Store", Finding{Label: "store", Value: "absent — run `angou init` to create one", Severity: SeverityBad})
		return
	}
	r.add("Store", Finding{Label: "store", Value: "present", Severity: SeverityGood})
}

func doctorKeyBundle(r *Report, dir string) {
	const title = "Key bundle"

	raw, err := os.ReadFile(filepath.Join(dir, store.BootstrapDir, store.KeyBundleName))
	if err != nil {
		r.add(title, Finding{Label: "key bundle",
			Value: "absent — the store cannot be opened on a new machine", Severity: SeverityBad})
		return
	}
	bundle, err := keybundle.Unmarshal(raw)
	if err != nil {
		r.add(title, Finding{Label: "key bundle", Value: "unreadable: " + err.Error(), Severity: SeverityBad})
		return
	}
	r.add(title, Finding{Label: "key bundle", Value: fmt.Sprintf("argon2id m=%d MiB t=%d p=%d",
		bundle.KDF.MemoryKiB/1024, bundle.KDF.Time, bundle.KDF.Parallelism)})

	if err := bundle.KDF.Validate(); err != nil {
		r.add(title, Finding{Label: "parameters", Indent: 1,
			Value: "REFUSED — " + err.Error(), Severity: SeverityBad})
	} else {
		r.add(title, Finding{Label: "parameters", Indent: 1,
			Value: "meet the pinned floor", Severity: SeverityGood})
	}
	if err := bundle.KDF.CheckMemory(); err != nil {
		r.add(title, Finding{Label: "memory", Indent: 1,
			Value: "INSUFFICIENT — " + err.Error(), Severity: SeverityBad})
	} else {
		r.add(title, Finding{Label: "memory", Indent: 1,
			Value: "sufficient on this machine", Severity: SeverityGood})
	}
}

func doctorBootstrapNamespace(r *Report, dir string, s *store.Store) {
	const title = "Bootstrap namespace"

	if s == nil {
		return
	}
	if floor := s.Meta().VersionFloor; floor != "" {
		if err := CheckVersionFloor(s, buildinfo.Version); err != nil {
			r.add(title, Finding{Label: "version floor",
				Value: floor + " — THIS BINARY IS OLDER AND WILL BE REFUSED", Severity: SeverityBad})
			r.add(title, Finding{Label: "this binary", Indent: 1, Value: buildinfo.Version})
			r.add(title, Finding{Label: "to fix", Indent: 1,
				Value: "install the current release; a signed old release is still an old release"})
		} else {
			r.add(title, Finding{Label: "version floor",
				Value: floor + " (older binaries are refused)", Severity: SeverityGood})
		}
	} else {
		r.add(title, Finding{Label: "version floor", Value: "none recorded"})
	}

	bootstrapDir := filepath.Join(dir, store.BootstrapDir)
	artifacts, err := release.List(bootstrapDir)
	if err != nil || len(artifacts) == 0 {
		r.add(title, Finding{Label: "platform binaries",
			Value: "none — this store cannot install angou on a machine that lacks it", Severity: SeverityWarn})
		r.add(title, Finding{Label: "to change that", Indent: 1,
			Value: "run `angou release` (optional; see the README)"})
		return
	}
	r.add(title, Finding{Label: "platform binaries",
		Value:    fmt.Sprintf("%d across %s", len(artifacts), strings.Join(release.Platforms(bootstrapDir), ", ")),
		Severity: SeverityGood})
}

func doctorLocal(r *Report, dir string) {
	const title = "This machine"

	if !localkey.Exists(dir) {
		r.add(title, Finding{Label: "local key",
			Value: "absent — this machine asks for the recovery passphrase", Severity: SeverityWarn})
		r.add(title, Finding{Label: "to change that", Indent: 1, Value: "run `angou bootstrap`"})
		return
	}
	fingerprint, err := localkey.Fingerprint(dir)
	if err != nil {
		r.add(title, Finding{Label: "local key", Value: "unusable: " + err.Error(), Severity: SeverityBad})
		return
	}
	r.add(title, Finding{Label: "local key", Value: "present for " + fingerprint, Severity: SeverityGood})
	if localDir, err := localkey.Dir(dir); err == nil {
		r.add(title, Finding{Label: "stored at", Indent: 1, Value: localDir})
	}
}

func doctorKeyring(r *Report, dir string) {
	const title = "Keyring"

	ring, err := keyring.Open()
	if err != nil {
		if errors.Is(err, keyring.ErrUnavailable) {
			r.add(title, Finding{Label: "keyring",
				Value: "unavailable — " + trimCause(err), Severity: SeverityWarn})
			if localkey.Exists(dir) {
				r.add(title, Finding{Label: "consequence", Indent: 1, Severity: SeverityBad,
					Value: "the local key cannot be unlocked; start the keyring or run `angou bootstrap --forget`"})
			} else {
				r.add(title, Finding{Label: "consequence", Indent: 1,
					Value: "none; this machine uses the recovery passphrase anyway"})
			}
			return
		}
		r.add(title, Finding{Label: "keyring", Value: "error: " + err.Error(), Severity: SeverityBad})
		return
	}
	defer func() { _ = ring.Close() }()
	r.add(title, Finding{Label: "keyring", Value: "reachable", Severity: SeverityGood})

	if !localkey.Exists(dir) {
		r.add(title, Finding{Label: "entry", Indent: 1,
			Value: "not applicable until this machine is bootstrapped"})
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
		r.add(title, Finding{Label: "entry", Indent: 1,
			Value: "MISSING for " + fingerprint, Severity: SeverityBad})
		r.add(title, Finding{Label: "consequence", Indent: 1, Severity: SeverityBad,
			Value: "the local key is unopenable and nothing local can recover it; run `angou bootstrap --force`"})
	case err != nil:
		r.add(title, Finding{Label: "entry", Indent: 1, Value: "error: " + err.Error(), Severity: SeverityBad})
	default:
		for i := range secret {
			secret[i] = 0
		}
		r.add(title, Finding{Label: "entry", Indent: 1,
			Value: "present for " + fingerprint, Severity: SeverityGood})
		r.add(title, Finding{Label: "consequence", Indent: 1, Severity: SeverityGood,
			Value: "this machine opens the store without the recovery passphrase"})
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
