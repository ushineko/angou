package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ushineko/angou/internal/container"
	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/release"
	"github.com/ushineko/angou/internal/store"
)

// StoreExists reports whether a directory already holds a store. Checked before
// anything is asked: prompting for a "new recovery passphrase" and only then
// reporting that the store already exists reads as though the store is about to
// be replaced, which is alarming and wrong.
func StoreExists(dir string) bool { return store.Exists(ExpandPath(dir)) }

// Init creates a store and its identity keypair.
//
// The store is created before a generated passphrase is shown to the user.
// Printing it first would tell them to write down a phrase that opens nothing if
// this fails — and it does fail, on a full disk, an unwritable directory, or a
// machine without the memory for the derivation.
func Init(dir string, recovery []byte, ev Events) (*Session, error) {
	dir = ExpandPath(dir)
	s, err := store.Init(dir, recovery)
	if err != nil {
		return nil, err
	}
	ev.logf("initialized store %s", dir)
	// Init opened the store with the recovery passphrase it was just given.
	return &Session{st: s, ev: ev, route: RouteRecovery}, nil
}

// SetUpResult reports how far bootstrapping got.
//
// UsedKeyring false is a success, not a failure: a machine with no keyring keeps
// using the recovery passphrase, which is the documented fallback (spec 001
// R2.5) rather than a broken state. Cause says why.
type SetUpResult struct {
	UsedKeyring bool
	Cause       error
}

// SetUpMachine stores a machine-local copy of the identity, wrapped by a fresh
// unlock passphrase held in the keyring, so commands stop asking for the
// recovery passphrase here.
func (s *Session) SetUpMachine(exported []byte) (SetUpResult, error) {
	dir, fingerprint := s.st.Root(), s.st.Fingerprint()

	// Probe before opening. Opening a wallet can raise a dialog and wait for a
	// person to answer it, which is correct on a desktop and a hang anywhere
	// else; this check tells the two apart without prompting, so a machine with
	// no keyring skips the attempt entirely.
	if !keyring.Available() {
		return s.withoutKeyring(errors.New("no keyring service is running"))
	}
	ring, err := keyring.Open()
	if err != nil {
		// A misspelt backend is the user's mistake to see, not something to
		// absorb into the no-keyring path.
		if errors.Is(err, keyring.ErrUnavailable) && !errors.Is(err, keyring.ErrBadBackend) {
			return s.withoutKeyring(err)
		}
		return SetUpResult{}, err
	}
	defer func() { _ = ring.Close() }()

	unlockSecret, err := localkey.GenerateUnlockPassphrase()
	if err != nil {
		return SetUpResult{}, err
	}
	defer prompt.Zero(unlockSecret)

	// Keyring first: a local key whose passphrase never reached the keyring is
	// unopenable, whereas a keyring entry with no local key is merely unused and
	// is overwritten by the next bootstrap.
	if err := ring.Set(fingerprint, unlockSecret); err != nil {
		return SetUpResult{}, err
	}
	if err := localkey.Write(dir, fingerprint, exported, unlockSecret); err != nil {
		return SetUpResult{}, err
	}
	// Confirm the machine can now open the store by the keyring route, so a
	// broken bootstrap is reported by bootstrap rather than by the next command
	// the user runs (spec 001 R5.9).
	opened, err := OpenLocal(dir, s.ev)
	if err != nil {
		return SetUpResult{}, fmt.Errorf("local key written but its self-test failed: %w", err)
	}
	if err := roundTripSelfTest(opened); err != nil {
		return SetUpResult{}, fmt.Errorf("local key written but its self-test failed: %w", err)
	}
	return SetUpResult{UsedKeyring: true}, nil
}

// withoutKeyring confirms the store is usable by the recovery passphrase before
// reporting that this machine will keep using it (spec 001 R2.5).
func (s *Session) withoutKeyring(cause error) (SetUpResult, error) {
	if err := roundTripSelfTest(s.st); err != nil {
		return SetUpResult{}, fmt.Errorf("the store did not pass its round-trip self-test: %w", err)
	}
	return SetUpResult{UsedKeyring: false, Cause: cause}, nil
}

// roundTripSelfTest writes a temporary blob, reads it back, and removes it,
// confirming the store is actually usable rather than merely openable
// (spec 001 R5.9).
func roundTripSelfTest(s *store.Store) error {
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return fmt.Errorf("generate self-test payload: %w", err)
	}
	const path = ".angou-selftest"
	if _, err := s.Put(path, probe, 0o600, 0, "application/octet-stream", container.EncodingArmor); err != nil {
		return err
	}
	env, err := s.Get(path)
	if err != nil {
		_ = s.Remove(path)
		return err
	}
	if !bytes.Equal(env.Content, probe) {
		_ = s.Remove(path)
		return errors.New("the self-test payload did not round-trip")
	}
	return s.Remove(path)
}

// SelfTest confirms this machine can open the store by the keyring route and
// actually use it, so a broken bootstrap or local rekey is reported by the
// command that caused it rather than by the next command the user runs
// (spec 001 R5.9).
func SelfTest(dir string, ev Events) error {
	s, err := OpenLocal(dir, ev)
	if err != nil {
		return err
	}
	return roundTripSelfTest(s)
}

// ForgetResult reports what forgetting removed.
type ForgetResult struct {
	// HadKey is false when this machine held no local key to begin with.
	HadKey bool
}

// ForgetMachine removes this machine's local key and its keyring entry,
// returning the machine to the recovery passphrase.
func ForgetMachine(dir string) (ForgetResult, error) {
	dir = ExpandPath(dir)
	if !localkey.Exists(dir) {
		return ForgetResult{HadKey: false}, nil
	}
	fingerprint, err := localkey.Fingerprint(dir)
	if err != nil {
		return ForgetResult{}, err
	}
	if ring, err := keyring.Open(); err == nil {
		defer func() { _ = ring.Close() }()
		if err := ring.Remove(fingerprint); err != nil {
			return ForgetResult{}, err
		}
	} else if !errors.Is(err, keyring.ErrUnavailable) {
		return ForgetResult{}, err
	}
	if err := localkey.Remove(dir); err != nil {
		return ForgetResult{}, err
	}
	return ForgetResult{HadKey: true}, nil
}

// ExportIdentity recovers the store identity with the recovery passphrase,
// which is how a machine that has never been set up reaches it.
func ExportIdentity(dir string, recovery []byte) ([]byte, error) {
	return store.ExportIdentity(dir, recovery)
}

// OpenWithExportedIdentity opens a store with an already-recovered identity.
func OpenWithExportedIdentity(dir string, exported []byte, ev Events) (*Session, error) {
	s, err := store.OpenWithExportedIdentity(dir, exported)
	if err != nil {
		return nil, err
	}
	return &Session{st: s, ev: ev, route: RouteRecovery}, nil
}

// HasLocalKey reports whether this machine holds a local key for the store.
func HasLocalKey(dir string) bool { return localkey.Exists(ExpandPath(dir)) }

// RotateLocalPassword replaces this machine's unlock passphrase and the local
// key it protects. The store is untouched and no other machine is affected.
//
// The replacement is written to a staging path first, so the wallet entry — the
// only copy of the passphrase for the key already in place — is not overwritten
// until its replacement is durable on disk. The remaining window is a single
// rename; if the process dies inside it, the machine needs
// `angou bootstrap --force`, which is recoverable with the recovery passphrase.
func (s *Session) RotateLocalPassword() error {
	dir := s.st.Root()

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

	fingerprint := s.st.Fingerprint()
	staged, err := localkey.WriteStaged(dir, fingerprint, exported, fresh)
	if err != nil {
		return err
	}
	if err := ring.Set(fingerprint, fresh); err != nil {
		_ = localkey.DiscardStaged(staged)
		return err
	}
	if err := localkey.CommitStaged(staged); err != nil {
		return err
	}
	if err := SelfTest(dir, s.ev); err != nil {
		return fmt.Errorf("rekey --local wrote local state but its self-test failed: %w", err)
	}
	return nil
}

// PruneBinaries removes superseded platform binaries from the bootstrap
// namespace, keeping the newest few per platform.
func (s *Session) PruneBinaries(keep int) ([]string, error) {
	return release.Prune(filepath.Join(s.st.Root(), store.BootstrapDir), keep)
}
