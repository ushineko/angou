package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ushineko/angou/internal/agent"
	"github.com/ushineko/angou/internal/buildinfo"
	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/release"
	"github.com/ushineko/angou/internal/store"
)

// BootstrapScriptName is the plaintext entrypoint kept beside the store.
const BootstrapScriptName = "bootstrap.sh"

// Open unlocks the store by whichever route this machine supports.
//
// The fast route is the machine-local copy of the identity, unwrapped with the
// unlock passphrase held in the keyring. The slow route is the store's own key
// bundle under the recovery passphrase, which is what a machine uses before it
// has been bootstrapped and the only route where no keyring backend exists
// (spec 001 R2.5).
func Open(dir string, secrets Secrets, ev Events) (*Session, error) {
	s, usedRecovery, err := open(dir, secrets, ev)
	if err != nil {
		return nil, err
	}
	// The version floor is checked on every unlock, not only in bootstrap.
	// Checking it there alone would leave the rollback R5.4.2 exists to stop
	// perfectly usable once the older binary was installed: it could still read
	// and write every blob, which is the part that matters.
	if err := CheckVersionFloor(s.Meta().VersionFloor, s.Root(), buildinfo.Version); err != nil {
		return nil, err
	}
	finish(s, ev)
	if usedRecovery {
		// After finish, not before: the order these lines appear in is part of
		// the output the e2e suite and the user's eye both depend on.
		suggestBootstrap(dir, ev)
	}
	return &Session{st: s, ev: ev}, nil
}

// OpenDiagnostic does everything Open does except enforce the version floor.
//
// It exists for `doctor`, which is the command someone runs to find out why
// everything else is refusing. A diagnostic that refuses for the very reason
// being diagnosed tells the user nothing; doctor reports the floor instead.
func OpenDiagnostic(dir string, secrets Secrets, ev Events) (*Session, error) {
	s, usedRecovery, err := open(dir, secrets, ev)
	if err != nil {
		return nil, err
	}
	finish(s, ev)
	if usedRecovery {
		suggestBootstrap(dir, ev)
	}
	return &Session{st: s, ev: ev}, nil
}

// open takes the first route this machine supports. The second return reports
// whether the recovery passphrase was used, which decides whether the caller
// suggests bootstrapping afterwards.
func open(dir string, secrets Secrets, ev Events) (*store.Store, bool, error) {
	ev.logf("opening store %s", dir)

	// The agent first, when one is running: it is the only route that costs
	// neither a key derivation nor a keyring round trip.
	if s, err := openFromAgent(dir); err == nil {
		ev.logf("using the running agent")
		return s, false, nil
	} else if !errors.Is(err, agent.ErrNoAgent) && !errors.Is(err, agent.ErrExpired) {
		// A reachable agent that refused is worth reporting rather than
		// silently working around.
		ev.noticef("angou: the agent for this store did not serve the key (%v); falling back.", err)
	}

	if localkey.Exists(dir) {
		ev.logf("using the machine-local key and the keyring")
		s, err := OpenLocal(dir, ev)
		return s, false, err
	}

	ev.logf("no local key on this machine; using the recovery passphrase")
	s, err := openWithRecovery(dir, secrets, ev)
	if err != nil {
		return nil, false, err
	}
	return s, true, nil
}

// suggestBootstrap points out the faster route, but only where taking it would
// actually work.
//
// This machine is opening the store the slow way — a passphrase prompt and a key
// derivation on every command — and that is the fallback for machines with no
// keyring rather than the way the tool is meant to be used. Someone who has
// never been told about `bootstrap` has no reason to suspect it exists. The
// keyring is checked first so the suggestion is never made where it cannot be
// followed.
func suggestBootstrap(dir string, ev Events) {
	// Available, not Open. Opening a wallet can raise a dialog and wait for it,
	// and blocking a command in order to offer advice about it would be a worse
	// bug than the missing advice.
	if !keyring.Available() {
		return
	}
	ev.noticef("angou: this machine asks for the recovery passphrase every time. "+
		"To stop that:\n    angou bootstrap --store %s", dir)
}

// openFromAgent takes the cached route.
func openFromAgent(dir string) (*store.Store, error) {
	client, err := agent.Dial(dir)
	if err != nil {
		return nil, err
	}
	identity, err := client.Identity()
	if err != nil {
		return nil, err
	}
	defer prompt.Zero(identity)
	return store.OpenWithExportedIdentity(dir, identity)
}

// OpenLocal takes the keyring route. It does not silently fall back to the
// recovery passphrase on failure: a local key that will not open is a state the
// user has to know about, and R2.4 requires the tool to say so rather than issue
// a passphrase prompt the user cannot answer.
func OpenLocal(dir string, ev Events) (*store.Store, error) {
	fingerprint, err := localkey.Fingerprint(dir)
	if err != nil {
		return nil, err
	}

	ring, err := keyring.Open()
	if err != nil {
		if errors.Is(err, keyring.ErrUnavailable) {
			return nil, fmt.Errorf("this machine holds a local key for the store, but no keyring is "+
				"reachable to unlock it.\nStart the keyring, or remove the local key and use the "+
				"recovery passphrase:\n    angou bootstrap --forget\nUnderlying cause: %w", err)
		}
		return nil, err
	}
	defer func() { _ = ring.Close() }()

	unlockSecret, err := ring.Get(fingerprint)
	if err != nil {
		if errors.Is(err, keyring.ErrNoEntry) {
			// R2.4: the keyring entry is the unlock passphrase's only copy, so
			// this state is unrecoverable locally. Say that, rather than
			// prompting for something the user was never told.
			return nil, fmt.Errorf("the local key for this store is present but its keyring entry is " +
				"gone, and that entry was the only copy of the passphrase protecting it.\n" +
				"Nothing local can recover it. Re-run bootstrap against the store:\n" +
				"    angou bootstrap --force")
		}
		return nil, err
	}
	defer prompt.Zero(unlockSecret)

	exported, err := localkey.Read(dir, unlockSecret)
	if err != nil {
		return nil, err
	}
	defer prompt.Zero(exported)

	ev.logf("unwrapped the local key with the keyring entry")
	return store.OpenWithExportedIdentity(dir, exported)
}

// openWithRecovery takes the recovery-passphrase route.
func openWithRecovery(dir string, secrets Secrets, ev Events) (*store.Store, error) {
	secret, err := secrets.Recovery("Recovery passphrase: ")
	if err != nil {
		return nil, err
	}
	defer prompt.Zero(secret)

	s, err := store.Open(dir, secret)
	if err != nil {
		return nil, err
	}
	ev.logf("opened the key bundle with the recovery passphrase")
	return s, nil
}

// finish runs the checks every unlock performs once the store is open.
func finish(s *store.Store, ev Events) {
	// Opportunistic drift check on every unlock (R5.8.1). A warning, never a
	// failure: an altered installer does not make the store unreadable.
	warnIfBootstrapDrifted(s, ev)
	ev.logf("store identity %s", s.Fingerprint())
	ev.logf("index %s", map[bool]string{true: "loaded", false: "missing or unverified"}[s.IndexTrusted])

	if !s.IndexTrusted {
		// R3.7: the index is a cache, never authoritative. Degrade browsing and
		// say so, rather than failing an operation that does not need it.
		ev.notice("angou: the index is missing or did not verify; run `angou reindex` to rebuild it.")
	}
}

// OpenQuietly opens the store by whichever route needs no interaction, so a
// diagnostic can report store-level facts when it can and stay silent when it
// cannot. It never prompts: doctor is what a user runs when something is already
// confusing, and a diagnostic that stops to ask for a passphrase is a worse
// diagnostic.
func OpenQuietly(dir string, secrets Secrets, ev Events) (*store.Store, error) {
	if localkey.Exists(dir) {
		s, err := OpenLocal(dir, ev)
		if err != nil {
			return nil, err
		}
		finish(s, ev)
		return s, nil
	}
	secret, err := secrets.Recovery("")
	if err != nil {
		return nil, errors.New("no non-interactive route into the store")
	}
	defer prompt.Zero(secret)
	s, err := store.Open(dir, secret)
	if err != nil {
		return nil, err
	}
	finish(s, ev)
	return s, nil
}

// warnIfBootstrapDrifted compares the installer beside the store against the
// digest recorded inside it. This is drift detection after the fact, never a
// guarantee about the first run.
func warnIfBootstrapDrifted(s *store.Store, ev Events) {
	recorded := s.Meta().BootstrapSHA256
	if recorded == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(s.Root(), BootstrapScriptName))
	if err != nil {
		return
	}
	if digest(raw) != recorded {
		ev.noticef("angou: WARNING — %s does not match the digest recorded in this store.\n"+
			"angou: Read it before any machine runs it; see `angou verify-bootstrap`.", BootstrapScriptName)
	}
}

// CheckVersionFloor refuses a binary older than the floor the store records.
//
// A validly signed old release is still an old release, and replaying one is how
// write access to a store becomes execution (R5.4.2).
func CheckVersionFloor(floor, root, version string) error {
	if floor == "" {
		return nil
	}
	if release.CompareVersions(version, floor) >= 0 {
		return nil
	}
	return fmt.Errorf("this angou is version %s, but %s has had %s installed from it.\n"+
		"Refusing to bootstrap with an older binary: a validly signed old release is still\n"+
		"an old release, and replaying one is how write access to a store becomes execution.\n"+
		"Install the current version and try again",
		version, root, floor)
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
