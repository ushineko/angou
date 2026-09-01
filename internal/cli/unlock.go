package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/ushineko/angou/internal/agent"
	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/store"
	"github.com/ushineko/angou/lib/container"
)

// unlock opens the store by whichever route this machine supports.
//
// The fast route is the machine-local copy of the identity, unwrapped with the
// unlock passphrase held in the keyring. The slow route is the store's own key
// bundle under the recovery passphrase, which is what a machine uses before it
// has been bootstrapped and the only route where no keyring backend exists
// (spec 001 R2.5).
func unlock() (*store.Store, error) {
	dir, err := storeDir()
	if err != nil {
		return nil, err
	}

	logf("opening store %s", dir)

	// The agent first, when one is running: it is the only route that costs
	// neither a key derivation nor a keyring round trip.
	if s, err := unlockFromAgent(dir); err == nil {
		logf("using the running agent")
		return finishUnlock(s)
	} else if !errors.Is(err, agent.ErrNoAgent) && !errors.Is(err, agent.ErrExpired) {
		// A reachable agent that refused is worth reporting rather than
		// silently working around.
		fmt.Fprintf(os.Stderr, "angou: the agent for this store did not serve the key (%v); falling back.\n", err)
	}

	if localkey.Exists(dir) {
		logf("using the machine-local key and the keyring")
		s, err := unlockLocal(dir)
		if err != nil {
			return nil, err
		}
		return finishUnlock(s)
	}
	logf("no local key on this machine; using the recovery passphrase")
	s, err := openWithRecovery(dir)
	if err != nil {
		return nil, err
	}
	suggestBootstrap(dir)
	return s, nil
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
func suggestBootstrap(dir string) {
	// Available, not Open. Opening a wallet can raise a dialog and wait for it,
	// and blocking a command in order to offer advice about it would be a worse
	// bug than the missing advice.
	if !keyring.Available() {
		return
	}
	fmt.Fprintf(os.Stderr, "angou: this machine asks for the recovery passphrase every time. "+
		"To stop that:\n    angou bootstrap --store %s\n", dir)
}

// unlockFromAgent takes the cached route.
func unlockFromAgent(dir string) (*store.Store, error) {
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

// unlockLocal takes the keyring route. It does not silently fall back to the
// recovery passphrase on failure: a local key that will not open is a state the
// user has to know about, and R2.4 requires the tool to say so rather than issue
// a passphrase prompt the user cannot answer.
func unlockLocal(dir string) (*store.Store, error) {
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

	logf("unwrapped the local key with the keyring entry")
	return store.OpenWithExportedIdentity(dir, exported)
}

// openWithRecovery takes the recovery-passphrase route.
func openWithRecovery(dir string) (*store.Store, error) {
	secret, err := prompt.Passphrase(global.passphraseFD, "Recovery passphrase: ")
	if err != nil {
		return nil, err
	}
	defer prompt.Zero(secret)

	s, err := store.Open(dir, secret)
	if err != nil {
		return nil, err
	}
	logf("opened the key bundle with the recovery passphrase")
	return finishUnlock(s)
}

func finishUnlock(s *store.Store) (*store.Store, error) {
	// The version floor is checked on every unlock, not only in bootstrap.
	// Checking it there alone would leave the rollback R5.4.2 exists to stop
	// perfectly usable once the older binary was installed: it could still read
	// and write every blob, which is the part that matters.
	if err := checkVersionFloor(s, container.Version); err != nil {
		return nil, err
	}
	return finishUnlockDiagnostic(s)
}

// finishUnlockDiagnostic does everything finishUnlock does except enforce the
// version floor.
//
// It exists for `doctor`, which is the command someone runs to find out why
// everything else is refusing. A diagnostic that refuses for the very reason
// being diagnosed tells the user nothing; doctor reports the floor instead.
func finishUnlockDiagnostic(s *store.Store) (*store.Store, error) {

	// Opportunistic drift check on every unlock (R5.8.1). A warning, never a
	// failure: an altered installer does not make the store unreadable.
	warnIfBootstrapDrifted(s)
	logf("store identity %s", s.Fingerprint())
	logf("index %s", map[bool]string{true: "loaded", false: "missing or unverified"}[s.IndexTrusted])

	if !s.IndexTrusted {
		// R3.7: the index is a cache, never authoritative. Degrade browsing and
		// say so, rather than failing an operation that does not need it.
		fmt.Fprintln(os.Stderr, "angou: the index is missing or did not verify; run `angou reindex` to rebuild it.")
	}
	return s, nil
}
