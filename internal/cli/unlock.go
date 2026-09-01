package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/ushineko/angou/internal/keyring"
	"github.com/ushineko/angou/internal/localkey"
	"github.com/ushineko/angou/internal/prompt"
	"github.com/ushineko/angou/internal/store"
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

	if localkey.Exists(dir) {
		s, err := unlockLocal(dir)
		if err != nil {
			return nil, err
		}
		return finishUnlock(s)
	}
	return openWithRecovery(dir)
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
	return finishUnlock(s)
}

func finishUnlock(s *store.Store) (*store.Store, error) {
	if !s.IndexTrusted {
		// R3.7: the index is a cache, never authoritative. Degrade browsing and
		// say so, rather than failing an operation that does not need it.
		fmt.Fprintln(os.Stderr, "angou: the index is missing or did not verify; run `angou reindex` to rebuild it.")
	}
	return s, nil
}
