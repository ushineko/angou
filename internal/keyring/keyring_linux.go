//go:build linux

package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

// ErrUnavailable is reserved for a backend that cannot be reached at all.
// A failure of an individual operation against a reachable backend is a plain
// error: treating it as unavailability would let a write that failed for some
// other reason be mistaken for "this machine has no keyring", and fall through
// to a path that silently changes nothing.
//
// KWallet talks to org.kde.kwalletd6 over the session bus. There is no
// kwallet-query subprocess and no CGO, so the static binary keeps working on a
// machine where the KDE command-line tools are absent (spec 001 R6.3).
const (
	kwalletService   = "org.kde.kwalletd6"
	kwalletPath      = "/modules/kwalletd6"
	kwalletInterface = "org.kde.KWallet"
	// appID is what KWallet shows the user when it asks whether to grant access.
	appID = "angou"
)

type kwallet struct {
	conn   *dbus.Conn
	object dbus.BusObject
	wallet string
	handle int32
}

// Open connects to the platform keyring.
//
// The cross-desktop Secret Service is tried first and the KWallet-specific API
// second. The order matters for portability rather than preference: a store is
// meant to work on every machine you carry it to, and speaking only
// org.kde.kwalletd6 meant that anywhere but KDE there was no keyring at all —
// not because the machine had none, but because angou could not talk to the one
// it had. KWallet remains as a fallback for a KDE session where ksecretd is not
// running.
func Open() (Keyring, error) {
	switch backend := os.Getenv(BackendEnv); backend {
	case BackendSecretService:
		return openSecretService()
	case BackendKWallet:
		return openKWallet()
	case "", BackendAuto:
	default:
		return nil, fmt.Errorf("%w: %s=%q; use %q, %q, or %q",
			ErrBadBackend, BackendEnv, backend, BackendAuto, BackendSecretService, BackendKWallet)
	}

	if secretServiceAvailable() {
		ring, err := openSecretService()
		if err == nil {
			return ring, nil
		}
		// A present but unusable Secret Service is worth trying past rather than
		// failing on: a KDE session can have both, and the point is to reach a
		// keyring rather than to reach a particular one.
		if kwalletAvailable() {
			if ring, kwErr := openKWallet(); kwErr == nil {
				return ring, nil
			}
		}
		return nil, err
	}
	return openKWallet()
}

// Backend selection, for a user who would rather pin one than let angou choose.
const (
	// BackendEnv names the environment variable that selects a backend.
	BackendEnv = "ANGOU_KEYRING"
	// BackendAuto is the default: the Secret Service, then KWallet.
	BackendAuto = "auto"
	// BackendSecretService is the cross-desktop org.freedesktop.secrets API.
	BackendSecretService = "secretservice"
	// BackendKWallet is the KDE-specific org.kde.kwalletd6 API.
	BackendKWallet = "kwallet"
)

// openKWallet connects through the KWallet-specific API, using the wallet named
// by WalletEnv when it is set and the session's default wallet otherwise.
//
// Naming a wallet that does not yet exist makes kwalletd raise a creation dialog
// on the user's desktop and wait for it, so WalletEnv is for selecting a wallet
// the user already has, not for conjuring one.
func openKWallet() (Keyring, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("%w: session bus: %w", ErrUnavailable, err)
	}
	object := conn.Object(kwalletService, dbus.ObjectPath(kwalletPath))

	name := os.Getenv(WalletEnv)
	if name == "" {
		// Bounded, because this call has no reason to be slow: it reports a
		// name, prompts for nothing, and touches no wallet. A kwalletd that
		// holds the bus name without answering — wedged, or mid-crash — would
		// otherwise hang every angou command for the D-Bus default timeout, and
		// "the keyring is broken" should degrade to the no-keyring path rather
		// than to a hang.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := object.CallWithContext(ctx, kwalletInterface+".localWallet", 0).Store(&name); err != nil {
			return nil, fmt.Errorf("%w: kwalletd6 is not answering: %w", ErrUnavailable, err)
		}
	}

	k := &kwallet{conn: conn, object: object, wallet: name}
	if err := k.openWallet(name); err != nil {
		return nil, err
	}
	return k, nil
}

// Available reports whether any keyring backend is present, without opening one.
//
// This exists because Open is not safe to use as a probe: opening a wallet can
// raise a dialog on the user's desktop and block until it is answered, so
// calling it merely to find out whether a keyring exists can hang a command that
// had no need of one. This asks the bus which services are running and nothing
// more, under a short timeout, so it cannot prompt and cannot wait.
func Available() bool {
	switch backend := os.Getenv(BackendEnv); backend {
	case BackendSecretService:
		return secretServiceAvailable()
	case BackendKWallet:
		return kwalletAvailable()
	case "", BackendAuto:
		return secretServiceAvailable() || kwalletAvailable()
	default:
		// Report available so the caller proceeds to Open and gets the real
		// complaint. Answering "no keyring" to a misspelt backend would turn a
		// typo into a silent, permanent fallback.
		return true
	}
}

// ValidateBackend checks the backend selector without connecting to anything.
//
// It is called once at start-up so a misspelt name is reported before a command
// does any work. Discovering it partway through — after a store has been created,
// say — leaves the user in a state they then have to reason about, for what is
// only a typo.
func ValidateBackend() error {
	switch backend := os.Getenv(BackendEnv); backend {
	case "", BackendAuto, BackendSecretService, BackendKWallet:
		return nil
	default:
		return fmt.Errorf("%w: %s=%q; use %q, %q, or %q",
			ErrBadBackend, BackendEnv, backend, BackendAuto, BackendSecretService, BackendKWallet)
	}
}

// kwalletAvailable reports whether kwalletd is running.
func kwalletAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dbus.SessionBusPrivate(dbus.WithContext(ctx))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Auth(nil); err != nil {
		return false
	}
	if err := conn.Hello(); err != nil {
		return false
	}

	var hasOwner bool
	err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, kwalletService).Store(&hasOwner)
	return err == nil && hasOwner
}

func (k *kwallet) openWallet(name string) error {
	// Deliberately unbounded. Opening a wallet can put a dialog on the user's
	// desktop and wait for them to answer it, which is correct behaviour and can
	// legitimately take as long as a person takes. The bounded check is in Open,
	// on a call that should never be slow.
	//
	// wId 0 means "no parent window": KWallet decides how to prompt.
	if err := k.object.Call(kwalletInterface+".open", 0, name, int64(0), appID).Store(&k.handle); err != nil {
		return fmt.Errorf("%w: open wallet %q: %w", ErrUnavailable, name, err)
	}
	if k.handle < 0 {
		// A negative handle is KWallet's refusal — typically the user declined
		// the access prompt, or the wallet is locked and stayed locked.
		return fmt.Errorf("%w: wallet %q was not unlocked", ErrUnavailable, name)
	}
	var created bool
	if err := k.object.Call(kwalletInterface+".createFolder", 0, k.handle, Folder, appID).Store(&created); err != nil {
		return fmt.Errorf("%w: create folder %q: %w", ErrUnavailable, Folder, err)
	}
	return nil
}

func (k *kwallet) Get(storeID string) ([]byte, error) {
	entry := EntryName(storeID)

	var present bool
	if err := k.object.Call(kwalletInterface+".hasEntry", 0, k.handle, Folder, entry, appID).Store(&present); err != nil {
		return nil, fmt.Errorf("query keyring entry: %w", err)
	}
	if !present {
		return nil, ErrNoEntry
	}

	// readEntry, not readPassword: the unlock passphrase is 32 raw random bytes
	// and D-Bus strings must be valid UTF-8, so the password API cannot carry it.
	var value []byte
	if err := k.object.Call(kwalletInterface+".readEntry", 0, k.handle, Folder, entry, appID).Store(&value); err != nil {
		return nil, fmt.Errorf("read keyring entry: %w", err)
	}
	if len(value) == 0 {
		return nil, ErrNoEntry
	}
	return value, nil
}

func (k *kwallet) Set(storeID string, secret []byte) error {
	var result int32
	err := k.object.Call(kwalletInterface+".writeEntry", 0,
		k.handle, Folder, EntryName(storeID), secret, appID).Store(&result)
	if err != nil {
		return fmt.Errorf("write keyring entry: %w", err)
	}
	if result != 0 {
		return fmt.Errorf("write keyring entry: kwalletd returned %d", result)
	}
	return nil
}

func (k *kwallet) Remove(storeID string) error {
	entry := EntryName(storeID)

	// Removing something that is not there is not an error — the point of the
	// call is to leave nothing behind — but a removal that failed for any other
	// reason must not be reported as success. The paths that call this claim to
	// have cleared the unlock passphrase, and acting on a false claim leaves it
	// in the wallet after the local key it protects is gone.
	var present bool
	if err := k.object.Call(kwalletInterface+".hasEntry", 0, k.handle, Folder, entry, appID).Store(&present); err != nil {
		return fmt.Errorf("query keyring entry: %w", err)
	}
	if !present {
		return nil
	}

	var result int32
	err := k.object.Call(kwalletInterface+".removeEntry", 0,
		k.handle, Folder, entry, appID).Store(&result)
	if err != nil {
		return fmt.Errorf("remove keyring entry: %w", err)
	}
	if result != 0 {
		return fmt.Errorf("remove keyring entry: kwalletd returned %d", result)
	}
	return nil
}

func (k *kwallet) Close() error {
	if k.conn == nil {
		return nil
	}
	err := k.conn.Close()
	k.conn = nil
	if err != nil && !errors.Is(err, dbus.ErrClosed) {
		return fmt.Errorf("close session bus: %w", err)
	}
	return nil
}
