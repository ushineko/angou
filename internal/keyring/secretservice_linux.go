//go:build linux

package keyring

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

// The Secret Service API (org.freedesktop.secrets) is the cross-desktop standard
// for a keyring. gnome-keyring implements it, KDE implements it through
// ksecretd, KeePassXC implements it, and so do others.
//
// It is preferred over the KWallet-specific API because angou's whole point is
// that a store works on every machine you carry it to. Speaking only
// org.kde.kwalletd6 meant that on GNOME, XFCE, Sway, or anything else, there was
// no keyring at all and the user typed the recovery passphrase for every command
// — the R2.5 fallback, reached not because the machine had no secret store but
// because angou could not talk to the one it had.
//
// It is also binary-safe by construction: a secret's value is a byte array
// rather than a string. That matters here, because the unlock passphrase is 32
// bytes of CSPRNG output and is not valid UTF-8.
const (
	ssService    = "org.freedesktop.secrets"
	ssPath       = "/org/freedesktop/secrets"
	ssIface      = "org.freedesktop.Secret.Service"
	ssCollection = "org.freedesktop.Secret.Collection"
	ssItem       = "org.freedesktop.Secret.Item"
	ssPrompt     = "org.freedesktop.Secret.Prompt"

	// attrService and attrStore identify angou's items. Searching by attribute
	// is how the API is meant to be used, and it means angou never enumerates
	// or reads items belonging to anything else.
	attrService = "xdg:schema"
	attrStore   = "angou:store"
	schemaName  = "org.ushineko.angou"
)

// ssSecret mirrors the (oayays) struct the API passes secrets in.
type ssSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

type secretService struct {
	conn       *dbus.Conn
	session    dbus.ObjectPath
	collection dbus.BusObject
}

// secretServiceAvailable reports whether the standard service is running,
// without opening anything. Same reasoning as the KWallet probe: this must not
// be able to prompt or block.
func secretServiceAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dbus.SessionBusPrivate(dbus.WithContext(ctx))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Auth(nil); err != nil || conn.Hello() != nil {
		return false
	}
	var hasOwner bool
	err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, ssService).Store(&hasOwner)
	return err == nil && hasOwner
}

// openSecretService connects and resolves the default collection.
func openSecretService() (Keyring, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("%w: session bus: %w", ErrUnavailable, err)
	}
	service := conn.Object(ssService, ssPath)

	// A plain session: the transport is a unix socket already restricted to this
	// user, and the DH-encrypted variant protects against a bus that can observe
	// message bodies — which, if it could, would already see everything else.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var output dbus.Variant
	var session dbus.ObjectPath
	if err := service.CallWithContext(ctx, ssIface+".OpenSession", 0, "plain", dbus.MakeVariant("")).
		Store(&output, &session); err != nil {
		return nil, fmt.Errorf("%w: %s is not answering: %w", ErrUnavailable, ssService, err)
	}

	var collectionPath dbus.ObjectPath
	if err := service.CallWithContext(ctx, ssIface+".ReadAlias", 0, "default").Store(&collectionPath); err != nil {
		return nil, fmt.Errorf("%w: no default collection: %w", ErrUnavailable, err)
	}
	if collectionPath == "/" {
		return nil, fmt.Errorf("%w: this secret service has no default collection", ErrUnavailable)
	}

	s := &secretService{conn: conn, session: session, collection: conn.Object(ssService, collectionPath)}
	if err := s.unlockCollection(collectionPath); err != nil {
		return nil, err
	}
	return s, nil
}

// unlockCollection unlocks the default collection, following a prompt if the
// service raises one.
func (s *secretService) unlockCollection(path dbus.ObjectPath) error {
	var locked bool
	if v, err := s.collection.GetProperty(ssCollection + ".Locked"); err == nil {
		_ = v.Store(&locked)
	}
	if !locked {
		return nil
	}

	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	service := s.conn.Object(ssService, ssPath)
	if err := service.Call(ssIface+".Unlock", 0, []dbus.ObjectPath{path}).Store(&unlocked, &prompt); err != nil {
		return fmt.Errorf("%w: unlock collection: %w", ErrUnavailable, err)
	}
	if len(unlocked) > 0 {
		return nil
	}
	if _, err := s.awaitPrompt(prompt); err != nil {
		return err
	}
	return nil
}

// awaitPrompt drives a Prompt object to completion.
//
// This is the part the KWallet API does not have: unlocking can require the user
// to answer a dialog, and the service reports that by handing back a prompt
// object whose result arrives as a signal. It is deliberately not bounded by a
// timeout — a person answering a dialog takes as long as they take.
func (s *secretService) awaitPrompt(prompt dbus.ObjectPath) (dbus.Variant, error) {
	var empty dbus.Variant
	if prompt == "" || prompt == "/" {
		return empty, nil
	}

	signals := make(chan *dbus.Signal, 1)
	s.conn.Signal(signals)
	defer s.conn.RemoveSignal(signals)

	match := []dbus.MatchOption{
		dbus.WithMatchObjectPath(prompt),
		dbus.WithMatchInterface(ssPrompt),
		dbus.WithMatchMember("Completed"),
	}
	if err := s.conn.AddMatchSignal(match...); err != nil {
		return empty, fmt.Errorf("watch for the prompt result: %w", err)
	}
	defer func() { _ = s.conn.RemoveMatchSignal(match...) }()

	if err := s.conn.Object(ssService, prompt).Call(ssPrompt+".Prompt", 0, "").Err; err != nil {
		return empty, fmt.Errorf("raise the prompt: %w", err)
	}

	for sig := range signals {
		if sig.Path != prompt || len(sig.Body) < 2 {
			continue
		}
		dismissed, _ := sig.Body[0].(bool)
		if dismissed {
			return empty, fmt.Errorf("%w: the keyring prompt was dismissed", ErrUnavailable)
		}
		result, _ := sig.Body[1].(dbus.Variant)
		return result, nil
	}
	return empty, errors.New("the keyring prompt produced no result")
}

func (s *secretService) attributes(storeID string) map[string]string {
	return map[string]string{
		attrService: schemaName,
		attrStore:   storeID,
	}
}

// findItem returns the item holding this store's unlock passphrase.
func (s *secretService) findItem(storeID string) (dbus.ObjectPath, error) {
	var items []dbus.ObjectPath
	if err := s.collection.Call(ssCollection+".SearchItems", 0, s.attributes(storeID)).Store(&items); err != nil {
		return "", fmt.Errorf("search the keyring: %w", err)
	}
	if len(items) == 0 {
		return "", ErrNoEntry
	}
	return items[0], nil
}

func (s *secretService) Get(storeID string) ([]byte, error) {
	item, err := s.findItem(storeID)
	if err != nil {
		return nil, err
	}
	var secret ssSecret
	if err := s.conn.Object(ssService, item).Call(ssItem+".GetSecret", 0, s.session).Store(&secret); err != nil {
		return nil, fmt.Errorf("read the keyring entry: %w", err)
	}
	if len(secret.Value) == 0 {
		return nil, ErrNoEntry
	}
	return secret.Value, nil
}

func (s *secretService) Set(storeID string, secret []byte) error {
	properties := map[string]dbus.Variant{
		ssItem + ".Label":      dbus.MakeVariant("angou unlock passphrase (" + storeID + ")"),
		ssItem + ".Attributes": dbus.MakeVariant(s.attributes(storeID)),
	}
	value := ssSecret{
		Session:     s.session,
		Parameters:  []byte{},
		Value:       secret,
		ContentType: "application/octet-stream",
	}

	var item, prompt dbus.ObjectPath
	// replace=true: re-running bootstrap should overwrite rather than accumulate.
	if err := s.collection.Call(ssCollection+".CreateItem", 0, properties, value, true).
		Store(&item, &prompt); err != nil {
		return fmt.Errorf("write the keyring entry: %w", err)
	}
	if item == "" || item == "/" {
		if _, err := s.awaitPrompt(prompt); err != nil {
			return err
		}
	}
	return nil
}

func (s *secretService) Remove(storeID string) error {
	item, err := s.findItem(storeID)
	if errors.Is(err, ErrNoEntry) {
		return nil
	}
	if err != nil {
		return err
	}
	var prompt dbus.ObjectPath
	if err := s.conn.Object(ssService, item).Call(ssItem+".Delete", 0).Store(&prompt); err != nil {
		return fmt.Errorf("remove the keyring entry: %w", err)
	}
	if _, err := s.awaitPrompt(prompt); err != nil {
		return err
	}
	return nil
}

func (s *secretService) Close() error {
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	if err != nil && !errors.Is(err, dbus.ErrClosed) {
		return fmt.Errorf("close session bus: %w", err)
	}
	return nil
}
