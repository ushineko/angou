//go:build windows

// This backend stores the unlock passphrase in the Windows Credential Manager,
// as a generic credential in the signed-in user's vault. It calls advapi32
// directly through x/sys/windows' lazy DLL loading, so the Windows CLI stays
// CGO-free: unlike the macOS Keychain, the Credential Manager API is callable
// without a C toolchain.
//
// What protects the entry: Windows encrypts the vault with DPAPI under the
// user's logon credentials, so another user on the machine cannot read it. Any
// process running as this user can, which is the same boundary the Secret
// Service and the login Keychain draw.

package keyring

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredReadW  = advapi32.NewProc("CredReadW")
	procCredWriteW = advapi32.NewProc("CredWriteW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric = 1
	// credPersistLocalMachine keeps the entry on this machine. The alternative,
	// CRED_PERSIST_ENTERPRISE, roams it with a domain profile — and the entry
	// wraps a key file that lives on this machine only, so a roamed copy would
	// be a secret on machines that have nothing for it to open.
	credPersistLocalMachine = 2
	// credMaxBlobSize is CRED_MAX_CREDENTIAL_BLOB_SIZE.
	credMaxBlobSize = 5 * 512

	errNotFound         = windows.Errno(1168)             // ERROR_NOT_FOUND
	errNoSuchLogonSesn  = windows.Errno(1312)             // ERROR_NO_SUCH_LOGON_SESSION
	credentialComment   = "angou store unlock passphrase" //nolint:gosec // G101: a label shown in Credential Manager, not a credential
	availabilityProbeID = "availability-probe"
)

// credential mirrors CREDENTIALW. Field order and types match the C layout, so
// Go's natural alignment produces the same offsets on amd64 and arm64.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// credManager is the Credential Manager backend. Like the Keychain it holds no
// connection; the type exists to satisfy the Keyring interface.
type credManager struct{}

// targetName is the credential's address in the vault. Credential Manager has
// one flat namespace per user, so the Folder prefix is what groups angou's
// entries and keeps them from colliding with another program's.
func targetName(storeID string) string { return Folder + "/" + EntryName(storeID) }

// Open reports the Credential Manager backend, or ErrUnavailable when the
// vault cannot be reached — a logon session with no credential store, such as
// a network logon over ssh, or ANGOU_KEYRING=none.
func Open() (Keyring, error) {
	if !Available() {
		return nil, ErrUnavailable
	}
	return &credManager{}, nil
}

// Available reports whether the vault answers, without prompting. It reads an
// entry that does not exist: a reachable vault says ERROR_NOT_FOUND, and a
// session with no vault says something else.
func Available() bool {
	if os.Getenv(BackendEnv) == BackendNone {
		return false
	}
	if procCredReadW.Find() != nil {
		return false
	}
	cred, err := credRead(targetName(availabilityProbeID))
	if err == nil {
		credFree(cred)
		return true
	}
	return errors.Is(err, errNotFound)
}

// ValidateBackend accepts "auto" and "none", the only two choices on Windows.
// A Linux backend name pinned in a shared shell profile is reported rather than
// silently ignored, for the reason ErrBadBackend exists.
func ValidateBackend() error {
	switch backend := os.Getenv(BackendEnv); backend {
	case "", BackendAuto, BackendNone:
		return nil
	default:
		return fmt.Errorf("%w: %s=%q (Windows has the Credential Manager only; use %q or %q)",
			ErrBadBackend, BackendEnv, backend, BackendAuto, BackendNone)
	}
}

// Get returns the unlock passphrase for a store, or ErrNoEntry.
//
// The vault's copy of the blob is zeroed before it is released to CredFree, so
// the only plaintext left in this process is the copy handed to the caller,
// which the caller zeroes.
func (c *credManager) Get(storeID string) ([]byte, error) {
	cred, err := credRead(targetName(storeID))
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, ErrNoEntry
		}
		return nil, fmt.Errorf("read credential: %w", err)
	}
	defer credFree(cred)
	if cred.CredentialBlobSize == 0 || cred.CredentialBlob == nil {
		return nil, ErrNoEntry
	}
	blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize) //nolint:gosec // G103: the vault-owned buffer CredReadW returned, sized by it
	out := make([]byte, len(blob))
	copy(out, blob)
	clear(blob)
	return out, nil
}

// Set writes the unlock passphrase, replacing any existing entry. CredWriteW
// overwrites a credential with the same target and type, so there is no
// add-or-update dance as there is on the Keychain.
func (c *credManager) Set(storeID string, secret []byte) error {
	if len(secret) == 0 || len(secret) > credMaxBlobSize {
		return fmt.Errorf("write credential: a secret of %d bytes is outside 1..%d", len(secret), credMaxBlobSize)
	}
	target, err := windows.UTF16PtrFromString(targetName(storeID))
	if err != nil {
		return fmt.Errorf("write credential: %w", err)
	}
	comment, err := windows.UTF16PtrFromString(credentialComment)
	if err != nil {
		return fmt.Errorf("write credential: %w", err)
	}
	user, err := windows.UTF16PtrFromString(Folder)
	if err != nil {
		return fmt.Errorf("write credential: %w", err)
	}
	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         target,
		Comment:            comment,
		CredentialBlobSize: uint32(len(secret)), //nolint:gosec // bounded by credMaxBlobSize above
		CredentialBlob:     &secret[0],
		Persist:            credPersistLocalMachine,
		UserName:           user,
	}
	r, _, callErr := procCredWriteW.Call(uintptr(unsafe.Pointer(&cred)), 0) //nolint:gosec // G103: CredWriteW takes a PCREDENTIALW
	if r == 0 {
		return fmt.Errorf("write credential: %w", callErr)
	}
	return nil
}

// Remove deletes the entry. Removing an absent entry is not an error; any other
// failure is reported, because the callers claim to have cleared the secret.
func (c *credManager) Remove(storeID string) error {
	target, err := windows.UTF16PtrFromString(targetName(storeID))
	if err != nil {
		return fmt.Errorf("remove credential: %w", err)
	}
	r, _, callErr := procCredDelete.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0) //nolint:gosec // G103: CredDeleteW takes an LPCWSTR
	if r == 0 && !errors.Is(callErr, errNotFound) {
		return fmt.Errorf("remove credential: %w", callErr)
	}
	return nil
}

// Close releases nothing: the backend holds no connection.
func (c *credManager) Close() error { return nil }

func credRead(target string) (*credential, error) {
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return nil, fmt.Errorf("credential target: %w", err)
	}
	var cred *credential
	r, _, callErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(name)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&cred))) //nolint:gosec // G103: CredReadW takes an LPCWSTR and a PCREDENTIALW*
	if r == 0 {
		if errors.Is(callErr, errNoSuchLogonSesn) {
			return nil, fmt.Errorf("%w: %w", ErrUnavailable, callErr)
		}
		return nil, fmt.Errorf("CredReadW: %w", callErr)
	}
	return cred, nil
}

func credFree(cred *credential) {
	_, _, _ = procCredFree.Call(uintptr(unsafe.Pointer(cred))) //nolint:gosec // G103: CredFree takes the pointer CredReadW returned
}
