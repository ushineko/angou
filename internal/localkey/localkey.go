// Package localkey manages the machine-local copy of the store identity.
//
// The local copy is wrapped by the unlock passphrase — 32 bytes from a CSPRNG,
// held only in the platform keyring (spec 001 R2.2, R2.4). It is disposable
// derived state: everything here can be rebuilt by re-running bootstrap against
// the store, so nothing in this package is a place of last resort for key
// material.
//
// No stretching is applied to the unlock passphrase. Argon2id exists on the
// recovery path because a human-chosen passphrase is guessable; a 256-bit random
// value is not, and spending 64 MiB and a quarter of a second on every command
// to stretch it would buy nothing. That difference in cost is the point of
// having two passphrases at all.
package localkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
)

// UnlockPassphraseLen is the size of the unlock passphrase (R2.2).
const UnlockPassphraseLen = 32

var (
	// ErrNoLocalKey reports that this machine holds no local copy for the store.
	ErrNoLocalKey = errors.New("no local key for this store")
	// ErrCorrupt reports local state that exists but cannot be used.
	ErrCorrupt = errors.New("local key state is unusable")
)

const fileVersion = 1

// file is the on-disk local key.
type file struct {
	Version int `json:"version"`
	// Fingerprint identifies which store this is, so the keyring entry can be
	// found without first decrypting the payload. It is local state in a 0700
	// directory, not something that travels with the store, so it carries none
	// of the correlation risk R1.3 keeps out of a blob header.
	Fingerprint string `json:"fingerprint"`
	Payload     []byte `json:"payload"`
}

// GenerateUnlockPassphrase draws a fresh unlock passphrase.
//
// It is drawn from crypto/rand and from nothing else. Deriving it from the
// hostname, /etc/machine-id, or any other host value would make the local
// wrapper recoverable by anyone who images the disk and reads this function
// (R2.3).
func GenerateUnlockPassphrase() ([]byte, error) {
	secret := make([]byte, UnlockPassphraseLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate unlock passphrase: %w", err)
	}
	return secret, nil
}

// Dir returns the directory holding local state for a store.
func Dir(storeDir string) (string, error) {
	abs, err := filepath.Abs(storeDir)
	if err != nil {
		return "", fmt.Errorf("resolve store directory: %w", err)
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(baseDir(), "local", hex.EncodeToString(sum[:8])), nil
}

// baseDir is ~/.local/share/angou, isolated from the user's GnuPG keyring
// (R2.6).
func baseDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "angou")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// No discoverable home: fall back to the working directory rather than
		// writing key material somewhere the user cannot find it.
		return ".angou"
	}
	return filepath.Join(home, ".local", "share", "angou")
}

func path(storeDir string) (string, error) {
	dir, err := Dir(storeDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.local"), nil
}

// Exists reports whether this machine holds a local copy for the store.
func Exists(storeDir string) bool {
	p, err := path(storeDir)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Fingerprint returns the identity fingerprint recorded alongside the local copy,
// which is what selects the keyring entry.
func Fingerprint(storeDir string) (string, error) {
	f, err := load(storeDir)
	if err != nil {
		return "", err
	}
	return f.Fingerprint, nil
}

// Write stores the identity wrapped under the unlock passphrase.
func Write(storeDir, fingerprint string, identity, unlock []byte) error {
	dir, err := Dir(storeDir)
	if err != nil {
		return err
	}
	// 0700 throughout: the local tree is key material (R2.6).
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create local key directory: %w", err)
	}
	payload, err := seal(unlock, identity)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(file{
		Version:     fileVersion,
		Fingerprint: fingerprint,
		Payload:     payload,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode local key: %w", err)
	}
	p, err := path(storeDir)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		return fmt.Errorf("write local key: %w", err)
	}
	return nil
}

// Read unwraps the identity with the unlock passphrase.
func Read(storeDir string, unlock []byte) ([]byte, error) {
	f, err := load(storeDir)
	if err != nil {
		return nil, err
	}
	identity, err := open(unlock, f.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: the keyring entry does not open the local key", ErrCorrupt)
	}
	return identity, nil
}

// Remove deletes the local copy. Removing absent state is not an error, because
// the operation's purpose is to leave nothing behind.
func Remove(storeDir string) error {
	dir, err := Dir(storeDir)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove local key: %w", err)
	}
	return nil
}

func load(storeDir string) (file, error) {
	var f file
	p, err := path(storeDir)
	if err != nil {
		return f, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return f, ErrNoLocalKey
		}
		return f, fmt.Errorf("read local key: %w", err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if f.Version != fileVersion {
		return f, fmt.Errorf("%w: unsupported version %d", ErrCorrupt, f.Version)
	}
	return f, nil
}

// deriveKey turns the unlock passphrase into an AES-256 key. HKDF rather than a
// password KDF: the input is already 256 bits of CSPRNG output, so this is
// domain separation, not stretching.
func deriveKey(unlock []byte) ([]byte, error) {
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, unlock, nil, []byte("angou local identity wrap v1"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("derive local wrapping key: %w", err)
	}
	return key, nil
}

func seal(unlock, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(unlock)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func open(unlock, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(unlock)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext is shorter than its nonce")
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	out, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("authenticated decryption failed: %w", err)
	}
	return out, nil
}

func newGCM(unlock []byte) (cipher.AEAD, error) {
	key, err := deriveKey(unlock)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize GCM: %w", err)
	}
	return gcm, nil
}
