// Package keybundle implements the symmetrically-encrypted export of the store
// identity (spec 001 R5.1, R5.2). The recovery passphrase is the single offline
// cracking target in the design: anyone with read access to the store can copy
// this file and guess against it without limit and without detection (R2.2.1).
// Its protection is therefore pinned here rather than inherited from any
// library's defaults.
//
// The construction is:
//
//	wrapping_key  = Argon2id(passphrase, salt, m, t, p) -> 32 bytes
//	wrapped_key   = AES-256-GCM(wrapping_key, bootstrap_key)
//	payload       = AES-256-GCM(bootstrap_key, identity_export)
//
// The passphrase never encrypts the identity directly; it wraps a random 32-byte
// bootstrap key which does the actual encryption, so rotating the passphrase
// (`angou passwd`) rewrites only the wrap.
//
// The bundle is deliberately not an OpenPGP message. R5.2.1 establishes that
// stock gpg cannot read an Argon2-protected message at all — Argon2 is S2K mode
// 4, and GnuPG 2.4.x implements modes 0, 1 and 3 — so OpenPGP framing here would
// buy no interoperability while making the KDF parameters awkward to read back
// and validate against the floor, which R2.2.1 requires on every read.
package keybundle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// ErrBadPassphrase reports a recovery passphrase that does not open the bundle.
var ErrBadPassphrase = errors.New("recovery passphrase does not open the key bundle")

// ErrWeakKDF reports a bundle whose recorded parameters fall below the pinned
// floor. Refusing it is what stops an attacker from editing the header to
// downgrade the KDF and then cracking the cheaper target (R2.2.1).
var ErrWeakKDF = errors.New("key bundle KDF parameters are below the pinned floor")

// Params are the Argon2id parameters, recorded in the clear beside the
// ciphertext and validated on every read.
type Params struct {
	Algorithm   string `json:"algorithm"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Time        uint32 `json:"time"`
	Parallelism uint8  `json:"parallelism"`
	Salt        []byte `json:"salt"`
}

// The pinned floor of R2.2.1.
//
// These are RFC 9106's second recommended configuration — the one it gives for
// memory-constrained environments — with the pass count raised so the wall-clock
// cost matches a gibibyte-scale configuration. The memory figure is chosen for
// portability rather than for maximum cost: a store is meant to open on every
// machine it syncs to, and a floor that a small container or VPS cannot meet
// makes the store unopenable there rather than making it safer.
//
// The cost is roughly a sixteenth of the attacker's per-guess memory, which
// bounds how many guesses a given rig runs in parallel. That matters only for a
// passphrase materially weaker than the entropy floor init enforces: at 77 bits
// the search is infeasible regardless of the derivation cost, and the derivation
// is defence in depth against the entropy estimate being wrong about a
// human-chosen phrase, not the primary control.
const (
	FloorMemoryKiB   uint32 = 64 << 10 // 64 MiB
	FloorTime        uint32 = 24
	FloorParallelism uint8  = 4
	FloorSaltLen            = 16
)

const algorithmArgon2id = "argon2id"

// Bundle is the on-disk key bundle.
type Bundle struct {
	Version    int    `json:"version"`
	KDF        Params `json:"kdf"`
	WrappedKey []byte `json:"wrapped_key"`
	Payload    []byte `json:"payload"`
}

const bundleVersion = 1

// DefaultParams returns the parameters a new bundle is written with.
func DefaultParams() (Params, error) {
	p := Params{
		Algorithm:   algorithmArgon2id,
		MemoryKiB:   FloorMemoryKiB,
		Time:        FloorTime,
		Parallelism: FloorParallelism,
	}
	p.Salt = make([]byte, FloorSaltLen)
	if _, err := rand.Read(p.Salt); err != nil {
		return Params{}, fmt.Errorf("generate salt: %w", err)
	}
	return p, nil
}

// Validate refuses parameters below the floor in force.
func (p Params) Validate() error {
	memFloor, timeFloor, parFloor := FloorMemoryKiB, FloorTime, FloorParallelism
	if p.Algorithm != algorithmArgon2id {
		return fmt.Errorf("%w: algorithm is %q, expected %q", ErrWeakKDF, p.Algorithm, algorithmArgon2id)
	}
	if p.MemoryKiB < memFloor {
		return fmt.Errorf("%w: memory %d KiB is below the floor of %d KiB", ErrWeakKDF, p.MemoryKiB, memFloor)
	}
	if p.Time < timeFloor {
		return fmt.Errorf("%w: time %d is below the floor of %d", ErrWeakKDF, p.Time, timeFloor)
	}
	if p.Parallelism < parFloor {
		return fmt.Errorf("%w: parallelism %d is below the floor of %d", ErrWeakKDF, p.Parallelism, parFloor)
	}
	if len(p.Salt) < FloorSaltLen {
		return fmt.Errorf("%w: salt is %d bytes, floor is %d", ErrWeakKDF, len(p.Salt), FloorSaltLen)
	}
	return nil
}

func (p Params) derive(passphrase []byte) []byte {
	return argon2.IDKey(passphrase, p.Salt, p.Time, p.MemoryKiB, p.Parallelism, 32)
}

// Seal wraps identity under passphrase.
func Seal(identity, passphrase []byte) (*Bundle, error) {
	params, err := DefaultParams()
	if err != nil {
		return nil, err
	}
	if err := params.checkMemory(); err != nil {
		return nil, err
	}
	bootstrapKey := make([]byte, 32)
	if _, err := rand.Read(bootstrapKey); err != nil {
		return nil, fmt.Errorf("generate bootstrap key: %w", err)
	}
	defer zero(bootstrapKey)

	wrappingKey := params.derive(passphrase)
	defer zero(wrappingKey)

	wrapped, err := sealAEAD(wrappingKey, bootstrapKey)
	if err != nil {
		return nil, fmt.Errorf("wrap bootstrap key: %w", err)
	}
	payload, err := sealAEAD(bootstrapKey, identity)
	if err != nil {
		return nil, fmt.Errorf("encrypt identity: %w", err)
	}
	return &Bundle{
		Version:    bundleVersion,
		KDF:        params,
		WrappedKey: wrapped,
		Payload:    payload,
	}, nil
}

// Open validates the recorded parameters and then unwraps the identity.
func (b *Bundle) Open(passphrase []byte) ([]byte, error) {
	if b.Version != bundleVersion {
		return nil, fmt.Errorf("unsupported key bundle version %d", b.Version)
	}
	// The floor check runs before any key derivation: a downgraded bundle is
	// refused rather than cheaply opened.
	if err := b.KDF.Validate(); err != nil {
		return nil, err
	}
	// Refuse a derivation the machine cannot complete, before attempting it.
	if err := b.KDF.checkMemory(); err != nil {
		return nil, err
	}
	wrappingKey := b.KDF.derive(passphrase)
	defer zero(wrappingKey)

	bootstrapKey, err := openAEAD(wrappingKey, b.WrappedKey)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	defer zero(bootstrapKey)

	identity, err := openAEAD(bootstrapKey, b.Payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt identity: %w", err)
	}
	return identity, nil
}

// Marshal renders the bundle. The parameters are plaintext by design: a reader
// must be able to check them against the floor before spending the derivation.
func Marshal(b *Bundle) ([]byte, error) {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode key bundle: %w", err)
	}
	return raw, nil
}

// Unmarshal parses a bundle.
func Unmarshal(raw []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse key bundle: %w", err)
	}
	return &b, nil
}

func sealAEAD(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func openAEAD(key, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
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

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key) // AES-256: callers pass 32-byte keys.
	if err != nil {
		return nil, fmt.Errorf("initialize AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize GCM: %w", err)
	}
	return gcm, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
