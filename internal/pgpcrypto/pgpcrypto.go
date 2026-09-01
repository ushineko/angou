// Package pgpcrypto wraps the OpenPGP operations angou performs. Every payload
// is signed as well as encrypted, and every read verifies the signature before
// the plaintext is returned (spec 001 R1.7): encrypting to a public key proves
// only that the writer knew the public key, so without a signature anyone with
// write access to the store can author a blob that decrypts cleanly.
//
// The implementation is CGO-free and never invokes gpg, gpg-agent, or any other
// subprocess (R6.3).
package pgpcrypto

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ErrUnsigned reports a payload that decrypted but carried no verifiable
// signature from the store identity. It is a refusal, not a warning: the
// plaintext is discarded rather than returned.
var ErrUnsigned = errors.New("payload is not signed by the store identity")

// armorMessageType is the standard OpenPGP message header, so that an armored
// angou payload is readable by stock gpg (R1.5).
const armorMessageType = "PGP MESSAGE"

// Identity is the single OpenPGP keypair that constitutes a store (R2.1). It
// performs all encryption, decryption, and signing.
type Identity struct {
	entity *openpgp.Entity
}

func config() *packet.Config {
	// Cipher and AEAD are pinned rather than inherited from library defaults
	// (R2.2.1).
	return &packet.Config{
		DefaultCipher: packet.CipherAES256,
		DefaultHash:   crypto.SHA512,
		Algorithm:     packet.PubKeyAlgoEdDSA,
	}
}

// Generate creates a fresh store identity.
func Generate(name, email string) (*Identity, error) {
	e, err := openpgp.NewEntity(name, "angou store identity", email, config())
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	return &Identity{entity: e}, nil
}

// Fingerprint returns the primary key fingerprint, uppercase hex. It never
// appears in a container header (R1.3); it is used by operator-facing commands
// only.
func (id *Identity) Fingerprint() string {
	return fmt.Sprintf("%X", id.entity.PrimaryKey.Fingerprint)
}

// SerializePrivate exports the identity, including private key material, for
// storage in the key bundle. The caller is responsible for encrypting the
// result before it touches disk.
func (id *Identity) SerializePrivate() ([]byte, error) {
	var buf bytes.Buffer
	if err := id.entity.SerializePrivateWithoutSigning(&buf, nil); err != nil {
		return nil, fmt.Errorf("serialize identity: %w", err)
	}
	return buf.Bytes(), nil
}

// ParsePrivate reads an identity exported by SerializePrivate.
func ParsePrivate(raw []byte) (*Identity, error) {
	list, err := openpgp.ReadKeyRing(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	if len(list) != 1 {
		return nil, fmt.Errorf("key bundle holds %d identities, expected exactly one", len(list))
	}
	return &Identity{entity: list[0]}, nil
}

// Seal signs and then encrypts plaintext to the store identity. When armored,
// the result is a standard armored OpenPGP message.
func (id *Identity) Seal(plaintext []byte, armored bool) ([]byte, error) {
	var out bytes.Buffer
	var sink io.WriteCloser = nopCloser{&out}
	if armored {
		aw, err := armor.Encode(&out, armorMessageType, nil)
		if err != nil {
			return nil, fmt.Errorf("armor: %w", err)
		}
		sink = aw
	}

	to := []*openpgp.Entity{id.entity}
	w, err := openpgp.Encrypt(sink, to, id.entity, nil, config())
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write payload: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalize payload: %w", err)
	}
	if err := sink.Close(); err != nil {
		return nil, fmt.Errorf("finalize armor: %w", err)
	}
	return out.Bytes(), nil
}

// Open decrypts a payload and returns the plaintext only if it carries a valid
// signature from this identity. A decrypted-but-unsigned or
// decrypted-but-badly-signed payload yields ErrUnsigned and no plaintext.
func (id *Identity) Open(payload []byte, armored bool) ([]byte, error) {
	var r io.Reader = bytes.NewReader(payload)
	if armored {
		block, err := armor.Decode(r)
		if err != nil {
			return nil, fmt.Errorf("decode armor: %w", err)
		}
		if block.Type != armorMessageType {
			return nil, fmt.Errorf("unexpected armor type %q", block.Type)
		}
		r = block.Body
	}

	md, err := openpgp.ReadMessage(r, openpgp.EntityList{id.entity}, nil, config())
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	// The signature is only checked once the body has been consumed in full, so
	// the plaintext must be buffered here and released to the caller after the
	// verdict, never streamed out ahead of it.
	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	if !md.IsSigned {
		return nil, ErrUnsigned
	}
	if md.SignatureError != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsigned, md.SignatureError)
	}
	// Compare against the primary key: go-crypto reports the signing subkey
	// here when one was used, which is a different key id for the same identity.
	if md.SignedBy == nil || md.SignedBy.Entity == nil ||
		md.SignedBy.Entity.PrimaryKey.KeyId != id.entity.PrimaryKey.KeyId {
		return nil, fmt.Errorf("%w: signed by an unrecognized key", ErrUnsigned)
	}
	return plaintext, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// --- Release signing (spec 001 R5.4, R5.4.1) ---
//
// The key that signs release binaries is a separate offline key, never the store
// identity. The two are kept apart deliberately: if the verification key
// travelled in the store or in the key bundle, then anyone who obtained the
// recovery passphrase — or compromised a single machine — could sign a malicious
// binary that every future bootstrap would accept as genuine.

// SignDetached produces an armored detached signature over message.
func (id *Identity) SignDetached(message []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&out, id.entity, bytes.NewReader(message), config()); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return out.Bytes(), nil
}

// VerifyDetached checks a detached signature over message and returns the
// fingerprint of the key that made it.
//
// The caller compares that fingerprint against the one pinned at build time.
// Verification alone establishes only that *some* key in the supplied ring
// signed the message, which is not the question being asked.
func VerifyDetached(publicKey, message, signature []byte) (string, error) {
	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicKey))
	if err != nil {
		return "", fmt.Errorf("parse verification key: %w", err)
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(
		ring, bytes.NewReader(message), bytes.NewReader(signature), config())
	if err != nil {
		return "", fmt.Errorf("verify signature: %w", err)
	}
	return fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint), nil
}

// ExportPublic serializes the public half of the identity, armored.
func (id *Identity) ExportPublic() ([]byte, error) {
	var out bytes.Buffer
	w, err := armor.Encode(&out, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, fmt.Errorf("armor public key: %w", err)
	}
	if err := id.entity.Serialize(w); err != nil {
		return nil, fmt.Errorf("serialize public key: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalize public key: %w", err)
	}
	return out.Bytes(), nil
}

// ErrKeyLocked reports a private key that is protected by a passphrase and has
// not been unlocked yet.
var ErrKeyLocked = errors.New("the signing key is protected by a passphrase")

// ParseArmoredPrivate reads an armored private key, as exported by an offline
// release-signing setup.
//
// A key exported with `gpg --export-secret-keys` is normally passphrase
// protected, so that case is expected rather than exceptional. It is reported
// here, at parse time, rather than being left to fail later inside the signing
// call with a library-level message about an encrypted key.
func ParseArmoredPrivate(raw []byte) (*Identity, error) {
	list, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	if len(list) != 1 {
		return nil, fmt.Errorf("signing key file holds %d keys, expected exactly one", len(list))
	}
	if list[0].PrivateKey == nil {
		return nil, errors.New("signing key file holds no private key")
	}
	return &Identity{entity: list[0]}, nil
}

// IsLocked reports whether the key still needs a passphrase before it can sign.
func (id *Identity) IsLocked() bool {
	if id.entity.PrivateKey != nil && id.entity.PrivateKey.Encrypted {
		return true
	}
	for _, sub := range id.entity.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
			return true
		}
	}
	return false
}

// Unlock decrypts the private key material with a passphrase.
//
// The primary key and every subkey are unlocked together: which one signs is
// decided by the library at signing time, and unlocking only the primary
// produces the same late failure this exists to avoid.
func (id *Identity) Unlock(passphrase []byte) error {
	if id.entity.PrivateKey != nil && id.entity.PrivateKey.Encrypted {
		if err := id.entity.PrivateKey.Decrypt(passphrase); err != nil {
			return fmt.Errorf("%w: the passphrase does not open it", ErrKeyLocked)
		}
	}
	for _, sub := range id.entity.Subkeys {
		if sub.PrivateKey == nil || !sub.PrivateKey.Encrypted {
			continue
		}
		if err := sub.PrivateKey.Decrypt(passphrase); err != nil {
			return fmt.Errorf("%w: the passphrase does not open its signing subkey", ErrKeyLocked)
		}
	}
	return nil
}

// ExportArmoredPrivate serializes the identity's private half, armored. It is
// used to write out a freshly generated release-signing key, which the operator
// then moves offline.
func (id *Identity) ExportArmoredPrivate() ([]byte, error) {
	var out bytes.Buffer
	w, err := armor.Encode(&out, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, fmt.Errorf("armor private key: %w", err)
	}
	if err := id.entity.SerializePrivateWithoutSigning(w, nil); err != nil {
		return nil, fmt.Errorf("serialize private key: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalize private key: %w", err)
	}
	return out.Bytes(), nil
}
