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
