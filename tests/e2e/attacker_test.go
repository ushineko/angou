//go:build e2e

package e2e

import (
	"bytes"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/stretchr/testify/require"

	"github.com/ushineko/angou/internal/keybundle"
)

// readIdentity opens the store's key bundle and returns the OpenPGP entity.
//
// This models the attacker of R-9 and R2.2.1 — someone holding the store and the
// recovery passphrase — not a user. It never stands in for behaviour that a user
// reaches through the binary, which R8.1 reserves to the binary itself.
func (e *env) readIdentity(t *testing.T) *openpgp.Entity {
	t.Helper()
	raw := readFile(t, e.storePath("bootstrap", "keybundle.json"))
	bundle, err := keybundle.Unmarshal(raw)
	require.NoError(t, err)
	exported, err := bundle.Open([]byte(e.recovery))
	require.NoError(t, err)
	list, err := openpgp.ReadKeyRing(bytes.NewReader(exported))
	require.NoError(t, err)
	require.Len(t, list, 1)
	return list[0]
}

// decryptEnvelope returns the envelope JSON inside a container, failing the test
// if it cannot.
func (e *env) decryptEnvelope(t *testing.T, entity *openpgp.Entity, blob []byte) []byte {
	t.Helper()
	out := e.tryDecryptEnvelope(entity, blob)
	require.NotNil(t, out, "blob did not decrypt")
	return out
}

// tryDecryptEnvelope returns nil rather than failing, so a caller can scan a
// store for the blob it wants.
func (e *env) tryDecryptEnvelope(entity *openpgp.Entity, blob []byte) []byte {
	_, payload, ok := bytes.Cut(blob, []byte("\n\n"))
	if !ok {
		return nil
	}
	payload = bytes.TrimSuffix(payload, []byte("-----END ANGOU1 BLOB-----\n"))

	block, err := armor.Decode(bytes.NewReader(payload))
	if err != nil {
		return nil
	}
	md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{entity}, nil, nil)
	if err != nil {
		return nil
	}
	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil
	}
	return plaintext
}
