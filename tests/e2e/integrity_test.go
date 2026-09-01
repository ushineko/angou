//go:build e2e

package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/stretchr/testify/require"
)

// TestRenamedBlobIsRefused covers R1.8. Every signature verifies and every digest
// matches on a blob served under another blob's name, so without the binding
// between filename and envelope path the wrong secret comes back with no error
// at all.
func TestRenamedBlobIsRefused(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	prod := e.writePlaintext("prod.env", []byte("FIELD=production-value\n"), 0o600)
	staging := e.writePlaintext("staging.env", []byte("FIELD=staging-value\n"), 0o600)
	e.mustRun("enc", "--as", "prod.env", prod)
	e.mustRun("enc", "--as", "staging.env", staging)

	prodBlob := e.blobFor(t, "prod.env")
	stagingBlob := e.blobFor(t, "staging.env")

	// Serve staging's ciphertext under prod's name — the rename an attacker with
	// write access to the synced store can perform.
	require.NoError(t, os.WriteFile(e.storePath(prodBlob), readFile(t, e.storePath(stagingBlob)), 0o600))

	r := e.run("dec", "prod.env")
	require.NotZero(t, r.code, "a blob served under the wrong name must be refused")
	require.Empty(t, r.stdout, "no plaintext may be returned")
	require.NotContains(t, r.stdout, "staging-value")
}

// TestReindexRefusesNameMismatch covers the reindex half of R1.8: the rebuild
// must not quietly index a blob under a name its envelope does not address.
func TestReindexRefusesNameMismatch(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	a := e.writePlaintext("a.env", []byte("A=1\n"), 0o600)
	b := e.writePlaintext("b.env", []byte("B=2\n"), 0o600)
	e.mustRun("enc", "--as", "a.env", a)
	e.mustRun("enc", "--as", "b.env", b)

	require.NoError(t, os.WriteFile(
		e.storePath(e.blobFor(t, "a.env")),
		readFile(t, e.storePath(e.blobFor(t, "b.env"))), 0o600))

	r := e.run("reindex")
	require.NotZero(t, r.code, "reindex must abort rather than index a mis-named blob")
}

// TestUnsignedBlobIsRefused covers R1.7. The attacker here holds the store's
// public key — which anyone with read access to the store does — and re-encrypts
// to it without the signing key.
//
// The forgery is built with the OpenPGP library directly rather than through the
// binary, because there is no angou command that writes an unsigned blob and
// there should not be one. Reaching into the module is what the *attacker* does
// here; the behaviour under test is still exercised only through the binary.
func TestUnsignedBlobIsRefused(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	src := e.writePlaintext("real.env", []byte("REAL=1\n"), 0o600)
	e.mustRun("enc", "--as", "real.env", src)
	blob := e.blobFor(t, "real.env")

	entity := e.readIdentity(t)
	envelopeJSON := e.decryptEnvelope(t, entity, readFile(t, e.storePath(blob)))
	forged := forgeUnsigned(t, entity, envelopeJSON)
	require.NoError(t, os.WriteFile(e.storePath(blob), forged, 0o600))

	r := e.run("dec", "real.env")
	require.NotZero(t, r.code, "a blob encrypted to the store key but not signed must be refused")
	require.Empty(t, r.stdout, "no plaintext may be returned")
	require.Contains(t, strings.ToLower(r.stderr), "sign",
		"the refusal should say the payload is not signed")
}

// TestCorruptedPayloadIsRefused checks the ordinary corruption case: a byte
// flipped by a sync service or a truncated file yields a refusal, not a partial
// write to stdout.
func TestCorruptedPayloadIsRefused(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	src := e.writePlaintext("c.env", []byte("C=1\n"), 0o600)
	e.mustRun("enc", "--as", "c.env", src)

	path := e.storePath(e.blobFor(t, "c.env"))
	raw := readFile(t, path)
	// Flip a byte well inside the armored payload.
	idx := bytes.Index(raw, []byte("-----BEGIN PGP MESSAGE-----")) + 80
	require.Less(t, idx, len(raw))
	raw[idx] ^= 0xFF
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	r := e.run("dec", "c.env")
	require.NotZero(t, r.code)
	require.Empty(t, r.stdout)
}

// TestPathGrammarIsEnforced covers R3.4.1 on the write side.
func TestPathGrammarIsEnforced(t *testing.T) {
	e := newEnv(t)
	e.initStore()
	src := e.writePlaintext("p.txt", []byte("x\n"), 0o600)

	for _, bad := range []string{
		"../../.ssh/authorized_keys",
		"/etc/shadow",
		"a/../b",
		"./a",
		"a/",
		"a//b",
		`C:\secrets\a`,
		`a\b`,
		"a\x01b",
	} {
		t.Run(bad, func(t *testing.T) {
			r := e.run("enc", "--as", bad, src)
			require.NotZero(t, r.code, "path %q must be refused rather than repaired", bad)
		})
	}
}

// TestDefaultPathIsRefusedNotRepaired covers R3.4.1 on the default logical path.
// Cleaning the input would store the file under a name the user neither asked for
// nor saw, which is precisely the silent repair the grammar exists to prevent.
func TestDefaultPathIsRefusedNotRepaired(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	for _, arg := range []string{"a/../a/plain.env", "./plain.env", "a/./plain.env"} {
		t.Run(arg, func(t *testing.T) {
			e.writePlaintext("a/plain.env", []byte("FIELD=value\n"), 0o600)
			e.writePlaintext("plain.env", []byte("FIELD=value\n"), 0o600)

			r := e.run("enc", arg)
			require.NotZero(t, r.code, "a non-conforming default path must be refused, not cleaned")
			require.Contains(t, r.stderr, "--as", "the refusal should say how to proceed")
			require.Empty(t, e.blobNames(), "nothing may be stored under a repaired name")
		})
	}
}

// TestExtractionRefusesSymlinkEscape covers R3.4.2. A planted symlink at an
// intermediate component would otherwise turn a decrypt into an arbitrary file
// write outside the destination root.
func TestExtractionRefusesSymlinkEscape(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	src := e.writePlaintext("key", []byte("confined-content\n"), 0o600)
	e.mustRun("enc", "--as", "ssh/key", src)

	dest := filepath.Join(e.work, "dest")
	outside := filepath.Join(e.work, "outside")
	mkdirAll(t, dest)
	mkdirAll(t, outside)
	require.NoError(t, os.Symlink(outside, filepath.Join(dest, "ssh")))

	r := e.run("get", "--dest", dest, "ssh/key")
	require.NotZero(t, r.code, "extraction must not traverse a symlink out of the destination root")

	_, err := os.Stat(filepath.Join(outside, "key"))
	require.True(t, os.IsNotExist(err), "nothing may be written outside the destination root")
}

// TestExtractionRefusesSymlinkAtEveryDepth covers the rest of R3.4.2. Guarding
// only the final component leaves a planted directory symlink to escape through,
// and guarding only the parents leaves the leaf itself.
func TestExtractionRefusesSymlinkAtEveryDepth(t *testing.T) {
	cases := []struct {
		name string
		// link is created inside the destination root, pointing outside it.
		link string
		// stored is the logical path the blob carries.
		stored string
		// escaped is the file that must not appear outside the root.
		escaped string
	}{
		{"symlink at the leaf", "secret.env", "secret.env", "secret.env"},
		{"symlink one level down", "a", "a/secret.env", "secret.env"},
		{"symlink several levels down", "a/b/c", "a/b/c/secret.env", "secret.env"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.initStore()

			src := e.writePlaintext("s", []byte("confined-content\n"), 0o600)
			e.mustRun("enc", "--as", tc.stored, src)

			dest := filepath.Join(e.work, "dest")
			outside := filepath.Join(e.work, "outside")
			mkdirAll(t, outside)
			link := filepath.Join(dest, tc.link)
			mkdirAll(t, filepath.Dir(link))

			target := outside
			if tc.name == "symlink at the leaf" {
				target = filepath.Join(outside, "secret.env")
			}
			require.NoError(t, os.Symlink(target, link))

			r := e.run("get", "--dest", dest, tc.stored)
			require.NotZero(t, r.code, "a symlink out of the root must be refused at any depth")

			_, err := os.Stat(filepath.Join(outside, tc.escaped))
			require.True(t, os.IsNotExist(err),
				"nothing may be written outside the destination root")
		})
	}
}

// --- helpers that play the attacker ---

func (e *env) blobFor(t *testing.T, logicalPath string) string {
	t.Helper()
	// The mapping from logical path to blob name is not exposed by the CLI, and
	// deliberately so. The attacker identifies the target the same way an
	// observer of the store would: by decrypting each blob it can and reading
	// the envelope. Here the test holds the key, so it can do that directly.
	entity := e.readIdentity(t)
	for _, name := range e.blobNames() {
		envJSON := e.tryDecryptEnvelope(entity, readFile(t, e.storePath(name)))
		if envJSON != nil && strings.Contains(string(envJSON), `"path":"`+logicalPath+`"`) {
			return name
		}
	}
	t.Fatalf("no blob in the store carries path %q", logicalPath)
	return ""
}

func forgeUnsigned(t *testing.T, entity *openpgp.Entity, plaintext []byte) []byte {
	t.Helper()
	var payload bytes.Buffer
	aw, err := armor.Encode(&payload, "PGP MESSAGE", nil)
	require.NoError(t, err)
	// Note the nil signer: this is the whole point of the test.
	w, err := openpgp.Encrypt(aw, []*openpgp.Entity{entity}, nil, nil, nil)
	require.NoError(t, err)
	_, err = w.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, aw.Close())

	var out bytes.Buffer
	out.WriteString("-----BEGIN ANGOU1 BLOB-----\n")
	out.WriteString("Format: ANGOU1\n")
	out.WriteString("Encoding: armor\n\n")
	out.Write(payload.Bytes())
	out.WriteString("\n-----END ANGOU1 BLOB-----\n")
	return out.Bytes()
}

// TestUnsignedIndexIsRefused covers the index half of R1.7. The index is the one
// blob whose contents the tool acts on without the user naming a path, so an
// index authored by anyone who can write to the store would otherwise steer
// every listing. It must be refused and rebuilt, not trusted.
func TestUnsignedIndexIsRefused(t *testing.T) {
	e := newEnv(t)
	e.initStore()

	src := e.writePlaintext("i.env", []byte("I=1\n"), 0o600)
	e.mustRun("enc", "--as", "real/i.env", src)
	require.Contains(t, e.mustRun("ls").stdout, "real/i.env")

	entity := e.readIdentity(t)
	forged := forgeUnsigned(t, entity, []byte(`{"entries":{"aaaaaaaaaaaaaaaaaaaaaaaaaa":`+
		`{"path":"attacker/planted.env","mime":"text/plain","size":1,"mtime":0,"mode":384}}}`))
	require.NoError(t, os.WriteFile(e.storePath("index.angou"), forged, 0o600))

	r := e.mustRun("ls")
	require.NotContains(t, r.stdout, "attacker/planted.env",
		"an index that decrypts but does not verify must not be trusted")
	require.Contains(t, r.stderr, "reindex", "the user should be told to rebuild it")

	// And the real content is still reachable, because retrieval never goes
	// through the index.
	require.Equal(t, "I=1\n", e.mustRun("dec", "real/i.env").stdout)
	e.mustRun("reindex")
	require.Contains(t, e.mustRun("ls").stdout, "real/i.env")
}
