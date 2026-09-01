// Package envelope defines the metadata envelope carried inside a blob's
// encrypted payload (spec 001 R1.4). The envelope is authoritative for a blob's
// identity: the plaintext container header carries none of this, so that a
// store on third-party infrastructure leaks no filenames (R1.3).
package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Envelope is the JSON document that a blob's payload decrypts to. `gpg
// --decrypt` on a blob body yields exactly these bytes, which is the recovery
// guarantee of R1.5.
type Envelope struct {
	// Path is the store-relative logical path, normalized per R3.4.1. The blob's
	// filename is bound to this value (R1.8).
	Path string `json:"path"`
	// MIME is the detected content type, advisory only.
	MIME string `json:"mime"`
	// Mode is the POSIX file mode, restored on extraction.
	Mode uint32 `json:"mode"`
	// MTime is the modification time in Unix seconds, restored on extraction.
	MTime int64 `json:"mtime"`
	// Size is the plaintext length in bytes.
	Size int64 `json:"size"`
	// Origin is where the file was on the machine that encrypted it, absolute.
	// It exists so a file can be put back where it belongs on a different
	// machine, which is most of the point of carrying SSH keys and credentials
	// in a store at all.
	//
	// It is only safe to act on because the envelope is signed (R1.7): an
	// attacker who can write to the store cannot forge this path, because
	// forging it means forging the signature. Without that, recording a
	// restore destination inside the store would hand anyone with write access
	// a way to direct writes anywhere the user can write.
	Origin string `json:"origin,omitempty"`
	// SHA256 is the hex digest of the plaintext. It is an integrity check
	// against corruption, not an authenticity control: an attacker who authors
	// a blob also chooses this value, which is why R1.7 requires a signature.
	SHA256 string `json:"sha256"`
	// Content is the plaintext, base64-encoded by encoding/json.
	Content []byte `json:"content"`
}

// ErrInvalid reports an envelope that is structurally unusable.
var ErrInvalid = errors.New("invalid envelope")

// New builds an envelope over content. The caller supplies an already-normalized
// path, and origin as an absolute path or empty.
func New(path, mime string, mode uint32, mtime int64, content []byte, origin string) Envelope {
	sum := sha256.Sum256(content)
	return Envelope{
		Path:    path,
		Origin:  origin,
		MIME:    mime,
		Mode:    mode,
		MTime:   mtime,
		Size:    int64(len(content)),
		SHA256:  hex.EncodeToString(sum[:]),
		Content: content,
	}
}

// Marshal renders the envelope for encryption.
func Marshal(e Envelope) ([]byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encode envelope: %w", err)
	}
	return raw, nil
}

// Unmarshal parses a decrypted payload and checks it against itself. The size
// and digest checks catch corruption; they say nothing about who wrote the blob,
// which the signature check upstream of this call is responsible for.
func Unmarshal(raw []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if e.Size != int64(len(e.Content)) {
		return e, fmt.Errorf("%w: declared size %d does not match %d bytes of content", ErrInvalid, e.Size, len(e.Content))
	}
	sum := sha256.Sum256(e.Content)
	if got := hex.EncodeToString(sum[:]); got != e.SHA256 {
		return e, fmt.Errorf("%w: content digest mismatch", ErrInvalid)
	}
	return e, nil
}
