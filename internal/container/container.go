// Package container implements the ANGOU1 blob container: a plaintext header,
// an OpenPGP payload, and a terminator (spec 001 R1.1).
//
// The header carries dispatch data only — format magic, format version, and
// payload encoding. It deliberately carries no filename, no plaintext size, no
// plaintext hash, and no recipient fingerprint (R1.3); descriptive metadata
// lives in the encrypted envelope instead.
package container

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// Container delimiters. These literals are duplicated in packaging/magic and
// packaging/angou.xml for file(1) and shared-mime-info, which cannot read a Go
// constant. Changing one means changing all three.
const (
	BeginLine = "-----BEGIN ANGOU1 BLOB-----"
	EndLine   = "-----END ANGOU1 BLOB-----"

	// Magic carries the format version, so an incompatible future format is a
	// different magic rather than a field a reader might overlook (R1.1).
	Magic = "ANGOU1"

	// Extension is used for both payload encodings; detection comes from the
	// magic entry and the MIME package, not from the suffix (R1.6).
	Extension = ".angou"
)

// Encoding declares how the payload is represented. Readers honour this field
// and never sniff the payload (R1.2).
type Encoding string

const (
	// EncodingArmor is ASCII-armored OpenPGP, the default. The payload is a
	// standard armored message, so `gpg --decrypt` reads it directly (R1.5).
	EncodingArmor Encoding = "armor"
	// EncodingBinary is raw OpenPGP packets, for large inputs.
	EncodingBinary Encoding = "binary"
)

const (
	headerFormat   = "Format"
	headerEncoding = "Encoding"
)

var (
	// ErrNotContainer reports input that is not an ANGOU1 blob at all.
	ErrNotContainer = errors.New("not an ANGOU1 container")
	// ErrMalformed reports an ANGOU1 blob whose framing or header is invalid.
	ErrMalformed = errors.New("malformed ANGOU1 container")
)

// Blob is a parsed container.
type Blob struct {
	Encoding Encoding
	Payload  []byte
}

// Marshal renders a blob in container framing.
func Marshal(b Blob) ([]byte, error) {
	if err := b.Encoding.validate(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(BeginLine + "\n")
	fmt.Fprintf(&out, "%s: %s\n", headerFormat, Magic)
	fmt.Fprintf(&out, "%s: %s\n", headerEncoding, b.Encoding)
	out.WriteString("\n")
	out.Write(b.Payload)
	// The separator before the terminator is unconditional, and Unmarshal strips
	// exactly one byte back off. Making it conditional on the payload's last
	// byte would silently eat a trailing newline that belonged to the payload —
	// which a binary payload ending in 0x0A can have.
	out.WriteString("\n" + EndLine + "\n")
	return out.Bytes(), nil
}

func (e Encoding) validate() error {
	switch e {
	case EncodingArmor, EncodingBinary:
		return nil
	default:
		return fmt.Errorf("%w: unknown payload encoding %q", ErrMalformed, string(e))
	}
}

// Unmarshal parses container framing and returns the payload together with the
// encoding the header declares.
func Unmarshal(raw []byte) (Blob, error) {
	var b Blob

	begin := []byte(BeginLine + "\n")
	if !bytes.HasPrefix(raw, begin) {
		return b, ErrNotContainer
	}
	body := raw[len(begin):]

	// The header runs to the first blank line; the payload runs from there to
	// the closing delimiter.
	sep := bytes.Index(body, []byte("\n\n"))
	if sep < 0 {
		return b, fmt.Errorf("%w: no blank line after header", ErrMalformed)
	}
	headerText := string(body[:sep])
	rest := body[sep+2:]

	end := []byte(EndLine)
	endAt := bytes.LastIndex(rest, end)
	if endAt < 0 {
		return b, fmt.Errorf("%w: missing closing delimiter", ErrMalformed)
	}
	payload := rest[:endAt]
	// Strip exactly the separator Marshal wrote, and require it to be there:
	// its absence means the framing was produced by something else.
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		return b, fmt.Errorf("%w: no separator before the closing delimiter", ErrMalformed)
	}
	payload = payload[:len(payload)-1]

	format, encoding, err := parseHeader(headerText)
	if err != nil {
		return b, err
	}
	if format != Magic {
		return b, fmt.Errorf("%w: unsupported format %q", ErrNotContainer, format)
	}
	if err := encoding.validate(); err != nil {
		return b, err
	}

	b.Encoding = encoding
	b.Payload = payload
	return b, nil
}

func parseHeader(text string) (format string, encoding Encoding, err error) {
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return "", "", fmt.Errorf("%w: header line %q has no separator", ErrMalformed, line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case headerFormat:
			format = value
		case headerEncoding:
			encoding = Encoding(value)
		default:
			// R1.3 keeps the header to dispatch data. An unrecognized field is
			// a signal that a writer put something there that does not belong,
			// so it is a parse failure rather than something to skip past.
			return "", "", fmt.Errorf("%w: unexpected header field %q", ErrMalformed, key)
		}
	}
	if format == "" {
		return "", "", fmt.Errorf("%w: missing %s header", ErrMalformed, headerFormat)
	}
	if encoding == "" {
		return "", "", fmt.Errorf("%w: missing %s header", ErrMalformed, headerEncoding)
	}
	return format, encoding, nil
}
