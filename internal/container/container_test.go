package container

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	for _, enc := range []Encoding{EncodingArmor, EncodingBinary} {
		t.Run(string(enc), func(t *testing.T) {
			payload := []byte("\x00\x01payload without a trailing newline")
			raw, err := Marshal(Blob{Encoding: enc, Payload: payload})
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(string(raw), BeginLine+"\n"))
			require.True(t, strings.HasSuffix(string(raw), EndLine+"\n"))

			got, err := Unmarshal(raw)
			require.NoError(t, err)
			require.Equal(t, enc, got.Encoding)
			require.Equal(t, payload, got.Payload)
		})
	}
}

func TestPayloadWithTrailingNewlineSurvives(t *testing.T) {
	payload := []byte("line one\nline two\n")
	raw, err := Marshal(Blob{Encoding: EncodingArmor, Payload: payload})
	require.NoError(t, err)
	got, err := Unmarshal(raw)
	require.NoError(t, err)
	require.Equal(t, payload, got.Payload)
}

func TestMarshalRejectsUnknownEncoding(t *testing.T) {
	_, err := Marshal(Blob{Encoding: Encoding("rot13"), Payload: []byte("x")})
	require.ErrorIs(t, err, ErrMalformed)
}

func TestUnmarshal(t *testing.T) {
	valid := BeginLine + "\nFormat: ANGOU1\nEncoding: armor\n\nbody\n" + EndLine + "\n"

	cases := []struct {
		name  string
		input string
		want  error
	}{
		{"valid", valid, nil},
		{"empty", "", ErrNotContainer},
		{"other format", strings.Replace(valid, "ANGOU1\nEncoding", "ANGOU2\nEncoding", 1), ErrNotContainer},
		{"wrong begin line", strings.Replace(valid, BeginLine, "-----BEGIN OTHER-----", 1), ErrNotContainer},
		{"no terminator", strings.Replace(valid, EndLine+"\n", "", 1), ErrMalformed},
		{"no blank line", BeginLine + "\nFormat: ANGOU1\nEncoding: armor\n" + EndLine + "\n", ErrMalformed},
		{"missing encoding", BeginLine + "\nFormat: ANGOU1\n\nbody\n" + EndLine + "\n", ErrMalformed},
		{"missing format", BeginLine + "\nEncoding: armor\n\nbody\n" + EndLine + "\n", ErrMalformed},
		{"unknown encoding", strings.Replace(valid, "Encoding: armor", "Encoding: rot13", 1), ErrMalformed},
		// R1.3 keeps the header to dispatch data. A writer that smuggles
		// metadata into it is a parse failure, not something to skip past.
		{"extra header field", strings.Replace(valid, "\n\nbody", "\nFilename: id_rsa\n\nbody", 1), ErrMalformed},
		{"header line without a separator", strings.Replace(valid, "Encoding: armor", "Encoding armor", 1), ErrMalformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Unmarshal([]byte(tc.input))
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}
}
