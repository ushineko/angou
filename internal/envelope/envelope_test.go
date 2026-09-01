package envelope

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	content := []byte("FIELD_ONE=value-one\n")
	e := New("app/.secrets.env", "text/plain", 0o600, 1756684800, content)

	raw, err := Marshal(e)
	require.NoError(t, err)

	got, err := Unmarshal(raw)
	require.NoError(t, err)
	require.Equal(t, e, got)
	require.Equal(t, int64(len(content)), got.Size)
}

func TestNewHandlesEmptyContent(t *testing.T) {
	e := New("empty", "text/plain", 0o600, 0, nil)
	raw, err := Marshal(e)
	require.NoError(t, err)
	got, err := Unmarshal(raw)
	require.NoError(t, err)
	require.Zero(t, got.Size)
	require.Empty(t, got.Content)
}

// TestUnmarshalRejectsInconsistentEnvelope covers the corruption checks. They
// are integrity only: an attacker who authors an envelope also chooses its
// digest, which is why the signature check upstream is the authenticity control.
func TestUnmarshalRejectsInconsistentEnvelope(t *testing.T) {
	valid := New("a", "text/plain", 0o600, 1, []byte("hello"))

	cases := map[string]func(*Envelope){
		"declared size disagrees with content": func(e *Envelope) { e.Size = 99 },
		"digest disagrees with content":        func(e *Envelope) { e.SHA256 = "00" },
		"content swapped under the digest":     func(e *Envelope) { e.Content = []byte("world") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := valid
			mutate(&tampered)
			raw, err := json.Marshal(tampered)
			require.NoError(t, err)

			_, err = Unmarshal(raw)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestUnmarshalRejectsGarbage(t *testing.T) {
	_, err := Unmarshal([]byte("not json"))
	require.ErrorIs(t, err, ErrInvalid)
}
