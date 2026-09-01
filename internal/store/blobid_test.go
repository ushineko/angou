package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func key(b byte) []byte {
	k := make([]byte, NameKeyLen)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestBlobIDIsDeterministic(t *testing.T) {
	a, err := BlobID(key(1), "projects/one/.secrets.env")
	require.NoError(t, err)
	b, err := BlobID(key(1), "projects/one/.secrets.env")
	require.NoError(t, err)
	require.Equal(t, a, b)
	require.Len(t, a, 26)
	require.True(t, LooksLikeBlobID(a))
}

func TestBlobIDIsKeyed(t *testing.T) {
	a, err := BlobID(key(1), "same/path")
	require.NoError(t, err)
	b, err := BlobID(key(2), "same/path")
	require.NoError(t, err)
	require.NotEqual(t, a, b, "a different K_name must produce a different name")
}

func TestBlobIDSeparatesPaths(t *testing.T) {
	a, err := BlobID(key(1), "one/.secrets.env")
	require.NoError(t, err)
	b, err := BlobID(key(1), "two/.secrets.env")
	require.NoError(t, err)
	require.NotEqual(t, a, b)
}

func TestBlobIDNormalizesBeforeHashing(t *testing.T) {
	a, err := BlobID(key(1), "caf\u00e9.env")
	require.NoError(t, err)
	b, err := BlobID(key(1), "cafe\u0301.env")
	require.NoError(t, err)
	require.Equal(t, a, b)
}

func TestBlobIDRejectsBadInput(t *testing.T) {
	_, err := BlobID(key(1), "../escape")
	require.ErrorIs(t, err, ErrBadPath)

	_, err = BlobID([]byte("short"), "a")
	require.Error(t, err)
}

func TestLooksLikeBlobID(t *testing.T) {
	valid, err := BlobID(key(1), "a")
	require.NoError(t, err)

	cases := map[string]bool{
		valid:   true,
		"index": false,
		"store": false,
		"index (nverenin's conflicted copy 2026-08-31)": false,
		"abcdefghijklmnopqrstuvwxyz":                    true,  // 26 chars, all in the alphabet
		"abcdefghijklmnopqrstuvwxy":                     false, // 25 chars
		"abcdefghijklmnopqrstuvwxy1":                    false, // '1' is not in the base32 alphabet
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ":                    false, // uppercase is not the alphabet used
	}
	for name, want := range cases {
		require.Equal(t, want, LooksLikeBlobID(name), "LooksLikeBlobID(%q)", name)
	}
}
