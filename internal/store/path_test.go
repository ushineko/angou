package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizePath(t *testing.T) {
	valid := []string{
		"a",
		"a/b/c.env",
		"projects/one/.secrets.env",
		"unicode/日本語.txt",
		"a.b.c/d-e_f",
	}
	for _, p := range valid {
		t.Run("accepts "+p, func(t *testing.T) {
			got, err := NormalizePath(p)
			require.NoError(t, err)
			require.Equal(t, p, got)
		})
	}

	invalid := map[string]string{
		"empty":               "",
		"absolute":            "/etc/shadow",
		"parent traversal":    "../../.ssh/authorized_keys",
		"embedded parent":     "a/../b",
		"current directory":   "./a",
		"trailing separator":  "a/b/",
		"empty component":     "a//b",
		"bare dot":            ".",
		"bare parent":         "..",
		"backslash separator": `a\b`,
		"drive letter":        `C:/secrets`,
		"unc prefix":          `\\server\share`,
		"NUL byte":            "a\x00b",
		"control character":   "a\x01b",
		"newline":             "a\nb",
	}
	for name, p := range invalid {
		t.Run("refuses "+name, func(t *testing.T) {
			_, err := NormalizePath(p)
			require.ErrorIs(t, err, ErrBadPath)
		})
	}
}

// TestNormalizePathAppliesNFC pins the normalization, because the HMAC that
// names the blob is taken over the result: the same path written two ways must
// address the same blob.
func TestNormalizePathAppliesNFC(t *testing.T) {
	composed := "caf\u00e9.env"    // é as one code point
	decomposed := "cafe\u0301.env" // e + combining acute
	require.NotEqual(t, composed, decomposed)

	a, err := NormalizePath(composed)
	require.NoError(t, err)
	b, err := NormalizePath(decomposed)
	require.NoError(t, err)
	require.Equal(t, a, b)
}
