package passphrase

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWordlistIsUsable pins the properties the entropy claim rests on. If the
// list is ever swapped, this is what catches a silent weakening of it.
func TestWordlistIsUsable(t *testing.T) {
	require.GreaterOrEqual(t, len(words), 512, "the list must be large enough to reach the floor in a memorable number of words")

	seen := map[string]bool{}
	for _, w := range words {
		require.False(t, seen[w], "duplicate word %q would overstate the entropy of every phrase", w)
		require.Equal(t, strings.ToLower(w), w, "word %q must be lowercase", w)
		require.NotContains(t, w, " ")
		seen[w] = true
	}
}

// TestGenerateDrawsDistinctWords pins the property Check depends on: a generated
// phrase must survive the same screen a typed one faces, which it cannot do if
// the draw repeats a word.
func TestGenerateDrawsDistinctWords(t *testing.T) {
	for i := 0; i < 200; i++ {
		phrase, _, err := Generate()
		require.NoError(t, err)
		fields := strings.Fields(phrase)
		seen := map[string]bool{}
		for _, f := range fields {
			require.False(t, seen[f], "generated phrase %q repeats %q", phrase, f)
			seen[f] = true
		}
		_, err = Check(phrase)
		require.NoError(t, err, "a generated phrase must pass its own screen")
	}
}

func TestGenerateClearsTheFloor(t *testing.T) {
	for i := 0; i < 20; i++ {
		phrase, bits, err := Generate()
		require.NoError(t, err)
		require.GreaterOrEqual(t, bits, float64(MinBits))
		require.GreaterOrEqual(t, Estimate(phrase), float64(MinBits),
			"a generated phrase must survive the same screen a typed one faces")
		_, err = Check(phrase)
		require.NoError(t, err)
	}
}

func TestGenerateDoesNotRepeat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		phrase, _, err := Generate()
		require.NoError(t, err)
		require.False(t, seen[phrase])
		seen[phrase] = true
	}
}

func TestCheckRefusesWeakInput(t *testing.T) {
	weak := map[string]string{
		"short":                   "abc123",
		"famous four-word phrase": "correct horse battery staple",
		"long but repetitive":     strings.Repeat("a", 64),
		"two alternating runes":   strings.Repeat("ab", 32),
		"empty":                   "",
		"short with digits":       "letmein1",
		"short wordlist phrase":   "jolly deer gadget",
	}
	for name, p := range weak {
		t.Run(name, func(t *testing.T) {
			_, err := Check(p)
			require.ErrorIs(t, err, ErrWeak)
		})
	}
}

func TestCheckAcceptsStrongInput(t *testing.T) {
	strong := map[string]string{
		"long random hex":     "9f3c1b7a2e5d4086bb17c9a0f4e2d8135c6a7b90de41f238",
		"wide-alphabet mixed": "xK9#mQ2!vBn7&Lp4@Zr8%Ws1jT6^cF0",
	}
	for name, p := range strong {
		t.Run(name, func(t *testing.T) {
			bits, err := Check(p)
			require.NoError(t, err)
			require.GreaterOrEqual(t, bits, float64(MinBits))
		})
	}
}

// TestWordlistPhrasesAreScoredExactly checks that a phrase drawn from the
// embedded list is credited at its true strength rather than at the generic
// per-token rate.
func TestWordlistPhrasesAreScoredExactly(t *testing.T) {
	phrase := strings.Join(words[:9], " ")
	require.InDelta(t, 9*bitsPerWord(), Estimate(phrase), 0.001)
}
