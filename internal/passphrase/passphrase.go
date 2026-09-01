// Package passphrase generates and screens recovery passphrases.
//
// The recovery passphrase is the single offline cracking target in the design
// (spec 001 R2.2.1): anyone with read access to the store can copy the key
// bundle and guess against it without limit and without detection. `angou init`
// therefore refuses a low-entropy passphrase outright rather than warning about
// one, and offers to generate a phrase instead.
package passphrase

import (
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"unicode"
)

//go:embed wordlist.txt
var wordlistData string

// MinBits is the entropy floor for a recovery passphrase (R2.2.1).
const MinBits = 77

// ErrWeak reports a passphrase below the entropy floor.
var ErrWeak = errors.New("recovery passphrase is too weak")

var words = func() []string {
	w := strings.Fields(wordlistData)
	return w
}()

// bitsPerWord is derived from the embedded list rather than hardcoded, so
// swapping the list for a longer one adjusts the generated phrase length
// automatically instead of silently invalidating the entropy claim.
func bitsPerWord() float64 { return math.Log2(float64(len(words))) }

// Generate returns a phrase carrying at least MinBits of entropy, drawn
// uniformly from the embedded wordlist with crypto/rand.
//
// Words are drawn without replacement. That is not a cosmetic choice: Check
// credits a phrase for its distinct words, so a draw that happened to repeat one
// would produce a phrase this package's own screen then refused. Sampling
// without replacement costs a fraction of a bit and keeps the two consistent.
func Generate() (string, float64, error) {
	n, bits := generatedWordCount()
	if n == 0 {
		return "", 0, errors.New("embedded wordlist is too small to reach the entropy floor")
	}

	pool := make([]string, len(words))
	copy(pool, words)

	picked := make([]string, n)
	for i := range picked {
		// Partial Fisher-Yates over the remaining pool.
		remaining := len(pool) - i
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(remaining)))
		if err != nil {
			return "", 0, fmt.Errorf("draw word: %w", err)
		}
		j := i + int(idx.Int64())
		pool[i], pool[j] = pool[j], pool[i]
		picked[i] = pool[i]
	}
	return strings.Join(picked, " "), bits, nil
}

// generatedWordCount returns the smallest number of words that reaches MinBits
// when drawn without replacement, together with the entropy that draw carries:
// log2(N) + log2(N-1) + ... for as many words as it takes.
func generatedWordCount() (int, float64) {
	var bits float64
	for n := 1; n <= len(words); n++ {
		bits += math.Log2(float64(len(words) - (n - 1)))
		if bits >= MinBits {
			return n, bits
		}
	}
	return 0, 0
}

// Check refuses a passphrase whose estimated entropy falls below MinBits and
// returns the estimate.
//
// The estimate is a deliberately conservative lower bound, not a measurement.
// Entropy is a property of how a passphrase was chosen, and this code sees only
// the result; a phrase you picked because it is memorable will score far above
// its real strength no matter what is done here. Treat a pass as "not obviously
// weak", never as "strong".
func Check(p string) (float64, error) {
	bits := Estimate(p)
	if bits < MinBits {
		return bits, fmt.Errorf("%w: about %.0f bits, floor is %d", ErrWeak, bits, MinBits)
	}
	return bits, nil
}

// Estimate returns the conservative entropy estimate described on Check.
func Estimate(p string) float64 {
	if p == "" {
		return 0
	}
	if bits, ok := wordlistEntropy(p); ok {
		return bits
	}

	return math.Min(charEstimate(p), tokenEstimate(p))
}

// charEstimate scores a passphrase against the alphabet it actually uses,
// capped by the class-derived alphabet, so neither a long repetitive string nor
// a short one drawn from a wide alphabet is overcredited.
func charEstimate(p string) float64 {
	runes := []rune(p)
	distinct := map[rune]struct{}{}
	for _, r := range runes {
		distinct[r] = struct{}{}
	}
	alphabet := math.Min(float64(len(distinct)), float64(classAlphabet(runes)))
	if alphabet < 2 {
		return 0
	}
	return float64(len(runes)) * math.Log2(alphabet)
}

// bitsPerUnknownWord is the credit given to a whitespace-separated token that is
// not in the embedded wordlist. It is the standard generous assumption for a
// word chosen from a large English vocabulary. Words a human actually reaches
// for are drawn from a far smaller set than that, so this remains an upper
// bound on such input rather than a lower one.
const bitsPerUnknownWord = 11

// tokenEstimate scores whitespace-separated input as a word sequence. Without
// it, charEstimate alone rates a famous four-word passphrase at several hundred
// bits purely on its length, which is precisely the input the screen exists to
// refuse.
func tokenEstimate(p string) float64 {
	fields := strings.Fields(p)
	if len(fields) < 2 {
		return math.Inf(1)
	}
	return float64(len(fields)) * bitsPerUnknownWord
}

func wordlistEntropy(p string) (float64, bool) {
	fields := strings.Fields(strings.ToLower(p))
	if len(fields) < 2 {
		return 0, false
	}
	index := make(map[string]struct{}, len(words))
	for _, w := range words {
		index[w] = struct{}{}
	}
	// Credit distinct words only. Repetition adds length without adding
	// choices, and crediting it would let "able able able able able able able
	// able able" clear the floor — which is exactly the kind of phrase a person
	// reaches for when told to type nine words.
	distinct := map[string]struct{}{}
	for _, f := range fields {
		if _, ok := index[f]; !ok {
			return 0, false
		}
		distinct[f] = struct{}{}
	}
	return float64(len(distinct)) * bitsPerWord(), true
}

func classAlphabet(runes []rune) int {
	var lower, upper, digit, other bool
	for _, r := range runes {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	size := 0
	if lower {
		size += 26
	}
	if upper {
		size += 26
	}
	if digit {
		size += 10
	}
	if other {
		size += 33
	}
	return size
}
