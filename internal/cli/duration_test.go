package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestParseDuration covers the forms a person actually types for a session
// lifetime. Every case marked "reported as an error" here used to be one, which
// is why the parser exists.
func TestParseDuration(t *testing.T) {
	valid := map[string]time.Duration{
		"30s":     30 * time.Second,
		"10m":     10 * time.Minute,
		"2h":      2 * time.Hour,
		"1h30m":   90 * time.Minute,
		"3600":    time.Hour,
		"99999":   99999 * time.Second,
		"1d":      24 * time.Hour,
		"2w":      14 * 24 * time.Hour,
		"  10m  ": 10 * time.Minute,
	}
	for text, want := range valid {
		t.Run(text, func(t *testing.T) {
			got, err := parseDuration(text)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}

	invalid := []string{"", "banana", "0", "-5", "-1h", "1y", "d", "1.5d", "10 m"}
	for _, text := range invalid {
		t.Run("refuses "+text, func(t *testing.T) {
			_, err := parseDuration(text)
			require.Error(t, err, "%q must be refused", text)
		})
	}
}

// TestParseDurationRefusesZero is called out separately because a zero lifetime
// does not fail loudly: it starts an agent that has already expired.
func TestParseDurationRefusesZero(t *testing.T) {
	for _, text := range []string{"0", "0s", "0m"} {
		_, err := parseDuration(text)
		require.ErrorContains(t, err, "positive")
	}
}

func TestDescribeTTL(t *testing.T) {
	cases := map[time.Duration]string{
		45 * time.Second:    "45s",
		10 * time.Minute:    "10m0s",
		90 * time.Minute:    "1h30m0s",
		24 * time.Hour:      "1 day",
		7 * 24 * time.Hour:  "7 days",
		99999 * time.Second: "1 day 3h47m0s",
	}
	for d, want := range cases {
		require.Equal(t, want, describeTTL(d), "describeTTL(%s)", d)
	}
}
