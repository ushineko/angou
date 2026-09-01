package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseDuration reads a lifetime, accepting more than Go's own syntax does.
//
// time.ParseDuration knows nothing above hours and rejects a bare number, so the
// four most obvious things to type for a session lifetime — 3600, 99999, 1d, 1w
// — are all errors. That is a poor way to meet a flag whose whole purpose is to
// say how long something should last.
//
// Accepted here: Go's own forms ("10m", "2h30m"), days and weeks ("1d", "2w"),
// and a bare number read as seconds.
func parseDuration(text string) (time.Duration, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, fmt.Errorf("no duration given")
	}

	var d time.Duration
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		// A bare number is seconds. Nothing else would be meant by "3600" here,
		// and refusing it only sends the user away to guess a suffix.
		d = time.Duration(n) * time.Second
	} else {
		// Days and weeks, which Go's parser has no units for.
		if scaled, ok := expandLargeUnits(text); ok {
			text = scaled
		}
		parsed, err := time.ParseDuration(text)
		if err != nil {
			return 0, fmt.Errorf("%q is not a duration.\n%s", text, durationForms)
		}
		d = parsed
	}

	// Checked on every path, including the bare number. A zero lifetime starts
	// something that has already expired, which is worse than an error.
	if d <= 0 {
		return 0, fmt.Errorf("%q is not a positive duration.\n%s", text, durationForms)
	}
	return d, nil
}

// durationForms is shown with every refusal. Someone who typed a zero needs to
// see what is accepted just as much as someone who typed a word.
const durationForms = "Give a number of seconds, or a number with a unit: 30s, 10m, 2h, 1d, 2w, 1h30m"

// expandLargeUnits rewrites a trailing d or w suffix into hours, so the rest of
// the string can go through the standard parser.
func expandLargeUnits(text string) (string, bool) {
	for _, unit := range []struct {
		suffix string
		hours  int64
	}{{"w", 24 * 7}, {"d", 24}} {
		body, found := strings.CutSuffix(text, unit.suffix)
		if !found {
			continue
		}
		n, err := strconv.ParseInt(body, 10, 64)
		if err != nil {
			return "", false
		}
		return strconv.FormatInt(n*unit.hours, 10) + "h", true
	}
	return "", false
}

// describeTTL renders a lifetime the way a person would say it, because
// "27h46m39s" is not a useful thing to read back to someone who typed 99999.
func describeTTL(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		days := d / (24 * time.Hour)
		rest := d % (24 * time.Hour)
		unit := "days"
		if days == 1 {
			unit = "day"
		}
		if rest == 0 {
			return fmt.Sprintf("%d %s", days, unit)
		}
		return fmt.Sprintf("%d %s %s", days, unit, rest.Round(time.Minute))
	case d >= time.Hour:
		return d.Round(time.Minute).String()
	default:
		return d.Round(time.Second).String()
	}
}
