package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// formatMode is listing rendering and stays in this package; the scanner it used
// to sit beside moved to internal/core (spec 002 pass 2).
func TestFormatMode(t *testing.T) {
	require.Equal(t, "rw-------", formatMode(0o600))
	require.Equal(t, "rw-r--r--", formatMode(0o644))
	require.Equal(t, "rwxr-xr-x", formatMode(0o755))
	require.Equal(t, "---------", formatMode(0))
}
