package gui

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// Spec 002 R7.2: no passphrase outlives the operation that needed it.
//
// These are unit tests rather than interaction tests because what they check is
// a property of the code, not of the window: that the buffer handed to core is
// wiped, and that nothing in this package keeps a field to put one in. Neither
// needs a display server, so they run under `make test` on a machine with none.

func TestZeroWipesTheBuffer(t *testing.T) {
	secret := []byte("not a real passphrase, just bytes")
	zero(secret)
	require.Equal(t, make([]byte, len(secret)), secret,
		"the buffer handed to core must be wiped, not merely dropped")
}

func TestZeroHandlesTheEmptyCase(t *testing.T) {
	require.NotPanics(t, func() { zero(nil) })
	require.NotPanics(t, func() { zero([]byte{}) })
}

// TestZeroLeavesNoTrailingPlaintext is the case that matters for a cancelled
// dialog: a short answer wiped over a longer earlier one must not leave the tail
// of the earlier one readable.
func TestZeroLeavesNoTrailingPlaintext(t *testing.T) {
	buf := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	zero(buf)
	copy(buf, []byte("bb"))
	zero(buf)
	require.False(t, bytes.Contains(buf, []byte("a")), "old bytes survived the wipe")
	require.False(t, bytes.Contains(buf, []byte("b")), "new bytes survived the wipe")
}

// TestSectionNamesNeedsNoApp: the flag help lists these while parsing flags,
// before there is a Fyne app to construct a theme icon against. Asking for one
// then made `angou-gui --version` print seven Fyne errors before its answer.
//
// This test would not catch that on its own — the logging is a side effect, not
// a failure — so it asserts the thing underneath: the names are available
// without touching the section table, and they still agree with it.
func TestSectionNamesNeedsNoApp(t *testing.T) {
	names := SectionNames()
	require.NotEmpty(t, names)
	require.Equal(t, []string{"Store", "Encrypt", "Doctor", "Machine", "Release", "Appearance", "About"}, names)

	// Every advertised name must have a section behind it. sections() walks
	// these titles, so a name with no builder would be offered by --section and
	// by the parity test while drawing nothing.
	for _, n := range names {
		require.Containsf(t, sectionBuilders(), n, "%q is advertised but has no section", n)
	}
	require.Len(t, sectionBuilders(), len(names), "a section exists that the navigation never shows")
}
