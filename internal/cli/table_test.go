package cli

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func sample(colour bool) string {
	t := newTable(colour)
	t.row(col(cDim, "MODE"), col(cDim, "SIZE"), col(cDim, "PATH"))
	t.row(col(cGreen, "rw-------"), col(cGreen, "2.0K"), col(cBlue, ".aws/credentials"))
	t.row(col(cGreen, "rw-r--r--"), col(cGreen, "312.5M"), col(cBlue, "Dropbox/a.mp4"))
	t.blank()
	t.row(colf(cBold, "%d files", 2), col(cBold, "314.5M"))

	var b bytes.Buffer
	t.render(&b)
	return b.String()
}

// The bug this exists for: text/tabwriter counts the runes in an ANSI escape
// towards the column width, so a coloured listing padded every column as though
// each cell were nine or ten characters wider than it looked. Colour is a
// property of how a cell is painted, never of how wide it is — so with the
// escapes stripped, coloured output must be identical to uncoloured output.
func TestColourDoesNotChangeAlignment(t *testing.T) {
	plain := sample(false)
	coloured := sample(true)

	require.NotEqual(t, plain, coloured, "the coloured rendering should actually be coloured")
	require.Contains(t, coloured, "\x1b[", "no escapes were emitted at all")
	require.Equal(t, plain, ansi.ReplaceAllString(coloured, ""),
		"colour changed the column layout")
}

// Columns line up on the width of the widest cell, plus the two spaces
// tabwriter was configured with, so an uncoloured listing is unchanged by the
// move away from it.
func TestColumnsAlign(t *testing.T) {
	lines := strings.Split(strings.TrimRight(sample(false), "\n"), "\n")
	require.Len(t, lines, 5)

	for _, l := range lines[:3] {
		require.Equal(t, strings.Index(lines[0], "SIZE"), strings.Index(l, strings.Fields(l)[1]),
			"the second column starts in a different place on %q", l)
	}
	require.Empty(t, lines[3], "the totals line is separated by a blank line")
	require.NotContains(t, lines[1], "  \n")
}

// A row shorter than the widest one must not pad out to trailing spaces: the
// totals line is two cells wide in a five-column table.
func TestShortRowsDoNotTrail(t *testing.T) {
	out := sample(false)
	for _, l := range strings.Split(out, "\n") {
		require.Equal(t, strings.TrimRight(l, " "), l, "line has trailing spaces: %q", l)
	}
}

// A totals line is one or two cells wide under a table of five. Letting it set
// the first column's width stretched every row above it to the width of
// "13 encrypted files", which is how this was found.
func TestATotalsLineDoesNotStretchTheBody(t *testing.T) {
	tb := newTable(false)
	tb.row(col(cDim, "SIZE"), col(cDim, "NAME"))
	tb.row(col(cGreen, "6.8K"), col(cBlue, "a.angou"))
	tb.blank()
	tb.row(colf(cBold, "%d encrypted files", 13))

	var b bytes.Buffer
	tb.render(&b)
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")

	require.Equal(t, "SIZE  NAME", lines[0], "the body is padded to its own widest cell")
	require.Equal(t, "6.8K  a.angou", lines[1])
	require.Equal(t, "13 encrypted files", lines[3])
}

// A double-width character occupies two screen columns and one rune. Counting
// runes — which is what tabwriter did — leaves the next column a character
// narrow for every row holding one, so a CJK or emoji filename in the listing
// pulls the rest of that row left.
func TestDoubleWidthCharactersAlign(t *testing.T) {
	tb := newTable(false)
	tb.row(col(cBlue, "機密.env"), col(cDim, "secret"))
	tb.row(col(cBlue, "plain.env"), col(cDim, "ordinary"))

	var b bytes.Buffer
	tb.render(&b)
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")

	// "機密.env" is 6 runes but 8 columns; "plain.env" is 9 of each. The wider
	// cell sets the column, so the second column starts at 11 on both rows —
	// which counting runes would have put at 10 for the first row and 11 for
	// the second.
	require.Equal(t, "機密.env   secret", lines[0])
	require.Equal(t, "plain.env  ordinary", lines[1])
}
