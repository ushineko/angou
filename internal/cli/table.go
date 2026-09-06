package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/mattn/go-runewidth"
)

// A column-aligned table that knows the difference between what it prints and
// what that occupies on screen.
//
// This replaces text/tabwriter, which counts every rune in a cell towards the
// column width — including the ones in an ANSI escape sequence, which occupy no
// screen columns at all. A coloured listing therefore padded its columns as
// though each cell were nine or ten characters wider than it looked, and the
// alignment fell apart in exactly the mode people read the listing in. The
// escape sequences are kept beside the text here rather than inside it, so a
// column's width is measured from the text alone.
//
// Width is counted in screen columns, not runes. tabwriter counted runes, which
// is right until a stored path holds a character that occupies two columns — a
// CJK filename, an emoji — and then the column it starts is a character narrow.
// go-runewidth carries the Unicode width tables that answer this properly, and
// it was already in the module graph for the desktop GUI.

// colGap is the space between columns, matching the padding tabwriter was
// configured with so the output is unchanged in the uncoloured case.
const colGap = 2

// cell is one column of one row: the text, and the colour it is printed in.
type cell struct {
	text   string
	colour string
}

// col is a cell in a colour; colf is the same with a format string. An
// uncoloured cell is col("", s), which prints its text and measures the same.
func col(colour, s string) cell { return cell{text: s, colour: colour} }
func colf(colour, format string, a ...any) cell {
	return cell{text: fmt.Sprintf(format, a...), colour: colour}
}

type table struct {
	colour bool
	rows   [][]cell
}

func newTable(colour bool) *table { return &table{colour: colour} }

// row adds a row. A row may be shorter than the widest one; the missing cells
// are simply absent rather than padded, which is what the totals line wants.
func (t *table) row(cells ...cell) { t.rows = append(t.rows, cells) }

// blank adds an empty line, for separating a totals line from the body.
func (t *table) blank() { t.rows = append(t.rows, nil) }

func (t *table) render(w io.Writer) {
	// Widths are measured per section, where a blank line ends a section. A
	// totals line is one or two cells wide under a table of five, and letting it
	// set the width of the first column stretched every row above it to the
	// width of "13 encrypted files". text/tabwriter ended a column block at a
	// line with fewer cells for the same reason; this is that rule, made
	// explicit rather than inferred from the cell count.
	for _, section := range t.sections() {
		widths := columnWidths(section)
		for _, r := range section {
			var b strings.Builder
			for i, c := range r {
				text := c.text
				if t.colour && c.colour != "" && text != "" {
					text = c.colour + text + cReset
				}
				b.WriteString(text)
				if i < len(r)-1 {
					b.WriteString(strings.Repeat(" ", widths[i]-runewidth.StringWidth(c.text)+colGap))
				}
			}
			// Trailing padding from empty cells at the end of a row is not worth
			// printing, and a line of spaces is something a diff will show.
			_, _ = fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
		}
	}
}

// sections splits the rows on blank lines, keeping the blank lines themselves so
// the output still has them.
func (t *table) sections() [][][]cell {
	var out [][][]cell
	var current [][]cell
	for _, r := range t.rows {
		if len(r) == 0 {
			if current != nil {
				out = append(out, current)
				current = nil
			}
			out = append(out, [][]cell{nil})
			continue
		}
		current = append(current, r)
	}
	if current != nil {
		out = append(out, current)
	}
	return out
}

func columnWidths(rows [][]cell) []int {
	widths := make([]int, 0, 8)
	for _, r := range rows {
		for i, c := range r {
			for i >= len(widths) {
				widths = append(widths, 0)
			}
			if n := runewidth.StringWidth(c.text); n > widths[i] {
				widths[i] = n
			}
		}
	}
	return widths
}
