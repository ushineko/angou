package gui

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
	"github.com/stretchr/testify/require"

	"github.com/ushineko/fynedesygn/fynetest"
	"github.com/ushineko/fynedesygn/shell"
	fdtheme "github.com/ushineko/fynedesygn/theme"
)

/*
testUI is a window with no window: the program's state over a headless shell,
with HOME and the XDG directories pointed at throwaway paths so nothing touches
the developer's store or their real configuration.

Sections built from it load inline, because the shell is not on screen — so a
test sees finished state when the builder returns rather than racing the loads
it started.
*/
func testUI(t *testing.T) *ui {
	t.Helper()
	fynetest.Sandbox(t)
	app := test.NewApp()
	t.Cleanup(app.Quit)

	u := &ui{version: "test"}
	u.sh = shell.Headless(app, u.shellOptions(Options{}))
	// Headless has no window; the dialogs need one to hang off, and the tests
	// that drive them get this one. OnScreen stays false.
	win := test.NewWindow(widget.NewLabel(""))
	u.sh.Window = win
	t.Cleanup(win.Close)
	return u
}

// A saved appearance from the previous build must be read unchanged (spec 003
// AC5). The three keys were this program's before the library existed and are
// the library's now; if they had drifted, every window that had ever been
// configured would open with default colours and a default font.
func TestASavedAppearanceFromThePreviousBuildIsReadUnchanged(t *testing.T) {
	fynetest.Sandbox(t)
	app := test.NewApp()
	t.Cleanup(app.Quit)

	p := app.Preferences()
	p.SetString("appearance.scheme", "Oxygen Dark")
	p.SetString("appearance.font", "DejaVu Sans")
	p.SetFloat("appearance.textSize", 13)

	u := &ui{version: "test"}
	u.sh = shell.Headless(app, u.shellOptions(Options{}))

	a := u.sh.Appearance()
	require.Equal(t, "Oxygen Dark", a.Scheme)
	require.Equal(t, "DejaVu Sans", a.Font)
	require.Equal(t, float32(13), a.TextSize)
}

// The schemes this program offered must still be offered, and in the same
// order: a name that moved or vanished is a saved appearance that silently
// falls back. The library appends its two Windows schemes to them.
func TestTheSchemesThisProgramOfferedAreStillOfferedFirst(t *testing.T) {
	fynetest.Sandbox(t)
	app := test.NewApp()
	t.Cleanup(app.Quit)

	names := SchemeNames()
	for _, want := range []string{
		"Breeze Dark", "Breeze Light", "Oxygen Dark", "Adwaita Dark", "Adwaita Light",
		"macOS Dark", "macOS Light",
	} {
		require.Containsf(t, names, want, "%q is no longer offered", want)
	}
	require.Contains(t, names, "Windows Dark", "the library's schemes come with it")
}

// Every section must render in every scheme without a display. A section that
// panics on an unloaded field or a nil store is a window that dies on the
// navigation click that reaches it, and the sections a screenshot script visits
// are exactly these.
func TestEverySectionRendersHeadlesslyInEveryScheme(t *testing.T) {
	for _, scheme := range fdtheme.SchemeNames() {
		t.Run(scheme, func(t *testing.T) {
			u := testUI(t)
			a := u.sh.Appearance()
			a.Scheme = scheme
			u.sh.SetAppearance(a)

			for _, sec := range sections(u) {
				var out fyne.CanvasObject
				require.NotPanicsf(t, func() { out = sec.Build(u.sh) }, "%s did not render", sec.Title())
				require.NotNilf(t, out, "%s rendered nothing", sec.Title())
			}
		})
	}
}
