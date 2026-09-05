package gui

import (
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
	"github.com/stretchr/testify/require"
)

// Tapping Browse… must open a chooser, not take the process with it.
//
// The first version of this button sized the dialog before showing it. In fyne
// 2.8.1 that path asks a dialog with no window yet for its minimum size and
// dereferences nil, so the crash was in the one interaction the button exists
// for. This drives the real widget under the test driver, which needs no
// display, so the regression cannot come back unnoticed.
func TestBrowseButtonOpensAChooser(t *testing.T) {
	app := test.NewApp()
	defer app.Quit()

	u := &ui{win: test.NewWindow(widget.NewLabel(""))}
	defer u.win.Close()

	for _, dir := range []bool{false, true} {
		field := widget.NewEntry()
		button := u.browseButton(field, dir)
		require.NotPanics(t, func() { test.Tap(button) }, "directory chooser: %v", dir)
	}
}

// A field holding a path that does not exist, or nothing at all, must still
// give the chooser somewhere to start rather than leaving it wherever the
// process happens to be.
func TestPickerStartFallsBackToHome(t *testing.T) {
	for _, text := range []string{"", "/nonexistent/path/for/a/test", "~"} {
		require.NotNil(t, pickerStart(text), "no starting location for %q", text)
	}
}
