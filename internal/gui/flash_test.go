package gui

import (
	"testing"

	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
	"github.com/stretchr/testify/require"
)

func testUI(t *testing.T) *ui {
	t.Helper()
	app := test.NewApp()
	t.Cleanup(app.Quit)
	u := &ui{app: app, win: test.NewWindow(widget.NewLabel("")), flashes: container.NewVBox()}
	t.Cleanup(func() { u.win.Close() })
	return u
}

// A failure waits to be dismissed. One that removes itself on a timer is an
// error nobody read, describing an operation that has already not happened.
func TestFlashKeepsFailuresUntilDismissed(t *testing.T) {
	_, fades := flashHold(StatusBad)
	require.False(t, fades, "a failure must not clear itself")

	warn, fades := flashHold(StatusWarn)
	require.True(t, fades)
	good, _ := flashHold(StatusGood)
	require.Greater(t, warn, good, "a warning names a condition to act on, so it stays longer")
	require.GreaterOrEqual(t, good.Seconds(), 5.0,
		"a banner must be up long enough to read, not merely long enough to notice")
}

// One banner at a time. The slot has a fixed height so nothing reflows when a
// result arrives, which only works if results replace each other rather than
// stacking up inside it.
func TestFlashShowsOneBannerAtATime(t *testing.T) {
	u := testUI(t)

	u.flash("first", StatusGood)
	require.Len(t, u.flashes.Objects, 1)

	u.flash("second", StatusBad)
	require.Len(t, u.flashes.Objects, 1, "a newer result replaces the older one")
}

// The fade timer of a banner that has already been replaced must not empty the
// slot underneath the banner that replaced it.
func TestClearFlashIgnoresAStaleTimer(t *testing.T) {
	u := testUI(t)

	u.flash("first", StatusGood)
	stale := u.flashSeq
	u.flash("second", StatusGood)

	u.clearFlash(stale)
	require.Len(t, u.flashes.Objects, 1, "the newer banner still owns the slot")

	u.clearFlash(u.flashSeq)
	require.Empty(t, u.flashes.Objects, "dismissing the current banner empties the slot")
}
