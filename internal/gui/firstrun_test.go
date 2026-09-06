package gui

import (
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
	"github.com/stretchr/testify/require"
)

// The first-run dialog offers two paths and must open on the one a second
// machine needs. An earlier version offered only creation, which is the wrong
// default for a store built to be synced: every machine after the first meets
// angou with the store already on disk.
func TestFirstRunOpensOnTheExistingStorePath(t *testing.T) {
	app := test.NewApp()
	defer app.Quit()

	u := &ui{app: app, win: test.NewWindow(widget.NewLabel(""))}
	defer u.win.Close()

	f := u.newFirstRunForm()
	require.Equal(t, firstRunOpen, f.choice.Selected, "first run must default to opening a store")
	require.Equal(t, []string{firstRunOpen, firstRunCreate}, f.choice.Options,
		"the existing-store path must come first")
	require.True(t, f.openBody.Visible(), "the existing-store fields must be showing")
	require.False(t, f.newBody.Visible(), "the create fields must be hidden until chosen")
}

// Exactly one set of fields is visible at a time, in both directions. Neither
// showing is a dialog with no fields; both showing is two Directory fields with
// nothing to say which one Continue reads.
func TestFirstRunShowsOneBodyAtATime(t *testing.T) {
	app := test.NewApp()
	defer app.Quit()

	u := &ui{app: app, win: test.NewWindow(widget.NewLabel(""))}
	defer u.win.Close()

	f := u.newFirstRunForm()

	f.choice.SetSelected(firstRunCreate)
	require.False(t, f.openBody.Visible())
	require.True(t, f.newBody.Visible())

	f.choice.SetSelected(firstRunOpen)
	require.True(t, f.openBody.Visible())
	require.False(t, f.newBody.Visible())
}

// Both paths offer to set the machine up, and both default to doing it. A first
// run that leaves the machine asking for the recovery passphrase on every
// operation is the state the Machine section exists to get out of, and it should
// not be where a first run lands by default.
func TestFirstRunOffersMachineSetupOnBothPaths(t *testing.T) {
	app := test.NewApp()
	defer app.Quit()

	u := &ui{app: app, win: test.NewWindow(widget.NewLabel(""))}
	defer u.win.Close()

	f := u.newFirstRunForm()
	require.True(t, f.openBootstrap.Checked, "opening a store must offer to set the machine up")
	require.True(t, f.bootstrap.Checked, "creating a store must offer to set the machine up")
	require.Equal(t, f.bootstrap.Text, f.openBootstrap.Text,
		"the same operation must be described the same way on both paths")
}
