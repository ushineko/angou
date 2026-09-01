// Package gui is the desktop front end of spec 002.
//
// This is the pass-1 prototype: the window, its navigation, and the layout of
// every section, driven by the fixtures in fixtures.go. It performs no store
// operation. It opens no store, reads no key material, and writes nothing
// outside its own window — including no preferences file, so running it leaves
// the machine exactly as it found it.
//
// Pass 2 extracts internal/core; pass 3 wires these views to it.
package gui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/ushineko/angou/internal/buildinfo"
)

// section is one entry in the left navigation.
type section struct {
	title string
	icon  fyne.Resource
	build func(*ui) fyne.CanvasObject
}

// ui holds the window's widgets. It deliberately holds no secret: see R7.2.
type ui struct {
	app     fyne.App
	win     fyne.Window
	version string
	session Session

	// appearance, persisted across runs. Held here so a change in one control
	// can rebuild the theme with the other two unchanged.
	scheme   string
	fontName string
	textSize float32

	content *container.Scroll
	nav     *widget.List
}

// Preference keys. Namespaced so a later setting cannot collide with one of
// these by accident.
const (
	prefScheme = "appearance.scheme"
	prefFont   = "appearance.font"
	prefSize   = "appearance.textSize"
)

// loadAppearance reads the saved appearance, falling back to the defaults. A
// stale value — a scheme that was renamed, a font since uninstalled — falls back
// rather than failing: paletteByName and loadFont both tolerate an unknown name.
func (u *ui) loadAppearance() {
	p := u.app.Preferences()
	u.scheme = p.StringWithFallback(prefScheme, palettes[0].name)
	u.fontName = p.StringWithFallback(prefFont, defaultFontName)
	u.textSize = float32(p.FloatWithFallback(prefSize, float64(defaultTextSize)))
}

// applyAppearance rebuilds the theme from the current settings and saves them.
func (u *ui) applyAppearance() {
	p := u.app.Preferences()
	p.SetString(prefScheme, u.scheme)
	p.SetString(prefFont, u.fontName)
	p.SetFloat(prefSize, float64(u.textSize))

	u.app.Settings().SetTheme(kdeTheme{
		p:    paletteByName(u.scheme),
		font: loadFont(u.fontName),
		text: u.textSize,
	})
}

func sections() []section {
	return []section{
		{"Store", theme.StorageIcon(), (*ui).buildStore},
		{"Encrypt", theme.ContentAddIcon(), (*ui).buildEncrypt},
		{"Doctor", theme.InfoIcon(), (*ui).buildDoctor},
		{"Machine", theme.ComputerIcon(), (*ui).buildMachine},
		{"Release", theme.DownloadIcon(), (*ui).buildRelease},
		{"Appearance", theme.ColorPaletteIcon(), (*ui).buildAppearance},
		{"About", theme.HelpIcon(), func(u *ui) fyne.CanvasObject {
			return u.buildAbout(u.version, buildinfo.Commit)
		}},
	}
}

// Options configure a run. Section and Scheme exist so a capture script can
// deep-link into the window: refreshing the README set otherwise means clicking
// through every section against a timer, and a screenshot that is tedious to
// refresh is a screenshot that goes stale. They override the saved appearance
// for that run without saving over it.
type Options struct {
	Version string
	Section string // navigation entry to open on; empty means the first
	Scheme  string // color scheme to force; empty means the saved one
}

// Run opens the window and blocks until it is closed.
func Run(o Options) {
	// Before the toolkit starts: GLFW reads the cursor theme from the
	// environment at init, and there is no second chance once the window is up.
	applyCursorTheme()

	// The ID gives the app a preferences store, which Fyne writes under the
	// user's config directory. That file holds appearance settings and nothing
	// else (R5A.6): no store path, no fingerprint, no secret. The prototype
	// still opens no store and reads no key material.
	a := app.NewWithID("io.ushineko.angou")
	u := &ui{app: a, version: o.Version, session: fixtureSession()}
	u.win = a.NewWindow("angou " + o.Version + " — prototype (fixture data, no store is opened)")
	u.win.SetIcon(appIcon())
	a.SetIcon(appIcon())
	u.loadAppearance()
	if o.Scheme != "" {
		// Forced for this run only, so a capture does not overwrite whatever
		// the user had chosen.
		u.scheme = paletteByName(o.Scheme).name
		u.app.Settings().SetTheme(kdeTheme{
			p: paletteByName(u.scheme), font: loadFont(u.fontName), text: u.textSize,
		})
	} else {
		u.applyAppearance()
	}

	u.content = container.NewScroll(widget.NewLabel(""))
	secs := sections()

	u.nav = widget.NewList(
		func() int { return len(secs) },
		func() fyne.CanvasObject {
			return container.NewHBox(widget.NewIcon(theme.StorageIcon()), widget.NewLabel("placeholder"))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			row := o.(*fyne.Container)
			row.Objects[0].(*widget.Icon).SetResource(secs[i].icon)
			row.Objects[1].(*widget.Label).SetText(secs[i].title)
		},
	)
	u.nav.OnSelected = func(i widget.ListItemID) { u.show(secs[i].build(u)) }

	split := container.NewHSplit(u.nav, u.content)
	split.SetOffset(0.16)

	u.win.SetContent(container.NewBorder(u.header(), u.statusBar(), nil, nil, split))
	u.win.Resize(fyne.NewSize(1180, 760))
	u.nav.Select(sectionIndex(secs, o.Section))
	u.win.SetMaster()
	u.win.ShowAndRun()
}

// sectionIndex resolves a section name to its position. An unknown name opens
// the first section rather than failing: a typo in a capture script should
// produce a wrong screenshot, which is obvious, not a dead window.
func sectionIndex(secs []section, name string) int {
	if name == "" {
		return 0
	}
	for i, s := range secs {
		if strings.EqualFold(s.title, name) {
			return i
		}
	}
	return 0
}

// SectionNames lists the navigation entries, for a capture script to iterate.
func SectionNames() []string {
	names := make([]string, 0)
	for _, s := range sections() {
		names = append(names, s.title)
	}
	return names
}

// SchemeNames lists the colour schemes, for the same reason.
func SchemeNames() []string { return paletteNames() }

func (u *ui) show(o fyne.CanvasObject) {
	u.content.Content = o
	u.content.Refresh()
	u.content.ScrollToTop()
}

// header carries the scheme picker. In the shipped GUI this moves into a
// preferences dialog; it sits in the window here because comparing the schemes
// is the point of this prototype.
func (u *ui) header() fyne.CanvasObject {
	title := widget.NewLabelWithStyle("angou", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	note := widget.NewLabel("prototype — every value below is fixture data")
	note.Importance = widget.LowImportance

	// The first-run flow is reachable here so it can be reviewed without
	// unconfiguring the machine. In the shipped GUI it opens by itself when no
	// store is configured (R5.10) and has no button of its own.
	setup := widget.NewButton("First-run setup…", func() { u.firstRun() })

	bar := container.NewHBox(title, note, layout.NewSpacer(), setup)
	return container.NewVBox(container.NewPadded(bar), widget.NewSeparator())
}

// statusBar shows the store directory, how this machine opens it, and the agent
// session's remaining time. Nothing else goes here: R5.1 keeps secrets out of
// the status bar, the window title, and every tooltip.
func (u *ui) statusBar() fyne.CanvasObject {
	store := widget.NewLabel(u.session.StoreDir)
	route := statusText(u.session.Route.String(), routeStatus(u.session.Route))

	agentTxt := "no session"
	agentStatus := StatusInfo
	if u.session.Agent.Running {
		agentTxt = "session " + u.session.Agent.Remaining.Round(time.Second).String() + " remaining"
		agentStatus = StatusGood
	}
	agent := statusText(agentTxt, agentStatus)

	bar := container.NewHBox(
		dim("store"), store, sep(),
		dim("unlocked by"), route, sep(),
		dim("agent"), agent,
	)
	return container.NewVBox(widget.NewSeparator(), container.NewPadded(bar))
}

func routeStatus(r UnlockRoute) Status {
	switch r {
	case UnlockLocalKey, UnlockAgent:
		return StatusGood
	case UnlockPassphrase:
		return StatusWarn
	}
	return StatusBad
}

// --- small shared widgets -------------------------------------------------

func dim(s string) fyne.CanvasObject {
	l := widget.NewLabel(s)
	l.Importance = widget.LowImportance
	return l
}

func sep() fyne.CanvasObject { return widget.NewLabel("·") }

// statusText colours a value by its status. The colour is drawn from the active
// scheme's negative/positive/neutral roles, so it stays legible in all three.
func statusText(s string, st Status) fyne.CanvasObject {
	l := widget.NewLabel(s)
	switch st {
	case StatusGood:
		l.Importance = widget.SuccessImportance
	case StatusWarn:
		l.Importance = widget.WarningImportance
	case StatusBad:
		l.Importance = widget.DangerImportance
	}
	return l
}

func heading(title, blurb string) fyne.CanvasObject {
	h := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	b := widget.NewLabel(blurb)
	b.Wrapping = fyne.TextWrapWord
	b.Importance = widget.LowImportance
	return container.NewVBox(h, b, widget.NewSeparator())
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func humanAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
