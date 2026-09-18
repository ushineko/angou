// Package gui is the desktop front end of spec 002.
//
// The window renders internal/core and does nothing else: it holds no store
// logic of its own and reaches no further than the core, which is the rule that
// keeps it in step with the CLI.
//
// Every core call runs off the UI thread — see state.go for why the passphrase
// and confirmation callbacks make that mandatory rather than merely tidy.
package gui

import (
	"image/color"
	"os"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	fd "github.com/ushineko/fynedesygn"
	"github.com/ushineko/fynedesygn/widgets"

	"github.com/ushineko/angou/internal/buildinfo"
	"github.com/ushineko/angou/internal/core"
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
	frame   *fyne.Container // holds the status bar, so it can be redrawn
	current int             // the selected section, so an operation can rebuild it

	// busyCount is how many operations are running. A count rather than a flag:
	// loading a section can start more than one, and the indicator must not go
	// out when the first of them finishes.
	busyCount int
	busyWhat  string

	// Loaded from the store on a goroutine, read and written on the UI thread.
	//
	// Each has a companion flag rather than being tested for emptiness. A
	// section asks for its data when it has none, and finishes by rebuilding
	// itself — so inferring "not loaded yet" from an empty slice makes an empty
	// store load forever, raising a fresh passphrase dialog every time round.
	// "Loaded and empty" and "not loaded" are different states and need to be
	// stored as such.
	entries    []StoreEntry
	entriesOK  bool
	doctor     []DoctorGroup
	doctorOK   bool
	releases   []ReleaseEntry
	releasesOK bool
	agentOK    bool
	// candidates has no companion flag: the scan is always explicit, so an
	// empty list means "not scanned yet" unambiguously.
	candidates []ScanCandidate
	scanning   bool
	scanRoot   string
	// flashes is the result-banner slot: one banner at a time, in a region of
	// the window that keeps its height whether or not anything is in it.
	flashes  *fyne.Container
	flashSeq int // identifies the banner that owns the slot, so a stale timer cannot clear a newer one
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
	u.scheme = p.StringWithFallback(prefScheme, defaultSchemeName())
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

// sectionTitles is the navigation in order.
//
// The order and the names live here, apart from the icons, because a theme icon
// cannot be constructed before an app exists: asking for one first makes Fyne
// log "Attempt to access current Fyne app when none is started", which is what
// `angou-gui --version` printed seven times, since the flag help lists these.
var sectionTitles = []string{
	"Store", "Encrypt", "Doctor", "Machine", "Release", "Appearance", "About",
}

// sectionBuilders is what each section is made of. sections() walks
// sectionTitles and looks each one up here, so a title with no builder is a
// missing section rather than a silently different list from the one --section
// and the capture script are told about.
// A function rather than a package variable: the builders reach back to
// sections() when a section rebuilds itself, and Go reports that as an
// initialization cycle in a package-level map.
func sectionBuilders() map[string]struct {
	icon  func() fyne.Resource
	build func(*ui) fyne.CanvasObject
} {
	return map[string]struct {
		icon  func() fyne.Resource
		build func(*ui) fyne.CanvasObject
	}{
		"Store":      {theme.StorageIcon, (*ui).buildStore},
		"Encrypt":    {theme.ContentAddIcon, (*ui).buildEncrypt},
		"Doctor":     {theme.InfoIcon, (*ui).buildDoctor},
		"Machine":    {theme.ComputerIcon, (*ui).buildMachine},
		"Release":    {theme.DownloadIcon, (*ui).buildRelease},
		"Appearance": {theme.ColorPaletteIcon, (*ui).buildAppearance},
		"About": {theme.HelpIcon, func(u *ui) fyne.CanvasObject {
			return u.buildAbout(u.version, buildinfo.Commit)
		}},
	}
}

func sections() []section {
	builders := sectionBuilders()
	out := make([]section, 0, len(sectionTitles))
	for _, title := range sectionTitles {
		b, ok := builders[title]
		if !ok {
			continue // a title with no builder draws nothing; see SectionNames
		}
		out = append(out, section{title: title, icon: b.icon(), build: b.build})
	}
	return out
}

// SectionNames lists the navigation entries, for a capture script to iterate.
//
// Reads the titles rather than building the sections: this is called while
// parsing flags, before there is an app to hang an icon on.
func SectionNames() []string { return append([]string(nil), sectionTitles...) }

// SchemeNames lists the colour schemes, for the same reason.
func SchemeNames() []string { return paletteNames() }

// Options configure a run. Section and Scheme exist so a capture script can
// deep-link into the window: refreshing the README set otherwise means clicking
// through every section against a timer, and a screenshot that is tedious to
// refresh is a screenshot that goes stale. They override the saved appearance
// for that run without saving over it.
type Options struct {
	Version string
	Section string // navigation entry to open on; empty means the first
	Scheme  string // color scheme to force; empty means the saved one
	Scan    string // directory to scan on startup; empty scans nothing
}

// Run opens the window and blocks until it is closed.
func Run(o Options) {
	// Before the toolkit starts: GLFW reads the cursor theme from the
	// environment at init, and there is no second chance once the window is up.
	applyCursorTheme()

	// The ID gives the app a preferences store, which Fyne writes under the
	// user's config directory. That file holds the appearance settings and the
	// chosen store directory (R5A.6), and nothing else: no fingerprint, no
	// passphrase, and nothing out of the store itself.
	a := app.NewWithID("io.ushineko.angou")
	home, _ := os.UserHomeDir()
	u := &ui{app: a, version: o.Version, scanRoot: home}
	u.win = a.NewWindow("angou " + o.Version)
	u.win.SetIcon(appIcon())
	a.SetIcon(appIcon())
	u.session = Session{StoreDir: u.storeDir()}
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
	u.flashes = container.NewVBox()
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
	u.nav.OnSelected = func(i widget.ListItemID) {
		u.current = i
		// Arriving at a section is a good moment to be current, where being
		// current is free. The store is a plain directory: the CLI writes to it,
		// and so does whatever syncs it between machines.
		if u.opensWithoutAsking() {
			u.entriesOK, u.doctorOK, u.agentOK = false, false, false
		}
		u.show(secs[i].build(u))
	}

	split := container.NewHSplit(u.nav, u.content)
	split.SetOffset(0.16)

	// Result banners get their own region above the status bar, and that region
	// keeps its height whether or not a banner is in it.
	//
	// Both of the obvious alternatives are worse. Stacked above the content,
	// every banner pushed the whole section down — the row under the pointer
	// moved out from under it, which is jarring in a window whose buttons
	// include Remove. Floated over the content, which is what this did until
	// now, nothing reflowed but the banner covered whatever was at the bottom
	// of the section: on Store that is Decrypt, Extract, Rename and Remove, and
	// on Encrypt it is the button that starts the encryption. A banner that
	// hides the controls you were about to use is not a lesser problem than one
	// that moves them.
	//
	// The reserved height is the price, and it is the same trade the progress
	// indicator in the status bar already makes.
	// The banner scrolls inside the slot rather than growing it, so a long
	// message cannot reflow the window either.
	u.frame = container.NewVBox(
		widgets.FixedHeight(container.NewVScroll(u.flashes), flashSlotHeight),
		u.statusBar(),
	)
	u.win.SetContent(container.NewBorder(u.header(), u.frame, nil, nil, split))
	// F5 and Ctrl+R reload, the two bindings people already try. The store is a
	// plain directory that other things write to, so "show me what is actually
	// there" needs to be one keystroke rather than a hunt for a button.
	for _, sc := range []fyne.Shortcut{
		&desktop.CustomShortcut{KeyName: fyne.KeyR, Modifier: fyne.KeyModifierControl},
	} {
		u.win.Canvas().AddShortcut(sc, func(fyne.Shortcut) { u.invalidate() })
	}
	u.win.Canvas().SetOnTypedKey(func(e *fyne.KeyEvent) {
		if e.Name == fyne.KeyF5 {
			u.invalidate()
		}
	})

	u.win.Resize(fyne.NewSize(1180, 760))
	u.nav.Select(sectionIndex(secs, o.Section))
	u.loadAgent() // the status bar names it, so it is not the Machine section's to fetch

	// R5.10: with no store configured, open on setup rather than on an empty
	// table full of errors about a directory that was never chosen. Deferred
	// until the window is up, because a dialog has nowhere to appear before
	// then.
	if u.storeDir() == "" {
		go func() { fyne.Do(u.firstRun) }()
	}
	if o.Scan != "" {
		// For captures: the Encrypt section is a list of what a scan found, and
		// a screenshot of it with nothing found shows nothing worth showing.
		u.scanRoot = o.Scan
		u.startScan(o.Scan)
	}
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

// rebuild redraws the whole window, including the status bar, which names the
// store. refresh alone only replaces the content pane.
func (u *ui) rebuild() {
	if u.frame != nil {
		u.frame.Objects[frameStatusBar] = u.statusBar()
		u.frame.Refresh()
	}
	u.refresh()
}

// refresh rebuilds the current section, so a view showing store contents picks
// up what an operation just changed. Called on the UI thread.
func (u *ui) refresh() {
	secs := sections()
	if u.current >= 0 && u.current < len(secs) {
		u.show(secs[u.current].build(u))
	}
}

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

	choose := widget.NewButtonWithIcon("Store…", theme.FolderOpenIcon(), func() { u.chooseStore() })
	// Not "First-run setup": it opens an existing store as readily as it makes
	// one, and calling it first-run hid that from every machine after the first.
	setup := widget.NewButton("Set up…", func() { u.firstRun() })

	bar := container.NewHBox(title, layout.NewSpacer(), choose, setup)
	return container.NewVBox(container.NewPadded(bar), widget.NewSeparator())
}

// statusBar shows the store directory, how this machine opens it, and the agent
// session's remaining time. Nothing else goes here: R5.1 keeps secrets out of
// the status bar, the window title, and every tooltip.
func (u *ui) statusBar() fyne.CanvasObject {
	dir := u.session.StoreDir
	if dir == "" {
		dir = "none chosen"
	}
	store := widget.NewLabel(dir)
	route := widgets.StatusText(u.session.Route.String(), routeStatus(u.session.Route))

	agentTxt := "no session"
	agentStatus := fd.StatusInfo
	if u.session.Agent.Running {
		agentTxt = "session " + u.session.Agent.Remaining.Round(time.Second).String() + " remaining"
		agentStatus = fd.StatusGood
	}
	agent := widgets.StatusText(agentTxt, agentStatus)

	// "unlocked by not open" is not a sentence. Before the store has been
	// opened the bar says so plainly instead.
	unlocked := container.NewHBox(widgets.Dim("unlocked by"), route)
	if u.session.Route == core.RouteNone {
		unlocked = container.NewHBox(widgets.Dim("state"), widgets.StatusText("not open yet", fd.StatusInfo))
	}

	// One HBox, laid out left to right, with a spacer pushing the progress slot
	// to the right-hand end. An earlier version gave the slot the border
	// layout's centre region, which is sized from what is left over rather than
	// from the slot's own width — so a long store path pushed the two into each
	// other. Sequential layout cannot overlap.
	bar := container.NewHBox(
		widgets.Dim("store"), store, widgets.Sep(),
		unlocked, widgets.Sep(),
		widgets.Dim("agent"), agent,
		layout.NewSpacer(),
		u.busyStrip(),
	)
	return container.NewVBox(widget.NewSeparator(), container.NewPadded(bar))
}

// routeStatus ranks a route: holding a local key or an agent session is the
// state to be in, the recovery passphrase works but means this machine asks
// every time, and not being open at all is neither.
// busyStrip is the right-hand end of the status bar: what is running, and a bar
// that says it is still running.
//
// It occupies the same height whether or not anything is happening. A slot that
// only exists while busy would resize the status bar as operations start and
// finish, which is the same reflow this placement exists to avoid, just at the
// other end of the window.
func (u *ui) busyStrip() fyne.CanvasObject {
	if u.busyCount == 0 {
		spacer := canvas.NewRectangle(nil)
		spacer.SetMinSize(fyne.NewSize(0, busyStripHeight))
		return spacer
	}

	label := widget.NewLabel(u.busyWhat)
	label.Truncation = fyne.TextTruncateEllipsis
	label.Alignment = fyne.TextAlignTrailing

	// Both halves are pinned to a width. An HBox hands a truncating label its
	// minimum size, which for a truncating label is nothing at all — the text
	// collapsed to an ellipsis and the indicator said nothing about what was
	// running. A progress bar left to itself has the opposite problem and
	// expands into whatever room the text beside it leaves.
	labelSlot := canvas.NewRectangle(nil)
	labelSlot.SetMinSize(fyne.NewSize(busyLabelWidth, busyStripHeight))

	barSlot := canvas.NewRectangle(nil)
	barSlot.SetMinSize(fyne.NewSize(120, busyStripHeight))

	return container.NewHBox(
		container.New(layout.NewStackLayout(), labelSlot, label),
		container.New(layout.NewStackLayout(), barSlot, widget.NewProgressBarInfinite()),
	)
}

// busyStripHeight keeps the status bar the same height whether or not something
// is running. busyLabelWidth is how much room the description gets: enough for a
// short phrase, and fixed so that starting an operation does not shuffle the
// rest of the bar sideways.
const (
	busyStripHeight = 18
	busyLabelWidth  = 260
)

func routeStatus(r core.Route) fd.Status {
	switch r {
	case core.RouteLocalKey, core.RouteAgent:
		return fd.StatusGood
	case core.RouteRecovery:
		return fd.StatusWarn
	}
	return fd.StatusInfo
}

// busy shows an indeterminate progress banner until the returned function is
// called.
//
// Indeterminate on purpose. None of the operations this covers can say how far
// along they are: a directory scan does not know how many files it will walk
// until it has walked them, and an Argon2id derivation is one long step rather
// than many short ones. A bar that filled steadily would be inventing a number,
// which is worse than admitting there isn't one.
//
// Safe to call from a goroutine: it hops to the UI thread itself, and so does
// the function it returns. Callers are core operations running off the UI
// thread, so requiring them to marshal by hand would be an invitation to forget.
//
// EVERY core call gets one. Not just the ones that are obviously slow: opening a
// store can mean an Argon2id derivation or a wallet that raises its own dialog,
// a scan walks a directory tree of unknown size, and the machine this runs on is
// not the machine it was written on. A window that sits still with no
// explanation reads as frozen, and the button that looks like it did nothing is
// the button that gets clicked twice.
//
// withSession wraps this around every session operation, so anything going
// through it is covered. A raw `go func()` calling into core is not, and needs
// its own.
func (u *ui) busy(what string) func() {
	fyne.Do(func() {
		u.busyCount++
		u.busyWhat = what
		u.redrawStatus()
	})

	var once sync.Once
	return func() {
		once.Do(func() {
			fyne.Do(func() {
				u.busyCount--
				if u.busyCount <= 0 {
					u.busyCount, u.busyWhat = 0, ""
				}
				u.redrawStatus()
			})
		})
	}
}

// redrawStatus repaints the status bar and nothing else.
//
// This is the whole reason progress lives down there. An indicator inserted
// above the content pushes everything below it down — the row the pointer is
// over moves out from under the pointer, mid-click, which is jarring in a
// window and dangerous in one whose buttons include Remove. The status bar is
// already at the bottom and already a fixed height, so putting it there moves
// nothing.
func (u *ui) redrawStatus() {
	if u.frame == nil {
		return
	}
	u.frame.Objects[frameStatusBar] = u.statusBar()
	u.frame.Refresh()
}

// The banner slot's geometry and timings.
const (
	// frameStatusBar is the status bar's position in u.frame, which also holds
	// the banner slot above it.
	frameStatusBar = 1
	// flashSlotHeight reserves room for a banner of a few lines. Reserved
	// whether or not one is showing, so nothing moves when one arrives.
	flashSlotHeight = 68
	// How long a banner stays before it starts fading. These were 1.6s, which
	// is long enough to notice something appeared and not long enough to read
	// it — the result was a window that reported its results to nobody. A
	// warning gets longer because it usually names a condition to act on.
	flashHoldGood = 6 * time.Second
	flashHoldWarn = 12 * time.Second
	// The fade itself. Long enough to read as intentional, short enough that
	// the banner is not sitting there half-gone.
	flashFade = 700 * time.Millisecond
)

// flashHold says how long a banner of this status stays up, and whether it goes
// on its own at all.
//
// A failure does not: it waits to be dismissed, or until another operation
// replaces it. An error that removes itself on a timer is an error nobody read,
// and the operation it describes has already not happened.
func flashHold(st fd.Status) (time.Duration, bool) {
	switch st {
	case fd.StatusBad:
		return 0, false
	case fd.StatusWarn:
		return flashHoldWarn, true
	default:
		return flashHoldGood, true
	}
}

// flash reports the result of an operation as a banner in the slot above the
// status bar. One banner shows at a time: a newer result replaces an older one
// rather than stacking, so the slot cannot overflow and the most recent thing
// that happened is always the thing on screen.
//
// This is the one place motion earns its keep in this window. It carries
// information — something changed, here, and this is what it was — rather than
// decorating a transition, and it degrades to nothing if the user looks away.
// Section changes are deliberately not animated: switching sections is the most
// frequent thing anyone does here, and animating it would add latency to every
// navigation in exchange for nothing.
//
// Fyne animates properties, not opacity: a widget has no alpha to fade. So the
// fade is on the banner's own background rectangle, whose colour animates from
// the status tint to fully transparent. The text is left at full strength for
// the whole life of the banner, which is the accessible choice anyway — fading
// text out is harder to read at every intermediate step.
func (u *ui) flash(text string, st fd.Status) {
	u.flashSeq++
	seq := u.flashSeq

	tint := u.flashTint(st)
	bg := canvas.NewRectangle(tint)
	bg.CornerRadius = 2

	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord

	// Dismissable, because a banner that only leaves on a timer leaves either
	// too early to read or too late to be rid of. This is also the only way to
	// clear a failure, which does not go on its own.
	dismiss := widget.NewButtonWithIcon("", theme.CancelIcon(), func() { u.clearFlash(seq) })
	dismiss.Importance = widget.LowImportance

	banner := container.NewStack(bg, container.NewPadded(
		container.NewBorder(nil, nil, widgets.Marker(st), dismiss, label)))
	u.flashes.Objects = []fyne.CanvasObject{banner}
	u.flashes.Refresh()

	hold, fades := flashHold(st)
	if !fades {
		return
	}

	transparent := color.NRGBA{R: tint.R, G: tint.G, B: tint.B, A: 0}
	go func() {
		time.Sleep(hold)
		fyne.Do(func() {
			if u.flashSeq != seq {
				return // a newer banner owns the slot
			}
			fade := canvas.NewColorRGBAAnimation(tint, transparent, flashFade, func(c color.Color) {
				bg.FillColor = c
				canvas.Refresh(bg)
			})
			fade.Curve = fyne.AnimationEaseIn
			fade.Start()
		})
		time.Sleep(flashFade)
		fyne.Do(func() { u.clearFlash(seq) })
	}()
}

// clearFlash empties the slot, unless a newer banner has taken it. Called from
// the dismiss button and from the fade's own timer, which may arrive after the
// banner it belongs to has already been replaced.
func (u *ui) clearFlash(seq int) {
	if u.flashSeq != seq {
		return
	}
	u.flashes.Objects = nil
	u.flashes.Refresh()
}

// flashTint is the banner's starting colour: the status role from the active
// scheme, at low alpha so text stays readable over it in all five schemes.
func (u *ui) flashTint(st fd.Status) color.NRGBA {
	p := paletteByName(u.scheme)
	var c color.Color
	switch st {
	case fd.StatusGood:
		c = p.positive
	case fd.StatusWarn:
		c = p.neutral
	case fd.StatusBad:
		c = p.negative
	default:
		c = p.selectionBG
	}
	r, g, b, _ := c.RGBA()
	return color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: 0x4d} //nolint:gosec // 16-bit channels; >>8 fits a byte
}

// --- small shared widgets -------------------------------------------------

// Actions is every operation this window can reach, named by the CLI command it
// corresponds to.
//
// It exists for the parity test in tests/e2e: that test walks the cobra command
// tree and this list and fails when either holds an operation the other does
// not. Adding a command without a GUI affordance breaks the build, which is the
// point — the two front ends drift silently otherwise, and a rule enforced only
// by review is a rule that lasts until the first busy week.
//
// A name here is a claim that the operation is reachable and wired, not that a
// button exists. Do not add one to quiet the test.
func Actions() []string {
	return []string{
		"init",
		"bootstrap",
		"doctor",
		"enc",
		"dec",
		"get",
		"ls",
		"rm",
		"mv",
		"reindex",
		"rekey",
		"passwd",
		"prune",
		"release",
		"verify-bootstrap",
		"clone",
		"agent",
		// The GUI's "use" is the Store… chooser in the header and the
		// existing-store path of first-run setup: both remember the directory
		// they were given, in the same file the command writes.
		"use",
	}
}
