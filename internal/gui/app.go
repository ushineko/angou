// Package gui is the desktop front end of spec 002.
//
// The window renders internal/core and does nothing else: it holds no store
// logic of its own and reaches no further than the core, which is the rule that
// keeps it in step with the CLI.
//
// The window itself — navigation, content pane, status bar, progress indicator
// and result banners — is fynedesygn's shell (spec 003). This package supplies
// the sections, the status bar's segments, the header's two buttons and
// everything about a store. The design system in it was written here and copied
// out by hand to two other programs; it came back as a library, and this is the
// last of the three to stop carrying its own copy.
//
// Every core call runs off the UI thread — see state.go for why the passphrase
// and confirmation callbacks make that mandatory rather than merely tidy.
package gui

import (
	"os"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	fd "github.com/ushineko/fynedesygn"
	"github.com/ushineko/fynedesygn/shell"
	fdtheme "github.com/ushineko/fynedesygn/theme"
	"github.com/ushineko/fynedesygn/widgets"

	"github.com/ushineko/angou/internal/buildinfo"
	"github.com/ushineko/angou/internal/core"
)

// appearanceSample is the monospace line the Appearance section shows, so the
// console font is judged on the text it will actually draw: a store listing.
const appearanceSample = "id_ed25519            1.2 KiB  0600  3d ago"

// homeDir is where a scan starts when no directory has been chosen.
func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// appID names the preference store and, on Wayland, the window's app_id, which
// compositors match to a desktop entry of the same basename.
//
// The preferences file it names holds the appearance settings and the chosen
// store directory (R5A.6), and nothing else: no fingerprint, no passphrase, and
// nothing out of the store itself.
const appID = "io.ushineko.angou"

// ui holds the window's state. It deliberately holds no secret: see R7.2.
type ui struct {
	// sh is the window: navigation, content pane, status bar, progress
	// indicator and banners. The shell stores itself here through
	// Options.OnCreate before it builds the first section, so every builder
	// and every dialog can rely on the field.
	sh      *shell.Shell
	version string
	session Session

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

// sectionEntry is what a section is made of: a deferred icon and its builder.
type sectionEntry struct {
	icon  func() fyne.Resource
	build func(*ui) fyne.CanvasObject
}

// sectionBuilders is what each section is made of. sections walks sectionTitles
// and looks each one up here, so a title with no builder is a missing section
// rather than a silently different list from the one --section is told about.
//
// A function rather than a package variable: the builders reach back to the
// sections when a section rebuilds itself, and Go reports that as an
// initialization cycle in a package-level map.
func sectionBuilders() map[string]sectionEntry {
	return map[string]sectionEntry{
		"Store":      {theme.StorageIcon, (*ui).buildStore},
		"Encrypt":    {theme.ContentAddIcon, (*ui).buildEncrypt},
		"Doctor":     {theme.InfoIcon, (*ui).buildDoctor},
		"Machine":    {theme.ComputerIcon, (*ui).buildMachine},
		"Release":    {theme.DownloadIcon, (*ui).buildRelease},
		"Appearance": {theme.ColorPaletteIcon, (*ui).buildAppearance},
		"About":      {theme.HelpIcon, (*ui).buildAbout},
	}
}

// sections is the navigation as the shell takes it. A nil u is enough for the
// titles, which is all SectionNames needs.
func sections(u *ui) []shell.Section {
	builders := sectionBuilders()
	out := make([]shell.Section, 0, len(sectionTitles))
	for _, title := range sectionTitles {
		b, ok := builders[title]
		if !ok {
			continue // a title with no builder draws nothing; see SectionNames
		}
		out = append(out, shell.NewSection(title, b.icon,
			func(*shell.Shell) fyne.CanvasObject { return b.build(u) }).
			OnArrive(u.arrive))
	}
	return out
}

/*
arrive drops the loaded flags when the navigation reaches a section and
reopening the store would go through silently.

Arriving at a section is a good moment to be current, where being current is
free. The store is a plain directory: the CLI writes to it, and so does
whatever syncs it between machines. Where reopening means a passphrase prompt,
doing that on every navigation would be intolerable, so those machines refresh
on request instead.

The shell calls this for navigation only, never for the rebuilds an operation
causes — which is the distinction this needs, because dropping the flags on a
rebuild would start the loads whose completion rebuilds.
*/
func (u *ui) arrive() {
	if u.opensWithoutAsking() {
		u.entriesOK, u.doctorOK, u.agentOK = false, false, false
	}
}

// SectionNames lists the navigation entries, for a capture script to iterate.
//
// Reads the titles rather than building the sections: this is called while
// parsing flags, before there is an app to hang an icon on.
func SectionNames() []string { return shell.Names(sections(nil)) }

// SchemeNames lists the colour schemes, for the same reason. The library's list
// is a superset of the seven this program offered: Windows Dark and Windows
// Light are appended to them.
func SchemeNames() []string { return fdtheme.SchemeNames() }

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
	u := &ui{version: o.Version}
	shell.Run(u.shellOptions(o))
}

// shellOptions describes this program to the shell.
func (u *ui) shellOptions(o Options) shell.Options {
	return shell.Options{
		AppID:        appID,
		Name:         "angou",
		Version:      o.Version,
		Icon:         appIcon(),
		Sections:     sections(u),
		Section:      o.Section,
		Scheme:       o.Scheme,
		Header:       func(*shell.Shell) []fyne.CanvasObject { return u.headerActions() },
		StatusBar:    func(*shell.Shell) []fyne.CanvasObject { return u.statusSegments() },
		OnCreate:     u.onCreate,
		OnStart:      func(*shell.Shell) { u.start(o) },
		OnInvalidate: u.onInvalidate,
	}
}

/*
onCreate takes the shell and works out where the store is.

Before the first section is built and before the status bar is composed, both of
which read this: the bar names the store directory from every section, and a bar
first drawn from an empty session says "none chosen" on a machine that has one,
until something else happens to redraw it.
*/
func (u *ui) onCreate(s *shell.Shell) {
	u.sh = s
	u.scanRoot = homeDir()
	u.session = Session{StoreDir: u.storeDir()}
}

// start is what has to wait until the window exists.
func (u *ui) start(o Options) {
	// Ctrl+R alongside the F5 the shell binds: the two bindings people already
	// try. The store is a plain directory that other things write to, so "show
	// me what is actually there" needs to be one keystroke rather than a hunt
	// for a button.
	u.sh.Window.Canvas().AddShortcut(
		&desktop.CustomShortcut{KeyName: fyne.KeyR, Modifier: fyne.KeyModifierControl},
		func(fyne.Shortcut) { u.sh.Invalidate() })

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
}

/*
onInvalidate discards what was loaded from the store, so the sections fetch
again, and reloads what the status bar shows from every section. The shell
rebuilds afterwards.

The agent state is fetched here rather than left to a section, because the
status bar reports it from every section. Left to the Machine section to load,
the bar said "no session" everywhere else — next to "unlocked by an agent
session", which is the same bar contradicting itself.
*/
func (u *ui) onInvalidate(*shell.Shell) {
	u.entriesOK = false
	u.doctorOK = false
	u.agentOK = false
	u.loadAgent()
}

// headerActions are this program's two header buttons, drawn after the shell's
// Refresh.
func (u *ui) headerActions() []fyne.CanvasObject {
	choose := widget.NewButtonWithIcon("Store…", theme.FolderOpenIcon(), func() { u.chooseStore() })
	// Not "First-run setup": it opens an existing store as readily as it makes
	// one, and calling it first-run hid that from every machine after the first.
	setup := widget.NewButton("Set up…", func() { u.firstRun() })
	return []fyne.CanvasObject{choose, setup}
}

/*
statusSegments are the status bar's facts, laid out left to right by the shell.

The progress indicator is the shell's own and is not one of these: it was an
18 px strip at the right-hand end of this bar until spec 003, and is now a popup
over the content, which is what the other two programs on the library do.
*/
func (u *ui) statusSegments() []fyne.CanvasObject {
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

	return []fyne.CanvasObject{
		widgets.Dim("store"), store, widgets.Sep(),
		unlocked, widgets.Sep(),
		widgets.Dim("agent"), agent,
	}
}

func routeStatus(r core.Route) fd.Status {
	switch r {
	case core.RouteLocalKey, core.RouteAgent:
		return fd.StatusGood
	case core.RouteRecovery:
		return fd.StatusWarn
	}
	return fd.StatusInfo
}

// buildAppearance is the library's scheme, font and text-size picker. Fyne
// draws its own widgets, so these settings are the whole of what makes the
// window look like it belongs on the user's desktop, which is why they are a
// section rather than a line in a preferences dialog. They are the only thing
// this program keeps in Fyne's own preference store.
func (u *ui) buildAppearance() fyne.CanvasObject {
	return shell.AppearanceSection(appearanceSample).Build(u.sh)
}

// buildAbout is what angou is and what it will and will not do, in the
// library's About shape.
func (u *ui) buildAbout() fyne.CanvasObject {
	return shell.AboutSection(u.about(u.version, buildinfo.Commit)).Build(u.sh)
}

// Actions lists what the GUI can do, for the parity check against the CLI.
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
