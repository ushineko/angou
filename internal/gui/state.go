package gui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"fyne.io/fyne/v2"

	angoucontainer "github.com/ushineko/angou/internal/container"
	"github.com/ushineko/angou/internal/core"
	"github.com/ushineko/angou/internal/store"
)

// Talking to the core from a GUI.
//
// internal/core is synchronous and asks for what it needs through callbacks: a
// passphrase through Secrets, a yes/no through Decider. On a terminal those
// block on a read. Here they have to block on a dialog, and a dialog cannot be
// answered by the thread that is blocked -- Fyne draws on one thread, and
// waiting on it from inside it is a deadlock.
//
// So every core call runs on a goroutine, and every callback hops back to the
// UI thread with fyne.Do to put its question on screen, then waits on a channel
// for the answer. That is the whole trick, and it is why nothing in this file
// may be called from a widget handler directly.

// StoreEnv names the environment variable holding the default store directory.
const StoreEnv = "ANGOU_STORE"

// prefStore is where the chosen store directory is remembered.
const prefStore = "store.dir"

// storeDir is the store this window is working with, or empty when none has
// been chosen.
//
// $ANGOU_STORE wins when it is set, so a shell that already names a store keeps
// naming it and the CLI and the GUI agree in that session. Otherwise the
// remembered choice is used, because a GUI is normally launched from a desktop
// entry with no environment at all — requiring the variable would mean the
// taskbar icon always led to first-run setup.
//
// A store path is not a secret. It is already in $ANGOU_STORE, in the shell
// history of anyone using the CLI, and in doctor's output. What is never
// written here is a fingerprint, a passphrase, or anything out of the store.
func (u *ui) storeDir() string {
	if v := os.Getenv(StoreEnv); v != "" {
		return v
	}
	return u.app.Preferences().String(prefStore)
}

// setStoreDir remembers a store and reloads everything for it.
func (u *ui) setStoreDir(dir string) {
	u.app.Preferences().SetString(prefStore, dir)
	u.session = Session{StoreDir: dir}
	// Everything on screen describes the previous store.
	u.entries, u.entriesOK = nil, false
	u.doctor, u.doctorOK = nil, false
	u.releases, u.agentOK = nil, false
	u.candidates = nil
	u.rebuild()
	if os.Getenv(StoreEnv) != "" && os.Getenv(StoreEnv) != dir {
		u.flash("$"+StoreEnv+" is set and takes precedence, so this window is still using "+
			os.Getenv(StoreEnv)+".", StatusWarn)
	}
}

// guiSecrets asks for a passphrase in a modal dialog.
//
// The buffer it returns is core's to zero. This type keeps no copy: R7.2 forbids
// a passphrase living in a widget, a field, or a closure past the operation that
// needed it, and a struct field here would be exactly that.
type guiSecrets struct{ u *ui }

func (g guiSecrets) Recovery(prompt string) ([]byte, error) {
	answer := make(chan []byte, 1)
	fyne.Do(func() { g.u.askPassphrase(prompt, answer) })
	secret := <-answer
	if secret == nil {
		return nil, core.ErrNoSecret
	}
	return secret, nil
}

// guiDecider answers core's mid-operation questions in a dialog.
type guiDecider struct{ u *ui }

func (g guiDecider) Ask(d core.Decision) bool {
	answer := make(chan bool, 1)
	fyne.Do(func() { g.u.askDecision(d, answer) })
	return <-answer
}

// events routes core's reporting into the window: verbose logging is dropped
// (there is no stderr to write to and no --verbose to ask for it), and notices
// become banners.
//
// The wording is core's, unchanged. That is the point of the contract: the two
// front ends must not drift into telling users different things about the same
// state.
func (u *ui) events() core.Events {
	return core.Events{
		Notice: func(msg string) {
			fyne.Do(func() { u.flash(msg, StatusWarn) })
		},
	}
}

// withSession runs fn against an open store, off the UI thread.
//
// The session is not cached between calls. Holding one open for the lifetime of
// the window would keep the unlocked identity in memory for as long as the
// window is up, which is the agent's job -- bounded and visible -- rather than
// something a window should do quietly. Where that cost is real, the answer is
// to start an agent, not to make this window a worse one.
func (u *ui) withSession(what string, fn func(*core.Session) error) {
	dir := u.storeDir()
	if dir == "" {
		u.flash("No store is configured. Set $"+StoreEnv+" or run the first-run setup.", StatusBad)
		return
	}
	go func() {
		done := u.busy(what + "…")
		defer done()

		s, err := core.Open(dir, guiSecrets{u: u}, u.events())
		if err != nil {
			// Mark the load attempted. Without this a failed or cancelled open
			// leaves the section asking again on the next rebuild, which turns
			// one declined passphrase dialog into an endless run of them.
			fyne.Do(func() { u.entriesOK, u.doctorOK, u.agentOK = true, true, true })
			u.report(what, err)
			return
		}
		if err := fn(s); err != nil {
			u.report(what, err)
		}
	}()
}

// report puts an error on screen, or says nothing when the user simply declined.
func (u *ui) report(what string, err error) {
	if errors.Is(err, core.ErrNoSecret) || errors.Is(err, core.ErrDeclined) {
		return // the user answered no; that is not a failure to report
	}
	fyne.Do(func() { u.flash(what+": "+err.Error(), StatusBad) })
}

// ok reports a completed operation and refreshes the current section.
func (u *ui) ok(msg string) {
	fyne.Do(func() {
		u.flash(msg, StatusGood)
		u.refresh()
	})
}

// Loaded data.
//
// Each section renders from these and asks for them when they are empty. They
// are filled on a goroutine and the section is rebuilt when they arrive, which
// is what keeps the window responsive while a store is being opened -- opening
// one can mean an Argon2id derivation and a passphrase dialog.

// loadEntries fills the store listing.
func (u *ui) loadEntries() {
	u.withSession("Open the store", func(s *core.Session) error {
		entries := make([]StoreEntry, 0, len(s.List()))
		for _, e := range s.List() {
			entries = append(entries, entryFrom(s, e))
		}
		trusted, route := s.IndexTrusted(), s.Route()
		fyne.Do(func() {
			u.entries, u.entriesOK = entries, true
			// The status bar names the route, so it is redrawn rather than
			// left showing what was true before the store was opened.
			u.session.Route = route
			if !trusted {
				u.flash("The index is missing or did not verify, so this listing is empty. "+
					"Reindex rebuilds it from the blobs themselves.", StatusWarn)
			}
			u.rebuild()
		})
		return nil
	})
}

// loadDoctor fills the diagnostic report.
//
// core.NoSecrets, not the dialog: doctor is what someone runs when a command is
// already failing in a way they do not understand, and opening it with a
// passphrase prompt would be a worse diagnostic. The report is smaller without
// the store-level facts, not wrong.
func (u *ui) loadDoctor() {
	dir := u.storeDir()
	if dir == "" {
		return
	}
	go func() {
		done := u.busy("Inspecting the store and this machine…")
		defer done()
		r := core.Doctor(dir, core.NoSecrets{}, core.Events{})
		groups := make([]DoctorGroup, 0, len(r.Sections))
		for _, sec := range r.Sections {
			g := DoctorGroup{Title: sec.Title}
			for _, f := range sec.Findings {
				g.Rows = append(g.Rows, DoctorRow{
					Label:  f.Label,
					Value:  f.Value,
					Status: statusFrom(f.Severity),
				})
			}
			groups = append(groups, g)
		}
		fyne.Do(func() {
			u.doctor, u.doctorOK = groups, true
			u.refresh()
		})
	}()
}

// loadAgent fills the session-cache state.
func (u *ui) loadAgent() {
	dir := u.storeDir()
	if dir == "" {
		return
	}
	go func() {
		done := u.busy("Checking for an agent session…")
		defer done()
		st, err := core.AgentState(dir)
		if err != nil {
			// Not worth a banner: an unreachable agent is the normal case. Mark
			// it loaded anyway, or the section asks again on every rebuild.
			fyne.Do(func() { u.agentOK = true })
			return
		}
		socket, _ := core.AgentSocket(dir)
		fyne.Do(func() {
			u.agentOK = true
			u.session.Agent = AgentState{
				Running:   st.Running && !st.Expired,
				Remaining: st.Remaining,
				Socket:    socket,
			}
			u.refresh()
		})
	}()
}

// entryFrom converts a core listing row into what the table renders.
func entryFrom(s *core.Session, e store.IndexEntry) StoreEntry {
	// The blob name is derived rather than stored in the index: it is the keyed
	// hash of the logical path, which is what makes the store's filenames
	// disclose nothing about what is in it.
	raw, err := s.BlobID(e.Path)
	if err != nil {
		raw = ""
	}
	return StoreEntry{
		LogicalPath: e.Path,
		RawName:     raw,
		Size:        e.Size,
		Mode:        e.Mode,
		Modified:    time.Unix(e.MTime, 0),
		Origin:      e.Origin,
	}
}

// statusFrom maps a core severity onto the window's own ranking. They are
// deliberately separate types: core's is about the finding, this one is about
// how to paint it.
func statusFrom(s core.Severity) Status {
	switch s {
	case core.SeverityGood:
		return StatusGood
	case core.SeverityWarn:
		return StatusWarn
	case core.SeverityBad:
		return StatusBad
	}
	return StatusInfo
}

// formatMode renders a POSIX mode as rwxr-xr-x. The CLI has its own copy beside
// its listing code; the two are small, independent, and would be a worse
// dependency than a duplicate.
func formatMode(mode uint32) string {
	const bits = "rwxrwxrwx"
	out := []byte("---------")
	for i := 0; i < 9; i++ {
		if mode&(1<<uint(8-i)) != 0 {
			out[i] = bits[i]
		}
	}
	return string(out)
}

// encryptSelected encrypts the ticked candidates.
//
// The checkbox list is the decider: core asks about each file, and the answer
// is already recorded. That is the same operation the CLI runs with --auto,
// with a different Decider behind it — which is the whole point of the contract.
func (u *ui) encryptSelected(cands []ScanCandidate) {
	var chosen []core.Candidate
	for _, c := range cands {
		if c.Selected && !c.Stored {
			chosen = append(chosen, core.Candidate{Path: c.Path, Reason: c.Reason, Size: c.Size})
		}
	}
	if len(chosen) == 0 {
		u.flash("Nothing is selected.", StatusWarn)
		return
	}

	u.withSession("Encrypt", func(s *core.Session) error {
		r, err := s.EncryptCandidates(context.Background(), chosen, angoucontainer.EncodingArmor,
			core.DeciderFunc(func(core.Decision) bool { return true }), core.EncryptProgress{
				Skipped: func(src string, err error) {
					if err != nil {
						path := src
						cause := err
						fyne.Do(func() { u.flash("Skipped "+path+": "+cause.Error(), StatusWarn) })
					}
				},
			})
		if err != nil {
			return err
		}
		u.ok(fmt.Sprintf("Encrypted %d, skipped %d. The originals are untouched.", r.Stored, r.Skipped))
		return nil
	})
}

// createStore is the first-run flow: init, then optionally set this machine up.
//
// The passphrase is shown only after the store it opens exists. Telling someone
// to write down a phrase before the thing it unlocks has been created hands them
// a phrase that opens nothing when creation fails — and creation does fail, on a
// full disk, an unwritable directory, or a machine without the memory for the
// derivation.
func (u *ui) createStore(dir string, generate, bootstrap bool) {
	if dir == "" {
		u.flash("Choose a directory for the store first.", StatusWarn)
		return
	}
	if core.StoreExists(dir) {
		u.flash(dir+" already holds a store, so there is nothing to initialize.", StatusBad)
		return
	}

	go func() {
		// Slow in a way that needs saying: creating a store derives a key with
		// Argon2id and generates a keypair, and a window that looks frozen
		// invites a second click on a button that must not run twice.
		done := u.busy("Creating the store at " + dir + "…")
		defer done()

		var (
			secret    []byte
			bits      float64
			generated bool
		)
		if generate {
			phrase, b, err := core.GeneratePassphrase()
			if err != nil {
				u.report("Create the store", err)
				return
			}
			secret, bits, generated = []byte(phrase), b, true
		} else {
			var err error
			secret, err = guiSecrets{u: u}.Recovery("Choose a recovery passphrase:")
			if err != nil {
				u.report("Create the store", err)
				return
			}
			bits, err = core.CheckPassphrase(string(secret))
			if err != nil {
				zero(secret)
				u.report("Create the store", err)
				return
			}
		}
		defer zero(secret)

		s, err := core.Init(dir, secret, u.events())
		if err != nil {
			u.report("Create the store", err)
			return
		}
		if generated {
			shown := string(secret)
			fyne.Do(func() { u.showRecoveryPassphrase(shown, bits) })
		}

		if !bootstrap {
			fyne.Do(func() { u.setStoreDir(dir) })
			u.ok("Created the store at " + dir + ".")
			return
		}
		exported, err := s.ExportLocalIdentity()
		if err != nil {
			u.report("Set this machine up", err)
			return
		}
		defer zero(exported)
		if _, err := s.SetUpMachine(exported); err != nil {
			u.report("Set this machine up", err)
			return
		}
		fyne.Do(func() { u.setStoreDir(dir) })
		u.ok("Created the store at " + dir + " and set this machine up.")
	}()
}
