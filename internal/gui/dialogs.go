package gui

import (
	"fmt"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	angoucontainer "github.com/ushineko/angou/internal/container"

	fd "github.com/ushineko/fynedesygn"
	"github.com/ushineko/fynedesygn/dialogs"

	"github.com/ushineko/angou/internal/core"
)

// zero overwrites a secret buffer. Best effort: Go's garbage collector may have
// already copied the value elsewhere. Never described as a guarantee.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// decryptDialog shows the choices `dec` takes as flags: where the plaintext
// goes, and whether an existing file may be replaced.
func (u *ui) decryptDialog(e StoreEntry) {
	dest := widget.NewRadioGroup([]string{
		"Back to where it came from",
		"To another path…",
	}, nil)
	if e.Origin == "" {
		dest.Options[0] = "Back to where it came from (no origin recorded)"
		dest.Disable()
		dest.SetSelected("To another path…")
	} else {
		dest.SetSelected("Back to where it came from")
	}

	path := widget.NewEntry()
	path.SetText(originOrNone(e))

	overwrite := widget.NewCheck("Replace an existing file at that path", nil)

	body := container.NewVBox(
		widget.NewLabelWithStyle(e.LogicalPath, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		dest, path, overwrite,
	)

	dialog.ShowCustomConfirm("Decrypt", "Decrypt", "Cancel", body, func(ok bool) {
		if !ok {
			return
		}
		toPath, overwriteChecked := path.Text, overwrite.Checked
		restore := dest.Selected == "Back to where it came from"

		u.withSession("Decrypt", func(s *core.Session) error {
			env, err := s.Get(e.LogicalPath)
			if err != nil {
				return err
			}
			if restore {
				// core asks the questions; guiDecider puts them on screen. The
				// destructive one keeps its no default, so a dialog dismissed
				// rather than answered does not replace a file.
				target, err := core.RestoreToOrigin(env, overwriteChecked, guiDecider{u: u})
				if err != nil {
					return err
				}
				u.ok("Restored " + e.LogicalPath + " to " + target)
				return nil
			}
			if err := core.WriteTo(toPath, env); err != nil {
				return err
			}
			u.ok("Wrote " + e.LogicalPath + " to " + toPath)
			return nil
		})
	}, u.win)
}

// firstRunForm is the first-run dialog's contents, kept separate from the dialog
// so the swap between its two paths can be tested without a window manager.
// Clicking a radio option is not something a headless test can do, and the
// failure it would miss — both bodies visible, or neither — is the whole of the
// rework.
type firstRunForm struct {
	body          fyne.CanvasObject
	choice        *widget.RadioGroup
	openDir       *widget.Entry
	openBootstrap *widget.Check
	newDir        *widget.Entry
	generate      *widget.Check
	bootstrap     *widget.Check
	openBody      *fyne.Container
	newBody       *fyne.Container
}

const (
	firstRunOpen   = "Open a store that already exists"
	firstRunCreate = "Create a new store"
)

func (u *ui) newFirstRunForm() *firstRunForm {
	f := &firstRunForm{}

	// --- open an existing store
	f.openDir = widget.NewEntry()
	f.openDir.SetText(u.storeDir())
	f.openDir.SetPlaceHolder("the store directory, wherever it synced to")

	f.openBootstrap = widget.NewCheck("Set this machine up so it does not ask for the passphrase every time", nil)
	f.openBootstrap.SetChecked(true)

	openNote := widget.NewLabel(
		"A store is a plain directory, so on every machine after the first it is already " +
			"here — synced, copied, or on a drive you plugged in. Opening it asks for the " +
			"recovery passphrase now, and with the box ticked this machine keeps a local key " +
			"afterwards and stops asking.")
	openNote.Wrapping = fyne.TextWrapWord
	openNote.Importance = widget.LowImportance

	f.openBody = container.NewVBox(
		widget.NewForm(widget.NewFormItem("Directory", dialogs.WithBrowse(u.win, f.openDir, true))),
		f.openBootstrap,
		openNote,
	)

	// --- create a new one
	f.newDir = widget.NewEntry()
	f.newDir.SetPlaceHolder("where the store directory will be created")

	f.generate = widget.NewCheck("Generate the recovery passphrase and show it once", nil)
	f.generate.SetChecked(true)

	f.bootstrap = widget.NewCheck("Set this machine up so it does not ask for the passphrase every time", nil)
	f.bootstrap.SetChecked(true)

	warn := widget.NewLabel(
		"The recovery passphrase is shown once and is not stored anywhere angou can reach. " +
			"If it is lost and no machine holds a local key, the store cannot be opened — not by " +
			"you and not by us.")
	warn.Wrapping = fyne.TextWrapWord
	warn.Importance = widget.WarningImportance

	f.newBody = container.NewVBox(
		widget.NewForm(widget.NewFormItem("Directory", dialogs.WithBrowse(u.win, f.newDir, true))),
		f.generate, f.bootstrap,
		widget.NewSeparator(),
		warn,
	)
	f.newBody.Hide()

	f.choice = widget.NewRadioGroup([]string{firstRunOpen, firstRunCreate}, func(sel string) {
		if sel == firstRunCreate {
			f.openBody.Hide()
			f.newBody.Show()
			return
		}
		f.newBody.Hide()
		f.openBody.Show()
	})
	f.choice.SetSelected(firstRunOpen)

	f.body = container.NewVBox(
		widget.NewLabel("No store is configured on this machine."),
		f.choice,
		widget.NewSeparator(),
		f.openBody,
		f.newBody,
	)
	return f
}

// firstRun is R5.9: with no store configured, the window opens here rather than
// on an empty table full of errors about a directory that was never chosen.
//
// It offers both paths, with the existing one first and selected. An earlier
// version offered only creation — one dialog titled "Set up angou" whose only
// button was "Create the store" — which reads as though angou has nothing to say
// to a machine that already has a store. That is the ordinary case, not the
// unusual one: the store is a plain directory built to be synced, so every
// machine after the first meets angou with the store already sitting on disk,
// and reaching it meant cancelling this dialog and finding a header button.
//
// Reachable from the header too, so it can be reviewed without unconfiguring the
// machine.
func (u *ui) firstRun() {
	f := u.newFirstRunForm()
	d := dialog.NewCustomConfirm("angou", "Continue", "Cancel", f.body, func(ok bool) {
		if !ok {
			return
		}
		if f.choice.Selected == firstRunCreate {
			u.createStore(f.newDir.Text, f.generate.Checked, f.bootstrap.Checked)
			return
		}
		u.openExistingStore(f.openDir.Text, f.openBootstrap.Checked)
	}, u.win)
	d.Resize(fyne.NewSize(560, 460))
	d.Show()
}

// useStore points the window at a store directory and remembers it, or says why
// it will not. Shared by first-run and the header's Store button, so the two
// cannot disagree about what counts as a store.
func (u *ui) useStore(dir string) bool {
	if dir == "" {
		u.flash("Choose the directory the store is in first.", fd.StatusWarn)
		return false
	}
	if !core.StoreExists(dir) {
		u.flash(dir+" does not hold a store. Check the path, or create a store there instead.",
			fd.StatusBad)
		return false
	}
	u.setStoreDir(dir)
	return true
}

// openExistingStore is the first-run path for a machine the store has synced to.
//
// It opens the store there and then rather than remembering the path and leaving
// the window to open it whenever something is navigated to. On a machine with no
// local key that open is the passphrase prompt, and the prompt is the next step:
// deferring it left someone looking at a window that had accepted their directory
// and then asked them for nothing, with the operation that would finish the job
// sitting in a different section.
func (u *ui) openExistingStore(dir string, bootstrap bool) {
	if !u.useStore(dir) {
		return
	}
	if !bootstrap || core.HasLocalKey(dir) {
		// Already set up here, or not asked for: opening the listing is the
		// whole of it, and that is what prompts.
		u.loadEntries()
		return
	}
	u.withSession("Open the store", func(s *core.Session) error {
		exported, err := s.ExportLocalIdentity()
		if err != nil {
			return err
		}
		defer zero(exported)
		r, err := s.SetUpMachine(exported)
		if err != nil {
			return err
		}
		if r.UsedKeyring {
			u.ok("Opened the store at " + dir + " and set this machine up.")
		} else {
			// Said rather than skipped: without a keyring the local key is not
			// re-protected here, so the passphrase is still what opens the store
			// and the user should not be told otherwise.
			u.flash("Opened the store at "+dir+", but this machine has no keyring, so the "+
				"identity was not re-protected here and the recovery passphrase is still "+
				"what opens the store.", fd.StatusWarn)
		}
		// The session that just bootstrapped holds the store open; the listing
		// is fetched with it rather than by opening a second time.
		fyne.Do(u.loadEntries)
		return nil
	})
}

// askPassphrase puts core's passphrase request on screen and sends the answer
// back down the channel. Called on the UI thread, by guiSecrets.
//
// The buffer sent is a copy the caller owns and zeroes. What cannot be cleaned
// up is the Go string inside the Entry: strings are immutable and the runtime
// may already have copied it. That is the R7.3 limitation, stated in About and
// in the README rather than papered over.
func (u *ui) askPassphrase(prompt string, answer chan<- []byte) {
	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder("recovery passphrase")

	note := widget.NewLabel(prompt)
	note.Wrapping = fyne.TextWrapWord

	caveat := widget.NewLabel(
		"Used for this operation and discarded. It is not kept while the window is open; " +
			"to avoid retyping, start an agent session, which expires on its own.")
	caveat.Wrapping = fyne.TextWrapWord
	caveat.Importance = widget.LowImportance

	sent := false
	send := func(v []byte) {
		if !sent {
			sent = true
			answer <- v
		}
	}

	d := dialog.NewCustomConfirm("angou", "Continue", "Cancel",
		container.NewVBox(note, entry, widget.NewSeparator(), caveat),
		func(ok bool) {
			if !ok {
				send(nil)
				entry.SetText("")
				return
			}
			secret := []byte(entry.Text)
			entry.SetText("")
			send(secret)
		}, u.win)
	d.Resize(fyne.NewSize(460, 260))
	d.Show()
	u.win.Canvas().Focus(entry)
}

// askDecision puts one of core's mid-operation questions on screen. The
// destructive ones get the destructive styling and keep their no default, the
// same way the CLI keeps the safe answer safe when there is nobody to ask.
func (u *ui) askDecision(dec core.Decision, answer chan<- bool) {
	body := widget.NewLabel(dec.Question)
	body.Wrapping = fyne.TextWrapWord

	d := dialog.NewCustomWithoutButtons("angou", container.NewVBox(body), u.win)

	sent := false
	send := func(v bool) {
		if !sent {
			sent = true
			answer <- v
		}
		d.Hide()
	}

	no := widget.NewButton("No", func() { send(false) })
	yes := widget.NewButton("Yes", func() { send(true) })
	if dec.Destructive {
		yes.Importance = widget.DangerImportance
	} else if dec.Default {
		yes.Importance = widget.HighImportance
	}
	d.SetButtons([]fyne.CanvasObject{no, yes})
	d.Resize(fyne.NewSize(500, 240))
	d.Show()
}

// --- operation dialogs -----------------------------------------------------

// extractDialog asks for a destination root. Extraction is confined beneath it
// and will not traverse a symlink to leave it, because a stored path is
// untrusted input: whoever can write to the store chooses it.
func (u *ui) extractDialog(e StoreEntry) {
	dest := widget.NewEntry()
	dest.SetPlaceHolder("destination root")

	note := widget.NewLabel("Every write is confined beneath this directory, and its own " +
		"directories are recreated inside it. The stored mode and modification time are restored.")
	note.Wrapping = fyne.TextWrapWord
	note.Importance = widget.LowImportance

	dialogs.Prompt(u.win, "Extract "+e.LogicalPath, "Extract",
		container.NewVBox(widget.NewForm(widget.NewFormItem("Destination", dialogs.WithBrowse(u.win, dest, true))), note),
		func() {
			u.withSession("Extract", func(s *core.Session) error {
				written, err := s.Extract(e.LogicalPath, dest.Text)
				if err != nil {
					return err
				}
				u.ok("Extracted to " + written)
				return nil
			})
		})
}

// renameDialog re-addresses a blob. The logical path is part of the signed
// envelope and is bound to the blob's filename, so the two change together
// rather than by renaming a file on disk.
func (u *ui) renameDialog(e StoreEntry) {
	to := widget.NewEntry()
	to.SetText(e.LogicalPath)

	note := widget.NewLabel("The blob is rewritten under the new path rather than renamed: " +
		"the path is inside the signed envelope and addresses the file on disk.")
	note.Wrapping = fyne.TextWrapWord
	note.Importance = widget.LowImportance

	dialogs.Prompt(u.win, "Rename "+e.LogicalPath, "Rename",
		container.NewVBox(widget.NewForm(widget.NewFormItem("New path", to)), note),
		func() {
			u.withSession("Rename", func(s *core.Session) error {
				if err := s.Move(e.LogicalPath, to.Text); err != nil {
					return err
				}
				u.ok("Renamed to " + to.Text)
				return nil
			})
		})
}

// encryptFileDialog encrypts one file. The plaintext is left where it is:
// removing an original is a separate, deliberate step, and angou will not
// delete a file you have not seen it store first.
func (u *ui) encryptFileDialog() {
	src := widget.NewEntry()
	src.SetPlaceHolder("file to encrypt")
	as := widget.NewEntry()
	as.SetPlaceHolder("store path (leave empty to derive one)")
	binary := widget.NewCheck("Store raw OpenPGP packets instead of ASCII armor", nil)

	dialogs.Prompt(u.win, "Encrypt a file", "Encrypt", container.NewVBox(widget.NewForm(
		widget.NewFormItem("File", dialogs.WithBrowse(u.win, src, false)),
		widget.NewFormItem("Store as", as),
	), binary), func() {
		u.withSession("Encrypt", func(s *core.Session) error {
			res, err := s.EncryptFile(src.Text, as.Text, encodingFor(binary.Checked))
			if err != nil {
				return err
			}
			u.ok("Stored as " + res.LogicalPath + ". The original is untouched.")
			return nil
		})
	})
}

// cloneDialog copies a store to another directory.
func (u *ui) cloneDialog() {
	to := widget.NewEntry()
	to.SetPlaceHolder("destination, which must not already exist")
	noBinaries := widget.NewCheck("Leave the platform binaries behind", nil)

	dialogs.Prompt(u.win, "Clone the store", "Clone", container.NewVBox(
		widget.NewForm(widget.NewFormItem("Destination", dialogs.WithBrowse(u.win, to, true))), noBinaries), func() {
		from := u.storeDir()
		go func() {
			done := u.busy("Copying the store…")
			defer done()
			n, err := core.CopyStore(from, to.Text, noBinaries.Checked)
			if err != nil {
				u.report("Clone", err)
				return
			}
			u.ok(fmt.Sprintf("Copied %d file(s) to %s", n, to.Text))
		}()
	})
}

// encodingFor maps the armor checkbox to a container encoding.
func encodingFor(binary bool) angoucontainer.Encoding {
	if binary {
		return angoucontainer.EncodingBinary
	}
	return angoucontainer.EncodingArmor
}

// showRecoveryPassphrase displays a generated passphrase exactly once.
//
// It is not written anywhere angou can reach, and this dialog is the only time
// it is shown. If it is lost and no machine holds a local key, the store cannot
// be opened — not by the user and not by us.
func (u *ui) showRecoveryPassphrase(phrase string, bits float64) {
	value := widget.NewLabelWithStyle(phrase, fyne.TextAlignCenter, fyne.TextStyle{Monospace: true, Bold: true})
	value.Wrapping = fyne.TextWrapBreak

	warn := widget.NewLabel(fmt.Sprintf(
		"This is shown exactly once, and it is about %.0f bits of entropy. Write it down now, "+
			"somewhere that is not this machine. There is no reset and no backdoor.", bits))
	warn.Wrapping = fyne.TextWrapWord
	warn.Importance = widget.WarningImportance

	d := dialog.NewCustom("Your recovery passphrase", "I have written it down",
		container.NewVBox(value, widget.NewSeparator(), warn), u.win)
	d.Resize(fyne.NewSize(520, 300))
	d.Show()
}

// chooseStore points the window at a store directory and remembers it.
//
// This is how the application is usable from a desktop entry at all: launched
// from a taskbar there is no environment, so without a remembered choice the
// window would open on first-run setup every time.
func (u *ui) chooseStore() {
	dir := widget.NewEntry()
	dir.SetText(u.storeDir())
	dir.SetPlaceHolder("the store directory")

	note := widget.NewLabel(
		"Remembered between runs, so the desktop entry opens this store. Only the path is " +
			"saved — no fingerprint, no passphrase, and nothing out of the store itself.")
	note.Wrapping = fyne.TextWrapWord
	note.Importance = widget.LowImportance

	env := widget.NewLabel("")
	env.Wrapping = fyne.TextWrapWord
	if v := os.Getenv(StoreEnv); v != "" {
		env.SetText("$" + StoreEnv + " is set to " + v + " and takes precedence over this " +
			"while it is. Unset it to use the remembered choice.")
		env.Importance = widget.WarningImportance
	}

	dialogs.Prompt(u.win, "Choose a store", "Use this store",
		container.NewVBox(widget.NewForm(widget.NewFormItem("Directory", dialogs.WithBrowse(u.win, dir, true))), note, env),
		func() {
			if u.useStore(dir.Text) {
				u.flash("Now using the store at "+dir.Text, fd.StatusGood)
			}
		})
}

// --- file chooser ----------------------------------------------------------
