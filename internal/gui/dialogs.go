package gui

import (
	"fmt"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	angoucontainer "github.com/ushineko/angou/internal/container"
	"github.com/ushineko/angou/internal/core"
)

// zero overwrites a secret buffer. Best effort: Go's garbage collector may have
// already copied the value elsewhere. Never described as a guarantee.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// confirmDestructive is R6.1: a confirmation that names what is about to happen
// in at least the detail the CLI gives, with the destructive button styled as
// destructive and the cancel as the safe default.
func (u *ui) confirmDestructive(title, detail, confirm string, do func()) {
	body := widget.NewLabel(detail)
	body.Wrapping = fyne.TextWrapWord

	d := dialog.NewCustomWithoutButtons(title, container.NewVBox(body), u.win)

	cancel := widget.NewButton("Cancel", func() { d.Hide() })
	proceed := widget.NewButton(confirm, func() {
		d.Hide()
		do()
	})
	proceed.Importance = widget.DangerImportance

	d.SetButtons([]fyne.CanvasObject{cancel, proceed})
	d.Resize(fyne.NewSize(520, 300))
	d.Show()
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

// firstRun is R5.9: with no store configured, the window opens on setup rather
// than on an empty table full of errors. Reachable from the header in the
// prototype so it can be reviewed without unconfiguring the machine.
func (u *ui) firstRun() {
	dir := widget.NewEntry()
	dir.SetPlaceHolder("where the store directory will be created")

	generate := widget.NewCheck("Generate the recovery passphrase and show it once", nil)
	generate.SetChecked(true)

	bootstrap := widget.NewCheck("Set this machine up so it does not ask for the passphrase every time", nil)
	bootstrap.SetChecked(true)

	warn := widget.NewLabel(
		"The recovery passphrase is shown once and is not stored anywhere angou can reach. " +
			"If it is lost and no machine holds a local key, the store cannot be opened — not by " +
			"you and not by us.")
	warn.Wrapping = fyne.TextWrapWord
	warn.Importance = widget.WarningImportance

	body := container.NewVBox(
		widget.NewLabel("No store is configured on this machine."),
		widget.NewForm(widget.NewFormItem("Store directory", dir)),
		generate, bootstrap,
		widget.NewSeparator(),
		warn,
	)

	d := dialog.NewCustomConfirm("Set up angou", "Create the store", "Cancel", body, func(ok bool) {
		if !ok {
			return
		}
		u.createStore(dir.Text, generate.Checked, bootstrap.Checked)
	}, u.win)
	d.Resize(fyne.NewSize(540, 380))
	d.Show()
}

// fixedHeight and fixedWidth pin a widget's minimum size. Fyne's list and table
// take all the space they are given; these keep a section's layout stable while
// it is being looked at.
func fixedHeight(o fyne.CanvasObject, h float32) fyne.CanvasObject {
	pad := canvas.NewRectangle(nil)
	pad.SetMinSize(fyne.NewSize(0, h))
	return container.New(layout.NewStackLayout(), pad, o)
}

func fixedWidth(o fyne.CanvasObject, w float32) fyne.CanvasObject {
	pad := canvas.NewRectangle(nil)
	pad.SetMinSize(fyne.NewSize(w, 0))
	return container.New(layout.NewStackLayout(), pad, o)
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

// pathDialog is the shape most of these take: a heading, one or more fields,
// and a confirm that hands the values to a core call.
func (u *ui) pathDialog(title, confirm string, body fyne.CanvasObject, do func()) {
	d := dialog.NewCustomConfirm(title, confirm, "Cancel", body, func(ok bool) {
		if ok {
			do()
		}
	}, u.win)
	d.Resize(fyne.NewSize(560, 300))
	d.Show()
}

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

	u.pathDialog("Extract "+e.LogicalPath, "Extract",
		container.NewVBox(widget.NewForm(widget.NewFormItem("Destination", dest)), note),
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

	u.pathDialog("Rename "+e.LogicalPath, "Rename",
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

	u.pathDialog("Encrypt a file", "Encrypt", container.NewVBox(widget.NewForm(
		widget.NewFormItem("File", src),
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

	u.pathDialog("Clone the store", "Clone", container.NewVBox(
		widget.NewForm(widget.NewFormItem("Destination", to)), noBinaries), func() {
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

	u.pathDialog("Choose a store", "Use this store",
		container.NewVBox(widget.NewForm(widget.NewFormItem("Directory", dir)), note, env),
		func() {
			if !core.StoreExists(dir.Text) {
				u.flash(dir.Text+" does not hold a store. Use first-run setup to create one.", StatusBad)
				return
			}
			u.setStoreDir(dir.Text)
			u.flash("Now using the store at "+dir.Text, StatusGood)
		})
}
