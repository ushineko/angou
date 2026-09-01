package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// passphraseDialog is the prototype of R7.1: a modal, masked entry whose
// backing buffer is zeroed when the dialog closes by any path.
//
// The zeroing here is honest about its reach. We can zero the []byte we take a
// copy into, and we do. We cannot zero the Go string inside the Entry widget:
// strings are immutable and the runtime may have copied or relocated it
// already. That is the R7.3 limitation, and it is the reason the README will
// describe the GUI's memory hygiene as weaker than the CLI's terminal read
// rather than equivalent to it.
func (u *ui) passphraseDialog(title, blurb string) {
	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder("recovery passphrase")

	note := widget.NewLabel(blurb)
	note.Wrapping = fyne.TextWrapWord

	caveat := widget.NewLabel(
		"The passphrase is used for this operation and discarded. It is not kept while " +
			"the window is open; to avoid retyping, start an agent session, which expires on its own.")
	caveat.Wrapping = fyne.TextWrapWord
	caveat.Importance = widget.LowImportance

	body := container.NewVBox(note, entry, widget.NewSeparator(), caveat)

	d := dialog.NewCustomConfirm(title, "Continue", "Cancel", body, func(ok bool) {
		secret := []byte(entry.Text)
		defer zero(secret)
		entry.SetText("")
		if ok {
			u.notWired(title, "the core operation, with the passphrase supplied by callback")
		}
	}, u.win)
	d.Resize(fyne.NewSize(460, 260))
	d.Show()
	u.win.Canvas().Focus(entry)
}

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
		"To the clipboard",
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
		if overwrite.Checked {
			u.confirmDestructive("Replace "+path.Text+"?",
				"A file already exists there. Decrypting will overwrite it, and what is "+
					"there now is not recoverable from the store.",
				"Replace", func() { u.notWired("Decrypt", "dec --overwrite") })
			return
		}
		u.notWired("Decrypt", "dec")
	}, u.win)
}

// progressDialog stands in for R3.4: a long operation reports progress and can
// be cancelled. Cancellation is the requirement worth seeing early — a GUI that
// cannot stop a re-encryption of every blob is not a usable GUI.
func (u *ui) progressDialog(title, step string) {
	bar := widget.NewProgressBar()
	bar.SetValue(0.375)
	label := widget.NewLabel(step)

	d := dialog.NewCustomWithoutButtons(title, container.NewVBox(bar, label), u.win)
	stop := widget.NewButton("Cancel", func() { d.Hide() })
	d.SetButtons([]fyne.CanvasObject{stop})
	d.Resize(fyne.NewSize(420, 200))
	d.Show()
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
		if ok {
			u.notWired("Create the store", "init, then bootstrap")
		}
	}, u.win)
	d.Resize(fyne.NewSize(540, 380))
	d.Show()
}

// notWired is the prototype's honest dead end. Every action reports which core
// operation it will call rather than pretending to have done something.
func (u *ui) notWired(what, cmd string) {
	body := container.NewVBox(
		widget.NewLabelWithStyle(what, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Not wired up in this prototype."),
		widget.NewSeparator(),
		widget.NewLabel("Pass 3 routes this to internal/core:"),
		widget.NewLabelWithStyle(cmd, fyne.TextAlignLeading, fyne.TextStyle{Monospace: true}),
	)
	d := dialog.NewCustom("Prototype", "Close", body, u.win)
	d.Resize(fyne.NewSize(440, 260))
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
