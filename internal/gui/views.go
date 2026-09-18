package gui

import (
	"fmt"
	"sort"
	"strconv"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	fd "github.com/ushineko/fynedesygn"
	"github.com/ushineko/fynedesygn/dialogs"
	"github.com/ushineko/fynedesygn/shell"
	"github.com/ushineko/fynedesygn/widgets"

	"github.com/ushineko/angou/internal/core"
)

// --- Store (R5.3) ---------------------------------------------------------

func (u *ui) buildStore() fyne.CanvasObject {
	entries := u.entries
	raw := false
	selected := -1
	sortCol, sortAsc := 0, true

	cols := []struct {
		title string
		width float32
	}{{"Path", 320}, {"Size", 90}, {"Mode", 110}, {"Modified", 110}, {"Origin", 300}}

	// resort orders the rows by the active column. It is stable, so re-sorting
	// by a column with ties leaves the previous order inside each tie rather
	// than shuffling rows the user was not asking about.
	resort := func() {
		sort.SliceStable(entries, func(i, j int) bool {
			a, b := entries[i], entries[j]
			less := false
			switch sortCol {
			case 0:
				if raw {
					less = a.RawName < b.RawName
				} else {
					less = a.LogicalPath < b.LogicalPath
				}
			case 1:
				less = a.Size < b.Size
			case 2:
				less = a.Mode < b.Mode
			case 3:
				less = a.Modified.Before(b.Modified)
			case 4:
				less = a.Origin < b.Origin
			}
			if sortAsc {
				return less
			}
			return !less
		})
	}
	resort()

	table := widget.NewTable(
		func() (int, int) { return len(entries), len(cols) },
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.Truncation = fyne.TextTruncateEllipsis
			return l
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			e := entries[id.Row]
			l := o.(*widget.Label)
			l.Importance = widget.MediumImportance
			switch id.Col {
			case 0:
				if raw {
					l.SetText(e.RawName)
				} else {
					l.SetText(e.LogicalPath)
				}
			case 1:
				l.SetText(widgets.HumanSize(e.Size))
			case 2:
				l.SetText(formatMode(e.Mode))
			case 3:
				l.SetText(widgets.HumanAgo(e.Modified))
			case 4:
				if e.Origin == "" {
					l.SetText("— none recorded")
					l.Importance = widget.LowImportance
				} else {
					l.SetText(e.Origin)
				}
			}
		},
	)
	// Row actions are disabled until a row is selected: R6.2 keeps a
	// destructive action from being the thing a stray Enter key reaches.
	dec := widget.NewButtonWithIcon("Decrypt", theme.VisibilityIcon(), nil)
	get := widget.NewButtonWithIcon("Extract to…", theme.FolderOpenIcon(), nil)
	mv := widget.NewButtonWithIcon("Rename", theme.DocumentIcon(), nil)
	rm := widget.NewButtonWithIcon("Remove", theme.DeleteIcon(), nil)
	rm.Importance = widget.DangerImportance
	rowActions := []*widget.Button{dec, get, mv, rm}
	for _, b := range rowActions {
		b.Disable()
	}

	table.ShowHeaderRow = true
	// Headers are buttons so a click can sort. A plain label cannot receive the
	// tap, and the arrow has to live in the header text because Fyne gives a
	// header cell one object.
	table.CreateHeader = func() fyne.CanvasObject {
		b := widget.NewButton("", nil)
		b.Importance = widget.LowImportance
		b.Alignment = widget.ButtonAlignLeading
		return b
	}
	table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		b := o.(*widget.Button)
		// Row headers are disabled in this table, but UpdateHeader is still
		// called with Col == -1 for the corner cell. Guard it rather than
		// indexing cols with a negative number.
		if id.Col < 0 || id.Col >= len(cols) {
			b.SetText("")
			b.OnTapped = nil
			return
		}
		title := cols[id.Col].title
		if id.Col == sortCol {
			if sortAsc {
				title += "  ↑"
			} else {
				title += "  ↓"
			}
		}
		b.SetText(title)
		col := id.Col
		b.OnTapped = func() {
			if sortCol == col {
				sortAsc = !sortAsc
			} else {
				sortCol, sortAsc = col, true
			}
			resort()
			// The selection indexed into the old order, so it no longer names
			// the row the user picked. Clearing it is the honest response:
			// carrying it over would leave the destructive buttons armed
			// against a different file than the one highlighted.
			selected = -1
			table.UnselectAll()
			for _, btn := range rowActions {
				btn.Disable()
			}
			table.Refresh()
		}
	}
	for i, c := range cols {
		table.SetColumnWidth(i, c.width)
	}

	table.OnSelected = func(id widget.TableCellID) {
		selected = id.Row
		for _, b := range rowActions {
			b.Enable()
		}
	}
	dec.OnTapped = func() { u.decryptDialog(entries[selected]) }
	get.OnTapped = func() { u.extractDialog(entries[selected]) }
	mv.OnTapped = func() { u.renameDialog(entries[selected]) }
	rm.OnTapped = func() {
		e := entries[selected]
		dialogs.ConfirmDestructive(u.sh.Window, "Remove "+e.LogicalPath+"?",
			"This deletes the blob and its index entry from the store. The plaintext at "+
				originOrNone(e)+" is not touched.\n\nThere is no undo inside angou. If the "+
				"store is the only copy, this is the only copy.",
			"Remove", func() {
				u.withSession("Remove", func(s *core.Session) error {
					if err := s.Remove(e.LogicalPath); err != nil {
						return err
					}
					u.ok("Removed " + e.LogicalPath)
					return nil
				})
			})
	}

	rawToggle := widget.NewCheck("Show the store as it sits on disk (ls --raw)", func(b bool) {
		raw = b
		if sortCol == 0 {
			resort() // column 0 sorts on a different key in raw mode
		}
		table.Refresh()
	})

	toolbar := container.NewHBox(
		widget.NewButtonWithIcon("Encrypt file…", theme.ContentAddIcon(), func() { u.encryptFileDialog() }),
		widget.NewButtonWithIcon("Scan directory…", theme.SearchIcon(), func() { u.sh.Select("Encrypt") }),
		widget.NewButtonWithIcon("Refresh", theme.ViewRestoreIcon(), func() { u.sh.Invalidate() }),
		widget.NewButtonWithIcon("Reindex", theme.MediaReplayIcon(), func() {
			u.withSession("Reindex", func(s *core.Session) error {
				r, err := s.Reindex()
				if err != nil {
					return err
				}
				u.ok(fmt.Sprintf("Reindexed %d entries.", r.Entries))
				for _, n := range r.Unreadable {
					name := n
					fyne.Do(func() {
						u.sh.Flash("Ignored "+name+" — it does not decrypt with this store's key. "+
							"Usually a leftover from an interrupted rekey; Prune removes them.", fd.StatusWarn)
					})
				}
				return nil
			})
		}),
		widget.NewButtonWithIcon("Prune…", theme.DeleteIcon(), func() {
			dialogs.ConfirmDestructive(u.sh.Window, "Prune the store?",
				"This removes superseded key bundles and unreadable leftovers.\n\n"+
					"Pruning the superseded bundle is what finally closes a rotation: until it is "+
					"gone, the key you rotated away from still opens the blobs it wrote. It also "+
					"means a machine still holding only that old key can no longer open anything.",
				"Prune", func() {
					u.withSession("Prune", func(s *core.Session) error {
						secret, err := guiSecrets{u: u}.Recovery("Recovery passphrase, to prune superseded bundles:")
						if err != nil {
							return err
						}
						defer zero(secret)
						if err := s.PruneSupersededBundles(secret); err != nil {
							return err
						}
						u.ok("Kept the key bundle that opens this store and removed the rest. " +
							"Confirm the old key opens nothing, in Doctor.")
						return nil
					})
				})
		}),
		widget.NewButtonWithIcon("Clone…", theme.ContentCopyIcon(), func() { u.cloneDialog() }),
	)

	head := widgets.Heading("Store", "What the store holds. Select a row to act on it.")
	switch {
	case !u.entriesOK:
		head = widgets.Heading("Store", "Opening the store…")
		u.loadEntries()
	case len(entries) == 0:
		// Loaded and genuinely empty. An empty table with no explanation reads
		// as a broken store.
		head = widgets.Heading("Store", "This store holds nothing yet. Encrypt a file, or scan a directory.")
	}
	top := container.NewVBox(head, toolbar, container.NewHBox(rawToggle))
	bottom := container.NewVBox(widget.NewSeparator(), container.NewHBox(rowActions[0], rowActions[1], rowActions[2], rowActions[3]))

	return container.NewBorder(top, bottom, nil, nil, widgets.FixedHeight(table, 380))
}

func originOrNone(e StoreEntry) string {
	if e.Origin == "" {
		return "its original location"
	}
	return e.Origin
}

// --- Encrypt (R5.4) -------------------------------------------------------

func (u *ui) buildEncrypt() fyne.CanvasObject {
	cands := u.candidates

	dir := widget.NewEntry()
	dir.SetText(u.scanRoot)
	dir.SetPlaceHolder("directory to scan")

	count := widget.NewLabel("")
	refreshCount := func() {
		n := 0
		for _, c := range cands {
			if c.Selected {
				n++
			}
		}
		count.SetText(fmt.Sprintf("%d of %d selected", n, len(cands)))
	}

	list := widget.NewList(
		func() int { return len(cands) },
		func() fyne.CanvasObject {
			check := widget.NewCheck("", nil)
			path := widget.NewLabel("")
			path.Truncation = fyne.TextTruncateEllipsis
			reason := widget.NewLabel("")
			reason.Importance = widget.LowImportance
			size := widget.NewLabel("")
			size.Importance = widget.LowImportance
			return container.NewBorder(nil, nil, check, size,
				container.NewVBox(path, reason))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			c := cands[i]
			row := o.(*fyne.Container)
			check := row.Objects[1].(*widget.Check)
			size := row.Objects[2].(*widget.Label)
			body := row.Objects[0].(*fyne.Container)
			path := body.Objects[0].(*widget.Label)
			reason := body.Objects[1].(*widget.Label)

			path.SetText(c.Path)
			size.SetText(widgets.HumanSize(c.Size))
			check.OnChanged = nil
			check.SetChecked(c.Selected)
			if c.Stored {
				// Already stored: shown so the scan is a complete account of
				// what it found, but not offered, because re-encrypting it is a
				// different operation with different consequences.
				reason.SetText(c.Reason + " — already in the store")
				check.Disable()
			} else {
				reason.SetText(c.Reason)
				check.Enable()
			}
			idx := i
			check.OnChanged = func(b bool) {
				cands[idx].Selected = b
				refreshCount()
			}
		},
	)
	refreshCount()

	all := widget.NewButton("Select all", func() {
		for i := range cands {
			if !cands[i].Stored {
				cands[i].Selected = true
			}
		}
		list.Refresh()
		refreshCount()
	})
	none := widget.NewButton("Select none", func() {
		for i := range cands {
			cands[i].Selected = false
		}
		list.Refresh()
		refreshCount()
	})

	// The dry run is the default and costs nothing. Encrypting is the second,
	// explicit step (R5.4).
	scan := widget.NewButtonWithIcon("Scan (dry run)", theme.SearchIcon(), func() {
		u.scanRoot = dir.Text
		u.startScan(dir.Text)
	})
	scan.Importance = widget.HighImportance
	if u.scanning {
		// A second scan while one is running would replace the list underneath
		// the first one's results.
		scan.Disable()
		scan.SetText("Scanning…")
	}

	run := widget.NewButtonWithIcon("Encrypt selected", theme.ConfirmIcon(), func() {
		dialogs.ConfirmDestructive(u.sh.Window, "Encrypt the selected files?",
			"Each selected file is encrypted into the store and its origin recorded.\n\n"+
				"The plaintext is left where it is. Removing the originals is a separate, "+
				"deliberate step — angou will not delete a file you have not seen it store first.",
			"Encrypt", func() { u.encryptSelected(cands) })
	})

	top := container.NewVBox(
		widgets.Heading("Encrypt",
			"Scan a directory for likely candidates for file encryption, such as credentials, "+
				"see why each file was flagged, and choose which to store."),
		container.NewBorder(nil, nil, widget.NewLabel("Directory"),
			nil, dialogs.WithBrowse(u.sh.Window, dir, true)),
		container.NewHBox(scan, all, none, count),
		widget.NewSeparator(),
	)
	bottom := container.NewVBox(widget.NewSeparator(), container.NewHBox(run))
	return container.NewBorder(top, bottom, nil, nil, widgets.FixedHeight(list, 420))
}

// --- Doctor (R5.5) --------------------------------------------------------

func (u *ui) buildDoctor() fyne.CanvasObject {
	body := container.NewVBox()
	if !u.doctorOK {
		u.loadDoctor()
	}
	for _, g := range u.doctor {
		body.Add(widget.NewLabelWithStyle(g.Title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
		for _, r := range g.Rows {
			label := widget.NewLabel(r.Label)
			label.Importance = widget.LowImportance
			row := container.NewBorder(nil, nil, widgets.FixedWidth(label, 170), nil,
				container.NewHBox(widgets.Marker(r.Status), widgets.StatusText(r.Value, r.Status)))
			body.Add(row)
			if r.Note != "" {
				note := widget.NewLabel(r.Note)
				note.Wrapping = fyne.TextWrapWord
				note.Importance = widget.LowImportance
				body.Add(container.NewBorder(nil, nil, widgets.FixedWidth(widget.NewLabel(""), 190), nil, note))
			}
		}
		body.Add(widget.NewSeparator())
	}

	// --old-key is an assertion, not a report, so it gets its own action and its
	// own result rather than a line in the listing above (R5.5).
	oldKey := widget.NewEntry()
	oldKey.SetPlaceHolder("fingerprint of a superseded key")
	assert := widget.NewButton("Assert this key opens nothing", func() {
		fingerprint := core.NormalizeFingerprint(oldKey.Text)
		if fingerprint == "" {
			u.sh.Flash("Enter the fingerprint of the superseded key first.", fd.StatusWarn)
			return
		}
		dir := u.storeDir()
		go func() {
			// This one reads every blob in the store, so it is slow in
			// proportion to how much is in it.
			done := u.sh.Busy("Checking the superseded key…")
			defer done()
			opened, err := core.AssertOldKeyDead(dir, fingerprint, guiSecrets{u: u})
			if err != nil {
				u.report("Assert old key", err)
				return
			}
			if len(opened) > 0 {
				fyne.Do(func() {
					u.sh.Flash(fmt.Sprintf("The rotation is incomplete: %s still opens %d file(s).",
						fingerprint, len(opened)), fd.StatusBad)
				})
				return
			}
			u.ok("The superseded key " + fingerprint + " opens nothing in this store.")
		}()
	})

	// The report is the reason the section exists, so it starts immediately under
	// the heading. The assertion is a secondary tool and sits below it: placed
	// above, its form pushed the findings down far enough that the first
	// warning fell off the bottom of a default-sized window, which defeats the
	// ranking the report is built around.
	top := widgets.Heading("Doctor",
		"What this machine can and cannot do with the store. Nothing here changes anything.")
	bottom := container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Check a superseded key", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("After rotating the identity, this is the only thing that tells a complete rotation from a partial one."),
		container.NewBorder(nil, nil, nil, assert, oldKey),
	)
	return container.NewBorder(top, bottom, nil, nil, container.NewVScroll(body))
}

// --- Machine (R5.6) -------------------------------------------------------

func (u *ui) buildMachine() fyne.CanvasObject {
	safe := container.NewVBox(
		action("Set this machine up", "Store a local key so commands stop asking for the recovery passphrase.",
			"Bootstrap", false, func() {
				u.withSession("Bootstrap", func(s *core.Session) error {
					exported, err := s.ExportLocalIdentity()
					if err != nil {
						return err
					}
					defer zero(exported)
					r, err := s.SetUpMachine(exported)
					if err != nil {
						return err
					}
					if !r.UsedKeyring {
						fyne.Do(func() {
							u.sh.Flash("No keyring is available on this machine, so the identity was not "+
								"re-protected here. The store remains reachable with the recovery "+
								"passphrase. Cause: "+r.Cause.Error(), fd.StatusWarn)
						})
						return nil
					}
					u.ok("This machine now opens the store without the recovery passphrase.")
					return nil
				})
			}),
		action("Change the machine password", "Rotates this machine's local password. The store is untouched, and no other machine is affected.",
			"Rotate local", false, func() {
				u.withSession("Rotate local", func(s *core.Session) error {
					if err := s.RotateLocalPassword(); err != nil {
						return err
					}
					u.ok("Rotated the machine password. No blob changed and no other machine is affected.")
					return nil
				})
			}),
		action("Change the recovery passphrase", "Re-wraps the key bundle under a new passphrase. Existing blobs are not rewritten.",
			"Change passphrase", false, func() {
				u.withSession("Change passphrase", func(s *core.Session) error {
					fresh, err := guiSecrets{u: u}.Recovery("New recovery passphrase:")
					if err != nil {
						return err
					}
					defer zero(fresh)
					if _, err := core.CheckPassphrase(string(fresh)); err != nil {
						return err
					}
					if err := s.RewrapRecovery(fresh); err != nil {
						return err
					}
					u.ok("Changed the recovery passphrase. Existing blobs were not rewritten.")
					return nil
				})
			}),
	)

	danger := container.NewVBox(
		action("Forget this machine",
			"Removes this machine's local key and its keyring entry. Every command here goes back to asking for the recovery passphrase. If you do not have that passphrase, this machine loses access to the store.",
			"Forget", true, func() {
				dialogs.ConfirmDestructive(u.sh.Window, "Forget this machine?",
					"This removes the local key and the keyring entry.\n\n"+
						"Afterwards this machine opens the store only with the recovery passphrase. "+
						"If you do not have it written down somewhere, this machine will not open the store again.",
					"Forget", func() {
						dir := u.storeDir()
						go func() {
							done := u.sh.Busy("Removing the local key…")
							defer done()
							r, err := core.ForgetMachine(dir)
							if err != nil {
								u.report("Forget", err)
								return
							}
							if !r.HadKey {
								u.ok("This machine holds no local key for " + dir + ".")
								return
							}
							u.ok("Removed this machine's local key. Commands will ask for the " +
								"recovery passphrase again until you bootstrap.")
						}()
					})
			}),
		action("Rotate the store identity",
			"Generates a new keypair and naming key and re-encrypts every blob in the store. Long-running. Every other machine must bootstrap again afterwards, and the superseded bundle stays in the store until you prune it.",
			"Rotate identity", true, func() {
				dialogs.ConfirmDestructive(u.sh.Window, "Rotate the store identity?",
					"Every blob in the store is re-encrypted under a new keypair, and every "+
						"logical path is re-addressed under a new naming key.\n\n"+
						"This cannot be undone from inside angou. Every other machine loses "+
						"access until it bootstraps again. The superseded bundle is kept — "+
						"deliberately, so an interruption is recoverable — which means the "+
						"rotation is not finished until you prune it and confirm the old key "+
						"opens nothing.",
					"Rotate", func() {
						u.withSession("Rotate identity", func(s *core.Session) error {
							secret, err := guiSecrets{u: u}.Recovery(
								"Recovery passphrase, to re-wrap the new key bundle:")
							if err != nil {
								return err
							}
							defer zero(secret)
							res, err := s.RekeyIdentity(secret)
							if err != nil {
								return err
							}
							u.ok(fmt.Sprintf("Rotated to %s. Every other machine must bootstrap again, "+
								"and the rotation is not finished until you prune the superseded bundle.",
								res.NewFingerprint))
							return nil
						})
					})
			}),
	)

	return container.NewVScroll(container.NewVBox(
		widgets.Heading("Machine", "What this machine holds, and how it opens the store."),
		widget.NewLabelWithStyle("Routine", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		safe,
		widget.NewSeparator(),
		u.buildAgentBlock(),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Irreversible", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		danger,
	))
}

// action renders one operation as a titled block with its consequences stated,
// rather than as a bare button. The GUI has room the flag list does not.
//
// The library hands back the button as well, for a section that gates it while
// work runs. This window rebuilds its sections from state instead, so the
// handle is dropped here rather than threaded through six call sites.
func action(title, blurb, button string, danger bool, tapped func()) fyne.CanvasObject {
	row, _ := widgets.Action(title, blurb, button, danger, tapped)
	return row
}

// --- Release (R5.7) -------------------------------------------------------

func (u *ui) buildRelease() fyne.CanvasObject {
	rels := u.releases
	if !u.releasesOK {
		u.loadReleases()
	}

	dist := widget.NewEntry()
	dist.SetText("dist/")
	key := widget.NewEntry()
	key.SetPlaceHolder("path to the armored release-signing key")
	// Prefilled rather than used silently. The path is on screen and editable,
	// so stashing still names the key deliberately — the user sees which one
	// before pressing the button, which is the part that matters for a key that
	// decides what every future bootstrap will trust.
	if core.SigningKeyPresent() {
		key.SetText(core.DefaultSigningKeyPath())
	}
	keep := widget.NewSelect([]string{"1", "2", "3", "5"}, nil)
	keep.SetSelected("3")

	form := widget.NewForm(
		widget.NewFormItem("Built binaries", dist),
		widget.NewFormItem("Signing key", key),
		widget.NewFormItem("Versions to keep", keep),
	)

	// Finding a key here is convenient and is also a finding. install.sh says to
	// move it offline once the release is made, and a key still sitting in the
	// config directory is one compromise away from signing binaries the other
	// machines will install and run.
	onDisk := container.NewVBox()
	if core.SigningKeyPresent() {
		w := widget.NewLabel("A release-signing key is present. Treat this key as an " +
			"important credential and move it off box if you are not using it.")
		w.Wrapping = fyne.TextWrapWord
		w.Importance = widget.WarningImportance
		onDisk.Add(w)
	}

	list := widget.NewList(
		func() int { return len(rels) },
		func() fyne.CanvasObject {
			return container.NewHBox(widget.NewIcon(theme.ConfirmIcon()), widget.NewLabel(""), widget.NewLabel(""), widget.NewLabel(""))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			r := rels[i]
			row := o.(*fyne.Container)
			icon := row.Objects[0].(*widget.Icon)
			if r.Signed {
				icon.SetResource(theme.ConfirmIcon())
			} else {
				icon.SetResource(theme.WarningIcon())
			}
			row.Objects[1].(*widget.Label).SetText(r.Kind)
			row.Objects[2].(*widget.Label).SetText(r.Platform + "  " + r.Version)
			size := row.Objects[3].(*widget.Label)
			size.Importance = widget.LowImportance
			if r.Signed {
				size.SetText(widgets.HumanSize(r.Size))
			} else {
				size.SetText(widgets.HumanSize(r.Size) + " — unsigned, this build will refuse to install it")
			}
		},
	)

	top := container.NewVBox(
		widgets.Heading("Release",
			"Stash built binaries in the store's bootstrap namespace so a bare machine can install one."),
		form,
		onDisk,
		container.NewHBox(
			widget.NewButtonWithIcon("Stash binaries", theme.UploadIcon(), func() {
				keepN, _ := strconv.Atoi(keep.Selected)
				u.withSession("Stash binaries", func(s *core.Session) error {
					if err := core.StashRelease(s, dist.Text, key.Text, keepN, guiSecrets{u: u}); err != nil {
						return err
					}
					u.ok("Stashed the binaries in the bootstrap namespace.")
					return nil
				})
			}),
			widget.NewButton("Verify bootstrap.sh", func() {
				u.withSession("Verify bootstrap", func(s *core.Session) error {
					c, err := s.VerifyBootstrap()
					if err != nil {
						return err
					}
					switch {
					case c.Recorded == "":
						u.ok("No digest is recorded for bootstrap.sh, so there is nothing to compare against.")
					case c.Matches:
						u.ok("bootstrap.sh matches the digest recorded in this store. " +
							"That is drift detection after the fact, not a guarantee about any run.")
					default:
						fyne.Do(func() {
							u.sh.Flash("bootstrap.sh does NOT match the digest recorded in this store. "+
								"Read it before any machine runs it.", fd.StatusBad)
						})
					}
					return nil
				})
			}),
			widget.NewButton("Generate a signing key…", func() {
				path := widget.NewEntry()
				path.SetPlaceHolder("where to write the signing key")
				warn := widget.NewLabel("The signing key decides which binaries every future " +
					"bootstrap accepts as genuine. Move it to offline storage once this finishes; " +
					"left here, it is one compromise away from letting someone plant a binary your " +
					"other machines install and run.")
				warn.Wrapping = fyne.TextWrapWord
				warn.Importance = widget.WarningImportance
				dialogs.Prompt(u.sh.Window, "Generate a release-signing key", "Generate",
					container.NewVBox(path, warn), func() {
						go func() {
							done := u.sh.Busy("Generating a signing key…")
							defer done()
							if err := core.GenerateSigningKey(path.Text); err != nil {
								u.report("Generate signing key", err)
								return
							}
							u.ok("Wrote a signing key to " + path.Text + ". Move it offline now.")
						}()
					})
			}),
		),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("In the bootstrap namespace", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		func() fyne.CanvasObject {
			l := widget.NewLabel("angou is the static CLI, which is what a bare machine is " +
				"recovered with. angou-gui is the desktop front end, stashed only for platforms " +
				"it has been built on: it needs CGO and cannot be cross-compiled.")
			l.Wrapping = fyne.TextWrapWord
			l.Importance = widget.LowImportance
			return l
		}(),
	)
	return container.NewBorder(top, nil, nil, nil, widgets.FixedHeight(list, 300))
}

// --- Session cache, inside Machine (R5.8) ---------------------------------

// buildAgentBlock is the agent, presented as what it is: the fallback for a
// machine that cannot bootstrap.
//
// It sat in the navigation as a peer of Store in the first draft, which
// advertised it as a feature. On a bootstrapped machine it is close to
// pointless — the local key carries no stretching at all (see
// internal/localkey), so the keyring route is already about as fast as the
// agent, and the agent gives up something real in exchange, because the
// keyring's copy becomes unavailable when the wallet locks and the agent's
// does not. Where it earns its place is a machine with no keyring backend, and
// today that includes every Mac, since the Darwin backend is a stub. There the
// alternative is an Argon2id derivation and a passphrase prompt on every
// command.
//
// Parity is unaffected: the operation is reachable, and the project rule is
// about operations rather than controls.
func (u *ui) buildAgentBlock() fyne.CanvasObject {
	a := u.session.Agent
	if !u.agentOK {
		u.loadAgent()
	}

	state := widgets.StatusText("not running", fd.StatusInfo)
	if a.Running {
		state = widgets.StatusText("running · "+a.Remaining.Round(1e9).String()+" remaining", fd.StatusGood)
	}

	stop := widget.NewButton("Stop the session", func() {
		dir := u.storeDir()
		go func() {
			done := u.sh.Busy("Stopping the agent…")
			defer done()
			stopped, err := core.StopAgent(dir)
			if err != nil {
				u.report("Stop agent", err)
				return
			}
			if !stopped {
				u.ok("No agent is running for this store.")
				return
			}
			u.ok("Stopped the agent.")
		}()
	})
	stop.Importance = widget.DangerImportance

	blurb := widget.NewLabel(
		"Holds the key in memory for a bounded time so commands do not re-derive it. " +
			"This machine does not need it: the local key already opens the store without a " +
			"passphrase, and a session is readable by anything running under your account for " +
			"as long as it lasts. It is here for machines with no keyring, where the " +
			"alternative is typing the recovery passphrase on every command.")
	blurb.Wrapping = fyne.TextWrapWord
	blurb.Importance = widget.LowImportance

	return container.NewVBox(
		widget.NewLabelWithStyle("Session cache", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		blurb,
		widget.NewForm(
			widget.NewFormItem("State", state),
			widget.NewFormItem("Socket", widget.NewLabel(a.Socket)),
		),
		container.NewHBox(
			widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() { u.loadAgent() }),
			stop,
		),
	)
}

// --- About ----------------------------------------------------------------

// projectURL is where the README lives. It is the one place the GUI sends a
// user outside itself, and it opens in the desktop's browser rather than in any
// view of ours.
const projectURL = "https://github.com/ushineko/angou"

// --- Appearance (R5A) -----------------------------------------------------

// about describes this program for the library's About section. The long-form
// documentation stays in the README; a shortened copy here would only drift.
func (u *ui) about(version, commit string) shell.About {
	return shell.About{
		Icon:    appIcon(),
		Name:    "angou",
		Version: version + " (" + commit + ")",
		Blurb: "angou converts sensitive files to and from encrypted blobs held in a plain " +
			"directory. The store is portable: rsync, a sync service, or removable media " +
			"carries it without any further state.",
		URL:     projectURL,
		URLText: "Project documentation",
		Notes: []shell.Note{
			{Title: "Encrypt and restore", Detail: "Files go into the store encrypted under OpenPGP and come back out where they came " +
				"from, with their mode and modification time intact."},
			{Title: "Find what is already on the machine", Detail: "Scan a directory for credentials — private keys, .env files, cloud config, netrc — " +
				"see why each was flagged, and choose what to store."},
			{Title: "Carry it anywhere", Detail: "The store is an ordinary directory. Sync it, rsync it, or put it on a USB stick; " +
				"there is no database and no state held outside it."},
			{Title: "Open it without retyping", Detail: "A machine you have set up holds its own key, unwrapped by the system keyring, and " +
				"stops asking for the recovery passphrase."},
			{Title: "Rotate what protects it", Detail: "Change the recovery passphrase, this machine's password, or the store's identity " +
				"keypair — the last re-encrypting every blob."},
			{Title: "Recover on a bare machine", Detail: "The store can carry signed binaries and a bootstrap script, so a machine with no " +
				"angou installed can get itself to a working one."},
			{Title: "Stay readable by other tools", Detail: "Blob bodies decrypt with stock gpg, and file(1) identifies them through the " +
				"shipped magic entry. Nothing here is a format only angou can read."},
			{Title: "Run without pulling anything in", Detail: "No gpg, no gpg-agent, no kwallet-query — no subprocesses at all. The " +
				"command-line binary is static and has no runtime dependencies."},
		},
		Facts: []shell.Fact{
			{Label: "Encryption", Value: "OpenPGP via ProtonMail/go-crypto"},
			{Label: "Container", Value: "ANGOU1, ASCII armor by default"},
			{Label: "Keyring", Value: "Secret Service over D-Bus"},
			{Label: "Licence", Value: "MIT"},
		},
	}
}
