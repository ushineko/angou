# Spec 003: Adopt fynedesygn

> **Note**: This work has no associated issue tracker ticket. The repository
> is a personal public project without an issue tracker.

## Status: COMPLETE

## Executive Summary

`internal/gui` imports `github.com/ushineko/fynedesygn` v0.1.4 for its design
system and runs the window on the library's shell; the palettes, the font
scanner, the cursor fix, the small widgets and the generic dialogs — all of
which were written here and copied out — are deleted, and the package's
non-test code goes from 3,728 to 2,373 lines while gaining the Windows
schemes, a monospace-font picker and an interface scale. angou was the origin
of this design system and is the last of its three programs to stop carrying
its own copy. Behaviour is kept: the same preference keys, sections,
operations and store handling, and every dialog that touches key material
stays in this package. Two deliberate changes are visible — progress is a
modal popup rather than an 18 px strip in the status bar, and result banners
float rather than sitting in a reserved 48 px slot. Reviewers should start
with `app.go` (the `ui` struct, `shellOptions`, `arrive`, `statusSegments`)
and the "Gaps found" list.

## Context

The design system in `internal/gui` was written here. It was copied by hand
into nmsbonker and clockwork-orange under "Copied from angou (same author) —
keep in sync by hand" headers, and both of those have since replaced their
copy with `github.com/ushineko/fynedesygn`, the library extracted from all
three. clockwork-orange adopted it in v4.1.0, nmsbonker in v0.4.0. angou is
the origin and the last one still carrying the original.

That leaves the oldest copy as the only one diverging. Everything the library
does, it does because this program did it first: the palettes, the font
scanner, the cursor fix, the banner rules, the section skeleton, the status
bar, `dim`/`sep`/`statusText`/`heading`/`humanSize`/`humanAgo`, the confirm
and browse dialogs. Adopting it here closes the loop, and the rationale
comments in this package travel with the code — they are the library's
comments now.

Two places where this program and the library disagree, and how each is
settled:

- **Progress.** This program shows a fixed 18 px strip in the status bar, so
  the window stays usable while an operation runs. The library shows a modal
  popup 300 ms in. Both honour "nothing transient may reflow the interface";
  they differ on whether the window stays live. The library's shape wins, so
  all three programs behave alike — and a cancellable operation can put its
  Cancel on the popup (fynedesygn spec 008).
- **Result banners.** This program reserves a 48 px slot above the status bar
  because a floating banner covered the buttons at the bottom of Store and
  Encrypt. The library floats them. The library's shape wins for consistency;
  the covering problem is recorded in "Gaps found" if it shows up again.

Secrets stay here. The passphrase prompt, the recovery-phrase display and
`zero` are this program's, not the library's: the project's own rules require
secret buffers to be zeroed and no passphrase to reach a log path, and the
library has no business holding any of that. The library's rule — no
application concepts — says the same thing from the other side.

## Requirements

- R1 `internal/gui` imports `github.com/ushineko/fynedesygn` v0.1.4 and the
  window runs on `shell.Run`. No `replace` directive.
- R2 These are deleted and replaced by the library:
  - R2.1 `theme.go`, `fonts.go`, `cursor_linux.go`, `cursor_other.go`,
    `icon.go` → `fynedesygn/theme` (`icon.go` only if the library's icon
    helper fits; angou's own icon resource stays).
  - R2.2 the shell in `app.go`: `Run`, `section`, `sections`, `rebuild`,
    `refresh`, `show`, `header`, `statusBar`, `busyStrip`, `busy`,
    `redrawStatus`, `flash`, `clearFlash`, `flashTint`, `flashHold` →
    `shell.Shell` and its `Options`.
  - R2.3 the small widgets: `dim`, `sep`, `statusText`, `heading`,
    `humanSize`, `humanAgo`, `fixedHeight`, `fixedWidth`, `marker`, `action`,
    `aboutNote` → `fynedesygn/widgets`.
  - R2.4 the generic dialogs: `confirmDestructive`, `askDecision`,
    `pathDialog`, `pickerStart`, `browseButton`, `withBrowse` →
    `fynedesygn/dialogs`.
  - R2.5 `Status` and its constants → `fynedesygn.Status`; `routeStatus`
    stays, returning the library's type.
  - R2.6 the Appearance and About sections → `shell.AppearanceSection` and
    `shell.AboutSection`, keeping what this program's About says.
- R3 These stay, because they are angou's:
  - R3.1 `askPassphrase`, `showRecoveryPassphrase`, `zero`, `decryptDialog`,
    `encryptFileDialog`, `extractDialog`, `renameDialog`, `cloneDialog`.
  - R3.2 the first-run flow: `firstRunForm`, `firstRun`, `useStore`,
    `openExistingStore`, `chooseStore`.
  - R3.3 the Store, Encrypt, Doctor, Machine and Release sections, and the
    model in `model.go` and `state.go`.
- R4 Behaviour is kept:
  - R4.1 the preference keys `appearance.scheme`, `appearance.font` and
    `appearance.textSize` are read and written unchanged, so a window that
    was configured before this change opens looking the same.
  - R4.2 `SectionNames()` returns the same seven titles in the same order and
    still needs no Fyne app; `SchemeNames()` keeps its five KDE/GNOME and two
    macOS schemes as a prefix of the library's nine (Windows Dark and Windows
    Light are appended).
  - R4.3 `Actions()` is unchanged.
  - R4.4 F5 and Ctrl+R still reload; `--section`, `--scheme` and `--scan`
    still do what they did, so the capture scripts keep working.
  - R4.5 the first run with no store still opens the setup flow rather than
    an empty table.
- R5 What the library lacks is recorded in "Gaps found" for a library spec,
  not worked around here.
- R6 Documentation: the design-language notes point at the library, and the
  "keep in sync by hand" headers go.

## Acceptance Criteria

- [x] AC1 `go.mod` requires `github.com/ushineko/fynedesygn` v0.1.4 with no
  `replace`, and `go mod tidy` leaves the `golang.org/x/*` modules at or above
  their current versions (R1).
- [x] AC2 The grep `func (u \*ui) (busy|flash|clearFlash|redrawStatus|rebuild|refresh|show|header|statusBar|busyStrip)\(` over `internal/gui` finds nothing (R2.2).
- [x] AC3 `theme.go`, `fonts.go`, `cursor_linux.go` and `cursor_other.go` are
  gone, and no file in `internal/gui` carries a "keep in sync by hand" header
  (R2.1, R6).
- [x] AC4 `SectionNames()` returns `Store, Encrypt, Doctor, Machine, Release,
  Appearance, About` with no Fyne app; `SchemeNames()` starts with the seven
  it returned before; `Actions()` is unchanged (R4.2, R4.3).
- [x] AC5 A saved appearance from the previous build is read unchanged: a test
  writes the three keys, opens the window headlessly and finds the same scheme,
  font and text size (R4.1).
- [x] AC6 The passphrase prompt, the recovery-phrase display and `zero` are
  still in `internal/gui`, and `secret_test.go` still passes (R3.1).
- [x] AC7 The first-run flow still opens with no store configured, and
  `firstrun_test.go` still passes (R3.2, R4.5). `browse_test.go` is deleted
  rather than kept: both regressions it pinned — the Browse button that
  panicked when a chooser was resized before it was shown, and the picker
  start falling back to home — are pinned by the library's own tests against
  the code that now runs (`dialogs.TestChooserResizeAfterShowDoesNotPanic`,
  `TestPickerStartPrefersTheFieldThenItsParentThenHome`). Keeping a copy here
  would test nothing this program owns.
- [x] AC8 `make test`, `make lint` and `go vet` clean; every section renders
  headlessly in every scheme (R4).
- [x] AC9 `govulncheck -mode binary` on the CLI and the GUI: no findings.
  Scanned on binaries built **without** `-w -s`; see "Notes" for why a
  stripped binary reports packages this program does not import.
- [x] AC10 The GUI is run on this machine under a throwaway HOME: Store,
  Encrypt, Doctor, Machine, Release, Appearance and About render; a banner
  shows; an operation shows the popup (manual, recorded in the report).
  _Done: all seven captured under a throwaway HOME, XDG and ANGOU_STORE
  against a real demo store, and checked against the committed 0.3.0 captures
  — the sections are the same but for the 48 px banner slot, which is content
  now, and the shell's Refresh joining the two header buttons. One capture
  shows the busy popup ("Open the store…"), a floating warning banner and
  this program's own passphrase dialog at once._
- [x] AC11 "Gaps found" is filled, and line counts of `internal/gui` before
  and after are in the validation report (R5).

## Risks & Assumptions

- **Assumption**: the library's behaviour matches this program's copy
  everywhere the tests pin it. A difference that is a library bug is fixed in
  the library first, as it was for the two adoptions before this.
- **Risk**: this program handles key material. The port moves window code
  only; no dialog that touches a passphrase changes hands, and `zero` stays
  where it is. Any diff that touches a secret path is a mistake in this port.
- **Risk**: the banner and progress changes are visible. Store and Encrypt
  have buttons at the bottom that a floating banner could cover — the reason
  the reserved slot exists. Checked in the manual run (AC10).
- **Risk**: appearance keys must not change (AC5), or every existing window
  opens with default colours.
- **Rollback**: `git revert` of the adoption commits. The previous binary
  reads the same preferences, the same configuration and the same store.

## Alternatives Considered

- Keeping the 18 px busy strip by adding a busy style to the library. Rejected
  for now: three programs behaving alike is worth more than the live window,
  and the strip can come back as a library option if it is missed.
- Moving the passphrase dialog into the library as a generic masked prompt.
  Rejected: the library's rule is no application concepts, and this project's
  rules put secret handling under its own review.

## Gaps found

1. **The shell does not tell a section why it is being built.** This window
   drops its loaded flags when the navigation *arrives* at a section and
   reopening the store would go through silently, so a file encrypted from the
   command line or synced in from another machine shows up without a restart.
   The shell rebuilds a section for navigation and for every operation alike
   through the same builder, and a builder that dropped the flags on a rebuild
   would start the loads whose completion rebuilds — a window that never stops
   reading the store. `ui.arrive` keys on the section title changing instead.
   Library candidate: a `Section` hook that runs on selection rather than on
   every build, or a flag on the build call saying which it is.

2. **`widgets.Action` hands back the button; this window does not want it.**
   The library's shape suits a section that gates its buttons while work runs.
   This one rebuilds from state, so the handle is dropped in a one-line
   adapter. Not a defect — recorded because a third consumer wanting the same
   would argue for an `Action` that returns only the row.

3. **A floating banner covers the row of actions at the bottom of a section.**
   This is the thing the reserved 48 px slot existed to avoid, and the manual
   run confirms it is real rather than theoretical: the banner sits at
   y≈1030–1095 in a 1194 px window, and Store's Decrypt / Extract to… /
   Rename / Remove row is at y≈1089. It is temporary — good banners hold six
   seconds, warnings twelve, and every banner has a dismiss — where the
   reserved slot cost 48 px permanently, which is the trade this adoption
   accepted deliberately. Library candidate: a banner that sits above a
   section's action row rather than over it, or a shell inset a section can
   declare.

Nothing here blocked the adoption, and nothing was worked around in a way that
would have to be undone: `arrive` is four lines, `action` is three, and the
third is a judgement about a trade, not a workaround.

## Notes

- **`govulncheck -mode binary` is unreliable on a stripped binary.** `make
  build` links with `-w -s`, and scanning what it produces reports symbols
  from packages this program does not import: GO-2026-5932 (the unmaintained
  `golang.org/x/crypto/openpgp`) against this branch, and GO-2026-6355
  (`x/crypto/ssh` `ssh.Dial`) against `origin/main` built the same way. angou
  imports neither — it uses `github.com/ProtonMail/go-crypto/openpgp`, and
  `go list -deps` confirms no `golang.org/x/crypto/openpgp` and no
  `x/crypto/ssh` in the graph. Built without `-w -s`, both binaries scan
  clean on both branches. Scan an unstripped build.
- The adoption does raise `golang.org/x/crypto` from v0.55.0 to v0.57.0,
  which moves past the real GO-2026-6355 (fixed in v0.56.0). angou does not
  call it, but a required module on the fixed version is better than one
  behind it.
