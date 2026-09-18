# Spec 003: Adopt fynedesygn

> **Note**: This work has no associated issue tracker ticket. The repository
> is a personal public project without an issue tracker.

## Status: INCOMPLETE

## Executive Summary

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

- [ ] AC1 `go.mod` requires `github.com/ushineko/fynedesygn` v0.1.4 with no
  `replace`, and `go mod tidy` leaves the `golang.org/x/*` modules at or above
  their current versions (R1).
- [ ] AC2 The grep `func (u \*ui) (busy|flash|clearFlash|redrawStatus|rebuild|refresh|show|header|statusBar|busyStrip)\(` over `internal/gui` finds nothing (R2.2).
- [ ] AC3 `theme.go`, `fonts.go`, `cursor_linux.go` and `cursor_other.go` are
  gone, and no file in `internal/gui` carries a "keep in sync by hand" header
  (R2.1, R6).
- [ ] AC4 `SectionNames()` returns `Store, Encrypt, Doctor, Machine, Release,
  Appearance, About` with no Fyne app; `SchemeNames()` starts with the seven
  it returned before; `Actions()` is unchanged (R4.2, R4.3).
- [ ] AC5 A saved appearance from the previous build is read unchanged: a test
  writes the three keys, opens the window headlessly and finds the same scheme,
  font and text size (R4.1).
- [ ] AC6 The passphrase prompt, the recovery-phrase display and `zero` are
  still in `internal/gui`, and `secret_test.go` still passes (R3.1).
- [ ] AC7 The first-run flow still opens with no store configured, and
  `firstrun_test.go` and `browse_test.go` still pass (R3.2, R4.5).
- [ ] AC8 `make test`, `make lint` and `go vet` clean; every section renders
  headlessly in every scheme (R4).
- [ ] AC9 `govulncheck -mode binary` on the CLI and the GUI: no findings.
- [ ] AC10 The GUI is run on this machine under a throwaway HOME: Store,
  Encrypt, Doctor, Machine, Release, Appearance and About render; a banner
  shows; an operation shows the popup (manual, recorded in the report).
- [ ] AC11 "Gaps found" is filled, and line counts of `internal/gui` before
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

_Filled during implementation._
