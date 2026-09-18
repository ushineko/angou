# Validation report: spec 003, adopt fynedesygn

Branch `adopt-fynedesygn`, from `origin/main` at 2a4b851 (release 0.4.0 —
macOS support).

## Tests

`make test` (`go test -race ./...`): every package passes, `internal/gui`
included.

Removed: `browse_test.go`, whose two regressions are pinned by the library's
own tests against the code that now runs; `flash_test.go`, whose banner
timings went with the banner code.

Added, in `internal/gui/gui_test.go`:

- `TestASavedAppearanceFromThePreviousBuildIsReadUnchanged` — the three
  preference keys are read by the library exactly as this program wrote them.
  Without this the whole adoption could land looking correct on a fresh
  machine and reset the colours of every window that had ever been configured.
- `TestTheSchemesThisProgramOfferedAreStillOfferedFirst` — a scheme that was
  renamed or dropped is a saved appearance that silently falls back.
- `TestEverySectionRendersHeadlesslyInEveryScheme` — all seven sections in all
  nine schemes.
- `testUI`, a shared headless shell with HOME and the XDG directories
  sandboxed; `firstrun_test.go` moves onto it.

## Code quality

`make lint` (golangci-lint v2.12.2): 0 issues. `go vet ./...`: clean.

The linter's Go toolchain was read out of `go.mod`'s `toolchain` line, which
go removed when the library's `go 1.26.0` requirement raised the go directive
past it — leaving the pin empty and the linter running under whatever Go is
installed, which panics when that is newer than the Go the linter was built
with. Pinned literally now, as nmsbonker and fynedesygn already do.

Lint also caught the one real regression in the port: `opensWithoutAsking`
went unused, because the shell has no equivalent of the old
`nav.OnSelected` hook that dropped the loaded flags on arriving at a section.
Restored as `ui.arrive`, keyed on the section title changing rather than on
the builder running — see the spec's "Gaps found".

## Manual verification (AC10)

A window under a throwaway HOME, XDG and `ANGOU_STORE`, against a demo store
built by `tools/screenshot.sh`'s own `demo`. All seven sections captured and
checked by eye, and compared against the committed 0.3.0 captures: the
sections are identical but for the 48 px banner slot, which is content now,
and the shell's Refresh joining the two header buttons. One capture shows the
busy popup ("Open the store…"), a floating warning banner and this program's
own passphrase dialog at once.

The floating banner does overlap the row of actions at the bottom of Store —
the thing the reserved slot existed to prevent. It is temporary where the slot
cost 48 px permanently. Recorded in the spec's "Gaps found" as a library
candidate rather than worked around here.

## Release safety

- Rollback: `git revert` of the two adoption commits. The previous binary
  reads the same preference keys, the same remembered store and the same
  store directory.
- Additive: no operation, flag or preference key removed. `SectionNames()`,
  `Actions()` and the `--section` / `--scheme` / `--scan` flags are unchanged,
  so `tools/screenshot.sh` and the parity test keep working. `SchemeNames()`
  gains two entries and loses none.
- `go.mod`'s go directive moves to 1.26.0, which the library requires.

## Security

This program handles key material, so the port was kept off every path that
touches it: `askPassphrase`, `showRecoveryPassphrase`, `zero`,
`decryptDialog`, `encryptFileDialog`, `extractDialog`, `renameDialog` and
`cloneDialog` are unchanged and still in this package. `secret_test.go` passes
unmodified. No new dependency reaches a secret: the library is window code and
has no network access and no filesystem access beyond the font directories its
package comment documents.

`govulncheck -mode binary` on `angou` and `angou-gui`: no vulnerabilities.

**Scan an unstripped binary.** `make build` links with `-w -s`, and scanning
what it produces reports symbols from packages this program does not import:
GO-2026-5932 (the unmaintained `golang.org/x/crypto/openpgp`) against this
branch, and GO-2026-6355 (`x/crypto/ssh`'s `ssh.Dial`) against `origin/main`
built the same way. angou imports neither — it uses
`github.com/ProtonMail/go-crypto/openpgp`, and `go list -deps ./cmd/angou-gui`
shows no `golang.org/x/crypto/openpgp` and no `x/crypto/ssh` in the graph.
Built without `-w -s`, both binaries scan clean on both branches.

The adoption does raise `golang.org/x/crypto` from v0.55.0 to v0.57.0, past
the real GO-2026-6355 (fixed in v0.56.0). This program does not call it, but a
required module on the fixed version is better than one behind it.

## Line counts (`internal/gui`, AC11)

| | Before (2a4b851) | After |
| --- | --- | --- |
| Non-test `.go` | 3,728 | 2,373 |
| Test `.go` | 228 | 214 |

Counted as the sum of `wc -l` over each `.go` file under `internal/gui` at
that commit.

Deleted: `theme.go` (354), `fonts.go` (234), `cursor_linux.go` (98),
`cursor_other.go` (8), `flash_test.go` (62), `browse_test.go` (39). `app.go`
738 → 376, `views.go` 1,012 → 855, `dialogs.go` 624 → 506, `state.go`
549 → 538, `model.go` 96 → 83, `icon.go` unchanged at 15. Added:
`gui_test.go` (101).

The non-test figures reconcile exactly: 3,728 − 694 deleted − 661 shrunk =
2,373. So does the test side: 228 − 101 deleted (`flash_test.go` 62,
`browse_test.go` 39) + 101 added (`gui_test.go`) − 14 from `firstrun_test.go`
moving onto the shared helper (67 → 53) = 214.
