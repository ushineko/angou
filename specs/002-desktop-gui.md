# 002 — angou: desktop GUI

## Status: INCOMPLETE

Implementation proceeds in passes.

- **Pass 1** picked the toolkit, fixed the architecture that keeps the two front ends in
  sync, and delivered a navigable prototype driven by fixture data so the look and feel
  could be judged before any operation was wired. Complete; reviewed and approved.

  Three requirements were added during the pass rather than planned: the colour schemes
  and appearance settings of R5A, the documentation captures of R5B, and the cursor-theme
  shim of R5C. The first is the mitigation for the toolkit's one real cost and belonged
  in the spec from the start; the other two are consequences of the toolkit that only
  surfaced once there was a window to look at.
- **Pass 2** extracted `internal/core` and moved the CLI onto it. Complete.

  Everything reaches the store through a `core.Session`, so the rule that neither front
  end assembles an operation out of store internals is held by the compiler. What
  `internal/cli` still names from the other packages is constants and types — the blob
  and index filenames, the encoding enum, the envelope — used to render output.

  Two contracts came out of it. `Secrets` supplies passphrases, so a package that never
  prompts can still need one. `Decider` answers questions that arise mid-operation, which
  is what makes `--overwrite` and `--auto` and the GUI's dialogs one mechanism rather than
  three. `EncryptProgress` reports per-file as the work runs (R3.4), because a summary at
  the end would change what both front ends show while a long operation is in flight.

  The claim that behaviour is unchanged is checked by `tools/regress.sh`, which diffs the
  binary against a baseline commit, not only by the suite. That distinction was earned:
  the first slice reordered two `--verbose` lines and every test stayed green.
- **Pass 3 (next)** wires the GUI to the core, command by command, and lands the parity
  test.

---

## Context

Spec 001 delivered seventeen subcommands over a portable encrypted store. Everything
the tool can do, it does through flags typed at a prompt. That suits the operations
that are already scripted — `enc`, `dec`, `release` — and suits the rest badly.

Three things in particular are worse on a command line than they need to be. The
directory scan (`enc --all --dry-run`) produces a list of candidate files with a reason
attached to each, and the natural response to that list is to accept some and reject
others; the CLI offers `--auto`, which accepts all of them, or a prompt per file. The
`doctor` report is a wall of key-value lines whose importance is not visually ranked,
so the one line that says this machine still needs the recovery passphrase reads the
same as the line naming the store directory. And the store listing is a table you
cannot act on: seeing an entry and decrypting it are two separate commands, and the
second one requires retyping the logical path.

The GUI exists for those. It is not a replacement for the CLI and must not become one.

### What this is not

The GUI is a second front end over the same store, not a second implementation and not
a privileged one. It gets no capability the CLI lacks, it relaxes no security property
for convenience, and it does not become the place where new features land first. That
constraint is written into `.claude/CLAUDE.md` as a project rule with a test behind it,
because two front ends over one core drift silently otherwise.

---

## Requirements

### R1 — Toolkit

**R1.1** The GUI is built with Fyne (`fyne.io/fyne/v2`).

**R1.2** The choice is recorded with its cost. Fyne draws its own widgets and looks
native on no platform, including this project's primary desktop. That is accepted in
exchange for a pure-Go dependency tree, no JavaScript toolchain, no system GTK or Qt at
build time, and a single self-contained binary — the same properties the CLI was built
for. See *Alternatives Considered*.

**R1.3** CGO is confined to the GUI. `cmd/angou` continues to build with
`CGO_ENABLED=0` and to link statically, because spec 001's bootstrap and bare-machine
claims depend on it. No change in this spec may make the CLI require CGO.

### R2 — Packaging

**R2.1** The GUI is a separate binary, `cmd/angou-gui`, built by `make build-gui` with
`CGO_ENABLED=1`.

**R2.2** `make build-all` and `angou release` continue to stash the static CLI only.
The GUI is not a bootstrap artifact: a bare machine recovers with the CLI, and putting
a binary that needs OpenGL and libX11 into the recovery path would weaken the one
guarantee the store makes about getting itself open again.

**R2.3** The GUI's runtime dependencies are stated in `README.md`. A user who installs
only the CLI must be able to tell from the documentation that they have given up
nothing operationally.

**R2.4** `install.sh` installs the GUI, its `.desktop` entry, and its icon by default,
with `--no-gui` to skip. A GUI that fails to build does not fail the install: the CLI
is the artifact bootstrap and bare-machine recovery depend on, so a missing C toolchain
skips the GUI with a note naming the packages needed, and installs the CLI regardless.
`uninstall.sh` removes everything the installer placed. Neither touches store or key
material.

### R3 — Shared core

**R3.1** A new package `internal/core` holds every operation as a headless function
taking a request struct and returning a result struct or an error. It writes nothing to
stdout, prompts for nothing, and has no dependency on cobra or Fyne.

**R3.2** Where an operation needs a secret, the request carries a callback that supplies
it — not the secret itself. The CLI supplies a terminal prompt or the
`--passphrase-fd` reader; the GUI supplies a modal dialog. The core never learns which.

**R3.3** Where an operation needs a decision mid-flight — overwrite this file, encrypt
this candidate — the request carries a policy value or a callback, so the CLI's
`--overwrite` / `--auto` and the GUI's checkbox list are two renderings of one
mechanism.

**R3.4** Long operations (`rekey --identity`, `enc --all`, `release`) report progress
through a callback and honour a `context.Context` for cancellation. A GUI that cannot
cancel a re-encryption of every blob in the store is not a usable GUI.

**R3.4.1** Every core call the GUI makes shows an in-progress indicator for as long as
it runs, whether or not it is expected to be slow. Opening a store can mean an Argon2id
derivation or a wallet raising a dialog of its own; a scan walks a tree of unknown size.
The indicator is indeterminate, because none of these can say how far along they are and
a bar that filled steadily would be inventing a number. The mechanism is one reusable
call, not a per-operation decision, so that covering a new operation is the default
rather than something to remember.

**R3.5** `internal/cli` is refactored to render `internal/core` results. It keeps its
existing output byte-for-byte: the e2e suite asserts on that output and must pass
unchanged. A refactor that alters CLI behaviour has failed.

**R3.6** Neither front end reaches past `internal/core` into `internal/store`,
`internal/keyring`, or `internal/keybundle` to assemble an operation itself.

### R4 — Coverage

**R4.1** Every operation in the CLI command tree is reachable from the GUI:
`init`, `bootstrap` (including `--force` and `--forget`), `enc` (single file, and
`--all` with its dry-run and selection), `dec` (with `--out`, `--restore`,
`--overwrite`, `--stdout`), `get`, `ls` (including `--raw`), `mv`, `rm`, `reindex`,
`rekey` (`--local` and `--identity`), `passwd`, `prune`, `doctor` (including
`--old-key`), `release`, `verify-bootstrap`, `clone`, and `agent`.

**R4.2** The GUI may present an operation differently from its flags. It may not leave
one unreachable.

**R4.3** A parity test in `tests/e2e` enumerates the cobra command tree and the GUI's
registered actions and fails when either holds an operation the other does not.
Exceptions live in an allow-list in that test, each with a stated reason.

### R5 — Structure of the interface

**R5.1** A single window with a left navigation list, a content pane, and a persistent
status bar. The status bar shows the store directory, the unlock state (recovery
passphrase / this machine's key / agent session, with remaining time), and nothing
else. No secret appears in the status bar, the window title, or any tooltip.

**R5.2** The sections are **Store**, **Encrypt**, **Doctor**, **Machine**,
**Release**, **Appearance**, and **About**.

**R5.3 — Store.** The `ls` listing as a sortable table, with a raw/logical toggle
mirroring `ls --raw`. Selecting a row enables Decrypt, Extract, Rename, and Remove.
Toolbar actions cover Encrypt file, Scan directory, Reindex, Prune, and Clone.

**R5.4 — Encrypt.** The directory scan as its primary flow: choose a directory, see the
candidates the scanner found with the reason for each, tick the ones to encrypt, and
run. The dry run is the default and the destructive step is a second, explicit action.

**R5.5 — Doctor.** The report grouped by subject with a status marker per row, so that
"this machine needs the recovery passphrase" is visually distinct from "the store
directory is here". `--old-key` is a separate action with its own result, because it is
an assertion rather than a report.

**R5.6 — Machine.** Bootstrap, forget, local rekey, and passphrase change. The
identity rekey lives here too, separated and labelled with what it does: it rewrites
every blob in the store and cannot be undone from inside the tool.

**R5.7 — Release.** Signing key, dist directory, retention count, and the listing of
what the bootstrap namespace currently holds. `verify-bootstrap` is an action here.

**R5.8 — Session cache (the agent), inside Machine.** State, remaining lifetime, and
start/stop, presented as the fallback it is rather than as a peer of Store.

The agent earns very little on a machine that has been bootstrapped. The local key
carries no stretching — Argon2id is on the recovery path only, because a 256-bit random
value does not need it — so the keyring route is already about as fast as the agent, and
the agent gives up something real in exchange: the keyring's copy becomes unavailable
when the wallet locks and the agent's does not. Where it earns its place is a machine
with no keyring backend, which today includes every Mac, since the Darwin backend is a
stub that reports no backend. There the alternative is an Argon2id derivation and a
passphrase prompt on every command.

Giving it a top-level section advertised it as a feature. It is a fallback, and it is
presented inside Machine where the other unlock routes are. R4.2 permits this: parity
is about operations, not controls.

**R5.9 — About.** What angou is, the build's version and commit, and a short account of
what it can do — encrypt and restore, scan for credentials, carry the store anywhere,
open it without retyping, rotate what protects it, recover on a bare machine, stay
readable by stock `gpg` and `file(1)`, and run without subprocesses.

Limitations stay in `README.md`, which carries a Safety section written for exactly
that. A shortened restatement in the window would become a second, less careful copy to
keep in sync, and the honest thing is one authoritative account plus a way to reach it.

**R5.9.1** About carries a single "Project documentation" hyperlink to the project's
README, opened in the desktop's browser. It is the only place the GUI sends the user
outside itself.

**R5.10 — First run.** With no store configured, the window opens on a setup flow
covering `init` and `bootstrap` rather than on an empty Store table with errors in it.

### R5A — Appearance

**R5A.1** The GUI ships a set of color schemes and a picker. Fyne draws its own
widgets (R1.2), so the schemes are what decide whether the window looks like it
belongs on the user's desktop. This is the mitigation for the toolkit's one real cost,
not a decoration.

**R5A.2** The initial set is **Breeze Dark**, **Breeze Light**, **Oxygen Dark**,
**Adwaita Dark**, and **Adwaita Light** — the two desktops this project's users are on.

**R5A.3** KDE schemes are transcribed from the `.colors` files in
`/usr/share/color-schemes/`, and each palette records which file it came from. Adwaita
has no such file — libadwaita compiles its named colors into the library — so its
palette records that its values are the documented named colors instead. Any departure
from the source scheme is commented with its reason; the Oxygen Dark
negative/positive/neutral triple is the current case, lightened because the upstream
values were authored for a light window and are unreadable on the dark one.

**R5A.4** The schemes are read at build time into Go values. The GUI does not read
`/usr/share/color-schemes/` at runtime, does not follow the desktop's current scheme,
and does not require KDE or GNOME to be installed.

**R5A.5** The application ships an SVG icon, used for the window, the taskbar, and the
`.desktop` entry. It is built from a small number of large shapes and carries no detail
that fails at 16px. It is embedded in the binary so the GUI needs no asset directory
alongside it, and installed to the icon theme for the desktop entry.

**R5A.5.1** The desktop entry is named `io.ushineko.angou.desktop`, matching the
application's unique ID, and carries `StartupWMClass=io.ushineko.angou`. Fyne sets the
Wayland `app_id` from that unique ID, and a compositor resolves a window's taskbar icon
by matching the `app_id` to a desktop file of the same basename; `StartupWMClass` covers
the X11 and XWayland case, where the match is on `WM_CLASS`. Naming the file
`angou.desktop` costs the taskbar icon on every Wayland session, silently — the window
still opens and the icon is simply generic — so the constraint is recorded here and in a
comment in the file itself.

**R5A.6** The chosen scheme, font, text size, and store directory are saved and restored
across runs. The preferences file holds no fingerprint, no passphrase, and nothing out
of the store itself. `uninstall.sh` names the file and the command to remove it rather
than deleting it, since the application wrote it and the installer did not.

The store path was excluded from this in the first draft, and that was wrong. A GUI is
normally launched from a desktop entry, which carries no environment, so a window that
can only learn its store from `$ANGOU_STORE` opens on first-run setup every time it is
started the way desktop applications are actually started. The path is also not a
secret worth withholding here: it is already in `$ANGOU_STORE`, in the shell history of
anyone using the CLI, and in `doctor`'s output.

**R5A.6.1** The store is resolved as `$ANGOU_STORE` when set, then the remembered
choice. The environment wins so that a shell already naming a store keeps naming it and
the two front ends agree within that session; the window says so when the two disagree
rather than silently ignoring the choice just made.

**R5A.7** The default text size is smaller than Fyne's own. This is a dense window of
tables and reports; the toolkit's 14pt default is sized for a touch target and makes it
read like a phone application.

**R5A.8** Fonts are discovered by scanning the system font directories, because Fyne
draws its own text and does not consult fontconfig. The list is therefore what is on
disk, not what the desktop is configured to use, and the interface says so rather than
implying it follows the desktop. A family missing a bold or italic face is drawn in its
regular face for those styles; monospace is always left to the bundled face, since
substituting a proportional family where monospace was asked for defeats the reason it
was asked for.

### R5B — Documentation captures

**R5B.1** `angou-gui` takes `--section` and `--scheme`, so a capture script can deep-link
into the window. Refreshing the README images otherwise means clicking through the
interface against a timer, and a set that is tedious to refresh goes stale.

**R5B.2** `tools/screenshot.sh --all` refreshes the README set unattended, forcing a
single scheme so the images do not depend on whoever ran it. The set covers Store,
Encrypt, Doctor, and Machine; Appearance and About are excluded, showing nothing the
text does not already say.

**R5B.3** The script confirms it holds focus before grabbing and checks the captured
aspect ratio against the window's afterwards. A grab that fires before the raise lands
captures a different window and writes a plausible-looking image of the wrong thing,
which is worse than failing.

**R5B.4** Alt text describes what is in each image — the actual rows, states, and
colours — and is checked against a new capture before it is committed.

### R5C — Desktop integration

**R5C.1** On Linux, the GUI sets `XCURSOR_THEME` and `XCURSOR_SIZE` from the desktop's
own configuration before the toolkit initializes, when they are not already set.

GLFW's Wayland backend does not implement `cursor-shape-v1`, the protocol a native
Wayland client uses to get the user's themed pointer, and falls back to those two
environment variables. Plasma sets them for XWayland clients but not for native ones,
which are expected to use the protocol GLFW lacks — so without this the pointer visibly
changes as it crosses the window's border while every other window has the user's theme.

The configuration is read from `kcminputrc` and the GTK settings files directly. No
subprocess is started for it: spec 001 R6.3 holds here too, and a cursor theme is not a
good enough reason to break it. This is a workaround for a toolkit gap and is removed if
GLFW gains `cursor-shape-v1`.

### R6 — Destructive operations

**R6.1** `rm`, `prune`, `rekey --identity`, `bootstrap --forget`, and any overwrite of
an existing file on decrypt require an explicit confirmation naming what is about to
happen, in at least the detail the CLI gives.

**R6.2** No destructive operation is the default action of a double-click, an Enter
key, or a focused button on window open.

### R7 — Secrets

**R7.1** Passphrase entry is a modal dialog with a masked field. The backing buffer is
zeroed when the dialog closes, by whichever path it closes.

**R7.2** No passphrase is held in a widget, a struct field, or a closure that outlives
the operation that needed it. Extending a session is the agent's job, not the window's.

**R7.3** Memory hardening is documented as best-effort. Fyne's text entry keeps its
contents in Go strings the runtime may copy and relocate, which is a weaker position
than the CLI's terminal read, and `README.md` says so rather than implying the two are
equivalent.

**R7.4** No secret, plaintext, or store content reaches any log path at any verbosity,
including Fyne's own diagnostic output.

### R8 — Testing

**R8.1** The core is covered by unit tests where it holds logic with edge cases, and by
the existing e2e suite by way of the unchanged CLI.

**R8.2** The GUI's view models — the types that turn a core result into what the widgets
display — are tested headlessly, without a display server.

**R8.3** Interaction tests use Fyne's `test` harness under the throwaway `HOME` and
`XDG_*` discipline of the project's testing conventions. They are not a substitute for
the e2e suite; the CLI remains the artifact the end-to-end claims are made about.

**R8.4** `make test` and `make e2e` must run to completion on a machine with no display
server. A GUI test that requires one is skipped there, not failed.

---

## Acceptance Criteria

### Pass 1 — prototype

- [x] `fyne.io/fyne/v2` is a direct dependency and `go.sum` is updated.
- [x] `make build-gui` produces `angou-gui`; `make build-static` still produces a
      CGO-free, statically linked `angou`, confirmed by `file` and `ldd`.
- [x] The prototype opens a window with the navigation, content pane, and status bar of
      R5.1, and all seven sections of R5.2 are reachable.
- [x] Each section shows its real layout populated with fixture data: the Store table,
      the Encrypt scan with reasons and per-row selection, the grouped Doctor report,
      the Machine actions, the Release panel, and the Agent panel.
- [x] The passphrase dialog, a destructive-operation confirmation, the long-operation
      progress dialog with its cancel, and the first-run setup flow are all present and
      reachable, driven by fixtures.
- [x] All five color schemes of R5A.2 are present and switchable in the window, and each
      palette names the source it was transcribed from.
- [x] `install.sh --dry-run` shows the GUI, its desktop entry, and its icon being
      installed by default, and `--no-gui` skips them.
- [x] The icon of R5A.5 exists, is embedded, and is set on the window and the app.
- [x] The prototype performs no store operation: it opens no store and reads no key
      material. The only thing it writes outside its window is the appearance
      preferences file of R5A.6, which contains no store path and no secret.
- [x] A font picker and a text-size picker are present, both persisted, and the default
      text size is smaller than Fyne's (R5A.7).
- [x] Fixture data is visibly fixture data — no credential-shaped constant is committed,
      not even a fake one.
- [x] `tools/screenshot.sh --all` refreshes the four README images unattended, and
      `README.md` carries them with alt text describing what each actually shows.
- [x] The cursor-theme shim of R5C is in place and the pointer matches the desktop's.
- [x] `make test` and `make lint` pass.

### Pass 2 — core extraction

- [x] `internal/core` exists and holds every operation of R4.1 as a headless function.
- [x] `internal/cli` renders core results and contains no store logic of its own.
- [x] The secret-supplying callback of R3.2 and the decision callback of R3.3 are in
      place, and the CLI uses both.
- [x] Cancellation and progress reporting (R3.4) are implemented for the long operations.
- [x] `make e2e` passes with no test changed. CLI output is byte-for-byte unchanged.

### Pass 3 — wiring

- [ ] Every operation of R4.1 is wired and works against a real store.
- [ ] The parity test of R4.3 exists, passes, and fails when a command is added without
      a GUI action.
- [ ] Destructive confirmations of R6 are in place for every operation listed there.
- [ ] Passphrase handling meets R7; the buffer-zeroing path is covered by a test.
- [ ] `README.md` documents the GUI, its runtime dependencies, and the R7.3 limitation.
- [ ] `install.sh` and `uninstall.sh` handle the GUI and its desktop entry, and are
      idempotent.
- [ ] `make test`, `make e2e`, and `make lint` pass.

---

## Risks & Assumptions

- **The core refactor is the risk in this spec, not the GUI.** `internal/cli` currently
  mixes orchestration with rendering — `doctor` writes into a `tabwriter` as it works.
  Pulling those apart touches every command. The mitigation is R3.5: the e2e suite
  asserts on CLI output and must pass unchanged, so a refactor that changes behaviour is
  caught rather than shipped. The refactor lands as its own commit, separate from any
  GUI code, so it can be reverted on its own.
- **Fyne looks foreign on every desktop.** Accepted knowingly in R1.2. If it proves
  unacceptable in review, the damage is confined to `cmd/angou-gui` and the view models,
  because R3 keeps the operations in a package that knows nothing about the toolkit.
- **CGO reaches the release path if we are careless.** R1.3 and R2.2 are the guards.
  The existing `build-static` check in the e2e suite is what catches a violation.
- **A GUI invites long-lived credentials.** The obvious convenience — remember the
  passphrase while the window is open — is exactly what R7.2 forbids. The agent already
  solves this with a bounded lifetime and is the only sanctioned route.
- **Rollback**: the GUI is additive. Pass 1 and 3 revert by dropping `cmd/angou-gui` and
  the `build-gui` target; the CLI is untouched by either. Pass 2 is the one revert that
  touches shipped code, and is committed on its own for that reason.
- **Assumption**: the GUI targets Linux and macOS, matching the existing
  `keyring_linux.go` / `keyring_darwin.go` split. Windows is not a target and no
  requirement here assumes it.

---

## Alternatives Considered

- **Wails.** Fastest route to a polished interface, and rejected on trust surface: it
  puts a browser engine and a JavaScript toolchain inside a tool that handles
  passphrases, and needs WebKitGTK present at runtime on Linux. For an encryption tool
  whose appeal is a small auditable dependency set, that is the wrong trade.
- **gotk4 + libadwaita.** The only option that looks genuinely native, on GNOME.
  Rejected for linking against system GTK and glib at build and run time, the heaviest
  CGO surface of the candidates, and a weak macOS story — for a native look this project
  would not get on its primary desktop anyway.
- **Gio.** Smallest footprint and no CGO required. Rejected on effort: it has almost no
  stock widget set, and this is a forms, tables, and dialogs application. Every text
  field and scrollable table would be hand-built.
- **A TUI instead of a GUI.** Considered and rejected for the directory-scan flow, which
  is the strongest reason for this spec. A checkbox list over a hundred scan candidates
  with a reason column is workable in a TUI and better with a pointer and a scrollbar.
