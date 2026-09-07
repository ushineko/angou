# 003 — angou: macOS support

## Status: INCOMPLETE

This work has no associated issue tracker ticket (personal public repository, per the
project's issue-tracking policy). No ticket ID is required.

---

## Context

macOS has been a nominal target since spec 002 — the `keyring_linux.go` /
`keyring_darwin.go` split exists, the CLI cross-compiles to `darwin/amd64` and
`darwin/arm64`, and Fyne draws on Cocoa without X11. What "target" has meant in practice
is "compiles." Building the tool on a Mac and running it are two different claims, and
the second one does not hold today.

Measured on darwin/arm64 (Go 1.25.12), the build surface is green:

- `make build`, `make build-static`, `make build-gui`, `make build-all` all exit 0.
  (`build-gui` emits one benign `ld: warning: ignoring duplicate libraries: '-lobjc'`.)
- `make test` / `go test ./...` pass with no failures.
- The GUI's fonts and theming are already macOS-safe: `internal/gui/fonts.go` includes
  `/System/Library/Fonts` and `/Library/Fonts`, and the colour palettes in
  `internal/gui/theme.go` are transcribed constants, not files read from
  `/usr/share/color-schemes`.

Everything below that line is where macOS diverges from "works":

- **`make e2e` does not compile on macOS.** `tests/e2e/harness_test.go:280` names
  `keyring.BackendEnv`, which is defined only in `keyring_linux.go` (`//go:build linux`).
  On darwin the constant is undefined and the e2e package fails to build. `make e2e` is
  the mandatory Phase-3 validation gate for this project (unit tests alone do not satisfy
  it), so on a Mac that gate cannot currently be met at all.
- **There is no secret backend.** `keyring_darwin.go` is a stub: `Open()` returns
  `ErrUnavailable`, `Available()` is false. Bootstrap cannot re-protect the key, so on
  every Mac the store stays under the recovery passphrase and each command pays an
  Argon2id derivation — the "weak macOS story" spec 002's assumptions already name. This
  is the deferred backend of spec 001 R2.5.
- **The agent fails closed.** `internal/agent/peer_other.go`'s `checkPeer()` returns an
  error unconditionally because `SO_PEERCRED` is Linux-only, and `server.go` refuses any
  request whose peer it cannot identify. The agent — the documented fallback for
  keyring-less machines, which README names Macs among — therefore serves nothing on
  macOS. The 0600 socket mode is the only control left standing.
- **Memory hardening is absent, not degraded.** `internal/keybundle/memory_other.go`
  returns an empty report (no pre-flight headroom check) and `LockMemory()` in
  `peer_other.go` errors out (no `mlockall`). Best-effort by design; on macOS it is
  currently no effort.
- **Nothing is packaged.** No `.app` bundle, `Info.plist`, or `.icns`, so the GUI runs as
  a bare binary with no Dock presence, no menu bar, and no Finder association.
  `install.sh` / `uninstall.sh` are entirely freedesktop — `.desktop`, MIME XML,
  `update-mime-database`, `~/.magic` — and none of it applies. `tools/screenshot.sh`
  hard-depends on `kdotool` and `spectacle`.

This spec makes macOS a real target: the tool runs, protects its key with the platform's
own secret store, passes its own gate on the platform, and installs as something a person
who did not build it can use.

### What this is not

This spec does not touch Windows. It does not change the Linux behaviour of any operation
— every requirement here is guarded by `//go:build darwin` or lives in a file the Linux
build does not compile. It does not relax any security property: passphrase zeroing, the
no-subprocess rule, and the no-secrets-in-logs rule hold on macOS exactly as they do on
Linux, and where a requirement below would appear to bend one, it says so and says why it
does not.

---

## Requirements

### R1 — Secret storage on macOS (the Keychain backend)

**R1.1** `keyring_darwin.go` gains a working backend over the macOS Keychain, replacing
the `ErrUnavailable` stub. `Open()` returns a `Keyring` that stores and retrieves the
wrapped unlock secret; `Available()` reports true when the backend is reachable. The
stored item is a generic password item scoped to angou (service = the store's identity),
not an internet-password item, and not shared across stores.

**R1.2** Bootstrap on macOS re-protects the key through this backend exactly as Linux
does through Secret Service / KWallet, closing spec 001 R2.5 for macOS. After a
successful bootstrap on a Mac with an unlocked login keychain, subsequent commands unlock
from the Keychain and do not prompt for the recovery passphrase.

**R1.3 — The macOS CLI links Security.framework via CGO (decided).** The Keychain lives
behind Security.framework, a C API, so the macOS keyring backend is built with CGO and
the darwin CLI links the framework directly through a cgo binding (such as
`go-keychain`). This relaxes spec 002 R1.3 ("CGO is confined to the GUI") and spec 001
R6.2 (the static CLI) — but only on Darwin, and only because the platform requires it.
The CGO-free rule those requirements state is a property worth holding *where it is
attainable and costs nothing*, which is Linux: a `CGO_ENABLED=0` musl build there is a
genuinely static, dependency-free bootstrap artifact. On macOS it never was — a
`CGO_ENABLED=0` Go binary still dynamically links `libSystem` — so the "static bootstrap"
property R6.2 protects does not exist to lose on Darwin. Both requirements are amended to
read, in effect, "CGO-free on Linux, where it is free; the macOS CLI links
Security.framework," and the amendment is written into spec 002 R1.3 and spec 001 R6.2
rather than left implicit here. The build system consequence: the darwin CLI is built
with `CGO_ENABLED=1`; the linux CLI stays `CGO_ENABLED=0`; `make build-static` and the
cross-compiled linux artifacts of `build-all` are unchanged.

The no-subprocess rule is not relaxed: the backend calls Security.framework directly and
never shells out to `/usr/bin/security`.

**R1.4** The wrapped secret is zeroed after use on the macOS path as it is on Linux. No
passphrase or plaintext key reaches a log at any verbosity. Keychain errors are reported
without echoing the secret.

**R1.5** When the login keychain is locked, or the item is denied, the backend fails the
way a missing keyring does elsewhere: it reports unavailable and the command falls back to
the recovery passphrase (or the agent, per R2), rather than hanging or crashing.

### R2 — The agent on macOS

**R2.1** A new `internal/agent/peer_darwin.go` (`//go:build darwin`) implements
`checkPeer` over `LOCAL_PEERCRED` / `getpeereid`, so the agent identifies its peer's uid
and serves requests from the same user. The `!linux` stub in `peer_other.go` is
constrained to `!linux && !darwin` so darwin no longer falls through to the fail-closed
path.

**R2.2** The agent authenticates the peer's uid against the server's own uid and refuses a
mismatch, matching the Linux guarantee that the agent hands key material only to the user
who started it. The 0600 socket mode remains, now as one control among two rather than the
only one.

**R2.3** With R1 in place the agent is no longer the *only* way to avoid re-derivation on
macOS, but it remains the fallback for a Mac with a locked or unavailable login keychain,
and README's "the agent is for machines with no keyring … or a Mac until the Keychain
backend lands" is updated to reflect that the backend has landed.

### R3 — The test gate compiles and passes on macOS

**R3.1** `make e2e` compiles on darwin. The backend-selection constants the harness needs
(`BackendEnv` and the `Backend*` selector values) are moved out of the linux-only
`keyring_linux.go` into a file the darwin build also compiles — either a platform-neutral
`keyring.go` or a small darwin counterpart — so `tests/e2e/harness_test.go:280` resolves
on both platforms.

**R3.2** The e2e suite runs and passes on macOS. Tests that assert a Linux-only mechanism
(Secret Service / KWallet backends, `SO_PEERCRED` specifics, `/proc`-based memory
reporting) either gain a darwin path that asserts the macOS equivalent, or skip on darwin
with a stated reason — never a silent skip, and never a `t.Fatal` that a developer must
read as expected. The keyring and agent e2e tests assert the Keychain backend and the
`LOCAL_PEERCRED` path on darwin.

**R3.3** The parity test (spec 002 R4.3) passes on macOS unchanged: no operation becomes
reachable on one platform's front end and not the other because of anything in this spec.

**R3.4** `make e2e` is run on macOS as part of this spec's validation, and the validation
report records it. The Phase-3 gate is met on the platform, not waived for it.

### R4 — Memory hardening on macOS

**R4.1** `peer_darwin.go` locks the derived-secret pages with `mlock` (or `mlockall`
where the platform honours it), replacing the erroring `LockMemory()` stub, so the macOS
agent gets the same best-effort protection the Linux one does.

**R4.2** The pre-derivation headroom check gains a darwin implementation (via
`host_statistics64` / `sysctl` for available memory) or is documented as deliberately
absent on macOS. Either way the behaviour is stated, not left as a silently-empty report.

**R4.3** The memory-hardening claims in `README.md` and command output stay honest on
macOS: best-effort is described as best-effort, and any check that does not run on macOS
is not implied to.

### R5 — Packaging: the .app bundle

**R5.1** `make` gains a target (`build-app` or equivalent) that assembles
`angou-gui.app` with `Contents/MacOS/angou-gui`, `Contents/Resources/`, and a generated
`Contents/Info.plist`. The bundle carries the version from `VERSION` and the commit from
the build, matching the ldflags the plain binary already gets.

**R5.2** An `.icns` is generated from `packaging/angou.svg` (the existing icon source) and
placed in the bundle. No second icon source is introduced; the SVG remains the origin as
it is for the Linux icon.

**R5.3** The `.angou` file association is declared in `Info.plist` as a Uniform Type
Identifier (the macOS counterpart to `packaging/angou.xml`'s freedesktop MIME type),
conforming to `public.data`, with the `-----BEGIN ANGOU1 BLOB-----` magic where the UTI
system can use it. This is a fourth home for the format literal; per the project's
"Format literals" convention, changing the delimiter now means changing spec 001 R1.1,
`packaging/magic`, `packaging/angou.xml`, **and** the `Info.plist` UTI, and that count is
updated in the convention.

**R5.4** The bundle runs from Finder and the Dock, not only from a terminal: launching it
shows a Dock icon and a menu bar, and double-clicking a `.angou` file opens it. Code
signing and notarization are out of scope for this spec (a developer-built, locally-run
bundle is the target); the spec notes that an unsigned bundle raises Gatekeeper on
machines other than the builder's, and leaves signing to a later spec.

### R6 — Install and uninstall on macOS

**R6.1** `install.sh` detects Darwin and takes a macOS path: it installs the CLI to a
directory on the user's PATH (`/usr/local/bin` or `~/.local/bin`, matching whatever the
script already prefers) and installs `angou-gui.app` to `~/Applications` (or
`/Applications` with the user's consent), instead of running the freedesktop steps
(`.desktop`, MIME XML, `update-mime-database`, `~/.magic`), which it skips on Darwin.

**R6.2** `uninstall.sh` reverses exactly what the macOS path installed and nothing else —
the CLI binary and the `.app` — and, honouring the existing uninstaller rule, never
removes keys or store data without being asked; it prints the command instead. Both
scripts keep their idempotence and `--dry-run` support on the macOS path.

**R6.3** The macOS config and state locations are decided and documented: either keep
`~/.config/angou` (the current XDG default, which works on macOS) for parity with Linux,
or move to `~/Library/Application Support/angou`. The spec records the choice and its
reason rather than leaving two conventions in play; parity with Linux is the default
argument for keeping `~/.config` unless review prefers the native location.

### R7 — Screenshots (deferred, documented)

**R7.1** `tools/screenshot.sh` is KDE-bound (`kdotool`, `spectacle`, forced Breeze Dark).
A macOS capture path (`screencapture` + `osascript` for window targeting) is out of scope
for this spec. The script gains a clear guard that it is Linux-only and exits with that
message on Darwin, so no one runs it expecting output. The README screenshot set stays the
Linux-captured one; this is stated, not silently platform-specific.

### R8 — Documentation

**R8.1** `README.md` states macOS as a supported platform with its runtime dependencies,
describes the Keychain backend the way it describes Secret Service / KWallet, and updates
the agent's "until the Keychain backend lands" language.

**R8.2** The stated limitations stay honest per the project's README conventions: the
unsigned-bundle Gatekeeper caveat (R5.4), any memory check that does not run on macOS
(R4.2), and the Linux-only screenshot tooling (R7.1) are each named where a reader would
otherwise assume a guarantee.

**R8.3** A changelog entry is added for the release that carries this work, and `VERSION`
/ `README.md` are bumped together per the versioning convention — the bump number
proposed to and approved by the user, not chosen unilaterally.

---

## Acceptance criteria

- [ ] R1.1 — `keyring_darwin.go` stores and retrieves the wrapped secret over the Keychain; `Available()` is true when reachable
- [ ] R1.2 — bootstrap re-protects the key on macOS; subsequent commands do not prompt for the recovery passphrase
- [ ] R1.3 — macOS CLI builds with `CGO_ENABLED=1` and links Security.framework; spec 002 R1.3 and spec 001 R6.2 amended to scope the CGO-free rule to Linux; linux CLI and `build-static` unchanged
- [ ] R1.4 — secret zeroed on the macOS path; no secret in any log; Keychain errors carry no secret
- [ ] R1.5 — locked/denied keychain falls back to recovery passphrase or agent, without hang or crash
- [ ] R2.1 — `peer_darwin.go` implements `checkPeer` over `LOCAL_PEERCRED`/`getpeereid`; `peer_other.go` constrained to `!linux && !darwin`
- [ ] R2.2 — agent authenticates peer uid against its own and refuses a mismatch
- [ ] R2.3 — README agent language updated
- [x] R3.1 — `make e2e` compiles on darwin; backend-selection constants reachable on both platforms — done in pass 1 (backend-selection constants hoisted to `internal/keyring/keyring.go`). Suite now compiles and runs on macOS: 126 pass / 15 fail / 3 skip. The 15 failures are the documented platform gaps addressed by later passes: agent peer-auth (4, R2), Linux-only `statically linked` assertion (1, R3.2 — confirms R6.2's "no static binary on macOS"), bootstrap gpg-check + installer chain (7, R3.2), and gpg-agent socket-path failure in the throwaway `GNUPGHOME` (3, R3.2). None involve the hoisted constants.
- [ ] R3.2 — e2e suite passes on macOS; Linux-only tests gain a darwin path or skip with a stated reason
- [ ] R3.3 — parity test passes on macOS unchanged
- [ ] R3.4 — `make e2e` run on macOS and recorded in the validation report
- [ ] R4.1 — `mlock` implemented on the macOS agent path
- [ ] R4.2 — headroom check implemented on darwin or documented as deliberately absent
- [ ] R4.3 — memory-hardening claims honest on macOS
- [ ] R5.1 — `make` builds `angou-gui.app` with a generated `Info.plist` carrying version and commit
- [ ] R5.2 — `.icns` generated from `packaging/angou.svg`
- [ ] R5.3 — `.angou` UTI declared in `Info.plist`; format-literal convention updated to count it
- [ ] R5.4 — bundle launches from Finder/Dock with Dock icon and menu bar; `.angou` double-click opens it; Gatekeeper caveat documented
- [ ] R6.1 — `install.sh` takes a Darwin path (CLI to PATH, `.app` to Applications), skipping freedesktop steps
- [ ] R6.2 — `uninstall.sh` reverses exactly the macOS install; never removes keys/store data unasked; both keep idempotence and `--dry-run`
- [ ] R6.3 — macOS config/state location decided and documented
- [ ] R7.1 — `screenshot.sh` guards Linux-only and exits with that message on Darwin
- [ ] R8.1 — README states macOS support, dependencies, and the Keychain backend
- [ ] R8.2 — unsigned-bundle, memory-check, and screenshot limitations documented
- [ ] R8.3 — changelog entry added; `VERSION`/`README.md` bumped together with user-approved number

---

## Suggested passes

1. **Unblock the gate.** R3.1 alone — hoist the backend constants so `make e2e` compiles
   on darwin. Nothing else can be validated on the platform until this lands, and it is a
   pure code-motion change with no behaviour to it. Land first, on its own.
2. **Secret storage and the agent.** R1 (Keychain backend, CGO per R1.3), R2
   (`peer_darwin.go`), R4 (`mlock` + headroom). This is the core of "runs on macOS" and
   carries the one real design decision. R3.2 lands with it, since the keyring and agent
   e2e tests are what prove this pass.
3. **Packaging and install.** R5 (`.app`, `Info.plist`, `.icns`, UTI), R6 (install /
   uninstall Darwin path), R7 (screenshot guard). Infrastructure, no core behaviour.
4. **Documentation and release.** R8 — README, changelog, version bump (user-approved),
   validation report with `make e2e` recorded on macOS.
