# 004 — angou: Windows support

**Issue**: #5

## Status: COMPLETE

---

## Context

Spec 003 made macOS a real target and said, in its own words, "This spec does not touch
Windows." Windows was not a nominal target either: nothing built.

Measured on windows/amd64 (Go 1.27.0, Windows 11 26200) before this work:

- **The CLI does not compile.** `internal/store/extract.go` and `internal/core/clone.go`
  open with `syscall.O_NOFOLLOW`, which Windows does not define.
- **The GUI needs a C toolchain** (Fyne draws through cgo and OpenGL) and none was
  installed. With MinGW-w64 gcc on PATH it builds unchanged.
- **There is no keyring backend.** `keyring_other.go` reports none, so every command on
  Windows would ask for the recovery passphrase and pay an Argon2id derivation.
- **The store's installer is POSIX shell.** `bootstrap.sh` refuses any `uname -s` other
  than Linux and Darwin. A Windows machine had no way to install angou from a store.
- **`build-all` produces nothing for Windows**, so a store carries no Windows binary for
  an installer to find.
- **A Windows checkout corrupts the installer.** Git for Windows defaults to
  `core.autocrlf=true`, which writes `internal/core/assets/bootstrap.sh` with CRLF line
  endings. That copy is what `go:embed` puts into the binary, and so what `angou
  release` writes into a store: a script `sh` cannot run (`set: -\r: invalid option`)
  under a signature made over the CRLF bytes.
- **The e2e gate cannot run.** The harness hands the passphrase down as descriptor 3
  through `ExtraFiles`, which Windows does not support; and `t.TempDir()` lives under
  `%LOCALAPPDATA%\Temp`, inside the user profile, so the HOME guard refuses every test.

The user's store lives in `~/Dropbox/angou`, synced from Linux machines, and carries CLI
builds for linux and darwin only.

### What this is not

No Linux or macOS behaviour changes except where noted (R7.3's fd 0 mapping is a no-op
off Windows; R4's second installer is written into every store). No security property is
relaxed: passphrase zeroing, the no-subprocess rule, and the no-secrets-in-logs rule hold
on Windows as they do elsewhere, and the Windows CLI stays CGO-free.

---

## Requirements

### R1 — The CLI builds and is CGO-free on Windows

**R1.1** `O_NOFOLLOW` is taken from a small `internal/fsx` package that defines it per
platform: `syscall.O_NOFOLLOW` off Windows, zero on Windows.

**R1.2** Where the no-follow open protects the leaf of an extraction
(`store.Extract`), Windows gets an explicit `Lstat` check first (`fsx.RefuseSymlink`).
That check and the open are two steps, so a symlink planted between them is not caught;
this is stated in the code, not hidden. Creating a symlink on Windows needs Developer
Mode or `SeCreateSymbolicLinkPrivilege`, which narrows who can race it. `CopyStore`
already opens with `O_EXCL`, which refuses any existing leaf, symlink included.

**R1.3** The Windows CLI is built with `CGO_ENABLED=0`. Its Credential Manager backend
(R2) calls `advapi32` through `x/sys/windows`' lazy DLL loading and needs no C toolchain.

**R1.4** Every commit-by-rename (`writeFileAtomic`, rekey's swaps, the local key, the
config) goes through `fsx.Rename`, which on Windows retries for up to two seconds on
`ERROR_ACCESS_DENIED`, `ERROR_SHARING_VIOLATION` and `ERROR_LOCK_VIOLATION`, and returns
any other error at once. Windows will not replace a file another process holds open
without `FILE_SHARE_DELETE`, and a sync client holds a file it has just seen change. Found
bootstrapping a real Dropbox store: the self-test's index commit was refused with "Access
is denied". Measured on a Dropbox folder, a replacement right after a write failed seven
times over 359 ms and then succeeded. Off Windows, `fsx.Rename` is `os.Rename`.

**R1.5** When the bootstrap self-test's `Put` fails, the probe is removed before the error
is returned. `Put` writes the blob before the index, so a failed index commit otherwise
leaves an unlisted `.angou-selftest` blob in the store, synced to every machine.

### R2 — Secret storage on Windows (the Credential Manager backend)

**R2.1** `keyring_windows.go` stores the unlock passphrase as a generic credential
(`CRED_TYPE_GENERIC`) in the signed-in user's Credential Manager vault, target
`angou/unlock-<fingerprint>`, persisted `CRED_PERSIST_LOCAL_MACHINE` — not
`ENTERPRISE`, which would roam it with a domain profile to machines that have no local
key for it to open.

**R2.2** `Available()` probes by reading an entry that does not exist: `ERROR_NOT_FOUND`
means the vault answers; anything else, including `ERROR_NO_SUCH_LOGON_SESSION` (a
network logon over ssh), means unavailable and the command falls back to the recovery
passphrase. `ANGOU_KEYRING=none` forces unavailable, as on every platform.
`ValidateBackend` accepts `auto` and `none` and reports a Linux backend name as
`ErrBadBackend` rather than ignoring it.

**R2.3** The vault's copy of the secret returned by `CredReadW` is zeroed before
`CredFree`. The protection is Windows': DPAPI under the user's logon credentials. Any
process running as the user can read the entry — the same boundary as the Secret Service
and the login Keychain — and the docs say so.

### R3 — The agent on Windows (refused, deliberately)

**R3.1** The agent is not implemented on Windows. It requires a peer credential check
before serving key material, and `AF_UNIX` on Windows has no `SO_PEERCRED`. The agent
exists to spare a keyring-less machine the passphrase; on Windows the Credential Manager
does that.

**R3.2** `angou agent start` refuses up front on Windows with a message saying why, after
parsing `--ttl` and before asking for a passphrase. Previously it would have started,
printed a socket, and then refused every connection, leaving each command to fall back to
the passphrase with no explanation. `core.AgentSupported()` carries the decision, so the
GUI and the CLI agree.

### R4 — Bootstrapping a Windows machine from a store

**R4.1** `angou release` writes `bootstrap.ps1` beside `bootstrap.sh`, with the same
release-key fingerprint baked in, signed by the same offline key
(`bootstrap.ps1.sig`), and its digest recorded in the store metadata as
`bootstrap_ps1_sha256`.

**R4.2** The new metadata field is additive and optional. A store written before it, or
rewritten by an older angou that drops the unknown field, has no record for
`bootstrap.ps1`, which reads as "nothing recorded" and not as a mismatch. Rekey carries
the field across.

**R4.3** `bootstrap.ps1` runs on the stock Windows PowerShell 5.1 and does what
`bootstrap.sh` does: pick the newest CLI for `windows-<arch>` by the same version
ordering, verify its signature with gpg and check that the signing key is the pinned
fingerprint, install it to `%LOCALAPPDATA%\Programs\angou\angou.exe` (or
`ANGOU_INSTALL_DIR`), install a GUI if the store carries one for the platform and add a
Start menu entry for it, warn when the install directory is not on PATH and print the
command that adds it, self-check its own signature afterwards with the same "detection
after execution" wording, and point at `angou bootstrap --store`. It never touches the
network and never asks for a passphrase.

**R4.3.1** Both installers word the closing step as conditional, because neither can tell
a first install from an upgrade without reading the store. `bootstrap.ps1` also checks the
saved user and machine PATH, not only the PATH it inherited, and says "from the next
terminal you open" when only the saved one has the directory.

**R4.4** `bootstrap.ps1` is ASCII. Windows PowerShell 5.1 reads a script without a
byte-order mark in the ANSI code page.

**R4.5** gpg is found on PATH, then under `%ProgramFiles%` where Gpg4win and Git for
Windows install it. Git for Windows' gpg is an MSYS build that reads `C:\x` as a
relative path, so the script detects it (its `--version` reports a POSIX home) and hands
it `/c/x`. Import and verify run with `--no-autostart`: neither needs gpg-agent, and
starting one fails under MSYS gpg when the temporary path is long. With no gpg, the
script names `winget install GnuPG.Gpg4win` and installs nothing.

**R4.6** `verify-bootstrap` and the drift warning on unlock cover every installer
present. `verify-bootstrap --record` records every installer present. The CLI now goes
through `core` for this (`Session.VerifyBootstraps`, `Session.RecordBootstraps`) rather
than reading the script itself, and the GUI's "Verify bootstrap.sh" button becomes
"Verify installers" over the same call.

**R4.7** The version-floor refusal names the installer for the host:
`powershell -NoProfile -ExecutionPolicy Bypass -File <store>\bootstrap.ps1` on Windows,
`sh <store>/bootstrap.sh` elsewhere.

### R5 — Build

**R5.1** `.gitattributes` sets `* text=auto eol=lf`, so every checkout writes LF on every
platform and the embedded installers are byte-identical to the ones a Linux build embeds.

**R5.2** The Makefile appends `$(go env GOEXE)` to host outputs (`angou.exe`,
`angou-gui.exe`) and to `ANGOU_E2E_BIN`. `build-all` cross-compiles `windows/amd64` and
`windows/arm64` CLIs, named without `.exe` in `dist/` so `angou release` reads the
platform from the name as it does for the others.

**R5.3** The Windows GUI links with `-H windowsgui`, or a Start menu launch opens a
console window beside it. `build-all`'s host GUI build now also passes `FYNE_TAGS`, which
it had been missing on every platform.

**R5.4** `install-lint` fetches the linter's `.zip` on Windows (Git Bash or MSYS
`uname`), checksum-verified like the tarball, and extracts it with `unzip` where present,
else `bsdtar`, which MSYS2 and Windows (`System32\tar.exe`) both ship.

### R6 — Behaviour that differs because Windows has no mode bits

**R6.1** Go reports `0666` (or `0444`) for every Windows file. Recording that would hand
the next Unix machine to decrypt the file a world-readable private key, so `enc` on
Windows records `0600`, or `0400` for a read-only file.

**R6.2** Restore-to-origin is already safe across platforms: a Windows origin
(`C:\...`) is not absolute on Unix and a Unix origin (`/home/...`) is not absolute on
Windows, so either is refused with "use -o" rather than written somewhere unexpected.

**R6.3** Config and local-key locations stay at `%USERPROFILE%\.config\angou` and
`%USERPROFILE%\.local\share\angou`, the same decision spec 003 R6.3 made for macOS:
parity with Linux over the native `%APPDATA%`. Files there are protected by the profile
directory's ACL, not by mode bits.

### R7 — The test gate runs on Windows

**R7.1** The e2e harness passes the passphrase pipe as an inherited handle
(`SysProcAttr.AdditionalInheritedHandles`) and names its value in `--passphrase-fd`;
`os.NewFile` takes a handle on Windows. Off Windows it is descriptor 3 as before.

**R7.2** The HOME guard still refuses a test home that is, or is inside, the real home —
except inside the system temporary directory when that directory is not the home itself,
which is where every Windows `t.TempDir()` lives. The child gets `USERPROFILE`,
`APPDATA`, `LOCALAPPDATA` and `TEMP` pointed into the sandbox, because
`os.UserHomeDir` reads `USERPROFILE` on Windows, not `HOME`.

**R7.3** `--passphrase-fd 0` means standard input on every platform. On Windows the value
otherwise names a handle, and standard input's handle is not 0.

**R7.4** Platform-specific assertions are made platform-aware rather than skipped
wholesale: mode-bit assertions apply where mode bits exist; the static-binary test checks
on Windows that every DLL in the PE import table is a System32 DLL (a CGO build would
import the MinGW runtime); the installer tests run `bootstrap.ps1` under
`powershell.exe` with a bare-machine environment; the agent tests skip on Windows with a
reason and a new test asserts the refusal of R3.2; gpg tests give MSYS gpg a short
`/c/...` GNUPGHOME.

### R8 — Dependencies

**R8.1** fynedesygn v0.1.40 → v0.1.84. No source change needed: the only breaking entry
in between (0.1.78) is in `glance/kwin`, which angou does not use, and 0.1.61's migration
note applies only to programs with a translucent `glance` window.

### R9 — Documentation and release

**R9.1** README states Windows as supported: what to install to build (Go, MinGW-w64 gcc
for the GUI, make), how to bootstrap from a store, the Credential Manager backend, that
the agent does not run on Windows and why, and the mode-bit behaviour of R6.1.

**R9.2** Changelog entry; `VERSION` and `README.md` bumped together, number approved by
the user.

---

## Acceptance criteria

- [x] R1.1–R1.3 — `CGO_ENABLED=0 go build ./cmd/angou` succeeds on windows/amd64; linux
      and darwin `go vet` unchanged
- [x] R1.4–R1.5 — `fsx.Rename` waits out a brief hold and gives up on a long one
      (`TestRenameWaitsOutABriefHold`, `TestRenameGivesUpOnAHoldThatOutlastsTheTimeout`)
- [x] R2.1–R2.3 — Credential Manager round-trip, replace, missing entry, remove-absent,
      oversize refusal and `ANGOU_KEYRING=none` unit-tested against the real vault
- [x] R3.1–R3.2 — `agent start` refuses before asking for a passphrase
      (`TestAgentRefusesToStartWhereUnsupported`)
- [x] R4.1–R4.7 — `bootstrap.ps1` written, signed and recorded; installer e2e tests pass
      under PowerShell 5.1 with Git for Windows' gpg; `TestVerifyBootstrapCoversTheWindowsInstaller`
- [x] R5.1 — `.gitattributes`; working tree renormalized to LF
- [x] R5.2–R5.4 — `make build-static`, `make build-gui`, `make build-all`, `make e2e` run
      on Windows
- [x] R6.1 — Windows `enc` records 0600 (`TestLsShowsDetail` sees `rw-------`)
- [x] R7.1–R7.4 — e2e harness changes
- [x] R7 — full `make e2e` passes on Windows and is recorded in the validation report
- [x] R8.1 — fynedesygn v0.1.84; GUI builds
- [x] R9.1–R9.2 — README, changelog, version bump (0.6.0)
- [x] A real store, released from Linux with the Windows CLI cross-compiled, bootstraps
      this Windows machine with no angou installed beforehand. 0.6.0 did, but its
      self-test failed on the index commit (R1.4) and left a probe behind (R1.5); 0.6.1
      fixes both and upgraded this machine from the store with `bootstrap.ps1`
