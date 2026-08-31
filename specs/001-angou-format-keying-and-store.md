# 001 — angou: container format, key model, store layout, and bootstrap

## Status: INCOMPLETE

---

## Executive Summary

_To be populated before opening the MR (per global spec conventions)._

---

## Context

`angou` is a CLI + GUI tool that converts sensitive files to and from encrypted
blobs using OpenPGP. Target content is small and high-value: `.secrets.env` files,
SSH private keys, and text files containing passwords or other sensitive data.

The backing store is a plain directory, typically Dropbox-synced, so the format must
survive a sync service that duplicates, renames, and occasionally corrupts files. The
tool must also bootstrap onto an unconfigured machine — initially CachyOS/Arch, with
macOS as a later target — recovering both the key material and a working binary from
that store alone.

The project is named `angou` (暗号 — cipher / encryption; 暗号化 *angouka* is
"encryption"). The romanization follows wapuro convention, matching the kana あんごう
directly rather than relying on a macron. The Go module path is
`github.com/ushineko/angou`; the container magic string is `ANGOU1` and the file
extension is `.angou`.

Design constraint carried from the project security policy: no key material,
passphrase, or store content is ever committed to the repository. All state lives in
`~/.local/share/angou/` and the user-designated store directory.

---

## Requirements

### R1 — Container format

R1.1 Blobs use a text container: a plaintext header, a payload, and a terminator. The
opening delimiter is the literal line `-----BEGIN ANGOU1 BLOB-----` and the closing
delimiter `-----END ANGOU1 BLOB-----`. The magic string `ANGOU1` carries the format
version, so a future incompatible format is a different magic rather than a field a
reader might overlook. These literals are duplicated in `packaging/` for `file(1)` and
`shared-mime-info`; changing one requires changing all three.

R1.2 The payload is ASCII-armored (base64) OpenPGP by default. A `--binary` mode
emits raw OpenPGP packets for large inputs. The header declares which encoding is in
use; readers never infer it.

R1.3 The plaintext header carries only dispatch data: format magic, format version,
payload encoding, and the recipient key fingerprint. It MUST NOT carry the original
filename, plaintext size, or any hash of the plaintext.

R1.4 Descriptive metadata — original name, MIME type, POSIX mode, mtime, size, and
plaintext SHA-256 — is carried in an envelope inside the encrypted payload. The
envelope is authoritative for a blob's identity.

R1.5 The payload is a standard OpenPGP message. `gpg --decrypt` on a blob body must
yield the envelope without requiring `angou`. This is a recovery guarantee, not an
interop convenience, and is load-bearing for R5.

R1.6 A single file extension (`.angou`) is used for both encodings. Detection is
provided by a `shared-mime-info` package for KDE and a `file(1)` magic entry.

### R2 — Key model

R2.1 One OpenPGP keypair per store constitutes the identity. It performs all
encryption and decryption and is necessarily identical across machines, since blobs
must be portable.

R2.2 Two distinct passphrases wrap that keypair:

- **Recovery passphrase** — human-memorized, never cached. Symmetrically encrypts the
  exported key bundle and the `bootstrap/` namespace (R5). A property of the store,
  identical on every machine.
- **Unlock passphrase** — 32 bytes from a CSPRNG, generated at bootstrap, never
  displayed to the user. Wraps the keypair in the local keyring only.

R2.3 The unlock passphrase MUST NOT be derived from the hostname, `/etc/machine-id`,
or any other host-identifying value. Derivation from host data would make the local
wrapper recoverable by anyone who images the disk and reads the derivation function.

R2.4 The unlock passphrase is stored in KWallet and is its only copy. Consequently the
local keyring is disposable derived state: loss of the wallet entry is recovered by
re-running bootstrap, not by any local means. The tool MUST detect the "key present,
wallet entry absent" state and direct the user to re-bootstrap rather than issuing an
unanswerable passphrase prompt.

R2.5 Where KWallet is unavailable (headless, non-KDE, future macOS before Keychain
support), bootstrap does not re-protect the imported key; it remains under the
recovery passphrase on that machine.

R2.6 Keyring state lives in `~/.local/share/angou/`, isolated from the user's
default GnuPG keyring.

### R3 — Store layout

R3.1 The store is a plain directory of opaque blobs, portable by `rsync`, Dropbox, or
removable media. No database.

R3.2 Blob filenames are keyed hashes of the store-relative logical path:

```
blob_id = base32( HMAC-SHA256(K_name, normalized_path) )[:26]
```

R3.3 `K_name` is 32 random bytes generated at store initialization and stored in
`store.angou`, a fixed-name blob encrypted to the keypair. Unlocking the store decrypts
`store.angou` once, yielding `K_name` and the index.

R3.4 Blob names MUST NOT be an unkeyed hash of the filename. Filenames are
low-entropy; an unkeyed hash permits an offline dictionary attack (`.env`, `id_rsa`,
`aws-credentials`) that reveals store contents without any key.

R3.5 The store is keyed by store-relative path, not basename, so identically-named
files from different projects do not collide. The GUI renders these paths as a tree.

R3.6 `index.angou` holds an encrypted map of `blob_id → {path, mime, size, mtime, tags}`
so the navigator can list the store without decrypting every blob.

R3.7 The index is a rebuildable cache and is never authoritative. `angou reindex`
reconstructs it from blob envelopes. A corrupt, conflicted, or absent index degrades
browsing only; retrieval by name is unaffected because it goes through R3.2.

R3.8 Accepted leak surface for a store on third-party infrastructure: blob count,
approximate sizes, and mtimes.

### R4 — Rotation and rekey

R4.1 `angou rekey --local` generates a fresh unlock passphrase, re-protects the
local key, and overwrites the wallet entry. No blob or remote state changes.

R4.2 `angou rekey --identity` generates a new keypair, re-encrypts every blob and
`store.angou` to it, and writes a new key bundle. This is the response to a genuinely
compromised machine, where the attacker holds the keypair and R4.1 provides no
protection.

R4.3 `rekey --identity` is transactional against a store that may be mid-sync: it
writes to a staging directory and commits by rename, so an interrupted rekey leaves
the previous store intact.

### R5 — Bootstrap and the `bootstrap/` namespace

R5.1 The store contains a `bootstrap/` namespace encrypted **symmetrically under the
recovery passphrase**, not to the keypair. It contains the exported key bundle and one
signed binary per supported OS/architecture.

R5.2 Symmetric encryption is required here to break a circular dependency: binaries in
the store cannot be encrypted to a keypair that is not yet present on the target
machine.

R5.3 `make release` stashes the built binaries into `bootstrap/` with a metadata
record capturing version, git commit, Go toolchain version, build flags, and SHA-256.

R5.4 Binaries are encrypted and OpenPGP-signed. They MUST NOT be stored in plaintext:
a plaintext executable in a synced directory turns write access to the sync account
into arbitrary code execution on every machine subsequently bootstrapped.

R5.5 The store root contains `bootstrap.sh`, a plaintext entrypoint script in the
style of an open-source install script (cf. the `herdr` bootstrap). It contains no
secrets and is therefore not encrypted. It is the documented first action on a new
machine.

R5.6 `bootstrap.sh` is responsible for first-run environment handling:

- Detect OS and architecture, normalizing to the `GOOS`/`GOARCH` names used by the
  `bootstrap/` namespace (`x86_64` to `amd64`, `aarch64`/`arm64` to `arm64`).
- Verify the platform is supported by the namespace and fail with the list of
  available platforms if not.
- Locate `gpg`. Where it is absent, print the correct install command for the detected
  platform (`pacman -S gnupg`, `brew install gnupg`, `apt install gnupg`) and exit
  non-zero rather than proceeding.
- Prompt for the recovery passphrase, decrypt the platform binary from `bootstrap/`,
  and verify its OpenPGP signature (R5.4) before installing it.
- Install to `~/.local/bin/angou`, warn if that directory is not on `PATH`, and hand
  off to `angou bootstrap` (R5.8) for the remainder.

R5.7 `bootstrap.sh` performs no network access. Its only inputs are the store
directory it resides in and the recovery passphrase. This bounds what a subverted copy
of the script can do without the change being conspicuous in a short, readable file.

R5.8 The SHA-256 of the current `bootstrap.sh` is recorded inside `store.angou`.
`angou verify-bootstrap` checks the on-disk script against that record.

R5.8.1 The primary invocation is **out-of-band**: run from a machine that already holds
a trusted `angou`, against the store, to detect alteration of the script that other
machines will subsequently run. `angou` additionally runs the check opportunistically
on store unlock, reporting a mismatch as a warning.

R5.8.2 `bootstrap.sh` also invokes the check immediately after installing the verified
binary, and exits non-zero with a prominent warning on mismatch. This is
detection-after-execution, not prevention: a deliberately subverted script would simply
omit the call. Its purpose is to catch accidental drift — a sync-service conflicted
copy, a truncated file, a local edit — and to leave an incident trail when the executed
script did not match the store record. Documentation and command output MUST describe it
in those terms and MUST NOT present it as a first-run integrity guarantee.

R5.8.3 Self-verification by an untrusted script is not a security control and no
ordering within `bootstrap.sh` makes it one. The first machine to run a subverted script
is unprotected; this is inherent to a plaintext entrypoint and is accepted (see R-8).

R5.9 `angou bootstrap` performs: dependency check → create
`~/.local/share/angou/` at 0700 → prompt recovery passphrase → decrypt key bundle →
import key and ownertrust → generate unlock passphrase and re-protect (R2.2, subject
to R2.5) → write wallet entry → install MIME, magic, and desktop files → round-trip
self-test on a temporary file.

R5.10 `bootstrap/` retains at most N versions per platform (default 3) so binary
history does not grow without bound in the synced directory. `angou clone
--no-binaries` produces a store copy omitting the namespace.

### R6 — Implementation

R6.1 Go, following `~/.claude/policies/languages/go.md` and the conventions of
`aiq_agent_go`.

R6.2 Two binaries:

- `angou` — CLI. Built `CGO_ENABLED=0` for a fully static artifact. This is the
  binary stashed per R5.3 and is sufficient for bootstrap on its own.
- `angou-gui` — desktop navigator over the store. Built separately; may require
  CGO. Never required for bootstrap.

R6.3 No subprocess invocation of `gpg`, `gpg-agent`, or `kwallet-query` in the normal
path. OpenPGP via `github.com/ProtonMail/go-crypto/openpgp`; KWallet via
`github.com/godbus/dbus/v5` against `org.kde.kwalletd6`. Both are CGO-free, so the CLI
has no package prerequisites on a bare system.

R6.4 CLI structure uses `spf13/cobra`, consistent with `aiq_agent_go`. Subcommands:
`enc`, `dec`, `ls`, `get`, `rm`, `mv`, `reindex`, `rekey`, `bootstrap`, `agent`,
`clone`, `verify-bootstrap`.

R6.5 Because there is no `gpg-agent`, `angou agent` provides session caching: a unix
socket in `$XDG_RUNTIME_DIR` at 0600 holding unlocked key material, `K_name`, and the
decrypted index under a TTL. Secret buffers are explicitly zeroed and `mlockall` is
attempted. Go's garbage collector may relocate heap secrets, so memory hardening is
best-effort and is documented as such rather than claimed.

R6.6 Package layout:

```
angou/
  cmd/angou/            CLI entry point
  cmd/angou-gui/        GUI entry point
  lib/container/          container format — exported, third-party readable
  internal/store/         blob addressing, index, reindex
  internal/envelope/      inner metadata envelope
  internal/keyring/       keyring_linux.go, keyring_darwin.go
  internal/agent/         session cache daemon
  specs/
  tests/
```

Platform-specific keyring files are split by build constraint so macOS Keychain
support is a new file rather than a refactor.

### R7 — Build and lint

R7.1 The Makefile follows the `aiq_agent_go` pattern: `default: help`, help generated
by the `##`-comment awk rule, `golangci-lint` pinned via `LINT_VERSION` and installed
to `$(go env GOPATH)/bin` with SHA-256 verification against the release checksum
manifest, and `GOTOOLCHAIN` pinned from `go.mod` so local lint matches CI.

R7.2 Targets: `help`, `install-lint`, `setup`, `lint`, `test`, `coverage`, `build`,
`build-static`, `build-gui`, `build-all`, `release`, `install`, `clean`.

R7.3 Builds use `-ldflags='-w -s' -trimpath`. Combined with a pinned toolchain this
yields near-reproducible binaries, which is what makes the R5.3 metadata record
meaningful.

---

## Acceptance Criteria

### Format

- [ ] A blob written by `enc` and read by `dec` round-trips byte-identical content,
      mode, and mtime for both a text and a binary input.
- [ ] The plaintext header of a produced blob contains no original filename and no
      plaintext hash, verified by asserting against the raw bytes.
- [ ] `--binary` and armored modes both round-trip, and a reader honours the header's
      declared encoding rather than sniffing.
- [ ] **Integration:** the system `gpg` binary decrypts an armored blob body produced
      by `angou` and yields a parseable envelope (R1.5). This test invokes real
      `gpg`, not a Go OpenPGP reimplementation.
- [ ] `file(1)` with the installed magic entry, and `xdg-mime query filetype`,
      both identify a `.angou` blob.

### Key model

- [ ] Bootstrap generates an unlock passphrase from `crypto/rand` that appears in no
      log, no terminal output, and no file other than the wallet entry.
- [ ] Two bootstraps of the same key bundle produce different unlock passphrases.
- [ ] With the wallet entry deleted and the keyring intact, the CLI reports a
      re-bootstrap instruction and exits non-zero without prompting for a passphrase.
- [ ] With KWallet unreachable, bootstrap completes and leaves the key under the
      recovery passphrase (R2.5).
- [ ] **Integration:** the wallet entry is written and read back through a live
      `org.kde.kwalletd6` D-Bus service, not a mocked bus.

### Store

- [ ] The same logical path encrypted twice resolves to the same `blob_id` and updates
      in place, leaving no orphan blob.
- [ ] Two stores initialized with different `K_name` produce different `blob_id`
      values for the same path.
- [ ] `get` retrieves by logical path with `index.angou` deleted.
- [ ] `reindex` reconstructs an index equal to the original after the index is deleted,
      and after it is replaced with a Dropbox-style conflicted copy.
- [ ] Identically-named files under different store-relative paths coexist.

### Rotation

- [ ] `rekey --local` leaves every `blob_id` and blob body byte-identical.
- [ ] `rekey --identity` re-encrypts all blobs; every blob decrypts under the new key
      and none under the old.
- [ ] `rekey --identity` interrupted mid-run (process killed) leaves the original store
      fully readable.

### Bootstrap

- [ ] **Integration:** on a container with no `angou`, no keyring, and no Go
      toolchain, `bootstrap.sh` extracts and installs a runnable binary from
      `bootstrap/` using system `gpg` and the recovery passphrase alone.
- [ ] Following that, `angou bootstrap` completes and the round-trip self-test passes.
- [ ] On a container with `gpg` absent, `bootstrap.sh` exits non-zero naming the
      correct install command for the detected platform and installs nothing.
- [ ] `bootstrap.sh` resolves `x86_64` to `amd64` and `aarch64` to `arm64`, and fails
      with the list of available platforms when the detected platform is absent from
      `bootstrap/`.
- [ ] `bootstrap.sh` refuses to install a binary whose OpenPGP signature does not
      verify.
- [ ] `verify-bootstrap` reports a mismatch after a single byte of `bootstrap.sh` is
      altered, and reports clean otherwise.
- [ ] `bootstrap.sh` exits non-zero with a visible warning when the post-install check
      finds a mismatch, and the warning text describes the check as detecting drift
      after execution rather than as a guarantee that the executed script was genuine.
- [ ] Store unlock emits a warning when the on-disk `bootstrap.sh` does not match the
      record in `store.angou`.
- [ ] `bootstrap.sh` passes `shellcheck`.
- [ ] A tampered `bootstrap/` binary fails signature verification and is refused.
- [ ] `make release` writes a binary plus a metadata record whose recorded SHA-256
      matches the decrypted artifact.
- [ ] Retention prunes to N versions per platform.

### Build

- [ ] `make lint` passes at the pinned `golangci-lint` version.
- [ ] `make test` passes with `-race`.
- [ ] `make build-static` produces a binary that `ldd` reports as not dynamically
      linked, and which runs in a `scratch`-based container.
- [ ] `make help` lists every target.

### Security

- [ ] A repository scan finds no key material, passphrase, or store content.
- [ ] No passphrase or plaintext appears in any log path at debug verbosity.

---

## Risks & Assumptions

**R-1 — KWallet is load-bearing for the local key.** Wiping the wallet strands the
local keyring. Accepted: re-bootstrap is inexpensive, and R2.4 requires the tool to
detect and explain the state rather than fail obscurely.

**R-2 — Go memory hardening is best-effort.** The garbage collector may copy secret
buffers before they are zeroed. Documented rather than claimed; `mlockall` and explicit
wipes reduce but do not eliminate exposure.

**R-3 — Bootstrap depends on system `gpg` on the target platform.** True on
Arch/CachyOS, where `pacman` depends on gnupg. It is not present by default on macOS.
This is handled rather than assumed away: R5.6 requires `bootstrap.sh` to detect the
absence and print the platform-appropriate install command. `gpg` is invoked exactly
once per machine, to decrypt the binary that cannot decrypt itself; no `angou`
operation after that point uses it.

**R-4 — Blob count, size, and mtime leak** to anyone holding the store (R3.8). Padding
and blob-count obfuscation are out of scope.

**R-5 — Binary retention inflates the synced directory.** A static Go binary is tens of
megabytes; N versions across platforms is the dominant contributor to store size.
Mitigated by R5.10 retention and `clone --no-binaries`.

**R-6 — Sync-service concurrency.** Two machines writing simultaneously can produce
conflicted copies. The index is rebuildable (R3.7) and rekey is transactional (R4.3);
concurrent writes to the *same* blob from two machines are last-writer-wins and are not
otherwise resolved.

**R-7 — Deleting plaintext after encryption is not a secure erase** on Btrfs (this
machine's filesystem) or on any copy-on-write or flash-translation-layer storage. The
default is therefore to leave the plaintext in place; `--shred` is opt-in and its
documentation must state the limitation rather than imply a guarantee.

**R-8 — `bootstrap.sh` is plaintext and is executed.** Write access to the store
therefore permits code execution on any machine that has not yet bootstrapped. This is
the same exposure R5.4 closes for the binaries, relocated to the entrypoint, and it is
the accepted trust model of any `curl | sh`-style installer. Mitigations: the script
takes no network input (R5.7), is short enough to read before running, and its hash is
pinned inside the encrypted store so tampering is detectable out-of-band from any
already-provisioned machine (R5.8.1).

The load-bearing property is R5.4. Because the binaries are encrypted and signed, an
attacker cannot achieve execution by modifying them alone — they are forced to also
modify `bootstrap.sh`. All possible tampering is therefore funnelled into a single
small, readable, hash-pinned plaintext file, which is the cheapest artifact to inspect
and to monitor.

The first machine to run a subverted script is not protected. No plaintext entrypoint
can protect it, and no placement of a self-check within the script changes this
(R5.8.3).

**Rollback**: the tool is a new, self-contained subproject with no existing consumers.
Rollback is removal of `~/.local/bin/angou*` and the installed MIME, magic, and
desktop entries. Stores written by a given format version are readable by that version;
`R1.1`'s version field exists so a future format change can be detected rather than
misparsed.

---

## Alternatives Considered

**Raw binary blobs as the default format.** Rejected: saves 33% on ciphertext that is
already a few kilobytes, while forfeiting paste-safety and resistance to editor and
line-ending corruption. GPG compresses before encrypting, so armored output for text
input is frequently smaller than the plaintext input.

**`sha256(plaintext)` as the blob filename.** Rejected: publishes a confirmation oracle
in directory listings. Low-entropy plaintexts become brute-forceable.

**`sha256(ciphertext)` as the blob filename.** Rejected: OpenPGP output is randomized,
so the name changes on every re-encryption. It provides no deduplication and no stable
identity — functionally a random identifier with extra steps.

**ULID blob filenames.** Rejected in favour of R3.2: loses determinism, so updates
create orphans and lookup by name requires the index.

**Unkeyed `sha256(filename)`.** Rejected per R3.4.

**An authoritative index.** Rejected: a sync service that duplicates files will
eventually desync an authoritative index from the blobs it describes, with no recovery
path. Envelope-as-truth makes every index problem repairable.

**Shelling out to `gpg` and `kwallet-query`.** Rejected: contradicts the standalone
requirement and, more concretely, the bootstrap requirement — the tool must run where
those packages are absent. Note that R1.5 deliberately retains `gpg` *readability* of
the output format while removing `gpg` as a runtime dependency.

**Single binary with an embedded web-UI navigator.** Rejected in favour of R6.2:
double-click handling and inline preview are desktop-integration features that a
browser tab serves poorly, and it would place plaintext in a browser process.

**Plaintext binaries in `bootstrap/`.** Rejected per R5.4.

**A documented `README.txt` one-liner instead of `bootstrap.sh`.** Rejected: it pushes
platform detection, `gpg` availability checking, and signature verification onto the
user at exactly the moment they have the least context. Its one advantage is that a
human reads a one-liner before running it, whereas a script is executed unread — that
gap is addressed by R5.7 and R5.8 rather than by keeping the weaker entrypoint.

**A separate lower-privilege index key**, permitting store listing without decrypt
authority. Rejected as unjustified complexity: it earns its keep only if a store is
browsed on a machine not trusted with its contents, which is not a use case here.

---

## Open Items

None blocking implementation. Deferred by decision: the macOS Keychain keyring backend
(R2.5 covers the interim). The macOS bootstrap first step, previously open, is closed by
R5.6.
