# 001 — angou: container format, key model, store layout, and bootstrap

## Status: INCOMPLETE

Implementation is proceeding in passes. The first pass covers the container format,
the metadata envelope, the recovery-passphrase half of the key model, store addressing,
the index, and the `init`, `enc`, `dec`, `get`, `ls`, `mv`, `rm`, and `reindex`
commands, together with the end-to-end test practice of R8. Twenty-five acceptance
criteria are met and checked below.

The unchecked criteria are unstarted rather than failing. They belong to the keyring
and unlock-passphrase model (R2.2 second half, R2.4, R2.5), the bootstrap and
release-signing chain (R5), rotation (R4), the session cache (R6.5), and the two
integration criteria that depend on them — `gpg` reading a blob body, which needs a key
export path, and `file(1)`/`xdg-mime` detection, which needs the packaging installed.

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

The project is named `angou` (暗号 — cipher / encryption). The Go module path is
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
and payload encoding. It MUST NOT carry the original filename, plaintext size, any hash
of the plaintext, or the recipient key fingerprint. A fingerprint in the clear is a
stable correlation handle that links every blob in every store to one identity, which
is a leak the header does not need to accept: a store holds one keypair (R2.1), so the
reader trial-decrypts rather than being told which key to use.

R1.4 Descriptive metadata — original name, MIME type, POSIX mode, mtime, size, and
plaintext SHA-256 — is carried in an envelope inside the encrypted payload. The
envelope is authoritative for a blob's identity.

R1.7 Every payload is **signed as well as encrypted** (sign-then-encrypt), and readers
MUST verify the signature before acting on the plaintext. Encrypting to a public key
proves only that the writer knew the public key; it says nothing about who wrote the
blob. Without a signature, anyone with write access to the store can author a blob or
an `index.angou` that decrypts cleanly and is treated as genuine. The plaintext
SHA-256 in the envelope does not help, because an attacker who authors the blob also
chooses that hash.

R1.8 A reader MUST reject a blob whose filename does not equal
`HMAC-SHA256(K_name, envelope.path)` (R3.2). Without this binding, an attacker who can
rename files in the store serves the contents of one secret under the name of another
— every signature verifies, every hash matches, and the wrong secret is returned with
no error. The name-to-content binding is a separate control from the signature and
neither substitutes for the other.

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

R2.2.1 The recovery passphrase is the single offline cracking target in this design.
Anyone with **read** access to the store can copy the key bundle and the `bootstrap/`
namespace and guess against them offline, without limit and without detection. Its
protection is therefore pinned explicitly and not left to OpenPGP defaults:

- The recovery passphrase does not encrypt the bundle directly. It derives a wrapping
  key via **Argon2id** with parameters recorded in the clear beside the ciphertext
  (m=64 MiB, t=24, p=4, 16-byte salt), and that key wraps a random 32-byte
  bootstrap key which does the actual encryption.
- Cipher and AEAD are pinned (AES-256, OCB where available, otherwise AES-256-CFB with
  MDC) rather than inherited from the implementation's defaults.
- Recorded parameters are validated on read: a bundle presenting parameters weaker than
  the pinned floor is refused, so an attacker cannot downgrade the KDF by editing the
  header.
- `angou init` MUST refuse a low-entropy recovery passphrase and offers to generate a
  diceware phrase of at least 77 bits. The generated phrase is displayed exactly once,
  and only after the store has been created: a phrase shown before the store is
  committed tells the user to write down something that opens nothing.
- Words in a generated phrase are drawn without replacement, and the entropy screen
  credits a typed phrase for its **distinct** words only. Crediting repetition would
  admit a phrase of one word repeated nine times.

R2.2.2 The memory parameter is set for **portability**, not for maximum cost, and the
reasoning is recorded because the number looks low beside RFC 9106's first
recommendation. These are RFC 9106's second recommended configuration — the one it
gives for memory-constrained environments — with the pass count raised so the
wall-clock cost is comparable to a gibibyte-scale configuration: measured at 0.24 s
and 77 MiB peak RSS, against 1.02 s and 1.03 GiB for m=1 GiB, t=4, p=4.

The driver is that a store must open on every machine it syncs to (R2.1, R3.1). A
gibibyte floor does not make such a store safer on a small VPS or a limited container;
it makes it unopenable there, which is a worse outcome than a lower per-guess cost.

The derivation is also not the primary defence against offline cracking, and pinning it
as though it were would misstate the design. Entropy is: at the 77-bit floor R2.2.1
enforces, an exhaustive search is infeasible even against a KDF-free hash. The
derivation earns its keep only where the entropy screen has over-credited a
human-chosen phrase, and the *memory* parameter specifically is what bounds an
attacker's parallelism — each concurrent guess needs its own allocation, which is why
Argon2id is used rather than an iteration-only construction.

R2.2.3 Because a failed allocation in Go is a runtime abort rather than a returnable
error, the memory required by a bundle's recorded parameters MUST be checked before the
derivation is attempted, against both the host's available memory and any cgroup limit
on the process. Without the check a constrained machine yields exit 137 and no output.
This is a pre-flight check specifically because there is no error to handle.

Disk space needs no equivalent check: every store write goes to a temporary file that
is written, fsynced, and renamed into place, so an out-of-space condition surfaces as an
error, leaves no debris, and never damages the previous version. A free-space pre-check
would be a time-of-check-to-time-of-use race and would not remove the need to handle the
error anyway.

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

R3.4.1 `normalized_path` is defined strictly, and the definition is a security
control rather than a convenience. A path MUST be relative, use `/` separators, contain
no `.` or `..` component, no leading `/`, no drive letter or UNC prefix, no NUL or
control characters, and no trailing separator; it is NFC-normalized and rejected rather
than silently repaired when it does not conform. Writers and readers apply the same
grammar.

R3.4.2 On extraction, the tool MUST resolve the destination under an explicit root and
refuse to write outside it, and MUST NOT follow symlinks when doing so. An envelope
path is attacker-controlled input in the write-access threat model (R-9): without this,
an envelope naming `../../.ssh/authorized_keys` turns a decrypt into an arbitrary file
write.

R3.5 The store is keyed by store-relative path, not basename, so identically-named
files from different projects do not collide. The GUI renders these paths as a tree.

R3.6 `index.angou` holds an encrypted map of `blob_id → {path, mime, size, mtime, tags}`
so the navigator can list the store without decrypting every blob.

R3.7 The index is a rebuildable cache and is never authoritative. `angou reindex`
reconstructs it from blob envelopes. A corrupt, conflicted, or absent index degrades
browsing only; retrieval by name is unaffected because it goes through R3.2.

R3.8 Accepted leak surface for a store on third-party infrastructure. Enumerated
honestly, because deterministic naming leaks more than a count:

- The number of secrets, and the approximate size of each.
- A **stable pseudonymous identity per file**. Because `blob_id` is deterministic
  (R3.2), an observer watching the store over time can follow one specific file across
  snapshots — when it changes, how often, and in what pattern — without ever learning
  its name. This is the significant leak, and it is the price of the determinism that
  makes updates land in place.
- Additions, deletions, and renames, each visible as a name appearing or disappearing.
- Growth of `index.angou`, which tracks the number of entries.
- The contents of `bootstrap/`: the binaries are plaintext (R5.1), so a reader learns
  that `angou` is in use, which operating systems and architectures, and the release
  history. Accepted deliberately in exchange for the bootstrap working with stock `gpg`
  and for the recovery passphrase guarding exactly one artifact.

Padding, size bucketing, and blob-count obfuscation are out of scope. `K_name`
rotation (R4.2.1) breaks the per-file identity chain at each identity rekey.

### R4 — Rotation and rekey

R4.1 `angou rekey --local` generates a fresh unlock passphrase, re-protects the
local key, and overwrites the wallet entry. No blob or remote state changes.

R4.2 `angou rekey --identity` generates a new keypair, re-encrypts every blob and
`store.angou` to it, and writes a new key bundle. This is the response to a genuinely
compromised machine, where the attacker holds the keypair and R4.1 provides no
protection.

R4.2.1 `rekey --identity` MUST also generate a fresh `K_name`, recompute every
`blob_id`, rename every blob accordingly, and rebuild the index. Rotating the keypair
while leaving `K_name` intact leaves the attacker able to continue tracking which
logical paths exist, which change, and how often — the deterministic names are a
metadata channel that survives an identity rotation unless the naming key rotates with
it. Metadata rotation is part of compromise recovery, not a separate operation.

R4.4 [`docs/compromise-recovery.md`](../docs/compromise-recovery.md) documents the full response to a lost or
compromised machine, because `rekey --identity` alone is insufficient: a stolen machine
may still hold a sync-service session token, the local keyring, an unlocked wallet, a
running agent, and possibly an observed recovery passphrase. The runbook covers, in
order — revoke sync-service sessions and devices; rotate the recovery passphrase;
`rekey --identity` (which rotates `K_name` per R4.2.1); prune superseded key bundles
and `bootstrap/` versions; and invalidate agents on every other machine.

R4.3 `rekey --identity` is transactional against a store that may be mid-sync: it
writes to a staging directory and commits by rename, so an interrupted rekey leaves
the previous store intact.

### R5 — Bootstrap and the `bootstrap/` namespace

R5.1 The store contains a `bootstrap/` namespace holding the exported key bundle and
one binary per supported OS/architecture, each with a detached signature. The two are
protected differently, because only one of them is secret:

- **The key bundle** is encrypted symmetrically under the recovery passphrase with the
  Argon2id construction of R2.2.1. It is the sole artifact in the store whose
  confidentiality matters at this stage.
- **The binaries are stored in plaintext** with detached OpenPGP signatures from the
  offline release-signing key (R5.4.1). They are public software; encrypting them
  protects nothing, and doing so actively weakened the design (R5.2.1).

R5.2 The key bundle is symmetrically encrypted rather than encrypted to the keypair, to
break a circular dependency: it cannot be encrypted to a keypair that is not yet present
on the target machine.

R5.2.1 An earlier revision encrypted the binaries symmetrically under the recovery
passphrase as well. That is withdrawn for two independent reasons, both discovered by
testing against a real `gpg`:

- **It does not work.** `bootstrap.sh` decrypts using system `gpg`, and GnuPG 2.4.9
  implements S2K modes 0, 1 and 3 only — Argon2 is mode 4, from the RFC 9580 refresh.
  An Argon2id-protected message is not decryptable by the tool the bootstrap depends on.
- **The obvious workaround is worse than the problem.** Using a `gpg`-compatible S2K for
  the binaries while reserving Argon2id for the key bundle would protect both artifacts
  with the same passphrase at different costs. An attacker would simply crack the cheaper
  one and obtain the passphrase, capping the whole system at the weaker KDF and making
  the Argon2id upgrade worthless. Two artifacts guarded by one secret are only as strong
  as the weaker guard.

Verifying a detached signature involves no S2K, so plaintext binaries keep stock `gpg`
sufficient for the bootstrap while confining the recovery passphrase to the one artifact
that needs it.

R5.3 `make release` stashes the built binaries into `bootstrap/` with a metadata
record capturing version, git commit, Go toolchain version, build flags, and SHA-256.

R5.4 Binaries are OpenPGP-signed, and signature verification before execution is
mandatory (R5.6). Tamper-resistance comes from the signature and the version floor, not
from encryption.

R5.4.0 A prior revision required the binaries to be encrypted, on the grounds that a
plaintext executable in a synced directory turns write access to the sync account into
arbitrary code execution. That reasoning predates R5.4.1 and R5.4.2, which close that
path directly: a substituted binary fails verification against the offline
release-signing key, and an older genuine binary fails the version floor. Encryption was
standing in for controls that now exist explicitly, while contributing nothing to
confidentiality — the binaries are published software. The residual exposure is that a
reader of the store learns the tool in use and the platforms in play, which R3.8 already
enumerates.

R5.4.1 The key that signs release binaries is a **separate offline release-signing
key**, not the store identity keypair. Its public fingerprint is compiled into the
`angou` binary and stated in `bootstrap.sh`. Store contents MUST NOT determine
release-signing trust: if the verification key travelled in the store or the key
bundle, then anyone who obtained the recovery passphrase — or compromised one machine —
could sign a malicious binary that every future bootstrap would accept as genuine. The
release key is used only at `make release`, never by the tool at runtime, and lives
offline.

R5.4.2 Binaries carry a **version floor**. `store.angou` records the highest release
version ever installed from this store, and `bootstrap.sh` and `angou bootstrap` refuse
a binary older than that floor. Signature verification alone does not establish
freshness: `bootstrap/` retains several versions (R5.10) and a sync service keeps its
own history, so an attacker with write access can replay an older, validly signed,
known-vulnerable binary and obtain execution **without modifying `bootstrap.sh` at
all**. Superseded versions are pruned rather than retained indefinitely, and a version
withdrawn for a vulnerability is removed from `bootstrap/` rather than left signed and
available.

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
- Verify the platform binary's detached signature against the release-signing
  fingerprint pinned in the script (R5.4.1), and refuse to install on failure. No
  passphrase is required for this step, and none is prompted for: the binary is not
  encrypted (R5.1).
- Check the binary's version against the floor recorded for the store and refuse an
  older one (R5.4.2).
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

R5.9.1 The store alone cannot establish the integrity of `bootstrap.sh` on a first
bootstrap, because the hash that would verify it (R5.8) is inside the store and reading
it requires the code being verified. The out-of-band anchor is the public repository:
release fingerprints and the `bootstrap.sh` hash for each release are published at
`github.com/ushineko/angou`, so a user setting up their first machine can compare
before executing. Store-only bootstrap MUST be described as recovering
**confidentiality**, not as establishing first-run code integrity.

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
`init`, `enc`, `dec`, `ls`, `get`, `rm`, `mv`, `reindex`, `rekey`, `passwd`, `prune`,
`doctor`, `bootstrap`, `agent`, `clone`, `release`, `verify-bootstrap`.

R6.4.1 Four of these exist specifically to make compromise recovery (R4.4) executable
rather than aspirational, and are specified here so the runbook does not document a
tool that was never designed:

- `passwd` — rotate the recovery passphrase and rewrite the key bundle under it,
  pruning superseded bundles. Distinct from `rekey`: it changes what guards the key,
  not the key itself.
- `prune --bootstrap --keep N` — remove superseded binaries and key bundles from
  `bootstrap/` beyond the retention floor (R5.10).
- `doctor --old-key <fingerprint>` — assert that a named key opens nothing in the
  store. This is the verification step after `rekey --identity`; without it the
  operator has no way to confirm the rotation was complete rather than partial.
- `agent stop` — terminate the session cache on a machine, releasing cached key
  material, `K_name`, and the decrypted index before their TTL expires.

`ls --long` renders envelope metadata for the whole store, which is what an operator
works from when enumerating the credentials that need rotating at source.
`bootstrap --force` re-runs bootstrap on a machine that already holds a superseded
key.

R6.5 Because there is no `gpg-agent`, `angou agent` provides session caching: a unix
socket in `$XDG_RUNTIME_DIR` at 0600 holding unlocked key material, `K_name`, and the
decrypted index under a TTL. Secret buffers are explicitly zeroed and `mlockall` is
attempted. Go's garbage collector may relocate heap secrets, so memory hardening is
best-effort and is documented as such rather than claimed. The socket mode excludes
other users only; it is not a boundary against processes running as the same user, and
the agent MUST NOT be described as providing one (R-10). The agent verifies peer
credentials, keeps its API minimal, and defaults to a short TTL.

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

### R8 — Testing

R8.1 Verification is end-to-end by default. Each e2e test builds the binary with the
`build-static` flags into a temporary directory and drives it as a subprocess. Tests
MUST NOT reach into internal packages to exercise behavior that a user reaches through
the binary.

R8.2 The rationale is specific to this tool rather than general preference: the
majority of the claims in this spec are properties of the artifact, not of a function.
R1.3 (the header leaks nothing), R1.5 (`gpg` can read the payload), R6.2 (the static
binary has no prerequisites), and R5.6 (a bare machine bootstraps) are each unfalsifiable
against a substitute, because the substitute is not the thing that carries the property.

R8.3 Every e2e run uses a throwaway store created by the tool, a recovery passphrase
generated per run from `crypto/rand`, and `HOME` plus `XDG_*` redirected to temporary
directories. No fixture store and no credential-shaped constant is committed.

R8.4 A test helper MUST fail — not skip — when `HOME` still refers to the real home
directory, so a suite cannot silently operate on a developer's own store, keyring, or
wallet.

R8.5 Tests requiring a real downstream system use a disposable instance of it: a
dedicated, test-named KWallet entry removed afterwards; a throwaway `GNUPGHOME`; a
container with no `angou`, no keyring, and no Go toolchain for the bootstrap path.

R8.6 Unit tests are permitted for logic with genuine edge cases — header parsing, path
normalization, HMAC addressing, retention pruning — and are kept simple: table-driven,
plain assertions, no fixture frameworks or mock hierarchies. Scaffolding-heavy unit
tests are a signal the behavior belongs in an e2e test.

R8.7 `make e2e` is required before a release commit. Unit tests alone do not satisfy
the Phase 3 validation gate.

---

## Acceptance Criteria

### Format

- [x] A blob written by `enc` and read by `dec` round-trips byte-identical content,
      mode, and mtime for both a text and a binary input.
- [x] The plaintext header of a produced blob contains no original filename and no
      plaintext hash, verified by asserting against the raw bytes.
- [x] `--binary` and armored modes both round-trip, and a reader honours the header's
      declared encoding rather than sniffing.
- [ ] **Integration:** the system `gpg` binary decrypts an armored blob body produced
      by `angou` and yields a parseable envelope (R1.5). This test invokes real
      `gpg`, not a Go OpenPGP reimplementation.
- [ ] `file(1)` with the installed magic entry, and `xdg-mime query filetype`,
      both identify a `.angou` blob.

### Authenticity and integrity

- [x] A blob whose signature does not verify is refused, and the plaintext is not
      written to disk or stdout (R1.7).
- [x] A blob re-encrypted to the store's public key by a party without the signing key
      is refused on read.
- [x] A blob renamed to another blob's `blob_id` is refused rather than returned under
      the wrong name (R1.8).
- [x] `reindex` refuses an envelope whose path does not match the blob's filename.
- [x] An `index.angou` that decrypts but does not verify is refused, and the tool falls
      back to `reindex` rather than trusting it.
- [ ] An envelope path of `../../.ssh/authorized_keys`, an absolute path, or a path
      with a NUL byte is refused on both write and extraction (R3.4.1).
- [x] Extraction refuses to follow a symlink out of the destination root (R3.4.2).

### Key model

- [x] The key bundle's Argon2id parameters are recorded beside the ciphertext, and a
      bundle presenting parameters below the pinned floor is refused (R2.2.1).
- [x] `init` refuses a low-entropy recovery passphrase and its generated phrase carries
      at least 77 bits of entropy.
- [x] The plaintext header of a blob contains no key fingerprint, and decryption
      succeeds without one (R1.3).
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

- [x] The same logical path encrypted twice resolves to the same `blob_id` and updates
      in place, leaving no orphan blob.
- [x] Two stores initialized with different `K_name` produce different `blob_id`
      values for the same path.
- [x] `get` retrieves by logical path with `index.angou` deleted.
- [x] `reindex` reconstructs an index equal to the original after the index is deleted,
      and after it is replaced with a Dropbox-style conflicted copy.
- [x] Identically-named files under different store-relative paths coexist.

### Rotation

- [ ] `rekey --local` leaves every `blob_id` and blob body byte-identical.
- [ ] `rekey --identity` re-encrypts all blobs; every blob decrypts under the new key
      and none under the old.
- [ ] `rekey --identity` interrupted mid-run (process killed) leaves the original store
      fully readable.
- [ ] `rekey --identity` changes every `blob_id`, so no filename in the new store
      appears in the old one (R4.2.1).
- [ ] After `rekey --identity`, the old `K_name` computes no filename present in the
      store.

### Bootstrap

- [ ] **Integration:** on a container with no `angou`, no keyring, and no Go
      toolchain, `bootstrap.sh` verifies and installs a runnable binary from
      `bootstrap/` using the system `gpg` present on that image, prompting for no
      passphrase at the binary step.
- [ ] **Integration:** the key bundle's Argon2id-protected symmetric message is
      produced and consumed by `angou` itself, and the test asserts that system `gpg`
      2.4.x cannot decrypt it — pinning the incompatibility that R5.2.1 records, so a
      future change cannot silently reintroduce it.
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
- [ ] A binary signed by the store identity key, rather than by the release-signing
      key, is refused (R5.4.1).
- [ ] An older but validly signed binary is refused once a newer version has been
      installed from that store (R5.4.2), with `bootstrap.sh` unmodified.
- [ ] The release-signing fingerprint compiled into the binary is not read from the
      store, verified by pointing the tool at a store carrying a different fingerprint
      and confirming it is ignored.
- [ ] `make release` writes a binary plus a metadata record whose recorded SHA-256
      matches the decrypted artifact.
- [ ] Retention prunes to N versions per platform.

### Build

- [x] `make lint` passes at the pinned `golangci-lint` version.
- [x] `make test` passes with `-race`.
- [ ] `make build-static` produces a binary that `ldd` reports as not dynamically
      linked, and which runs in a `scratch`-based container.
- [x] `make help` lists every target.

### Testing discipline

- [x] The e2e suite runs against a binary it built itself, not against internal
      packages, and fails if that binary is absent.
- [x] The suite fails with a clear message when `HOME` points at the real home
      directory (R8.4).
- [x] Two consecutive e2e runs use different recovery passphrases.
- [x] After a full run, no file under the real `~/.local/share/angou/` and no KWallet
      entry outside the test-named one has been created or modified.

### Security

- [x] A repository scan finds no key material, passphrase, or store content.
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
the same exposure R5.4 and R5.4.2 close for the binaries, relocated to the entrypoint,
and it is the accepted trust model of any `curl | sh`-style installer. Mitigations: the script
takes no network input (R5.7), is short enough to read before running, and its hash is
pinned inside the encrypted store so tampering is detectable out-of-band from any
already-provisioned machine (R5.8.1).

Signing raises the cost of the alternative path but does not close it, and an earlier
draft of this section overstated the position. Signing the binaries stops an attacker
from *authoring* a malicious one, but signature validity is not freshness:
without R5.4.2's version floor, replaying an older validly signed binary from
`bootstrap/` or from the sync service's own history yields execution with
`bootstrap.sh` untouched. With the version floor in place, the claim holds in its
narrower form — an attacker cannot install a binary that is either unsigned or older
than the floor, so modifying `bootstrap.sh` becomes the remaining path, and tampering is
funnelled into a single small, readable, hash-pinned plaintext file. The strong version
of the claim depends on R5.4.2, not on the signature alone. Note that the binaries are
themselves plaintext (R5.1): their protection is the signature and the floor, never
secrecy.

The first machine to run a subverted script is not protected. No plaintext entrypoint
can protect it, and no placement of a self-check within the script changes this
(R5.8.3).

**R-9 — A writable store permits rollback and denial of service.** Anyone who can
write to the store — a sync-service operator, or someone with the account — can replace
a current blob with an older, still-valid, still-signed ciphertext, or simply delete
blobs. The tool will accept the older version: it decrypts, its signature verifies, and
its name binding holds, because it was genuine when it was written. The practical
consequence is that a secret rotation can be silently undone, or a deleted key
resurrected. Accepted and documented rather than mitigated. Freshness would require a
signed manifest carrying monotonic store epochs and per-blob generations, anchored
against local last-seen state; that machinery is disproportionate for a
single-operator personal store and is deliberately deferred. Users who need it should
rely on the sync service's own version history and audit log.

**R-10 — The agent gives no protection against same-user malware.** The `0600` socket
excludes other users, not other processes running as you. Anything running under your
UID after unlock can connect within the TTL and request decryption or read cached
material; `mlockall` and buffer zeroing (R6.5) do not change this. Same-UID compromise
after unlock is explicitly out of scope. Mitigations are limited to keeping the agent
API small, verifying peer credentials, and keeping the TTL short.

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
(R2.5 covers the interim), and freshness/anti-rollback machinery for the store itself
(R-9 — accepted and documented rather than built). The macOS bootstrap first step,
previously open, is closed by R5.6.

**Review history.** A security-focused design review (Codex, 2026-08-31) produced seven
blocking and four advisory findings against the draft preceding this revision. All were
accepted. The substantive changes: pinned Argon2id parameters for the recovery
passphrase (R2.2.1); signing of payloads and binding of `blob_id` to `envelope.path`
(R1.7, R1.8); `K_name` rotation on identity rekey (R4.2.1); a separate offline
release-signing key (R5.4.1); a version floor against signed-binary rollback (R5.4.2);
a strict path grammar (R3.4.1, R3.4.2); an honest leak enumeration (R3.8); and the
correction of an overstated claim in R-8, which had asserted that signing the binaries
forced an attacker to modify `bootstrap.sh` when binary rollback in fact bypassed it.
