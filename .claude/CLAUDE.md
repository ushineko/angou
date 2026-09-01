# angou Project Guidelines

Follows the Ralph Wiggum methodology (see `~/.claude/CLAUDE.md`) with the extensions
below.

---

## Project Overview

- **Type**: Go CLI + desktop GUI
- **Purpose**: OpenPGP encryption of sensitive files into a portable, syncable store
- **Module**: `github.com/ushineko/angou`

---

## Selected Policies

Load the following policy modules from `~/.claude/policies/`:

- `languages/go.md`
- `languages/bash.md`
- `git/standard.md`
- `release-safety/minimal.md`
- `security/owasp-review.md`
- `testing/philosophy.md`
- `communication/standards.md`

---

## Ralph Settings

```yaml
validation: milestones-only
```

---

## Issue Tracking

Personal public GitHub repository, no issue tracker. Spec files are named without
ticket IDs (`specs/NNN-short-description.md`). Do not prompt for ticket IDs.

---

## Security (non-negotiable)

This project handles key material. The following hold without exception:

- No key, passphrase, or store content may be committed. `.gitignore` blocks
  `*.angou` and `bootstrap/`; that is a backstop, not the control.
- No passphrase or plaintext may reach any log path at any verbosity.
- Secret buffers are explicitly zeroed after use. Memory hardening is documented as
  best-effort (Go's GC may relocate secrets) and must never be described as a
  guarantee.
- Security claims in docs and command output must state what is actually enforced.
  Spec 001 R5.8.2 is the reference case: the bootstrap self-check is described as
  post-execution drift detection, never as a first-run integrity guarantee.

---

## Conventions

- Build and lint targets follow `aiq_agent_go`: `##`-comment help, `golangci-lint`
  pinned by version and checksum-verified on install, `GOTOOLCHAIN` pinned from
  `go.mod`, builds with `-ldflags='-w -s' -trimpath`.
- The CLI uses `spf13/cobra`.
- No `gpg`, `gpg-agent`, or `kwallet-query` subprocesses in the normal path. OpenPGP
  via `ProtonMail/go-crypto`, keyring access via `godbus/dbus`. The static CLI must
  build with `CGO_ENABLED=0`.
- Platform-specific keyring code is split by build constraint
  (`keyring_linux.go`, `keyring_darwin.go`).

---

## Testing Conventions

**End-to-end against a real build is the default. Mocking is the exception and needs
a reason.**

Nearly every claim this tool makes is a claim about the artifact, not about a
function: that a header leaks nothing, that the static binary has no runtime
dependencies, that `gpg` can still read a blob, that a bare machine can bootstrap from
a store. A mock cannot confirm any of those, because the mock is not the thing making
the claim. A test suite that passes entirely against fakes tells us the code is
self-consistent, which is not what we need to know.

### The shape of an e2e test

Every e2e test builds the tool fresh and drives it as a subprocess:

1. **Throwaway build.** Build the real binary — `CGO_ENABLED=0`, same flags as
   `build-static` — into a temporary directory. Do not call internal packages
   directly; invoke the binary. Testing the artifact is the entire point.
2. **Throwaway store.** A fresh store under `t.TempDir()`, initialized by the tool
   itself. Never a fixture store checked into the repository.
3. **Throwaway credentials.** Generate the recovery passphrase per run from
   `crypto/rand`. No credential-shaped constant is ever committed, even a fake one.
4. **Throwaway environment.** Set `HOME` and the `XDG_*` variables to temporary
   directories so the test cannot reach the developer's real store, keyring, or
   wallet.
5. **Assert on observable output**: exit codes, bytes on disk, stdout. Not on internal
   state.

### Hard guards

- A test helper MUST refuse to run when `HOME` still points at the real home
  directory. This is a `t.Fatal`, not a skip — a test that silently writes to a
  developer's actual store is worse than one that fails.
- KWallet tests use a dedicated wallet named for the test run and remove it
  afterwards. They never read or write the user's real wallet entries.
- `gpg` interop tests use a throwaway `GNUPGHOME` under `t.TempDir()`.
- The bootstrap test runs in a container with no `angou`, no keyring, and no Go
  toolchain, because "works on an unconfigured machine" cannot be tested on a
  configured one.

### Unit tests

Unit tests are welcome where a piece of logic has real edge cases worth pinning —
container header parsing, path normalization, HMAC addressing, retention pruning.

Keep them simple. Table-driven, plain `testify` assertions, no fixture frameworks, no
elaborate builders, no mock hierarchies. If a unit test needs significant scaffolding
to exist, that is a signal the behavior belongs in an e2e test instead.

Do not chase coverage. Coverage is for finding untested critical paths, never a
number to maximize.

### Running

```bash
make test           # unit tests, fast, no build required
make e2e            # builds the binary, runs against throwaway stores
make e2e-container  # the bare-machine bootstrap test
```

`make e2e` is required before any release commit. Unit tests alone do not satisfy the
Phase 3 validation gate for this project.

---

## House Conventions (ag-scripts style)

This project follows the `ag-scripts` sub-project conventions, adapted for a
standalone repository.

### Versioning

- `VERSION` at the repository root is the single source of truth. The Makefile reads
  it into the build via `-ldflags -X`, and `README.md` states the same string.
- **ASK THE USER** to approve any version bump before making it. Propose a number;
  do not choose one unilaterally.
- After approval, update `VERSION` and `README.md` together and verify they match.
  A release commit where they disagree is wrong.

### README

`README.md` follows the style of `ag-scripts/terrariabonker/README.md`:

- Lowercase project name as the H1, then a plain-prose description of what the tool
  does and who it is for. No feature-bullet openings, no marketing register.
- A `**Version**:` line, then a Table of Contents.
- Second person, present tense, plain words. Explain consequences rather than
  listing capabilities — what is irreversible, what is session-only, what a given
  setting actually costs the user.
- State limitations where the user would otherwise assume a guarantee. The `--shred`
  and `verify-bootstrap` entries are the reference cases: both describe what is *not*
  promised, in the same breath as what is.
- A `## Changelog` section with an entry per released version.

### Installer and uninstaller

- `install.sh` and `uninstall.sh` live at the repository root, are idempotent, and
  support `--dry-run` where practical.
- The uninstaller removes everything the installer placed and nothing else. It must
  never remove keys or store data without the user asking; print the command instead.

### Release procedure

1. Tests, code-quality pass, and security review pass.
2. Version bump approved by the user, applied to `VERSION` and `README.md`.
3. Changelog entry added.
4. Validation report written to `validation-reports/` (the `milestones-only` setting
   above means release commits require one).
5. Commit, then tag.

### Tagging

Tags are plain `vX.Y.Z` (annotated), not the `<subproject>/vX.Y.Z` form used in the
`ag-scripts` monorepo — this repository holds one project, so the scoping prefix has
nothing to disambiguate.

```bash
git tag -a "v1.0.0" -m "angou v1.0.0 — <summary>"
git push origin "v1.0.0"
```

The tag must point at the commit that bumped `VERSION` and `README.md`; verify with
`git show <tag> --stat`.

### Format literals

The container delimiters (`-----BEGIN ANGOU1 BLOB-----`) appear in three places:
spec 001 R1.1, `packaging/magic`, and `packaging/angou.xml`. They are duplicated by
necessity — `file(1)` and `shared-mime-info` cannot read a Go constant. Changing one
means changing all three, plus `internal/container`.

---

## Git Commit Rules

**NEVER** add `Co-Authored-By` trailers or AI attribution footers to commit messages
or PR descriptions.
