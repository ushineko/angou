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

## Git Commit Rules

**NEVER** add `Co-Authored-By` trailers or AI attribution footers to commit messages
or PR descriptions.
