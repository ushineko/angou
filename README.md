# angou

Encrypts sensitive files into a portable store you can keep in Dropbox, on a USB
stick, or anywhere else you can copy a directory. `angou` (暗号 — cipher) wraps each
file in an OpenPGP blob whose filename and metadata give nothing away, and the store
carries everything needed to rebuild itself on a machine that has never seen it.

It is built for small, high-value files: `.secrets.env`, SSH private keys, and text
files with passwords in them.

*Nothing about your keys or your data lives in this repository. The store is yours and
stays where you put it.*

**Version**: 0.1.0-dev

> **Status**: the design is complete and this document describes it in the present
> tense. No code is written yet. Read
> [`specs/001-angou-format-keying-and-store.md`](specs/001-angou-format-keying-and-store.md)
> for the design of record, including the alternatives that were rejected and why.

## Table of Contents

- [What it does](#what-it-does)
- [What a stolen store gives away](#what-a-stolen-store-gives-away)
- [Two passwords, two jobs](#two-passwords-two-jobs)
- [Bootstrapping a new machine](#bootstrapping-a-new-machine)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage (CLI)](#usage-cli)
  - [Not built yet](#not-built-yet)
- [Usage (GUI)](#usage-gui)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Safety](#safety)
- [Changelog](#changelog)

## What it does

**Encrypts a file into a blob.** The blob is text by default — base64, so it survives
being pasted into a chat window, opened in an editor, or dragged through a sync
service that rewrites line endings. Large files can be stored as raw binary instead.
The choice is written into the blob, so it is never guessed at when reading.

**Keeps the blobs in a plain directory.** No database. Copy it, `rsync` it, put it in
Dropbox, carry it on a stick. Whatever you can do to a folder, you can do to the store.

**Hides what it is holding.** A blob's filename is a keyed hash of the path you gave
it, so the store is a directory of opaque names. The original filename lives inside
the encryption, not beside it.

**Stays readable without this tool.** Blobs are ordinary OpenPGP messages. If `angou`
is ever missing, unbuildable, or you are on a machine that cannot run it, `gpg
--decrypt` gets your data back. This is deliberate and will not be traded away for a
cleverer format.

**Carries its own installer.** The store holds a signed copy of the program for each
platform, so a new machine needs the store and one password — not a Go toolchain, and
not this repository.

## What a stolen store gives away

Worth being precise about, since the point of the store is that it lives somewhere you
do not control.

Someone holding a copy of your store, without your passwords, does not learn the
filenames, the contents, or what kinds of files they are. What they do learn:

- how many secrets you have, and roughly how big each one is;
- **which one is which, over time.** Each file keeps the same scrambled name for as
  long as it exists, so someone watching your store across weeks can follow one
  particular file — see that it changes every Friday, or that you touched it the day
  something happened — without ever learning what it is;
- when you add, delete or rename something;
- that you use `angou`, which operating systems you run, and which versions, since the
  installers the store carries are ordinary files.

Rotating your identity with `angou rekey --identity` renames everything and breaks that
tracking, which is part of why it is the right response to a lost machine.

Someone who can **write** to your store — not just read it — is a different problem.
They cannot forge a secret, because everything is signed and each file is bound to its
own name. But they can put back an older copy of something you already had: undo a
password rotation, or restore a key you deleted. Your sync service's own version
history is the defense there, and `angou` does not add another.

They also cannot make you run something. The program the store carries is signed by a
key kept offline, and refused if it is older than the newest version you have already
installed — so neither a swapped copy nor an old one can be quietly put back. The
program itself is not encrypted, and does not need to be: it is the same software
anybody can download, and what protects you is the signature, not secrecy.
The one exception is `bootstrap.sh`, which is plaintext by necessity, because something
has to run before the program exists. Its hash is recorded inside the store and
published on GitHub, so you can check it before running it on your first machine and
`angou verify-bootstrap` will catch a change from any machine you have already set up.

## Two passwords, two jobs

**Your recovery password** is the one you memorize. It is the only thing standing
between a copy of your store and everything in it, so make it long and keep it in a
password manager or on paper. You type it when you set up a new machine, and almost
never otherwise.

**The unlock password is not yours.** Each machine generates its own — 32 random bytes,
never shown to you, never written down, kept in your KDE wallet and nowhere else. You
will never type it and there is nothing to remember.

The result is that a machine holds no secret worth stealing on its own. Wipe your
wallet, reinstall your OS, lose the laptop: nothing is lost, because a machine's setup
is rebuilt from the store rather than recovered. Nothing derives it from your hostname
or hardware either, so imaging the disk and reading this source gets an attacker
nowhere.

On a machine with no KDE wallet — a server, or a Mac for now — nothing is generated and
the key stays under your recovery password instead.

## Bootstrapping a new machine

Copy the store over, then:

```bash
cd /path/to/store
./bootstrap.sh
```

It works out your OS and CPU, checks you have `gpg` and tells you how to install it if
not, asks for your recovery password, checks the signature on the program before
installing it, and hands over to `angou bootstrap` to finish. Nothing is downloaded;
everything comes out of the store you just copied.

`gpg` is needed for exactly this one step, because the program that would otherwise
decrypt itself is the thing being installed. On Arch it is already there — `pacman`
depends on it. Nothing after this point uses it.

## Requirements

- **Linux** (developed on CachyOS/Arch). macOS is a later target.
- **KDE Plasma** for password caching. Without it you will be asked for your recovery
  password rather than having it cached.
- **`gpg`** for the first-run bootstrap only, and not afterwards.
- **Go 1.25+** to build from source. You do not need it to install from a store.

The program itself has no runtime dependencies. It is a static binary and does not
call out to `gpg`, `gpg-agent`, or `kwallet-query`.

## Installation

From a store, use `bootstrap.sh` above. From this repository:

```bash
git clone git@github.com:ushineko/angou.git
cd angou
./install.sh
```

Installs the `angou` command, the desktop entry, and the file-type rules that let KDE
recognize a `.angou` blob. Remove it all with `./uninstall.sh`.

## Usage (CLI)

Every command needs to know which store to work on, and needs the recovery
passphrase to open it. Name the store with `--store`, or set `ANGOU_STORE` once and
leave it out.

```bash
export ANGOU_STORE=~/Dropbox/angou

angou init                        # create the store and its keypair
angou init --generate             # ... and let angou choose the passphrase

angou enc .secrets.env            # encrypt into the store
angou enc ~/.ssh/id_ed25519 --as work/ssh/id_ed25519
angou dec work/ssh/id_ed25519     # plaintext to stdout
angou dec .secrets.env -o /tmp/x  # ... or to one named file
angou get .secrets.env --dest ~/restored   # rebuild the file under a root

angou ls                          # what is in the store
angou ls --long                   # with sizes, modes, and times
angou mv old/path new/path
angou rm work/ssh/id_ed25519
angou reindex                     # rebuild the listing from the blobs
```

`dec` writes one file's plaintext where you point it. `get` rebuilds the file under a
directory you name, restoring its permissions and modification time. `get` needs
`--dest` and has no default, because the stored path decides where the write lands and
anyone who can write to your store chooses that path; confining it to a root you named
is what stops a stored path from writing somewhere else.

`enc` leaves your original file alone.

### Not built yet

The commands below are specified and documented but not implemented. They arrive with
the keyring, bootstrap, and rotation passes:

```
angou bootstrap                   # set up a new machine from the store
angou verify-bootstrap            # has the plaintext installer been altered?
angou rekey --local               # new machine password; changes nothing else
angou rekey --identity            # NEW KEYPAIR, re-encrypts everything
angou passwd                      # change the recovery passphrase
angou prune --bootstrap --keep 3
angou doctor --old-key <fingerprint>
angou release --dist dist/
angou agent                       # session cache
angou clone --no-binaries
```

Until the keyring pass lands there is no machine password and no session cache, so
every command asks for the recovery passphrase and spends about a quarter of a second
deriving a key from it. That is the headless fallback the design already allows for,
not a shortcut: nothing weaker guards the store in the meantime.

The derivation needs about 96 MB of memory. angou checks for it, and for any cgroup
limit on the process, before starting — a container too small to finish the derivation
is told so rather than being killed part-way through.

## Usage (GUI)

`angou-gui` browses the store as a tree of the names you gave your files, rather than
the hashed names on disk. Double-clicking a blob shows it inline when it is text, and
offers to decrypt it beside the original when it is not. It is a separate program from
the CLI and is never needed to set a machine up.

## Project layout

```
angou/
├── cmd/angou/              the command line
├── cmd/angou-gui/          the desktop browser (not built yet)
├── lib/container/          the blob format — readable by other tools
├── internal/cli/           the command tree
├── internal/store/         blob naming, the index, rebuilding it, extraction
├── internal/envelope/      the metadata sealed inside each blob
├── internal/pgpcrypto/     signing, encryption, and verification
├── internal/keybundle/     the key bundle and its Argon2id protection
├── internal/passphrase/    generating and screening recovery passphrases
├── internal/prompt/        reading a passphrase without echoing or logging it
├── internal/keyring/       keys, and the KDE wallet (not built yet)
├── internal/agent/         the session cache (not built yet)
├── packaging/              desktop file-type rules, icon, magic
├── config/                 pinned linter configuration
├── specs/                  design specs
├── docs/                   format reference and runbooks
│   └── compromise-recovery.md
├── tests/                  test suite
└── validation-reports/     release validation records
```

## Testing

```bash
make test           # unit tests, fast
make e2e            # builds the real binary, runs it against throwaway stores
make e2e-container  # bootstrap onto a machine with nothing installed
make lint           # pinned golangci-lint, checksum-verified when installed
make shellcheck     # the plaintext bootstrap installer
```

Testing here is end-to-end by default and barely mocked at all. Most of what this
program claims is a claim about the built binary rather than about a function inside
it — that a blob header gives nothing away, that the binary needs nothing installed,
that `gpg` can still read what it wrote, that a bare machine can set itself up from a
store. None of that can be confirmed against a stand-in, so it is confirmed against
the real thing.

Each run builds a throwaway copy of the tool, points it at a throwaway store with a
throwaway password, and redirects `HOME` somewhere temporary. Your own store, keys and
wallet are never touched, and the suite refuses to run rather than fall back to them.
The bootstrap test runs in a container with nothing installed, because "works on a new
machine" cannot honestly be tested on this one.

## Safety

- **Your recovery password cannot be recovered.** Lose it and the store is lost. There
  is no reset, no backdoor, and no support channel. Write it down somewhere real.
- **`--shred` is not a secure erase.** On Btrfs, on any copy-on-write filesystem, and
  on any SSD, overwriting a file does not reliably destroy the old copy. The default is
  to leave your original in place precisely so this is your decision and not a false
  promise.
- **Rotating `angou` does not un-disclose anything.** If someone read your store, the
  secrets in it are out, permanently. Rekeying protects the store from here on; the
  actual work is going to each service and changing the credential. See
  [docs/compromise-recovery.md](docs/compromise-recovery.md).
- **`rekey --identity` rewrites the whole store.** It is the right response to a
  compromised machine and the wrong thing to run casually. It works on a copy and
  commits at the end, so an interruption leaves the original intact.
- **A conflicted copy of the index is harmless.** The blobs are the truth and the
  listing is rebuilt from them. If two machines write at once, run `angou reindex`.
- **Once a store is unlocked, anything running as you can use it.** The session cache
  keeps the store open for a while so you are not retyping passwords; during that time
  a program running under your own account can ask it to decrypt. This is true of ssh-agent
  and every password manager too, and it is not something `angou` tries to solve.
- **Don't put the store in this repository, or in any repository.** It is ignored here
  as a backstop, not as a plan.

## Changelog

### 0.1.0-dev

- First implementation pass, command line only: the container format, the metadata
  envelope, keyed blob naming, the store index, and `init`, `enc`, `dec`, `get`, `ls`,
  `mv`, `rm`, and `reindex`. Payloads are signed as well as encrypted and the signature
  is verified before any plaintext is returned. The key bundle is held under the
  recovery passphrase with Argon2id at m=1 GiB, t=4, p=4, and a bundle recording weaker
  parameters is refused.
  Extraction is confined to a directory the caller names, using a held directory
  descriptor rather than a path check, so a symlink planted at any depth cannot
  redirect a write out of it.
- The key bundle is protected with Argon2id at m=64 MiB, t=24, p=4 — RFC 9106's
  configuration for memory-constrained environments, with the pass count raised to keep
  the cost comparable to a gibibyte-scale one. The memory figure is chosen so a store
  opens on every machine it syncs to, including small containers, rather than for
  maximum per-guess cost; the passphrase entropy floor is what makes an exhaustive
  search infeasible.
- End-to-end test practice established: 28 tests that build the real binary and drive
  it as a subprocess against throwaway stores, with a per-run passphrase and a
  redirected `HOME` the suite refuses to run without.
- Not yet built: the KDE wallet and the machine password, `bootstrap.sh` and the
  release-signing chain, rotation, the session cache, and the desktop browser. Design
  for all of them is complete in spec 001.

## License

MIT. See [LICENSE](LICENSE).
