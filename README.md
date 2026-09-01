# angou

Encrypts sensitive files into a portable store you can keep in Dropbox, on a USB
stick, or anywhere else you can copy a directory. `angou` (暗号 — cipher) wraps each
file in an OpenPGP blob whose filename and metadata give nothing away, and the store
carries everything needed to rebuild itself on a machine that has never seen it.

It is built for small, high-value files: `.secrets.env`, SSH private keys, and text
files with passwords in them.

*Nothing about your keys or your data lives in this repository. The store is yours and
stays where you put it.*

**Version**: 0.1.0

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
- [Using it](#using-it)
  - [Making a store](#making-a-store)
  - [Putting things in and getting them out](#putting-things-in-and-getting-them-out)
  - [Stopping the passphrase prompts](#stopping-the-passphrase-prompts)
  - [Holding the key for a while](#holding-the-key-for-a-while)
  - [Setting up a new machine](#setting-up-a-new-machine)
  - [When something looks wrong](#when-something-looks-wrong)
  - [Changing what protects the store](#changing-what-protects-the-store)
  - [Copying a store](#copying-a-store)
  - [Things worth knowing](#things-worth-knowing)
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
not, checks the signature on the program before installing it, and stops. Then run
`angou bootstrap`, which is the step that asks for your recovery password. Nothing is
downloaded; everything comes out of the store you just copied.

The installer asks for no password, because the program is not secret — it is published
software, stored in the clear and signed. What protects it is the signature and a
refusal to install a version older than one you have already used. Encrypting it would
have protected nothing and, as it turned out, would not even have worked: `gpg` cannot
read the key derivation angou uses for the parts that are secret.

`gpg` is needed for exactly this one step, to check that signature, because the program
that would otherwise do it is the thing being installed. On Arch it is already there —
`pacman` depends on it. Nothing after this point uses it.

Read `bootstrap.sh` before you run it. It is short and deliberately so, it never
touches the network, and it is the one part of the store that nothing protects until
after it has run.

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

## Using it

Every command works on one store. Name it with `--store`, or set `ANGOU_STORE` once
and leave the flag off:

```bash
export ANGOU_STORE=~/Dropbox/angou
```

### Making a store

```bash
angou init --generate
```

This creates the store, generates its keypair, and prints a recovery passphrase once.
Write it down before you press anything else. There is no reset: the passphrase is the
only thing that opens the store on a machine that has not been set up, and if you lose
it the contents are gone.

Then run `angou bootstrap` (below). Until you do, every command asks for that
passphrase — the name is accurate about its job, but you only meet that job on a machine
that has not been set up yet.

If you would rather choose your own, leave off `--generate` and you will be prompted.
A passphrase that scores below 70 bits is refused rather than accepted with a warning,
because the store is a file that other people may hold, and a passphrase they can guess
offline is not a passphrase. The score is a ceiling, not a measurement — angou sees the
result, not how you chose it — so treat passing as "not obviously weak" rather than as
approval.

### Putting things in and getting them out

```bash
angou enc .secrets.env                # store it under the name you typed
angou enc ~/.ssh/id_ed25519           # an absolute path keeps its structure
angou enc ~/.ssh/id_ed25519 --as work/ssh/id_ed25519   # or name it yourself

angou dec work/ssh/id_ed25519          # plaintext to stdout
angou dec .secrets.env -o /tmp/env     # or to one named file
angou get .secrets.env --dest ~/restored   # rebuild it, mode and mtime and all

angou ls                               # what is in there
angou ls --long                        # with sizes, modes, and times
angou mv old/path new/path
angou rm work/ssh/id_ed25519
```

`enc` leaves your original file where it is. Deleting it is your decision, and on a
copy-on-write filesystem or an SSD deleting it is not erasing it.

The name you give a file is the name it keeps. Encrypting the same path again replaces
that entry rather than adding a second one, so updating a secret is just `enc` again.
Two files called `.secrets.env` in different projects do not collide, because the whole
path is the name.

If you do not pass `--as`, angou works the name out and tells you what it chose. A
relative path is used exactly as you typed it. An absolute one — which is what your
shell hands over when you write `~/.secrets.env` — is placed relative to your home
directory, so `~/projects/one/.secrets.env` is stored as `projects/one/.secrets.env`.
Files outside your home keep their path with the leading `/` removed. The structure is
kept rather than reduced to a filename, because a filename alone would put every
project's `.secrets.env` on the same name and each would replace the last.

`dec` writes one file where you point it. `get` rebuilds it under a directory you name
and restores its permissions and timestamp. `get` requires `--dest` and has no default:
the stored path decides where the write lands, anyone who can write to your store
chooses that path, and confining it to a directory you named is what stops a stored
path from writing somewhere else on your disk.

### Stopping the passphrase prompts

**Do this once, on every machine.** Without it you type the recovery passphrase for
every single command, which is not what that passphrase is for and is not how the tool
is meant to be used:

```bash
angou bootstrap
```

That takes the key out of the store, wraps it under a fresh 32-byte machine password,
and puts that password in your KDE wallet. Afterwards this machine opens the store on
its own, in about five milliseconds instead of a quarter of a second. You are never
shown the machine password and never need it.

If you delete the wallet entry, this machine can no longer open its local copy and
nothing local can bring it back — the wallet held the only copy. That is not a
disaster: run `angou bootstrap --force` with your recovery passphrase and the machine
is set up again. angou tells you this rather than prompting for something you were
never given.

`angou bootstrap --forget` undoes it, which is what to run before handing a machine on.

On a machine with no wallet — headless, or not KDE — `bootstrap` says so and changes
nothing. The store still works there; it just asks for the recovery passphrase.

### Holding the key for a while

```bash
angou agent start --ttl 10m     # or 3600, or 2h, or 1d
angou agent status
angou agent stop
```

**You probably do not need this if you have run `angou bootstrap`.** Measured on the
same store:

| How the store gets opened | Time per command |
|---|---|
| Recovery passphrase | 0.218 s |
| Keyring, after `angou bootstrap` | 0.005 s |
| Agent | 0.003 s |

Two milliseconds is not worth anything, and you give up something to get it. The
keyring's copy of the key stops being available when your wallet locks; the agent's does
not, because it is sitting in a running process. Leaving an agent up permanently trades
a boundary you had for a saving you cannot measure.

Where it does earn its place is a machine with no keyring — headless, a server, or a Mac
until the Keychain backend lands. There every command otherwise costs a passphrase
prompt and a quarter of a second, which is the kind of friction that makes people paste
secrets somewhere worse.

Be precise about what it protects. The socket is readable only by you, which keeps out
other users of the machine. It does not keep out anything else running as **you**: while
the agent is up, any process under your account can ask it for the key and get it. The
lifetime is the real protection, not the socket permissions, which is why `--ttl` exists
and why `agent stop` is worth reaching for when you are done rather than waiting it out.

### Setting up a new machine

A store can carry the tool that opens it. From a machine that already works:

```bash
angou release --new-signing-key ~/angou-release.asc   # once, ever
make build-all RELEASE_KEY=<the fingerprint it printed>
angou release --dist dist/ --signing-key ~/angou-release.asc
```

That puts a binary for each platform into the store, signs each one, and writes
`bootstrap.sh` beside them. Move the signing key to offline storage afterwards and
delete it from the machine. It is not the store's key and must never become it: anyone
who has it can sign a binary that every future bootstrap will accept.

The key `--new-signing-key` writes is not passphrase-protected, deliberately: moving it
offline is the control, and a passphrase on a file left on the machine would suggest
more protection than it gives. If you would rather have both, make the key with `gpg`
instead and export it — angou takes a passphrase-protected key and asks for the
passphrase before it does anything:

```bash
gpg --quick-generate-key 'angou release <you@example.com>' ed25519 sign never
gpg --armor --export-secret-keys <fingerprint> > ~/angou-release.asc
```

Once a build has a fingerprint pinned into it, that build will only stash binaries
signed by that key. It refuses others rather than producing a store it could not itself
install from.

On the new machine, with nothing installed but `gpg`:

```bash
sh /path/to/store/bootstrap.sh
angou bootstrap --store /path/to/store
```

The script detects the platform, checks the binary's signature against a fingerprint
written into the script itself, installs it, and stops. It asks for no passphrase,
because the binary is not secret — only signed. It touches the network never.

Read the script before you run it. It is short, and it is the one part of the store
that nothing protects. Its own signature is checked *after* it has already run, which
catches a file that changed but cannot tell you the file you just ran was genuine. For
a machine you are setting up for the first time, compare it against the copy published
in the repository; that is the only check that happens before rather than after.

### When something looks wrong

```bash
angou doctor        # what this machine can and cannot do, and why
```

`doctor` changes nothing and is the right first move when a command fails in a way you
do not understand. It reports whether the store is there, whether its key bundle is
usable, whether this machine has a local key, whether the wallet has the matching
entry, and what the version floor is.

```bash
angou reindex       # rebuild the listing from the blobs themselves
```

The listing is a cache and is never the truth. If a sync service leaves a conflicted
copy or the listing goes missing, `reindex` rebuilds it by reading the files. Getting a
file by name never needed the listing anyway. If `reindex` reports files it could not
read, they are usually left over from an interrupted rotation; `angou prune --orphans`
removes them. It will refuse to remove a file that decrypts but sits under the wrong
name — that is not debris, and deleting it would destroy the evidence.

```bash
angou verify-bootstrap   # has the installer in the store been altered?
```

Run this from a machine you trust, against the store, to notice tampering with the
script your other machines will run.

### Changing what protects the store

Two different problems, two different commands, and picking the wrong one leaves you
exposed:

```bash
angou passwd              # someone may have seen your recovery passphrase
angou rekey --local       # you want a new machine password on this machine
angou rekey --identity    # a machine holding the key may be compromised
```

`passwd` changes what guards the key. No file in the store changes and no other machine
needs anything done to it.

`rekey --local` changes this machine's password only. Every blob stays byte-identical.

`rekey --identity` is the serious one. It generates a new keypair *and* a new naming
key, then re-encrypts and renames every file. The renaming matters as much as the
re-encryption: the names are derived from a key, and leaving that key in place would
let anyone watching your store keep following each file across snapshots even after the
keypair changed.

After it finishes, every machine must run `angou bootstrap` again, and you should check
the rotation was complete:

```bash
angou doctor --old-key <the old fingerprint it printed>
```

Do this before `angou prune --bundles`, because pruning removes the old key bundle and
the check needs it. Once the bundle is gone, angou will tell you the check cannot be
performed rather than reporting a clean result it did not establish.

One thing `rekey --identity` does not do: it does not un-leak anything. If a machine
holding the key was compromised, treat every secret the store held as known, and change
those secrets where they actually live. Rotating the store protects what you put in it
next. [`docs/compromise-recovery.md`](docs/compromise-recovery.md) is the full runbook.

### Copying a store

```bash
angou clone --to /media/backup/angou
angou clone --to /media/backup/angou --no-binaries
```

A clone opens with the same passphrase and holds the same secrets, so guard it the same
way. `--no-binaries` omits the platform binaries, which are most of the size; the copy
still holds everything, it just cannot set up a bare machine on its own.

`clone` refuses a destination inside the store, and refuses to follow a symlink it finds
there. Neither is fussiness: the first would copy the store into itself until the disk
filled, and the second would let anyone who can write to a synced store point at a file
of yours and have its contents copied out.

### Things worth knowing

Every command takes `--verbose` (`-v`), which reports what angou is doing on stderr. It
never prints a passphrase or the contents of a file.

Opening the store costs about a quarter of a second and 96 MB of memory, once, unless
the wallet or the agent is doing it for you. angou checks that the memory is available —
including any container limit on the process — and explains the shortfall rather than
being killed part-way through.

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
│   └── assets/             the bootstrap installer, as shipped into a store
├── internal/store/         blob naming, the index, rotation, extraction
├── internal/envelope/      the metadata sealed inside each blob
├── internal/pgpcrypto/     signing, encryption, and verification
├── internal/keybundle/     the key bundle and its Argon2id protection
├── internal/passphrase/    generating and screening recovery passphrases
├── internal/keyring/       the KDE wallet, split by platform
├── internal/localkey/      this machine's copy of the key
├── internal/release/       the bootstrap namespace and version ordering
├── internal/agent/         the session cache
├── internal/prompt/        reading a passphrase without echoing or logging it
├── packaging/              desktop file-type rules, icon, magic
├── config/                 pinned linter configuration
├── specs/                  design specs
├── docs/                   format reference and runbooks
│   └── compromise-recovery.md
├── tests/e2e/              the end-to-end suite
└── validation-reports/     release validation records
```


## Testing

```bash
make test           # unit tests, fast
make e2e            # builds the real binary, runs it against throwaway stores
make e2e-keyring    # the KWallet tests; needs you at the desktop, see below
make e2e-container  # bootstrap onto a machine with nothing installed
make lint           # pinned golangci-lint, checksum-verified when installed
make shellcheck     # the plaintext bootstrap installer
```

`make e2e` never touches your wallet. The tests that do are behind their own target,
because they operate the wallet you keep real secrets in and KWallet offers no way to
make a throwaway one — opening a wallet that does not exist raises a dialog and waits
for you. Those tests write an entry named for the run and remove it afterwards, and
they need a human at the desktop to answer any access prompt.

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

### 0.1.0

The command line is complete: all seventeen subcommands of spec 001 are implemented,
and every acceptance criterion in that spec is met. The desktop browser is not started.

- **The format.** A text container whose plaintext header carries only the format and
  the payload encoding — no filename, no plaintext hash, no key fingerprint. Metadata
  travels in an envelope inside the encrypted payload. Payloads are signed as well as
  encrypted, and the signature is verified before any plaintext is returned. Stock
  `gpg` can decrypt a blob body without angou, which is a recovery guarantee rather
  than an interoperability nicety, and a test proves it against the real `gpg`.
- **The store.** Blob names are keyed hashes of the logical path, so a directory
  listing gives up no filenames even to a dictionary attack. A blob whose name does not
  match its own envelope is refused, which is what stops one secret being served under
  another's name. The index is a rebuildable cache and never the truth.
- **Keys.** The key bundle is held under Argon2id at m=64 MiB, t=24, p=4 — RFC 9106's
  configuration for memory-constrained environments, with the pass count raised. The
  memory figure is chosen so a store opens on every machine it syncs to, including
  small containers, rather than for maximum per-guess cost; the passphrase entropy floor
  is what makes an exhaustive search infeasible. A bundle recording weaker parameters is
  refused, and the memory required is checked before it is spent.
- **Machines.** `bootstrap` wraps the key under a 32-byte machine password held in
  KWallet, after which commands open the store in milliseconds. The "key present, wallet
  entry gone" state is explained rather than met with an unanswerable prompt.
- **Rotation.** `passwd` changes what guards the key; `rekey --local` changes the
  machine password; `rekey --identity` changes the keypair *and* the naming key,
  re-encrypting and renaming everything. Rotation is staged and verified before anything
  live is touched, and an interrupted one leaves the previous store intact.
- **Bootstrap.** A store can carry signed binaries and a plaintext installer that
  verifies one against a fingerprint written into the script rather than read from the
  store — so an attacker who re-signs a binary and swaps the public key is still refused.
- **The agent.** A session cache with a short lifetime, documented as excluding other
  users and explicitly not as a boundary against anything running as you.
- **Testing.** 69 end-to-end tests that build the binary and drive it as a subprocess
  against throwaway stores, at the parameters users actually get, with a per-run
  passphrase and a redirected `HOME` the suite refuses to run without.

## License

MIT. See [LICENSE](LICENSE).
