# angou

Encrypts sensitive files into a portable store you can keep in Dropbox, on a USB
stick, or anywhere else you can copy a directory. `angou` (暗号 — cipher) wraps each
file in an OpenPGP blob whose filename and metadata give nothing away, and the store
carries everything needed to rebuild itself on a machine that has never seen it.

It is built for small, high-value files: `.secrets.env`, SSH private keys, and text
files with passwords in them.

*Nothing about your keys or your data lives in this repository. The store is yours and
stays where you put it.*

**Version**: 0.2.1

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
  - [Putting a file back where it belongs](#putting-a-file-back-where-it-belongs)
  - [Sweeping up what is already on the machine](#sweeping-up-what-is-already-on-the-machine)
  - [Looking at what you have](#looking-at-what-you-have)
  - [Using the store on your other machines](#using-the-store-on-your-other-machines)
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
never shown to you, never written down, kept in your desktop's keyring and nowhere
else. You
will never type it and there is nothing to remember.

The result is that a machine holds no secret worth stealing on its own. Wipe your
wallet, reinstall your OS, lose the laptop: nothing is lost, because a machine's setup
is rebuilt from the store rather than recovered. Nothing derives it from your hostname
or hardware either, so imaging the disk and reading this source gets an attacker
nowhere.

angou uses the freedesktop Secret Service, which GNOME, KDE, XFCE and others all
implement, so this works on most desktops rather than only on KDE. `ANGOU_KEYRING=kwallet`
pins the older KDE-specific API if you would rather use it.

On a machine with no keyring at all — a server, or a Mac for now — nothing is generated
and the key stays under your recovery password instead.

## Bootstrapping a new machine

**If the machine already has `angou`**, there is nothing to bootstrap in this sense. Let
the store sync there, and `angou ls` works immediately against your recovery passphrase;
`angou bootstrap` then stops it asking. That is the ordinary case and the rest of this
section does not apply to it.

The rest is for a machine that does not have `angou` at all, and it comes in two
flavours depending on what you put in the store.

**If you can install it normally** — the machine has Go, or you can copy a binary onto
it — do that, and you are in the ordinary case above. This is the simplest answer and
usually the right one.

**If you want the store itself to carry the program**, so a machine needs nothing but
the store and `gpg`, then it has to be put there first. The easiest way is to let the
installer do it:

```bash
./install.sh --publish-to ~/Dropbox/angou
```

`install.sh` also notices on its own: if `ANGOU_STORE` points at a store that carries no
binaries, it says so and offers. It asks rather than assuming, because publishing means
creating a release-signing key and that is a decision — the key decides which binaries
every future bootstrap accepts, so leave it on the machine and one compromise there
becomes code execution on all the others. Move it offline when the installer tells you
to.

A store made by `angou init` carries no binaries, and `angou doctor` says so. Once it
does:

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

This creates the store, generates its keypair, prints a recovery passphrase once, and
sets this machine up so you are not asked for that passphrase again here.

Write the passphrase down before you press anything else. There is no reset: it is the
only thing that opens the store on a machine that has not been set up, and if you lose
it the contents are gone. You will not need it day to day — that is what "recovery"
means — but you will need it on the next machine, and if this machine's keyring entry
is ever lost.

Where no keyring is available, `init` says so and the store stays on the recovery
passphrase. `--no-bootstrap` opts out deliberately, for a machine you would rather not
leave holding a copy of the key.

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

angou dec work/ssh/id_ed25519         # put it back where it came from
angou dec .secrets.env --stdout       # or just print it
angou dec .secrets.env -o /tmp/env    # or write it somewhere you choose

angou ls                              # what is in there
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

### Putting a file back where it belongs

`enc` records where a file was when you encrypted it. `dec` uses that: on another
machine, `angou dec .ssh/id_ed25519` offers to put the key back in `~/.ssh` rather than
dropping it in whatever directory you happen to be standing in. You are shown the
destination and asked before anything is written, and asked again before an existing
file is replaced. Permissions come back too, so a key restored over a world-readable
file ends up `0600` again.

```bash
angou dec .ssh/id_ed25519                        # offers to restore it
angou dec .ssh/id_ed25519 --overwrite            # replace without the second question
angou dec .ssh/id_ed25519 --restore --overwrite  # for scripts: no questions at all
angou dec .ssh/id_ed25519 --stdout               # never touch the disk
```

When the output is piped or redirected, the plaintext goes there and nothing is written
to disk, so `angou dec x > file` keeps working. `--restore` asks for the file to be put
back regardless, which is what a script wants; with nothing to answer a question it will
restore, but it will not replace an existing file unless you also pass `--overwrite`.

Acting on a location that came out of the store is only safe because every payload is
signed. Forging that destination means forging the signature, so someone who can write
to your store cannot use this to direct writes around your disk. A symlink at the
destination is refused rather than written through.

### Sweeping up what is already on the machine

```bash
angou enc ~ --all --dry-run   # show what it found and why, store nothing
angou enc ~ --all             # ask about each thing found
angou enc ~ --all --auto      # take them all without asking
```

**Start with `--dry-run`.** It prints what the scan picked and why, and stores nothing:

```
SIZE   FILE                        WHY
1.6K   ~/.ssh/id_rsa               SSH private key
2.0K   ~/.aws/credentials          AWS credentials
8.7K   ~/.kube/config              Kubernetes credentials
496B   ~/git/proj/.env             environment file
1.6K   ~/.minikube/ca.key          private key
```

`--all` looks for the kinds of file credentials usually live in: SSH private keys, cloud
and cluster credentials, `.env` files, `.netrc`, `.pgpass`, keys and key stores, and
files whose names mention a secret.

Where a name alone is not enough, it looks at the file. A `.key` extension means a
private key in some tools and a session handle in others, so `.key` and `.pem` files are
offered only if they actually begin with a private-key header — a certificate is not a
secret and neither is a cache entry. A name merely mentioning "password" is as likely to
be a note about passwords as a file containing one, so those must also look like
assignments and must not be source code, documentation, or a manual page. Templates
(`.env.example`, `.env.template`) are skipped: showing the shape of a credential is the
opposite of being one.

It does not descend into `node_modules`, `.git`, caches, tool state or installed
software, because a vendored copy of a `.env` is noise.

It asks about each file by default, because the list is a guess and a guess is worth
checking. Without a terminal to ask, it refuses rather than assuming yes — sweeping a
home directory into a store is not something to do because nobody was there to object.

**An empty or short result is not a clean bill of health.** The scan knows the usual
names and places. It will miss a credential in a file it has never heard of.

### Looking at what you have

```bash
angou ls           # the detailed listing
angou ls --names   # just the paths, one per line, for scripts
angou ls --raw     # the store as it sits on disk
```

The default listing shows permissions, size, when each file last changed, its name, and
where it came from. It is coloured on a terminal and plain when piped, so a script never
has to strip escapes; `--no-color` and `NO_COLOR` both turn it off. A file stored with
permissions that let anyone but you read it is flagged, because that is worth noticing
on the way past.

`--raw` shows the store as the filesystem holds it, and needs no passphrase — these are
the names anyone holding your store already sees:

```
SIZE  MODIFIED  NAME                              WHAT IT IS
1.0K  just now  4sovzy6otqqah2p7644cz2w246.angou  encrypted file
—     just now  bootstrap                         key bundle and platform binaries
1.6K  just now  index.angou                       listing cache, rebuildable
704B  just now  store.angou                       store metadata, holds the naming key
```

It is worth looking at once. The names give up no filenames, but the number of files,
their sizes, and the fact that a particular one changed today are all visible to whoever
holds the store.

### Using the store on your other machines

This is what the store is for, and it needs no export step and no re-encryption. The
store holds one keypair, carried inside it, so a file encrypted on one machine opens on
any machine that can open the store.

Let the store sync across — Dropbox, `rsync`, a USB stick, it does not matter — and it
already works there:

```bash
angou ls                            # asks for the recovery passphrase
angou dec work/.secrets.env         # the file you encrypted on the other machine
```

The store does not have to sit at the same path on both machines, and nothing about the
first machine has to travel with it. The recovery passphrase is the one thing you carry
in your head.

Then, once, on that machine:

```bash
angou bootstrap
```

That takes the key out of the store, wraps it under a fresh 32-byte machine password,
and puts that password in your desktop's keyring. Afterwards this machine opens the store on
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

Everything here is **optional**. It is for the case where a machine has no `angou` and
you would rather not install one the usual way — you want the store to carry the program
so that the machine needs nothing but the store and `gpg`. If you are happy to install
angou on the new machine as you did on the first, skip this section entirely; a store
made by `angou init` carries no binaries and does not need to.

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
never prints a passphrase, the contents of a file, or a digest of one.

Opening the store costs about a quarter of a second and 96 MB of memory, once, unless
the wallet or the agent is doing it for you. angou checks that the memory is available —
including any container limit on the process — and explains the shortfall rather than
being killed part-way through.

## Usage (GUI)

> **Status**: the GUI is not part of a release yet. Every operation is wired to the same
> code the CLI runs, and a parity test fails the build if either front end grows an
> operation the other lacks — but it has had far less use than the CLI, and the CLI is
> what this version is for.

`angou-gui` is a desktop front end over the same store. It does everything the CLI does — the two are kept in step deliberately, and neither is allowed a
capability the other lacks. It is a separate program from the CLI and is never needed
to set a machine up or to recover one.

It is worth having for three things the command line does poorly. The directory scan
becomes a list you tick, rather than `--auto` taking everything the scanner found or a
prompt for every file. The `doctor` report becomes a ranked report, so the line saying
this machine still needs the recovery passphrase no longer reads the same as the line
naming the store directory. And the listing becomes something you can act on, instead
of a table you read before retyping a path into a second command.

It is built with Fyne, which draws its own widgets and so looks native on no desktop.
The mitigation is a set of transcribed color schemes — Breeze Dark, Breeze Light,
Oxygen Dark, Adwaita Dark, and Adwaita Light — with a font and text-size picker beside
them, under **Appearance**. Those settings and the store directory are all the GUI
saves between runs; the file holds no fingerprint, no passphrase, and nothing out of
the store itself.

The GUI finds its store from `$ANGOU_STORE` when that is set, and otherwise from the
directory you last chose with **Store…**. The environment wins, so a shell that already
names a store keeps naming it and the two front ends agree in that session.

The GUI needs CGO, OpenGL, and a display server. The CLI needs none of those and never
will, because bootstrapping a bare machine depends on it staying a static binary with
no runtime dependencies. `angou release` stashes both in the store, but a store carries
the CLI for every platform and the GUI only for the ones it has been built on — the GUI
cannot be cross-compiled. `bootstrap.sh` installs the CLI first and never waits on the GUI, so recovery does not
depend on it. When the store does carry one for that machine, it is installed alongside,
with a desktop entry and an icon. `install.sh` installs both by default and skips the GUI with a
note if it cannot be built; `--no-gui` skips it deliberately.

One caveat specific to the GUI: text typed into a field is held in a Go string, which
cannot be overwritten afterwards. The CLI's terminal read is better in this respect.
Neither is a guarantee — see **Safety** below.

![The Store section: a sortable table of four stored files — demo/credentials, demo/id_ed25519, demo/prod.env and demo/work.ovpn — each with its size, POSIX mode, age, and the path it was encrypted from. A toolbar offers Encrypt file, Scan directory, Refresh, Reindex, Prune and Clone; the Decrypt, Extract, Rename and Remove buttons along the bottom are greyed out until a row is selected. The status bar reads: store, the directory; unlocked by an agent session; agent, session 9m58s remaining.](assets/screenshot-store.png)

![The Encrypt section: a scan of a directory listing five candidates, each with the reason it was flagged — "AWS credentials" for .aws/credentials, "netrc credentials" for .netrc, "SSH private key" for both .ssh/id_ecdsa and .ssh/id_rsa, and "environment file" for projects/api/.env. All five are ticked, and the count reads "5 of 5 selected". A .env.example file in the same tree was not flagged. Scan is a dry run; Encrypt selected sits apart at the bottom.](assets/screenshot-encrypt.png)

![The Doctor section: findings grouped by subject with a status marker on each row. Store shows the directory and a green tick for the store being present. Key bundle shows argon2id m=64 MiB t=24 p=4, with green ticks for parameters meeting the pinned floor and memory being sufficient. This machine shows an orange warning — "local key: absent — this machine asks for the recovery passphrase" — followed by "to change that: run `angou bootstrap`". Keyring is reachable, with its entry not applicable until the machine is bootstrapped. A superseded-key assertion field sits below the report.](assets/screenshot-doctor.png)

![The Machine section in three parts. Routine: set this machine up, change the machine password, change the recovery passphrase. Session cache: the agent, described as unnecessary on a machine that already holds a local key and there for machines with no keyring, with its state and socket path. Irreversible, with buttons in red: forget this machine, and rotate the store identity — each stating what it costs, including that forgetting loses access if the recovery passphrase is gone.](assets/screenshot-machine.png)

The screenshots are captured by `tools/screenshot.sh --all`, which drives the window
itself rather than relying on anyone clicking through it. It builds its own throwaway
store to photograph, with obviously invented contents, and never opens the one you use:
a store's listing is a list of where you keep your credentials, and these images are
published.

## Project layout

```
angou/
├── cmd/angou/              the command line
├── cmd/angou-gui/          the desktop browser (not built yet)
├── internal/container/     the blob format
├── internal/buildinfo/     what this binary was built from
├── internal/cli/           the command tree
│   └── assets/             the bootstrap installer, as shipped into a store
├── internal/store/         blob naming, the index, rotation, extraction
├── internal/envelope/      the metadata sealed inside each blob
├── internal/pgpcrypto/     signing, encryption, and verification
├── internal/keybundle/     the key bundle and its Argon2id protection
├── internal/passphrase/    generating and screening recovery passphrases
├── internal/keyring/       the desktop keyring, split by platform and API
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
make e2e-keyring    # the keyring tests; needs you at the desktop, see below
make e2e-container  # bootstrap onto a machine with nothing installed
make lint           # pinned golangci-lint, checksum-verified when installed
make shellcheck     # the plaintext bootstrap installer
```

`make e2e` never touches your keyring. The tests that do are behind their own target,
because they operate the keyring you keep real secrets in and KWallet offers no way to
make a throwaway wallet — opening a wallet that does not exist raises a dialog and waits
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

### 0.2.1

Three fixes, all found by publishing 0.2.0 to a real store and bootstrapping a second
machine from it.

- **`angou release` refused nothing, and would stash a binary from any build.** The
  metadata beside a stashed artifact records the version and commit of the tool doing
  the stashing, not of the artifact — so a `dist/` directory left over from an earlier
  build was signed under the current version. A store ended up holding
  `angou-linux-amd64-0.2.0` whose binary reported 0.1.4, and the machine that installed
  it was then refused by the store's own version floor. The signature was valid
  throughout: it signs the bytes, and cannot notice that the description beside them is
  wrong.

  Artifacts are now checked against the commit doing the stashing, read from the
  binary's recorded VCS revision rather than by running it — asking an artifact what it
  is by executing it means executing it before deciding whether to trust it.
- **A leading `~` in a path is expanded.** A shell does this only for an unquoted tilde,
  and the GUI has no shell at all, so `~/Dropbox/angou` typed into a field arrived
  literally and created a store in a directory named `~`.
- **Creating anything under a directory named `~` is refused.** That directory is a trap
  rather than a mess: from its parent, the obvious way to remove it is `rm -rf ~`, which
  the shell expands to your home directory before `rm` runs. Opening an existing one
  still works, or the remedy for having made one would be being unable to reach what is
  inside it.
- The version-floor refusal now says how to fix itself. A machine holding an older angou
  and a synced store has the current version and an installer for it sitting right there,
  so the message names that command instead of saying "install the current version".

### 0.2.0

- **A desktop GUI**, `angou-gui`, over the same store. It does everything the CLI does,
  and a test fails the build if either front end grows an operation the other lacks. It
  is a separate binary: the CLI stays static and CGO-free, because bootstrapping a bare
  machine depends on that and the GUI needs OpenGL and a display server.

  It exists for the three things a command line does worst. The directory scan becomes a
  list you tick rather than `--auto` taking everything the scanner found. The `doctor`
  report becomes ranked, so "this machine still needs the recovery passphrase" no longer
  reads the same as "the store directory is here". And the listing becomes something you
  can act on instead of a table you read before retyping a path into a second command.

  Built with Fyne, which draws its own widgets and so looks native nowhere. The
  mitigation is a set of colour schemes transcribed from the desktops' own files —
  Breeze Dark, Breeze Light, Oxygen Dark, Adwaita Dark and Light — with a font and
  text-size picker beside them.
- **Everything moved into `internal/core`.** Both front ends run on it; neither
  reimplements an operation or reaches past it into the store. Two contracts came out of
  it: `Secrets`, so a package that never prompts can still need a passphrase, and
  `Decider`, which makes `--overwrite`, `--auto` and the GUI's dialogs one mechanism
  rather than three. The CLI's output is unchanged, byte for byte, and
  `tools/regress.sh` is what holds it there — it diffs the built binary against a
  previous commit's, because the test suite asserts what someone thought to assert and
  the first slice of this refactor reordered two `--verbose` lines with every test still
  green.
- **The scan finds private keys by their header, not only by their name.** A key called
  `njv_ssh_key` was missed by every rule — outside `.ssh`, no `id_` prefix, and "key"
  without a dot in front of it is not the `.key` extension — while its first line said
  `-----BEGIN OPENSSH PRIVATE KEY-----`. That check existed and was only ever used to
  confirm a name that had already matched. This is the case a name-based scan is worst
  at and the one most worth finding: anyone naming keys conventionally was already
  covered.
- **The store can carry the GUI, and a bootstrap installs it** with its desktop entry
  and icon when one is there for that platform. Never a dependency: the CLI is installed
  first and nothing about the GUI step can fail a recovery. The GUI cannot be
  cross-compiled, so a store holds the CLI for every platform and the GUI only for those
  someone has built on.
- `angou release` reports where a signing key is when one exists, and the GUI prefills
  the path, but neither signs with a key you did not name. Which key signs a release
  decides which binaries every future bootstrap trusts, and finding a file is not the
  same as choosing one.

### 0.1.4

- **`angou enc <dir> --all --dry-run`** prints what the scan found and why, and stores
  nothing. Run it first: the scan is a guess, and this is how you find out whether the
  guess is any good on your machine before acting on it.
- **The scan is far less credulous.** Rules resting on a name alone were the problem,
  and running the previous version against a real home directory is what showed it: it
  offered eighteen session-state files ending in `.key`, Python's own `secrets.py` and
  `token.py`, two libssh2 manual pages, a pkg-config file, a PowerShell script, an XSLT
  stylesheet, five CI configs named `secret-report.yml`, and twenty `.env.example`
  templates.

  A `.key` or `.pem` is now offered only if it begins with a private-key header, so a
  certificate and a session handle are both declined. A name merely mentioning a secret
  must also carry something that looks like an assignment, must not be source code,
  documentation or a manual page, and must not be binary — without that last condition a
  PDF matched because its bytes happened to read as `key: value`. Templates are skipped
  entirely, since showing the shape of a credential is the opposite of being one.

  On that same directory the result went from 140 files to 88, and every remaining match
  of the weakest rule is a real credential. Those cases are in the tests by name, so a
  future change to these rules has to argue with them.
- The container package moved from `lib/` to `internal/`. It was public on the grounds
  of being "third-party readable", which does not hold: `gpg` already reads a blob body
  without angou, which serves anyone rather than only someone writing Go. A public
  package instead commits us to keeping every exported symbol, and nothing had asked for
  that. Build metadata moved to `internal/buildinfo`, since it had been living in the
  format's package only because that is where the `-ldflags` path pointed.

### 0.1.3

- `angou enc <dir> --all` looks through a directory for the kinds of file credentials
  live in — SSH keys, cloud and cluster credentials, `.env` files, `.netrc`, `.pgpass`,
  keys and certificates — and offers each one. `--auto` takes them without asking. It
  skips public keys and does not descend into `node_modules`, `.git` or caches. Without
  a terminal to ask and without `--auto` it refuses, rather than treating silence as
  consent. An empty result is reported as what it is: the scan knows the usual names and
  places, not every way a secret can be written down.
- `enc` records where a file was, and `dec` offers to put it back there. On a second
  machine that means an SSH key returns to `~/.ssh` rather than landing wherever you are
  standing, with its permissions intact — a key restored over a world-readable file ends
  up `0600` again. You are asked before anything is written and again before a file is
  replaced; `--overwrite` skips the second question and `--restore` makes it work
  unattended. Piped output is unchanged, so `angou dec x > file` still does what it did.
  Acting on a location out of the store is only safe because payloads are signed, and a
  symlink at the destination is refused rather than written through.
- `angou ls` is a detailed listing: permissions, size, age, path, and where each file
  came from, coloured on a terminal and plain when piped. A file stored with permissions
  that let anyone but you read it is flagged. `--names` prints just the paths for
  scripts, and `--raw` shows the store as it sits on disk — which needs no passphrase,
  because those are the names anyone holding your store already sees.

### 0.1.2

- **The keyring is reached through the freedesktop Secret Service**
  (`org.freedesktop.secrets`) in preference to the KDE-specific API, with KWallet kept
  as a fallback. Speaking only `org.kde.kwalletd6` made the keyring a KDE feature: on
  GNOME, XFCE, Sway or anything else, angou reported no keyring and fell back to asking
  for the recovery passphrase on every command — not because the machine had no secret
  store, but because angou could not talk to the one it had. Since a store is meant to
  work on every machine you carry it to, that made the portability of your files
  contingent on your desktop environment.

  The Secret Service is implemented by gnome-keyring, by KDE through `ksecretd`, and by
  KeePassXC among others. It is also binary-safe by construction, which the older API
  was not: a secret's value is a byte array rather than a string, and the unlock
  passphrase is 32 bytes of random data that is not valid text.

  `ANGOU_KEYRING=kwallet` pins the older API; `secretservice` pins the new one. A name
  that is neither is refused at start-up, before the command does anything, rather than
  quietly becoming "this machine has no keyring".

- Both backends are exercised by the same test, so neither is verified only by
  inference from the other.

### 0.1.1

Fixes for the first-run experience, all of them found by using the tool rather than by
testing it. Each was a case where the program worked and the path through it did not.

- `angou init` now sets up the machine it runs on. It previously created a store and
  left that machine unable to open it without the recovery passphrase, so every command
  asked for one — contradicting this document, which says you type that passphrase when
  setting up a machine "and almost never otherwise". Requiring a separate
  `angou bootstrap` afterwards asked for the same passphrase that had just been used, to
  perform a step with no separate decision in it. `--no-bootstrap` opts out.
- `angou enc ~/.secrets.env` worked. The shell expands the tilde before angou sees it,
  and absolute paths were refused, so the most natural invocation there is did not work.
  Absolute paths now map into the store's namespace, keeping their structure so two
  files of the same name from different projects still do not collide.
- `--ttl` accepts the durations people type. Go's own syntax has no unit above hours and
  rejects a bare number, so `3600`, `1d`, `1w` and `99999` were all errors.
- `install.sh --publish-to=STORE` puts signed binaries and the installer into a store, so
  a machine with no angou can install one from it. The installer also offers this when it
  notices a store that carries no binaries. It asks rather than assuming: publishing
  creates a release-signing key, and that key decides which binaries every future
  bootstrap accepts.
- `angou doctor` reports the version floor and what the bootstrap namespace holds, and
  says what to do about each. It no longer refuses to run when this binary is below the
  store's version floor — that is the situation someone runs it to diagnose.
- `angou init` refuses a directory that already holds a store *before* asking for a
  passphrase. Asking for a "new recovery passphrase" and only then reporting that the
  store exists reads as though the store is about to be replaced. It never was — `init`
  refuses before generating a key or writing anything — but the ordering was alarming
  for no reason.
- `install.sh` no longer tells you to run `angou init` after it has just set up the
  store you already had. Its closing advice now depends on what it actually did.
- A keyring that holds its D-Bus name without answering no longer hangs every command.
  The call that asks which wallet to use is bounded at five seconds — it reports a name
  and prompts for nothing, so it has no business being slow — and a broken keyring
  degrades to the recovery-passphrase path with an accurate reason. Opening a wallet
  stays unbounded, because that can legitimately wait for a person to answer a dialog.
- Decrypting on a machine other than the one that encrypted is the point of the store,
  and now has tests: a second machine with its own home, its own store path, no local
  key and no keyring reads what the first one wrote, and writes back.

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
