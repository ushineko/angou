# angou

Encrypts sensitive files into a portable store you can keep in Dropbox, on a USB stick, or
anywhere else you can copy a directory. `angou` (暗号 — cipher/password) wraps each file in
an OpenPGP encrypted format, and the store carries everything needed to rebuild itself
across multiple machines.

It is built for small, high-value files: `.secrets.env`, SSH private keys, and text files
with passwords in them.

*Nothing about your keys or your data lives in this repository. The store stays where you
put it.*

**Version**: 0.2.1

> The specs are the design of record, including the alternatives that were rejected and
> why: [`specs/001`](specs/001-angou-format-keying-and-store.md) for the format, key
> model and store, and [`specs/002`](specs/002-desktop-gui.md) for the GUI.

## Table of Contents

- [What it does](#what-it-does)
- [Security Guarantees](#security-guarantees)
- [Credentials](#credentials)
- [How the encryption works](#how-the-encryption-works)
- [Bootstrapping](#bootstrapping)
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
- [License](#license)

## What it does

**Encrypts a file into a blob.** The blob is text by default — base64, so it survives
being pasted into a chat window, opened in an editor, or dragged through a sync service
that rewrites line endings. Large files can be stored as raw binary instead. The choice is
written into the blob, so it is never guessed at when reading.

**Keeps the blobs in a plain directory.** No database. Copy it, `rsync` it, put it in
Dropbox, carry it on a stick. Whatever you can do to a folder, you can do to the store.

**Hides what it is holding.** A blob's filename is a keyed hash of the path you gave it,
so the store is a directory of opaque names. The original filename lives inside the
encryption, not beside it.

**Stays readable without this tool.** Blobs are ordinary OpenPGP messages. If `angou` is
ever missing, unbuildable, or you are on a machine that cannot run it, `gpg --decrypt`
gets your data back. This is deliberate and will not be traded away for a cleverer format.

**Carries its own installer.** The store holds a signed copy of the program for each
platform, so a new machine needs the store and one password — not a Go toolchain, and not
this repository.

## Security Guarantees

Someone holding a copy of your store, without your passwords, does not learn the
filenames, the contents, or what kinds of files they are. What they do learn:

- how many secrets you have, and roughly how big each one is;
- **which one is which, over time.** Each file keeps the same scrambled name for as long
  as it exists, so someone watching your store across weeks can follow one particular file
  — see that it changes every Friday, or that you touched it the day something happened —
  without ever learning what it is;
- when you add, delete or rename something;
- that you use `angou`, which operating systems you run, and which versions, since the
  installers the store carries are ordinary files.

Rotating your identity with `angou rekey --identity` renames everything and breaks that
tracking, which is part of why it is the right response to a lost machine.

Someone who can **write** to your store — not just read it — is a different problem. They
cannot forge a secret, because everything is signed and each file is bound to its own
name. But they can put back an older copy of something you already had: undo a password
rotation, or restore a key you deleted. Your sync service's own version history is the
defense there, and `angou` does not add another.

They also cannot make you run something. The program the store carries is signed by a key
kept offline, and refused if it is older than the newest version you have already
installed — so neither a swapped copy nor an old one can be quietly put back. The program
itself is not encrypted, and does not need to be: it is the same software anybody can
download, and what protects you is the signature, not secrecy. The one exception is
`bootstrap.sh`, which is plaintext by necessity, because something has to run before the
program exists. Its hash is recorded inside the store and published on GitHub, so you can
check it before running it on your first machine and `angou verify-bootstrap` will catch a
change from any machine you have already set up.

## Credentials

**Your recovery password** is the one you memorize. It is the only thing standing between
a copy of your store and everything in it, so make it long and keep it in a password
manager or on paper. You type it when you set up a new machine, and almost never
otherwise.

**The unlock password is not yours.** Each machine generates its own — 32 random bytes,
never shown to you, never written down, kept in your desktop's keyring and nowhere else.
You will never type it and there is nothing to remember.

The result is that a machine holds no secret worth stealing. Wipe your wallet, reinstall
your OS, lose the laptop: nothing is lost, because a machine's setup is rebuilt from the
store rather than recovered. Nothing derives it from your hostname or hardware either, so
imaging the disk and reading this source is not an attack vector.

angou uses the freedesktop Secret Service, which GNOME, KDE, XFCE and others all
implement, so this should work on most desktops rather than only on KDE.
`ANGOU_KEYRING=kwallet` pins the older KDE-specific API if you would rather use it.

This tool can still be used on a system with no keyring, but it will be less friendly to
use.

## How the encryption works

Every blob is encrypted to a single OpenPGP **identity keypair**, generated by `angou
init` and carried inside the store. That is why a file encrypted on one machine opens on
any machine holding the store: the key travels with it.

Getting to that keypair takes one of two routes.

```mermaid
flowchart TD
    RP["Recovery passphrase<br>you memorise it"]
    UP["Unlock password<br>32 random bytes, in the keyring"]

    RP -->|"Argon2id<br>64 MiB, t=24, p=4"| WK["Wrapping key"]
    WK -->|"AES-256-GCM<br>opens wrapped_key"| BK["Bootstrap key<br>32 random bytes"]
    BK -->|"AES-256-GCM<br>opens payload"| ID["Identity keypair<br>OpenPGP, one per store"]

    UP -->|"HKDF"| LW["Local wrap key"]
    LW -->|"AES-256-GCM<br>opens the local copy"| ID

    ID -->|"encrypts and signs"| BL["Every blob in the store"]
```

**The recovery route** is what a machine uses before it has been set up. The passphrase
is stretched with Argon2id into a wrapping key, which decrypts the bootstrap key, which
decrypts the identity. The bootstrap key is 32 random bytes and exists so the expensive
derivation guards a 256-bit random value rather than the identity itself.

**The keyring route** is what a machine uses after `angou bootstrap`. Bootstrap writes a
local copy of the same identity, wrapped under a 32-byte unlock password held in the
keyring. HKDF rather than Argon2id, because stretching is for guessable human input and
a CSPRNG value is not guessable. That is the difference between a quarter of a second
and five milliseconds.

Both routes end at the same keypair. Nothing per-machine ever encrypts a blob, and the
local copy is disposable — delete it and `angou bootstrap` rebuilds it from the store.

What lives where:

| | Where it is kept |
|---|---|
| Identity keypair | In the store, encrypted inside the key bundle |
| Bootstrap key | In the store, encrypted under the wrapping key |
| Wrapping key | Derived on each use, never stored |
| Unlock password | This machine's keyring, nowhere else |
| Local copy of the identity | This machine's disk, wrapped |
| Recovery passphrase | Your head, and wherever you wrote it down |

The Argon2id parameters are stored in the clear beside the ciphertext, because a reader
has to check them before spending the derivation. They are validated against a pinned
floor on every read, so an attacker cannot edit the header to downgrade the work factor
and crack a cheaper target.

Rotating the recovery passphrase with `angou passwd` writes a whole new key bundle — a
fresh bootstrap key and a re-encrypted payload. No blob is touched and no other machine
is affected, because the identity inside is unchanged.

## Bootstrapping

For a machine that does not have `angou` at all, it comes in two flavours depending on
what you put in the store.

**If you can install it normally** — the machine has Go, or you can copy a binary onto it
— do that. This is the simplest way. If no other system has it and you are trying it for
the first time, you want this method.

**The store itself is designed to carry the program**, which is done via the following
example command.

```bash
./install.sh --publish-to ~/Dropbox/angou
```

`install.sh` takes care of the details on publishing and signing the binaries.

Use `angou doctor` to diagnose issues with the init/store.

In order to use a pre-existing store on additional systems, use the bootstrap script.

```bash
cd /path/to/store
./bootstrap.sh
```

This will install the included binaries from the publish step, check the environment for
suitability, and check the binary signatures.

Afterwards run `angou bootstrap`, which is the step that asks for your recovery password.
Nothing is downloaded; everything comes out of the store you just copied.

The installer protects the binaries with a signature and a refusal to install a version
older than one you have already used.

`gpg` is needed for exactly this one step, to check that signature, because the program
that would otherwise do it is the thing being installed. On Arch it is already there —
`pacman` depends on it. Nothing after this point uses it.

As a matter of security best practice, read `bootstrap.sh` before you run it. It is short
and deliberately so.

## Requirements

- **Linux** (developed on CachyOS/Arch). Other platforms may be a later target.
- **Secret Service** for password caching. Without it you will be asked for your recovery
  password rather than having it cached. This is supported on most modern Linux desktop
  environments such as KDE and GNOME.
- **`gpg`** for the first-run bootstrap only, and not afterwards.
- **Go 1.25+** to build from source.

The program itself has no runtime dependencies. It is a static binary and does not call
out to `gpg`, `gpg-agent`, or `kwallet-query`.

The GUI is linked against platform-standard X11 and OpenGL libraries, and will only work
on systems that supply those dependencies as part of their core environment.

## Installation

From a store, use `bootstrap.sh` as explained above. From this repository:

```bash
git clone git@github.com:ushineko/angou.git
cd angou
./install.sh
```

Installs the `angou` command, the desktop entry, and the file-type rules that let the
desktop recognize a `.angou` blob. Remove it all with `./uninstall.sh`.

## Using it

Every command works on one store. Name it with `--store`, or set `ANGOU_STORE` once and
leave the flag off:

```bash
export ANGOU_STORE=~/Dropbox/angou
```

### Making a store

```bash
angou init --generate
```

This creates the store, generates its keypair, prints a recovery passphrase once, and sets
this machine up so you are not asked for that passphrase again here.

Write the passphrase down before you press anything else. This is similar to an API key.
Once you set it, it's gone forever if you don't remember it or write it down.

Where no keyring is available, you may be prompted multiple times for the recovery
password.

You may choose your own passphrase by leaving off `--generate` and you will be prompted. A
passphrase must score above a minimum number of entropy bits which guarantees a certain
length and complexity (e.g. repeating characters don't count).

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

`enc` leaves your original file where it is. Deleting it is your decision, and on a copy-
on-write filesystem or an SSD deleting it is not erasing it.

The name you give a file is the name it keeps. Encrypting the same path again replaces
that entry rather than adding a second one, so updating a secret is just `enc` again. Two
files called `.secrets.env` in different projects do not collide, because the whole path
is the name.

If you do not pass `--as`, angou works the name out and tells you what it chose. A
relative path is used exactly as you typed it. An absolute one — which is what your shell
hands over when you write `~/.secrets.env` — is placed relative to your home directory, so
`~/projects/one/.secrets.env` is stored as `projects/one/.secrets.env`. Files outside your
home keep their path with the leading `/` removed. The structure is kept rather than
reduced to a filename, because a filename alone would put every project's `.secrets.env`
on the same name and each would replace the last.

### Putting a file back where it belongs

`enc` records where a file was when you encrypted it. `dec` uses that: on another machine,
`angou dec .ssh/id_ed25519` offers to put the key back in `~/.ssh` rather than dropping it
in whatever directory you happen to be standing in. You are shown the destination and
asked before anything is written, and asked again before an existing file is replaced.
Permissions come back too, so a key restored over a world-readable file ends up `0600`
again.

```bash
angou dec .ssh/id_ed25519                        # offers to restore it
angou dec .ssh/id_ed25519 --overwrite            # replace without the second question
angou dec .ssh/id_ed25519 --restore --overwrite  # for scripts: no questions at all
angou dec .ssh/id_ed25519 --stdout               # never touch the disk
```

When the output is piped or redirected, the plaintext goes there and nothing is written to
disk, so `angou dec x > file` keeps working. `--restore` asks for the file to be put back
regardless, which is what a script wants; with nothing to answer a question it will
restore, but it will not replace an existing file unless you also pass `--overwrite`.

Acting on a location that came out of the store is only safe because every payload is
signed. Forging that destination means forging the signature, so someone who can write to
your store cannot use this to direct writes around your disk. A symlink at the destination
is refused rather than written through.

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
and cluster credentials, `.env` files, `.netrc`, `.pgpass`, keys and key stores, and files
whose names mention a secret.

Where a name alone is not enough, it looks at the file. A `.key` extension means a private
key in some tools and a session handle in others, so `.key` and `.pem` files are offered
only if they actually begin with a private-key header — a certificate is not a secret and
neither is a cache entry. A name merely mentioning "password" is as likely to be a note
about passwords as a file containing one, so those must also look like assignments and
must not be source code, documentation, or a manual page. Templates (`.env.example`,
`.env.template`) are skipped: showing the shape of a credential is the opposite of being
one.

It does not descend into `node_modules`, `.git`, caches, tool state or installed software.

The default is to ask before importing the file to the store.

The scan only checks common cases for keys and credentials and does not necessarily catch
all files you might want to encrypt. For example, documents with sensitive information, or
files that are other binary formats that don't match the common filters.

### Looking at what you have

```bash
angou ls           # the detailed listing
angou ls --names   # just the paths, one per line, for scripts
angou ls --raw     # the store as it sits on disk
```

The default listing shows permissions, size, when each file last changed, its name, and
where it came from. It is coloured on a terminal and plain when piped, so a script never
has to strip escapes; `--no-color` and `NO_COLOR` both turn it off. A file stored with
permissions that let anyone but you read it is flagged, because that is worth noticing on
the way past.

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

The store holds one keypair, carried inside it, so a file encrypted on one machine opens
on any machine that can open the store. There is no export step and no re-encryption.

Let the store sync across — Dropbox, `rsync`, a USB stick — and it works there:

```bash
angou ls                            # asks for the recovery passphrase
angou dec work/.secrets.env         # the file you encrypted on the other machine
```

The store does not have to sit at the same path on both machines. The recovery passphrase
is the only thing you carry between them.

Then, once, on that machine:

```bash
angou bootstrap
```

This takes the key out of the store, wraps it under a fresh 32-byte machine password, and
puts that password in the keyring. Afterwards the machine opens the store on its own, in
about five milliseconds instead of a quarter of a second.

If you delete the keyring entry, the machine can no longer open its local copy and nothing
local can restore it. Run `angou bootstrap --force` with your recovery passphrase to set
the machine up again.

`angou bootstrap --forget` undoes it. Run it before handing a machine on.

On a machine with no keyring, `bootstrap` says so and changes nothing. The store still
works there and asks for the recovery passphrase.

### Holding the key for a while

```bash
angou agent start --ttl 10m     # or 3600, or 2h, or 1d
angou agent status
angou agent stop
```

**You probably do not need this if you have run `angou bootstrap`.** Measured on the same
store:

| How the store gets opened | Time per command |
|---|---|
| Recovery passphrase | 0.218 s |
| Keyring, after `angou bootstrap` | 0.005 s |
| Agent | 0.003 s |

Two milliseconds is not worth much, and there is a trade. The keyring's copy of the key
stops being available when the keyring locks; the agent's does not, because it sits in a
running process.

The agent is for machines with no keyring — headless, a server, or a Mac until the
Keychain backend lands. There, every command otherwise costs a passphrase prompt and a
quarter of a second.

The socket is readable only by you, which keeps out other users of the machine. It does
not keep out anything else running as **you**: while the agent is up, any process under
your account can ask it for the key. The lifetime is the real protection, which is what
`--ttl` and `agent stop` are for.

### Setting up a new machine

This is **optional**, and only for the case where a machine has no `angou` and you want
the store to carry the program so the machine needs nothing but the store and `gpg`. If
you can install angou there the usual way, skip this section.

From a machine that already works:

```bash
angou release --new-signing-key ~/angou-release.asc   # once, ever
make build-all RELEASE_KEY=<the fingerprint it printed>
angou release --dist dist/ --signing-key ~/angou-release.asc
```

This puts a binary for each platform into the store, signs each one, and writes
`bootstrap.sh` beside them. Move the signing key to offline storage afterwards and delete
it from the machine. Anyone who has it can sign a binary that every future bootstrap will
accept.

The key `--new-signing-key` writes is not passphrase-protected. Moving it offline is the
control. If you want both, make the key with `gpg` and export it — angou accepts a
passphrase-protected key and asks for the passphrase first:

```bash
gpg --quick-generate-key 'angou release <you@example.com>' ed25519 sign never
gpg --armor --export-secret-keys <fingerprint> > ~/angou-release.asc
```

A build with a fingerprint pinned into it will only stash binaries signed by that key.

`angou release` also refuses a binary that was not built from the commit doing the
stashing. The metadata beside a stashed artifact records the version and commit, and a
stale `dist/` would be signed under a version its bytes do not have.

On the new machine, with nothing installed but `gpg`:

```bash
sh /path/to/store/bootstrap.sh
angou bootstrap --store /path/to/store
```

The script detects the platform, checks the binary's signature against a fingerprint
written into the script itself, installs it, and stops. It asks for no passphrase and does
not use the network. If the store carries a GUI for that platform, it installs that too,
along with a desktop entry and icon.

Read the script before you run it. Its own signature is checked *after* it has run, which
catches a file that changed but does not tell you the file you just ran was genuine. On a
first machine, compare it against the copy published in the repository.

### When something looks wrong

```bash
angou doctor        # what this machine can and cannot do, and why
```

`doctor` changes nothing and is the first thing to run when a command fails in a way you
do not understand. It reports whether the store is there, whether its key bundle is
usable, whether this machine has a local key, whether the keyring holds the matching
entry, and what the version floor is.

```bash
angou reindex       # rebuild the listing from the blobs themselves
```

The listing is a cache, not the source of truth. If a sync service leaves a conflicted
copy or the listing goes missing, `reindex` rebuilds it by reading the files. Getting a
file by name does not use the listing.

If `reindex` reports files it could not read, they are usually left over from an
interrupted rotation, and `angou prune --orphans` removes them. It will not remove a file
that decrypts but sits under the wrong name.

```bash
angou verify-bootstrap   # has the installer in the store been altered?
```

Run this from a machine you trust to detect tampering with the script your other machines
will run.

### Changing what protects the store

Three commands for three different problems:

```bash
angou passwd              # someone may have seen your recovery passphrase
angou rekey --local       # you want a new machine password on this machine
angou rekey --identity    # a machine holding the key may be compromised
```

`passwd` changes what guards the key. No file in the store changes and no other machine is
affected.

`rekey --local` changes this machine's password only. Every blob stays byte-identical.

`rekey --identity` generates a new keypair *and* a new naming key, then re-encrypts and
renames every file. The renaming matters as much as the re-encryption: the names are
derived from a key, and leaving that key in place would let anyone holding your store
follow each file across snapshots after the keypair changed.

Afterwards every machine must run `angou bootstrap` again, and you should confirm the
rotation was complete:

```bash
angou doctor --old-key <the old fingerprint it printed>
```

Run this before `angou prune --bundles`. Pruning removes the old key bundle, and the check
needs it.

### Copying a store

```bash
angou clone --to /media/backup/angou
angou clone --to /media/backup/angou --no-binaries
```

A clone opens with the same passphrase and holds the same secrets, so protect it the same
way. `--no-binaries` omits the platform binaries, which are most of the size; the copy
still holds everything but cannot set up a bare machine on its own.

`clone` refuses a destination inside the store, which would copy the store into itself,
and refuses to follow a symlink it finds there, which would let anyone who can write to a
synced store have a file of yours copied out.

### Things worth knowing

Every command takes `--verbose` (`-v`), which reports what angou is doing on stderr. It
never prints a passphrase, file contents, or a digest of one.

Opening the store costs about a quarter of a second and 96 MB of memory, once, unless the
keyring or the agent is doing it for you. angou checks the memory is available — including
any container limit on the process — and reports the shortfall rather than being killed
part-way through.

## Usage (GUI)

> **Status**: shipped in 0.2.0, and it has had far less use than the CLI. Every operation
> runs the same code the CLI does, and a parity test fails the build if either front end
> grows an operation the other lacks.

`angou-gui` is a desktop front end over the same store. It does everything the CLI does.
It is a separate program and is never needed to set a machine up or recover one.

It is worth having for three things the command line does poorly. The directory scan
becomes a list you tick, rather than `--auto` taking everything or a prompt per file. The
`doctor` report becomes ranked, so "this machine needs the recovery passphrase" does not
read the same as "the store directory is here". And the listing becomes something you can
act on, rather than a table you read before retyping a path into a second command.

It is built with Fyne, which draws its own widgets rather than using the platform's
toolkit, so it is not a GTK or Qt application and does not inherit your widget style. It
does inherit your colours: the schemes under **Appearance** are transcribed from the
desktops' own files, so it looks best on KDE Plasma (Breeze Dark, Breeze Light, Oxygen
Dark) and GNOME (Adwaita Dark, Adwaita Light). A font and text-size picker sits beside
them. Those settings and the store directory are all the GUI saves between runs; the file
holds no fingerprint, no passphrase, and nothing out of the store.

The GUI finds its store from `$ANGOU_STORE` when set, and otherwise from the directory you
last chose with **Store…**. The environment wins, so a shell that already names a store
keeps naming it.

The GUI needs CGO, OpenGL, and a display server. The CLI needs none of those, because
bootstrapping a bare machine depends on it staying a static binary. `angou release`
stashes both, but a store carries the CLI for every platform and the GUI only for the ones
it has been built on, since the GUI cannot be cross-compiled. `bootstrap.sh` installs the
CLI first and never waits on the GUI; when the store carries one for that machine it is
installed alongside, with a desktop entry and icon. `install.sh` installs both by default
and skips the GUI with a note if it cannot be built. `--no-gui` skips it deliberately.

Text typed into a GUI field is held in a Go string and cannot be overwritten afterwards.
The CLI's terminal read is better in this respect. Neither is a guarantee — see **Safety**
below.

![The Store section: a sortable table of four stored files — demo/credentials, demo/id_ed25519, demo/prod.env and demo/work.ovpn — each with its size, POSIX mode, age, and the path it was encrypted from. A toolbar offers Encrypt file, Scan directory, Refresh, Reindex, Prune and Clone; the Decrypt, Extract, Rename and Remove buttons along the bottom are greyed out until a row is selected. The status bar reads: store, the directory; unlocked by an agent session; and the agent's remaining session time.](assets/screenshot-store.png)

![The Encrypt section: a scan of a directory listing five candidates, each with the reason it was flagged — "AWS credentials" for .aws/credentials, "netrc credentials" for .netrc, "SSH private key" for both .ssh/id_ecdsa and .ssh/id_rsa, and "environment file" for projects/api/.env. All five are ticked, and the count reads "5 of 5 selected". A .env.example file in the same tree was not flagged. Scan is a dry run; Encrypt selected sits apart at the bottom.](assets/screenshot-encrypt.png)

![The Doctor section: findings grouped by subject with a status marker on each row. Store shows the directory and a green tick for the store being present. Key bundle shows argon2id m=64 MiB t=24 p=4, with green ticks for parameters meeting the pinned floor and memory being sufficient. This machine shows an orange warning — "local key: absent — this machine asks for the recovery passphrase" — followed by "to change that: run `angou bootstrap`". Keyring is reachable, with its entry not applicable until the machine is bootstrapped. A superseded-key assertion field sits below the report.](assets/screenshot-doctor.png)

![The Machine section in three parts. Routine: set this machine up, change the machine password, change the recovery passphrase. Session cache: the agent, described as unnecessary on a machine that already holds a local key and there for machines with no keyring, with its state and socket path. Irreversible, with buttons in red: forget this machine, and rotate the store identity — each stating what it costs, including that forgetting loses access if the recovery passphrase is gone.](assets/screenshot-machine.png)

The screenshots are captured by `tools/screenshot.sh --all`, which drives the window
itself rather than relying on anyone clicking through it. It builds its own throwaway
store to photograph, with obviously invented contents, and never opens the one you use: a
store's listing is a list of where you keep your credentials, and these images are
published.

## Project layout

```
angou/
├── cmd/angou/              the command line
├── cmd/angou-gui/          the desktop GUI
├── internal/core/          the operations both front ends run on
│   └── assets/             the bootstrap installer and icon, as shipped into a store
├── internal/cli/           the command tree
├── internal/gui/           the desktop window
├── internal/container/     the blob format
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
├── internal/buildinfo/     what this binary was built from
├── packaging/              desktop file-type rules, icon, magic
├── tools/                  screenshot capture and the release regression diff
├── config/                 pinned linter configuration
├── specs/                  design specs
├── docs/                   format reference and runbooks
├── tests/e2e/              the end-to-end suite
└── validation-reports/     release validation records
```

Operations live in `internal/core`. Both front ends render it and neither reaches past it,
so a feature cannot land in one without the other. A test enforces this.

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
because they operate the keyring you keep real secrets in. They write an entry named for
the run and remove it afterwards, and need a human at the desktop to answer any access
prompt.

Testing is end-to-end by default. Most of what this program claims is a claim about the
built binary rather than about a function inside it: that a blob header gives nothing
away, that the binary needs nothing installed, that `gpg` can still read what it wrote,
that a bare machine can set itself up from a store. None of that can be confirmed against
a stand-in.

Each run builds a throwaway copy of the tool, points it at a throwaway store with a
throwaway password, and redirects `HOME` somewhere temporary. Your own store, keys and
keyring are never touched, and the suite refuses to run rather than fall back to them.

`tools/regress.sh` diffs the CLI's output against a previous commit's binary. The test
suite asserts what someone thought to assert; the diff asserts everything else.

## Safety

- **Your recovery password cannot be recovered.** Lose it and the store is lost. There is
  no reset and no backdoor. Write it down somewhere real.
- **`--shred` is not a secure erase.** On Btrfs, on any copy-on-write filesystem, and on
  any SSD, overwriting a file does not reliably destroy the old copy. The default leaves
  your original in place so this stays your decision.
- **Rotating does not un-disclose anything.** If someone read your store, those secrets
  are out permanently. Rekeying protects the store from here on; the actual work is
  changing the credential at each service. See [docs/compromise-
  recovery.md](docs/compromise-recovery.md).
- **`rekey --identity` rewrites the whole store.** It works on a copy and commits at the
  end, so an interruption leaves the original intact.
- **A conflicted copy of the index is harmless.** The blobs are the truth and the listing
  is rebuilt from them. If two machines write at once, run `angou reindex`.
- **Once a store is unlocked, anything running as you can use it.** During a session any
  process under your account can ask it to decrypt. This is true of ssh-agent and every
  password manager, and angou does not try to solve it.
- **Do not put the store in this repository, or any repository.** It is ignored here as a
  backstop, not as a plan.

## Changelog

### 0.2.1

Three fixes, all found by publishing 0.2.0 to a real store and bootstrapping a second
machine from it.

- **`angou release` would stash a binary from any build.** The metadata beside a stashed
  artifact recorded the version and commit of the tool doing the stashing, not of the
  artifact, so a stale `dist/` was signed under the current version. A store held `angou-
  linux-amd64-0.2.0` whose binary reported 0.1.4, and the machine that installed it was
  then refused by the store's own version floor. Artifacts are now checked against the
  commit doing the stashing, read from the binary's recorded VCS revision rather than by
  running it.
- **A leading `~` in a path is expanded.** A shell does this only for an unquoted tilde,
  and the GUI has no shell, so `~/Dropbox/angou` typed into a field created a store in a
  directory named `~`.
- **Creating anything under a directory named `~` is refused.** From its parent, the
  obvious way to remove it is `rm -rf ~`, which the shell expands to your home directory.
  Opening an existing one still works.
- The version-floor refusal now names the installer in the store instead of saying
  "install the current version".

### 0.2.0

- **A desktop GUI**, `angou-gui`, over the same store. It does everything the CLI does,
  and a test fails the build if either front end grows an operation the other lacks. It is
  a separate binary: the CLI stays static and CGO-free, because bootstrapping a bare
  machine depends on that.

It exists for the directory scan, which becomes a list you tick; the `doctor` report,
which becomes ranked; and the listing, which becomes something you can act on.

Built with Fyne. The colour schemes are transcribed from the desktops' own files, so it
looks best on KDE Plasma (Breeze Dark, Breeze Light, Oxygen Dark) and GNOME (Adwaita Dark
and Light), with a font and text-size picker beside them. - **Operations moved into
`internal/core`.** Both front ends run on it and neither reimplements an operation. The
CLI's output is unchanged, byte for byte; `tools/regress.sh` holds it there by diffing
against a previous commit's binary. - **The scan finds private keys by their header, not
only by their name.** A key called `njv_ssh_key` was missed by every name rule while its
first line said `-----BEGIN OPENSSH PRIVATE KEY-----`. - **The store can carry the GUI,
and a bootstrap installs it** with its desktop entry and icon when one is there for that
platform. Never a dependency: the CLI is installed first and nothing about the GUI step
can fail a recovery. - `angou release` reports where a signing key is when one exists, and
the GUI prefills the path, but neither signs with a key you did not name.

### 0.1.4

- **`angou enc <dir> --all --dry-run`** prints what the scan found and why, and stores
  nothing. Run it first: the scan is a guess, and this is how you find out whether the
  guess is any good on your machine before acting on it.
- **The scan is far less credulous.** Rules resting on a name alone were the problem, and
  running the previous version against a real home directory is what showed it: it offered
  eighteen session-state files ending in `.key`, Python's own `secrets.py` and `token.py`,
  two libssh2 manual pages, a pkg-config file, a PowerShell script, an XSLT stylesheet,
  five CI configs named `secret-report.yml`, and twenty `.env.example` templates.

A `.key` or `.pem` is now offered only if it begins with a private-key header, so a
certificate and a session handle are both declined. A name merely mentioning a secret must
also carry something that looks like an assignment, must not be source code, documentation
or a manual page, and must not be binary — without that last condition a PDF matched
because its bytes happened to read as `key: value`. Templates are skipped entirely, since
showing the shape of a credential is the opposite of being one.

On that same directory the result went from 140 files to 88, and every remaining match of
the weakest rule is a real credential. Those cases are in the tests by name, so a future
change to these rules has to argue with them. - The container package moved from `lib/` to
`internal/`. It was public on the grounds of being "third-party readable", which does not
hold: `gpg` already reads a blob body without angou, which serves anyone rather than only
someone writing Go. A public package instead commits us to keeping every exported symbol,
and nothing had asked for that. Build metadata moved to `internal/buildinfo`, since it had
been living in the format's package only because that is where the `-ldflags` path
pointed.

### 0.1.3

- `angou enc <dir> --all` looks through a directory for the kinds of file credentials live
  in — SSH keys, cloud and cluster credentials, `.env` files, `.netrc`, `.pgpass`, keys
  and certificates — and offers each one. `--auto` takes them without asking. It skips
  public keys and does not descend into `node_modules`, `.git` or caches. Without a
  terminal to ask and without `--auto` it refuses, rather than treating silence as
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
- `angou ls` is a detailed listing: permissions, size, age, path, and where each file came
  from, coloured on a terminal and plain when piped. A file stored with permissions that
  let anyone but you read it is flagged. `--names` prints just the paths for scripts, and
  `--raw` shows the store as it sits on disk — which needs no passphrase, because those
  are the names anyone holding your store already sees.

### 0.1.2

- **The keyring is reached through the freedesktop Secret Service**
  (`org.freedesktop.secrets`) in preference to the KDE-specific API, with KWallet kept as
  a fallback. Speaking only `org.kde.kwalletd6` made the keyring a KDE feature: on GNOME,
  XFCE, Sway or anything else, angou reported no keyring and fell back to asking for the
  recovery passphrase on every command — not because the machine had no secret store, but
  because angou could not talk to the one it had. Since a store is meant to work on every
  machine you carry it to, that made the portability of your files contingent on your
  desktop environment.

The Secret Service is implemented by gnome-keyring, by KDE through `ksecretd`, and by
KeePassXC among others. It is also binary-safe by construction, which the older API was
not: a secret's value is a byte array rather than a string, and the unlock passphrase is
32 bytes of random data that is not valid text.

`ANGOU_KEYRING=kwallet` pins the older API; `secretservice` pins the new one. A name that
is neither is refused at start-up, before the command does anything, rather than quietly
becoming "this machine has no keyring".

- Both backends are exercised by the same test, so neither is verified only by inference
  from the other.

### 0.1.1

Fixes for the first-run experience, all of them found by using the tool rather than by
testing it. Each was a case where the program worked and the path through it did not.

- `angou init` now sets up the machine it runs on. It previously created a store and left
  that machine unable to open it without the recovery passphrase, so every command asked
  for one — contradicting this document, which says you type that passphrase when setting
  up a machine "and almost never otherwise". Requiring a separate `angou bootstrap`
  afterwards asked for the same passphrase that had just been used, to perform a step with
  no separate decision in it. `--no-bootstrap` opts out.
- `angou enc ~/.secrets.env` worked. The shell expands the tilde before angou sees it, and
  absolute paths were refused, so the most natural invocation there is did not work.
  Absolute paths now map into the store's namespace, keeping their structure so two files
  of the same name from different projects still do not collide.
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
  refuses before generating a key or writing anything — but the ordering was alarming for
  no reason.
- `install.sh` no longer tells you to run `angou init` after it has just set up the store
  you already had. Its closing advice now depends on what it actually did.
- A keyring that holds its D-Bus name without answering no longer hangs every command. The
  call that asks which wallet to use is bounded at five seconds — it reports a name and
  prompts for nothing, so it has no business being slow — and a broken keyring degrades to
  the recovery-passphrase path with an accurate reason. Opening a wallet stays unbounded,
  because that can legitimately wait for a person to answer a dialog.
- Decrypting on a machine other than the one that encrypted is the point of the store, and
  now has tests: a second machine with its own home, its own store path, no local key and
  no keyring reads what the first one wrote, and writes back.

### 0.1.0

The command line is complete: all seventeen subcommands of spec 001 are implemented, and
every acceptance criterion in that spec is met. The desktop browser is not started.

- **The format.** A text container whose plaintext header carries only the format and the
  payload encoding — no filename, no plaintext hash, no key fingerprint. Metadata travels
  in an envelope inside the encrypted payload. Payloads are signed as well as encrypted,
  and the signature is verified before any plaintext is returned. Stock `gpg` can decrypt
  a blob body without angou, which is a recovery guarantee rather than an interoperability
  nicety, and a test proves it against the real `gpg`.
- **The store.** Blob names are keyed hashes of the logical path, so a directory listing
  gives up no filenames even to a dictionary attack. A blob whose name does not match its
  own envelope is refused, which is what stops one secret being served under another's
  name. The index is a rebuildable cache and never the truth.
- **Keys.** The key bundle is held under Argon2id at m=64 MiB, t=24, p=4 — RFC 9106's
  configuration for memory-constrained environments, with the pass count raised. The
  memory figure is chosen so a store opens on every machine it syncs to, including small
  containers, rather than for maximum per-guess cost; the passphrase entropy floor is what
  makes an exhaustive search infeasible. A bundle recording weaker parameters is refused,
  and the memory required is checked before it is spent.
- **Machines.** `bootstrap` wraps the key under a 32-byte machine password held in
  KWallet, after which commands open the store in milliseconds. The "key present, wallet
  entry gone" state is explained rather than met with an unanswerable prompt.
- **Rotation.** `passwd` changes what guards the key; `rekey --local` changes the machine
  password; `rekey --identity` changes the keypair *and* the naming key, re-encrypting and
  renaming everything. Rotation is staged and verified before anything live is touched,
  and an interrupted one leaves the previous store intact.
- **Bootstrap.** A store can carry signed binaries and a plaintext installer that verifies
  one against a fingerprint written into the script rather than read from the store — so
  an attacker who re-signs a binary and swaps the public key is still refused.
- **The agent.** A session cache with a short lifetime, documented as excluding other
  users and explicitly not as a boundary against anything running as you.
- **Testing.** 69 end-to-end tests that build the binary and drive it as a subprocess
  against throwaway stores, at the parameters users actually get, with a per-run
  passphrase and a redirected `HOME` the suite refuses to run without.

## License

MIT. See [LICENSE](LICENSE).