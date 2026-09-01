# Compromise recovery

What to do when a machine, your sync account, or your recovery passphrase has been
exposed. Required by spec 001 R4.4.

Read [The one thing this cannot fix](#the-one-thing-this-cannot-fix) first. It is the
part people skip and the part that matters most.

## Table of Contents

- [The one thing this cannot fix](#the-one-thing-this-cannot-fix)
- [Work out what was exposed](#work-out-what-was-exposed)
- [Order of operations](#order-of-operations)
- [1. Cut off access](#1-cut-off-access)
- [2. Rotate the secrets themselves](#2-rotate-the-secrets-themselves)
- [3. Rotate angou](#3-rotate-angou)
- [4. Deal with sync history](#4-deal-with-sync-history)
- [5. Re-establish your other machines](#5-re-establish-your-other-machines)
- [6. Verify](#6-verify)
- [Scenarios](#scenarios)
- [What each command actually does](#what-each-command-actually-does)

## The one thing this cannot fix

**Rotating `angou` does not un-disclose your secrets.**

If someone got into your store, they have the contents. Every AWS key, SSH key,
database password and API token that was in there is disclosed, permanently, and no
amount of rekeying changes that. `angou rekey --identity` protects the store *going
forward*. It does nothing about the copy the attacker already made.

So the real work of a compromise is not in this tool. It is going to each service and
rotating the actual credential: issuing a new AWS key and deleting the old one,
removing the old public key from `~/.ssh/authorized_keys` on every host, changing the
database password, revoking the token. `angou` rotation is step 3 of that job, not a
substitute for it.

Treat every secret that was in the store as burned unless you have positive evidence
the attacker never had the means to read it.

## Work out what was exposed

Answer these before doing anything, because they determine how much of the runbook
applies.

| Question | If yes |
| :--- | :--- |
| Did they have the store contents (sync account, or a machine with a copy)? | The **ciphertext** is out. Whether they can read it depends on the next two answers. |
| Did they have the recovery passphrase — typed on that machine, in a password manager they reached, written down nearby? | Assume **everything** is readable. Full recovery. |
| Was a bootstrapped machine taken while running or suspended, or was its disk unencrypted with a weak login password? | Assume the **keypair** is readable, so all blobs are. Full recovery. |
| Was the machine off, with an encrypted disk and a strong login password? | The keypair is behind your login password. Rotate anyway, but you have time. |
| Did they have write access to the store? | They could also have **rolled back or deleted** blobs (R-9). Check for missing or reverted secrets. |

A machine that was merely *lost* — dropped in a taxi, not targeted — is usually the
last row. A machine that was *stolen for its contents*, or one that ran malware, is the
third.

## Order of operations

The order is deliberate. Cutting off access first stops the attacker following along as
you rotate; rotating the underlying secrets before the store means the new values are
never written under the old key.

```
1. Cut off access            revoke sync sessions, unlink devices, kill agents
2. Rotate the secrets        the actual AWS keys, SSH keys, passwords
3. Rotate angou              recovery passphrase, K_name, identity keypair
4. Deal with sync history    the old ciphertext is still there
5. Re-establish machines     bootstrap the ones you still trust
6. Verify                    confirm the old key opens nothing
```

## 1. Cut off access

Do this before anything else, from a machine you trust.

- **Unlink the lost device** in your sync service and **revoke all sessions**. In
  Dropbox this is Settings → Security → Devices, plus "Sign out of all sessions". A
  device that is merely unlinked but still signed in may keep syncing.
- **Change the sync account password** and check its second factor is still yours.
- **Stop agents everywhere else**: `angou agent stop` on each remaining machine. An
  agent holds unlocked key material and `K_name` for its TTL.
- If the store lives on a machine you still control, **take a copy now**, before any
  rotation, in case you need to compare against what the attacker may have altered.

## 2. Rotate the secrets themselves

The part `angou` cannot do for you. Work from a listing of the store:

```bash
angou ls --long
```

For each entry, rotate the credential at its source and confirm the old one no longer
works. SSH keys are the ones most often missed — generating a new keypair is not enough;
the old public key has to come out of `authorized_keys` on every host that has it.

Put the new values into the store as you go. They will be re-encrypted again in step 3,
which is harmless.

## 3. Rotate angou

**If the recovery passphrase was exposed, rotate it first.** Everything else is
pointless while the attacker can open the key bundle:

```bash
angou passwd
```

This generates or accepts a new recovery passphrase and rewrites the key bundle under
it. Old bundles are pruned; see step 4 for why that is not sufficient on its own.

Then rotate the identity:

```bash
angou rekey --identity
```

This generates a new keypair, re-encrypts every blob to it, **and rotates `K_name`**,
which renames every blob (R4.2.1). The renaming matters: without it an attacker who
kept the old `K_name` can carry on watching which of your files change and when, even
though they can no longer read any of them.

It is transactional (R4.3) — it stages and commits by rename, so an interruption leaves
the previous store intact. On a large store it will take a while and will make the sync
service re-upload everything.

## 4. Deal with sync history

**Rotation does not remove the old ciphertext from your sync service.** Dropbox and its
equivalents keep deleted and superseded file versions for 30 days or more. An attacker
who holds the old keypair, and who still has account access, can retrieve the old blobs
from that history and read them.

This is why step 1 comes first. Once access is cut, the history is only a risk if they
regain it.

If the exposure was serious enough to warrant it:

- Purge deleted files and version history in the sync service, if it offers that.
- Or move to a fresh store location — `angou clone` to a new directory, and delete the
  old one — so that the history attaches to a path the attacker's copy does not cover.

Prune stale bootstrap material either way:

```bash
angou prune --bootstrap --keep 1
```

## 5. Re-establish your other machines

The rotation invalidates every existing machine, because they all hold the old key.
On each machine you still trust:

```bash
angou bootstrap --force
```

This re-imports the new key bundle under the new recovery passphrase and generates a
fresh unlock passphrase for that machine.

Do **not** do this on a machine you suspect. Rebuild it first.

## 6. Verify

```bash
angou verify-bootstrap          # the plaintext installer is unaltered
angou ls                        # every entry is listed and decrypts
angou doctor --old-key <fpr>    # the old key opens nothing in the store
```

Confirm as well that no blob filename in the rotated store matches one from before —
that is the observable signal that `K_name` actually rotated:

```bash
comm -12 <(sort old-listing.txt) <(ls store/ | sort)   # expect no output
```

## Scenarios

### Laptop stolen, disk encrypted, powered off

Least urgent. The keypair is behind full-disk encryption and your login password. Cut
off sync access (step 1), then rotate `angou` (step 3) at your convenience. Rotating the
underlying secrets is optional if you are confident the disk held; do it anyway if any
of them are high value.

### Machine ran malware while unlocked

Worst case, and easy to underestimate. During the agent TTL, anything running as you
could ask the agent to decrypt anything (R-10). Assume **everything** in the store is
disclosed. Full runbook, starting from step 2, and rebuild the machine before step 5.

### Recovery passphrase exposed

If it was typed on a compromised machine, or lived in a password manager that was
breached, then the key bundle is readable by anyone who also has the store. Full
runbook. Step 3's `angou passwd` comes first and is urgent.

### Sync account compromised, machines fine

They have ciphertext but no key, so contents are probably safe — the exception is the
key bundle, whose only protection is your recovery passphrase and the Argon2id work
factor (R2.2.1). If that passphrase is weak or old, treat it as exposed.

They may also have **written** to the store: check for reverted or missing secrets
(R-9). Cut access, rotate the sync password, then rekey.

### Store deleted or ransomwared

Not a disclosure event, an availability one. Restore from the sync service's version
history or from any bootstrapped machine's local copy. Nothing needs rotating unless
the deletion came with access you have not accounted for.

## What each command actually does

Useful when deciding how far to go.

| Command | Fixes | Does not fix |
| :--- | :--- | :--- |
| `angou rekey --local` | This machine's unlock passphrase | Anything an attacker already has. Not a compromise response. |
| `angou passwd` | Future access via the key bundle | Copies of the old bundle already taken |
| `angou rekey --identity` | Future readability of every blob, plus filename tracking | Contents already copied. Old ciphertext in sync history. |
| `angou prune --bootstrap` | Old binaries and bundles in the store | The sync service's own retained history |
| Sync session revocation | Ongoing access, and access to history | Anything already downloaded |
| Rotating the credentials themselves | **The actual exposure** | Nothing. This is the one that counts. |
