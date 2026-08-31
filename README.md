# angou

`angou` (暗号 — cipher, encryption) converts sensitive files to and from encrypted
blobs using OpenPGP, and keeps them in a portable store that can be synced through
Dropbox, `rsync`, or removable media.

**Status**: design complete, implementation not started. See
[`specs/001-angou-format-keying-and-store.md`](specs/001-angou-format-keying-and-store.md).

---

## What it is for

Small, high-value files: `.secrets.env`, SSH private keys, and text files holding
passwords or other sensitive data.

## Design summary

- **Container** — a text container with an armored (base64) OpenPGP payload by
  default, `--binary` for large inputs. The plaintext header carries only the format
  magic, version, payload encoding, and recipient fingerprint. The original filename
  and all other metadata live *inside* the encrypted payload, so a directory listing
  leaks nothing about what a blob holds.
- **Recoverable without this tool** — payloads are standard OpenPGP messages, so
  `gpg --decrypt` retrieves the content if `angou` is ever unavailable.
- **Two passphrases** — one memorized recovery passphrase guards the exported key
  bundle. The per-machine unlock passphrase is randomly generated, never displayed,
  and held only in the platform keyring, which makes the local key disposable state
  that is re-derived by bootstrapping again.
- **Store** — a plain directory of opaque blobs named by
  `HMAC-SHA256(K_name, path)`, so names are stable enough to update in place but not
  guessable by dictionary attack. An encrypted index makes listing cheap and is a
  rebuildable cache, never authoritative.
- **Bootstrap anywhere** — the store carries signed, encrypted binaries for each
  supported platform alongside a plaintext `bootstrap.sh` entrypoint, so an
  unconfigured machine reaches a working install from the store and the recovery
  passphrase alone.

## Building

```
make help          # list targets
make build-static  # the CGO-free CLI; this is the bootstrap artifact
make lint          # pinned golangci-lint, checksum-verified on install
make test          # go test -race
```

## Security

No key material, passphrase, or store content belongs in this repository. All state
lives in `~/.local/share/angou/` and the user-designated store directory.

## License

MIT. See [LICENSE](LICENSE).
