#!/usr/bin/env bash
#
# Installs the angou CLI, the desktop browser, and the file-type rules that let
# the desktop recognize a .angou blob. Idempotent: safe to re-run.

set -euo pipefail

BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
MIME_DIR="${HOME}/.local/share/mime/packages"
ICON_DIR="${HOME}/.local/share/icons/hicolor/scalable/apps"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SIGNING_KEY="${HOME}/.config/angou/release-signing.asc"

DRY_RUN=0
WITH_GUI=1
PUBLISH_TO=""
SET_UP_EXISTING=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --with-gui) WITH_GUI=1 ;;
        --no-gui) WITH_GUI=0 ;;
        --publish-to=*) PUBLISH_TO="${arg#--publish-to=}" ;;
        -h|--help)
            cat <<'USAGE'
Usage: install.sh [--dry-run] [--no-gui] [--publish-to=STORE]

  --dry-run             Show what would be installed, change nothing
  --no-gui              Install the CLI only, skipping angou-gui

The desktop GUI is installed by default, along with its desktop entry and icon.
It needs CGO and a C toolchain; if it will not build, the CLI is still installed
and the GUI is skipped with a note. The CLI itself is static and needs neither.
  --publish-to=STORE    Also put signed binaries and the installer into STORE,
                        so a machine with no angou can install it from there

--publish-to is not the default, and the reason is worth reading before you use
it. Putting binaries in the store means signing them, and the signing key decides
which binaries every future bootstrap will accept as genuine. Left on this
machine, it is one compromise away from letting someone plant a binary that your
other machines install and run. It is written to:

    ~/.config/angou/release-signing.asc

and you should move it to offline storage once this finishes. You do not need it
again until you publish a new version.

If you can install angou on your other machines the ordinary way, you do not need
any of this and the store does not need to carry binaries at all.
USAGE
            exit 0
            ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "  would run: $*"
    else
        "$@"
    fi
}

echo "Installing angou from ${REPO_DIR} ..."

if ! command -v go >/dev/null 2>&1; then
    echo "Error: go is not installed. Install Go 1.25+, or bootstrap from a store" >&2
    echo "       instead: see the Installation section of README.md." >&2
    exit 1
fi

# Publishing ends in `angou release`, which asks for the store's recovery
# passphrase on the terminal. Check for one now rather than after several minutes
# of cross-compiling.
if [ -n "$PUBLISH_TO" ] && [ ! -t 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    echo "Error: --publish-to needs an interactive terminal: putting binaries in the" >&2
    echo "       store means opening it, and that asks for your recovery passphrase." >&2
    exit 1
fi

# The release-signing fingerprint has to be compiled into the binary, so it must
# be known before anything is built (spec 001 R5.4.1). A build without one refuses
# to install from a store rather than trusting any signature it can verify, which
# is the correct default for a machine that has no release-signing key.
#
# A machine that *has* one is a different case, and it is the one this used to get
# wrong: the fingerprint was read only when publishing, so an ordinary install on
# the machine that signs the releases built a binary that could never install from
# its own store. The key beside it is the statement of which signatures to trust,
# whether or not this run is publishing anything.
RELEASE_KEY=""
if [ -n "$PUBLISH_TO" ] && [ ! -f "$SIGNING_KEY" ]; then
    echo "Creating a release-signing key at ${SIGNING_KEY} ..."
    run mkdir -p "$(dirname "$SIGNING_KEY")"
    run make -C "$REPO_DIR" build-static
    run "${REPO_DIR}/angou" release --new-signing-key "$SIGNING_KEY"
fi
# Read in a dry run too. It is a read-only gpg call, and without it a dry run
# reports an empty RELEASE_KEY on the one machine where a real run would set it,
# which is exactly backwards for a flag whose job is to show what would happen.
if [ -f "$SIGNING_KEY" ]; then
    # Reuse rather than rotate: binaries already installed elsewhere pin this
    # fingerprint, and a new key would make them refuse the store.
    RELEASE_KEY="$(gpg --show-keys --with-colons "$SIGNING_KEY" 2>/dev/null |
        awk -F: '/^fpr:/{print $10; exit}')"
    if [ -z "$RELEASE_KEY" ]; then
        if [ -n "$PUBLISH_TO" ]; then
            echo "Error: could not read a fingerprint from ${SIGNING_KEY}" >&2
            exit 1
        fi
        # Not publishing, so this is not fatal: the build simply falls back to
        # trusting no store binaries, which is what a machine with no key does.
        echo "Warning: could not read a fingerprint from ${SIGNING_KEY}; building" >&2
        echo "         without one, so this install will not accept a binary from" >&2
        echo "         a store." >&2
    else
        echo "Release-signing key: ${RELEASE_KEY}"
    fi
fi

echo "Building the CLI ..."
run make -C "$REPO_DIR" build-static RELEASE_KEY="$RELEASE_KEY"

echo "Installing the CLI to ${BIN_DIR} ..."
run install -Dm755 "${REPO_DIR}/angou" "${BIN_DIR}/angou"

# The GUI is installed by default, but a failure to build it must not take the
# CLI installation down with it. The CLI is the artifact everything else depends
# on — bootstrap, recovery on a bare machine — and a missing C toolchain is a
# reason to skip the GUI, not a reason to leave the machine without angou.
if [ "$WITH_GUI" -eq 1 ]; then
    echo "Building the desktop GUI ..."
    # RELEASE_KEY belongs here as much as on the CLI build: the GUI installs
    # binaries from a store too, and a GUI built without it refuses every one of
    # them while the CLI beside it accepts them.
    if [ "$DRY_RUN" -eq 1 ] || make -C "$REPO_DIR" build-gui RELEASE_KEY="$RELEASE_KEY"; then
        run install -Dm755 "${REPO_DIR}/angou-gui" "${BIN_DIR}/angou-gui"
        run install -Dm644 "${REPO_DIR}/packaging/io.ushineko.angou.desktop" "${APP_DIR}/io.ushineko.angou.desktop"
        run install -Dm644 "${REPO_DIR}/packaging/angou.svg" "${ICON_DIR}/angou.svg"
    else
        WITH_GUI=0
        echo
        echo "The GUI did not build, so it was skipped. The CLI is unaffected and does" >&2
        echo "everything the GUI does. Building it needs CGO and a C toolchain:" >&2
        echo "    Debian/Ubuntu: build-essential libgl1-mesa-dev xorg-dev" >&2
        echo "    Fedora:        gcc mesa-libGL-devel libXi-devel libXcursor-devel libXrandr-devel libXinerama-devel" >&2
        echo "    Arch:          base-devel libgl libxi libxcursor libxrandr libxinerama" >&2
        echo "Re-run with --no-gui to skip it without this message." >&2
        echo
    fi
fi

echo "Installing file-type rules ..."
run install -Dm644 "${REPO_DIR}/packaging/angou.xml" "${MIME_DIR}/angou.xml"
if command -v update-mime-database >/dev/null 2>&1; then
    run update-mime-database "${HOME}/.local/share/mime"
fi
if [ "$WITH_GUI" -eq 1 ] && command -v update-desktop-database >/dev/null 2>&1; then
    run update-desktop-database "${APP_DIR}"
fi

echo "Installing the file(1) magic entry ..."
if [ "$DRY_RUN" -eq 1 ]; then
    echo "  would append the angou magic entry to ${HOME}/.magic"
elif [ -f "${HOME}/.magic" ] && grep -q "ANGOU1" "${HOME}/.magic"; then
    echo "  already present, leaving ${HOME}/.magic alone"
else
    cat "${REPO_DIR}/packaging/magic" >> "${HOME}/.magic"
fi

# A store that exists but has not been set up on this machine asks for the
# recovery passphrase on every command. `angou init` does this for a store it
# creates, but a store made earlier, or synced here from elsewhere, has nobody to
# do it — and the user has no reason to know the step exists.
if [ "$DRY_RUN" -eq 0 ] && [ -n "${ANGOU_STORE:-}" ] && [ -f "${ANGOU_STORE}/store.angou" ]; then
    if "${BIN_DIR}/angou" doctor --store "$ANGOU_STORE" 2>/dev/null | grep -q "local key:.*absent"; then
        echo
        echo "The store at ${ANGOU_STORE} is not set up on this machine, so every command"
        echo "asks for your recovery passphrase. Setting it up puts a machine password in"
        echo "your keyring and stops the prompts."
        echo
        if [ -t 0 ]; then
            printf "Set it up now? You will be asked for the recovery passphrase once. [Y/n] "
            read -r reply
            case "$reply" in
                [Nn]*) echo "Skipped. Run: angou bootstrap --store ${ANGOU_STORE}" ;;
                *) if "${BIN_DIR}/angou" bootstrap --store "$ANGOU_STORE"; then
                    SET_UP_EXISTING=1
                else
                    echo "Setup did not complete. You can retry with:" >&2
                    echo "  angou bootstrap --store ${ANGOU_STORE}" >&2
                fi ;;
            esac
        else
            echo "Not asking, because this is not an interactive shell."
            echo "Run: angou bootstrap --store ${ANGOU_STORE}"
        fi
    fi
fi

# If a store is already there and carries no binaries, offer rather than require
# the user to have known about --publish-to. Asked, not assumed: it creates a
# signing key, and that is a decision rather than a detail.
if [ -z "$PUBLISH_TO" ] && [ "$DRY_RUN" -eq 0 ]; then
    CANDIDATE="${ANGOU_STORE:-}"
    if [ -n "$CANDIDATE" ] && [ -f "${CANDIDATE}/store.angou" ] &&
        ! ls "${CANDIDATE}/bootstrap"/angou-* >/dev/null 2>&1; then
        echo
        echo "The store at ${CANDIDATE} carries no angou binaries, so a machine that does not"
        echo "already have angou cannot install it from there. Adding them means creating a"
        echo "release-signing key, which you should then move offline: it decides which"
        echo "binaries every future bootstrap accepts."
        echo
        if [ -t 0 ]; then
            printf "Add them now? [y/N] "
            read -r reply
            case "$reply" in
                [Yy]*) PUBLISH_TO="$CANDIDATE" ;;
                *) echo "Skipped. Run install.sh --publish-to=${CANDIDATE} later if you change your mind." ;;
            esac
        else
            echo "Not asking, because this is not an interactive shell."
            echo "Run: install.sh --publish-to=${CANDIDATE}"
        fi
    fi
fi

# Publishing needs the fingerprint compiled in, and the binary was already built
# above. Rebuild with the key pinned when the answer came from the prompt.
if [ -n "$PUBLISH_TO" ] && [ -z "$RELEASE_KEY" ] && [ "$DRY_RUN" -eq 0 ]; then
    if [ ! -f "$SIGNING_KEY" ]; then
        echo "Creating a release-signing key at ${SIGNING_KEY} ..."
        mkdir -p "$(dirname "$SIGNING_KEY")"
        "${BIN_DIR}/angou" release --new-signing-key "$SIGNING_KEY"
    fi
    RELEASE_KEY="$(gpg --show-keys --with-colons "$SIGNING_KEY" 2>/dev/null |
        awk -F: '/^fpr:/{print $10; exit}')"
    if [ -z "$RELEASE_KEY" ]; then
        echo "Error: could not read a fingerprint from ${SIGNING_KEY}" >&2
        exit 1
    fi
    echo "Rebuilding the CLI with release key ${RELEASE_KEY} pinned ..."
    make -C "$REPO_DIR" build-static RELEASE_KEY="$RELEASE_KEY"
    install -Dm755 "${REPO_DIR}/angou" "${BIN_DIR}/angou"
fi

if [ -n "$PUBLISH_TO" ]; then
    echo "Building binaries for every supported platform ..."
    run make -C "$REPO_DIR" build-all RELEASE_KEY="$RELEASE_KEY"

    echo "Publishing them into ${PUBLISH_TO} ..."
    run "${BIN_DIR}/angou" release \
        --store "$PUBLISH_TO" --dist "${REPO_DIR}/dist" --signing-key "$SIGNING_KEY"
fi

echo
echo "Done."
case ":${PATH}:" in
    *":${BIN_DIR}:"*) ;;
    *) echo "Note: ${BIN_DIR} is not on your PATH." ;;
esac
if [ "$SET_UP_EXISTING" -eq 1 ]; then
    echo "This machine is set up for ${ANGOU_STORE}. Nothing else to do:"
    echo "commands will not ask for your recovery passphrase here."
    echo
    echo "  angou ls        # what is in the store"
    echo "  angou doctor    # what this machine can and cannot do"
elif [ -n "${ANGOU_STORE:-}" ] && [ -f "${ANGOU_STORE}/store.angou" ]; then
    echo "Your store at ${ANGOU_STORE} already exists. To set this machine up to"
    echo "open it without the recovery passphrase:"
    echo
    echo "  angou bootstrap --store ${ANGOU_STORE}"
else
    echo "Next:"
    echo
    echo "  angou init ~/Dropbox/angou"
    echo
    echo "That makes a store, shows you a recovery passphrase once, and sets this machine"
    echo "up so you are not asked for it again here. On any other machine, once the store"
    echo "has synced there, run: angou bootstrap --store ~/Dropbox/angou"
fi

if [ -n "$PUBLISH_TO" ]; then
    echo
    echo "The store now carries signed binaries, so a machine with no angou can install"
    echo "one from it by running bootstrap.sh in the store directory."
    echo
    echo "Move ${SIGNING_KEY} to offline storage and delete it from"
    echo "this machine. It decides which binaries every future bootstrap will accept."
fi
