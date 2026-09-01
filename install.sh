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

DRY_RUN=0
WITH_GUI=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --with-gui) WITH_GUI=1 ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--with-gui]"
            echo
            echo "  --dry-run    Show what would be installed, change nothing"
            echo "  --with-gui   Also build and install angou-gui (needs CGO)"
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

echo "Building the CLI ..."
run make -C "$REPO_DIR" build-static

echo "Installing the CLI to ${BIN_DIR} ..."
run install -Dm755 "${REPO_DIR}/angou" "${BIN_DIR}/angou"

if [ "$WITH_GUI" -eq 1 ]; then
    echo "Building the desktop browser ..."
    run make -C "$REPO_DIR" build-gui
    run install -Dm755 "${REPO_DIR}/angou-gui" "${BIN_DIR}/angou-gui"
    run install -Dm644 "${REPO_DIR}/packaging/angou.desktop" "${APP_DIR}/angou.desktop"
    run install -Dm644 "${REPO_DIR}/packaging/angou.svg" "${ICON_DIR}/angou.svg"
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

echo
echo "Done."
case ":${PATH}:" in
    *":${BIN_DIR}:"*) ;;
    *) echo "Note: ${BIN_DIR} is not on your PATH." ;;
esac
echo "Next, two steps:"
echo
echo "  1. angou init ~/Dropbox/angou      # make a store; writes down a passphrase"
echo "  2. angou bootstrap --store ~/Dropbox/angou"
echo
echo "The second one is not optional in practice. Without it every command asks for"
echo "the recovery passphrase and spends a fifth of a second on it; with it, this"
echo "machine opens the store from your keyring in about five milliseconds. Nothing"
echo "here can do it for you: it needs a store to exist and a passphrase typed in."
