#!/usr/bin/env bash
#
# Removes everything install.sh puts in place. Leaves your store and your keys
# alone — those are removed by hand, on purpose. Idempotent.

set -euo pipefail

BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
MIME_DIR="${HOME}/.local/share/mime/packages"
ICON_DIR="${HOME}/.local/share/icons/hicolor/scalable/apps"
STATE_DIR="${HOME}/.local/share/angou"

echo "Removing angou ..."

for f in "${BIN_DIR}/angou" "${BIN_DIR}/angou-gui" \
         "${APP_DIR}/angou.desktop" "${APP_DIR}/io.ushineko.angou.desktop" "${MIME_DIR}/angou.xml" \
         "${ICON_DIR}/angou.svg"; do
    if [ -e "$f" ]; then
        echo "  removing $f"
        rm -f "$f"
    fi
done

if [ -f "${HOME}/.magic" ] && grep -q "ANGOU1" "${HOME}/.magic"; then
    echo "  removing the magic entry from ${HOME}/.magic"
    sed -i '/ANGOU1/,+1d' "${HOME}/.magic"
fi

command -v update-mime-database >/dev/null 2>&1 && \
    update-mime-database "${HOME}/.local/share/mime" || true
command -v update-desktop-database >/dev/null 2>&1 && \
    update-desktop-database "${APP_DIR}" || true

# The GUI's appearance preferences are written by the application, not by the
# installer, so they are not removed here. They hold nothing but a color scheme,
# a font name, and a text size — no store path, no fingerprint, no secret.
FYNE_PREFS="${HOME}/.config/fyne/io.ushineko.angou"
if [ -d "$FYNE_PREFS" ]; then
    echo
    echo "The GUI's saved appearance settings are still in:"
    echo
    echo "    ${FYNE_PREFS}"
    echo
    echo "They hold a color scheme, a font, and a text size, and nothing else."
    echo "To remove them:  rm -rf ${FYNE_PREFS}"
fi

echo
echo "Done."
if [ -d "$STATE_DIR" ]; then
    echo
    echo "Your keys are still in ${STATE_DIR} and your store is untouched."
    echo "Neither is removed automatically. To remove this machine's keys:"
    echo
    echo "    rm -rf ${STATE_DIR}"
    echo
    echo "Your store still opens with your recovery password, so this is"
    echo "reversible by running bootstrap again."
fi
