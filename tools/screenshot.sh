#!/usr/bin/env bash
# Capture angou-gui for the README, on KDE/Wayland.
#
# Unlike a hand-driven capture, this one drives the window itself: angou-gui takes
# --section and --scheme, so the script starts a fresh window on the section it wants,
# grabs it, and kills it. Refreshing the whole set is one command with nothing to click,
# which is the difference between screenshots that track the interface and screenshots
# that quietly go stale.
#
# Two things still make this less trivial than "take a screenshot":
#
#   1. The active window is almost never the one we want. Refreshing these usually means
#      an agent or a terminal driving the capture, so whatever has focus is the terminal.
#      The window is therefore raised first, and found by window *class* -- searching by
#      name also matches a browser sitting on the project's GitHub page, which is not a
#      hypothetical: it happened the first time this was run.
#   2. When a dialog is open the dialog *is* the active window, so an active-window grab
#      returns the dialog alone on a transparent background. For those shots pass
#      --with-dialog: it captures the whole desktop and crops to the window's geometry,
#      keeping the dialog where it actually sits.
#
# Requires kdotool (Wayland's xdotool), spectacle, and python3 with Pillow, all present
# on a normal KDE desktop except Pillow.
set -euo pipefail

CLASS="io.ushineko.angou"
# Everything the captures show comes from a store this script builds and throws
# away. It must never photograph the developer's own: these images go into a
# public README, and a store's listing is a list of where that person keeps
# their credentials. HOME and the XDG directories are redirected too, so the
# window cannot reach a remembered store either.
DEMO=""
BIN="${ANGOU_GUI:-$(command -v angou-gui || echo ./angou-gui)}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    cat <<'USAGE'
usage: tools/screenshot.sh [--with-dialog] [--scheme NAME] --section NAME <output.png>
       tools/screenshot.sh --all

  --section NAME  which section to open on (Store, Encrypt, Doctor, Machine, ...)
  --scheme NAME   colour scheme for this run; not saved over the user's choice
  --with-dialog   a dialog is open: capture the desktop and crop, rather than grabbing
                  the active window (which would be the dialog on its own)
  --all           refresh the whole README set into assets/, then print the alt-text
                  checklist

The README set is four images. Appearance and About are left out deliberately: one is a
form of three dropdowns and the other is prose, and neither shows a reader anything the
text does not already say.

  assets/screenshot-store.png       the listing, with row actions
  assets/screenshot-encrypt.png     the scan, with reasons and per-file selection
  assets/screenshot-doctor.png      the ranked report
  assets/screenshot-machine.png     unlock routes, the session cache, and the
                                    irreversible operations

The alt text in README.md describes what is actually in each image. It is the only
description a screen-reader user gets, and a stale one is worse than none -- check it
still matches before committing a new capture.
USAGE
}

with_dialog=0
section=""
scheme=""
out=""
all=0
while [ $# -gt 0 ]; do
    case "$1" in
        --with-dialog) with_dialog=1 ;;
        --section) shift; section="${1:-}" ;;
        --scheme) shift; scheme="${1:-}" ;;
        --all) all=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) out="$1" ;;
    esac
    shift
done

for tool in kdotool spectacle python3; do
    command -v "$tool" >/dev/null || { echo "$tool is not installed" >&2; exit 1; }
done
python3 -c "import PIL" 2>/dev/null || { echo "python3 Pillow is not installed" >&2; exit 1; }
[ -x "$BIN" ] || { echo "angou-gui not found (set ANGOU_GUI, or run make build-gui)" >&2; exit 1; }

# capture starts a window on the requested section, grabs it, and stops it again.
# Starting fresh per shot rather than reusing one window keeps each image independent
# of whatever the previous one left selected.
capture() {
    local sect="$1" dest="$2" scan="${3:-}"

    # Wait for any previous instance to be gone before starting the next. Two windows of
    # the same class at once means `search --class | head -1` can return the one that is
    # on its way out, and every check downstream then refers to the wrong window.
    local gone=0
    while [ "$gone" -lt 40 ]; do
        [ -z "$(timeout 10 kdotool search --class "$CLASS" 2>/dev/null || true)" ] && break
        sleep 0.25
        gone=$((gone + 1))
    done

    # HOME and the XDG config/data directories are redirected so the window
    # cannot reach a remembered store. XDG_RUNTIME_DIR is deliberately NOT:
    # that is where the Wayland display socket lives, and pointing it at a
    # temporary directory leaves the window unable to reach the compositor at
    # all, which looks exactly like the window failing to start.
    ANGOU_STORE="$DEMO/store" HOME="$DEMO/home" \
        XDG_CONFIG_HOME="$DEMO/home/.config" XDG_DATA_HOME="$DEMO/home/.local/share" \
        "$BIN" --section "$sect" ${scheme:+--scheme "$scheme"} \
        ${scan:+--scan "$scan"} >/dev/null 2>&1 &
    local pid=$!
    # shellcheck disable=SC2064  # pid is captured deliberately, at trap-set time
    trap "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true" RETURN

    # Poll rather than sleeping a fixed time: a cold start after a rebuild is much
    # slower than a warm one, and a fixed wait is either flaky or wasteful.
    local wid="" waited=0
    while [ "$waited" -lt 40 ]; do
        wid=$(timeout 10 kdotool search --class "$CLASS" 2>/dev/null | head -1 || true)
        [ -n "$wid" ] && break
        sleep 0.25
        waited=$((waited + 1))
    done
    [ -n "$wid" ] || { echo "the window never appeared (no window of class $CLASS)" >&2; return 1; }

    # Activating is asynchronous, and `spectacle -a` grabs whatever is active at the
    # moment it fires. If the raise has not landed yet it silently captures the
    # terminal, or another monitor's window, and writes a plausible-looking PNG of the
    # wrong thing -- which is how the first run of this script produced a 2160x3840
    # image of a portrait monitor. So: activate, then confirm we actually have focus
    # before grabbing, and only then trust the shot.
    local active="" tries=0
    while [ "$tries" -lt 12 ]; do
        timeout 10 kdotool windowactivate "$wid" >/dev/null 2>&1 || true
        sleep 0.5
        active=$(timeout 10 kdotool getactivewindow 2>/dev/null || true)
        [ "$active" = "$wid" ] && break
        tries=$((tries + 1))
    done
    [ "$active" = "$wid" ] || { echo "could not focus the window (active=$active want=$wid)" >&2; return 1; }
    sleep 1.0                   # let it repaint after the raise

    rm -f "$dest"
    if [ "$with_dialog" -eq 0 ]; then
        # -S drops the compositor's drop shadow, which otherwise pads the image unevenly
        timeout 30 spectacle -a -b -n -S -o "$dest" >/dev/null 2>&1 || true
        sleep 1.5
    else
        local tmp; tmp=$(mktemp --suffix=.png)
        timeout 30 spectacle -f -b -n -o "$tmp" >/dev/null 2>&1 || true
        sleep 1.5
        local geo; geo=$(timeout 10 kdotool getwindowgeometry "$wid")
        python3 "${REPO_DIR}/tools/crop.py" "$tmp" "$dest" \
            "$(printf '%s' "$geo" | awk '/Position/{print $2}')" \
            "$(printf '%s' "$geo" | awk '/Geometry/{print $2}')"
        rm -f "$tmp"
    fi

    [ -s "$dest" ] || { echo "capture produced nothing" >&2; return 1; }

    # A last sanity check on the geometry. Even with the focus check above, a grab can
    # land on the wrong surface; an image wildly wider or taller than the window we
    # asked for is not a screenshot of it, and shipping it to the README unnoticed is
    # worse than failing here.
    local geo_check; geo_check=$(timeout 10 kdotool getwindowgeometry "$wid" 2>/dev/null || true)
    python3 - "$dest" "$(printf '%s' "$geo_check" | awk '/Geometry/{print $2}')" <<'PY'
import sys
from PIL import Image

path, dim = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
im = Image.open(path)
if dim and "x" in dim:
    w, h = (float(v) for v in dim.split("x"))
    # Allow for output scaling (the capture is in device pixels) but reject an
    # aspect ratio that is not the window's.
    want, got = w / h, im.width / im.height
    if abs(want - got) / want > 0.05:
        sys.exit("captured %dx%d, but the window is %gx%g -- wrong window grabbed"
                 % (im.width, im.height, w, h))
PY
    python3 - "$dest" <<'PY'
import os, sys
from PIL import Image
p = sys.argv[1]
im = Image.open(p)
print("  %s  %dx%d  %.0fK" % (os.path.basename(p), im.width, im.height,
                              os.path.getsize(p) / 1024))
PY
}

# demo builds the store the captures are taken against, seeds it with obviously
# invented content, and opens it with an agent.
#
# An agent rather than bootstrap: bootstrapping writes an entry into the
# developer's real wallet, which the project's testing rules forbid, and without
# some unlocked route the window would sit on a passphrase dialog. The agent's
# socket lives in the throwaway runtime directory and dies with the store.
demo() {
    DEMO=$(mktemp -d)
    mkdir -p "$DEMO/home/.config" "$DEMO/home/.local/share" "$DEMO/run" "$DEMO/scan/.ssh" \
        "$DEMO/scan/.aws" "$DEMO/scan/projects/api"

    # Per-run, from a CSPRNG. No credential-shaped constant is committed, not
    # even for a screenshot.
    head -c 32 /dev/urandom | base64 | tr -d '\n' > "$DEMO/pw"

    local ang; ang=$(dirname "$BIN")/angou
    [ -x "$ang" ] || ang="$REPO_DIR/angou"
    [ -x "$ang" ] || { echo "the CLI is not built (make build-static)" >&2; exit 1; }

    # The agent's socket name is derived from the store path, so a throwaway
    # store gets its own socket in the real runtime directory and cannot
    # collide with one the developer is using.
    run_angou() { HOME="$DEMO/home" \
        sh -c 'exec 9<"$1"; shift; exec "$@" --passphrase-fd 9' _ "$DEMO/pw" "$ang" "$@"; }

    run_angou init --no-bootstrap --store "$DEMO/store" >/dev/null 2>&1

    # Content that is plainly invented: nothing here is a key, and the bodies say so.
    printf 'this is not a private key, it is screenshot filler\n' > "$DEMO/home/id_ed25519"
    printf 'not credentials either\n' > "$DEMO/home/credentials"
    printf 'PLACEHOLDER=not-a-real-value\n' > "$DEMO/home/prod.env"
    printf 'nothing secret in here\n' > "$DEMO/home/work.ovpn"
    for f in id_ed25519 credentials prod.env work.ovpn; do
        run_angou enc "$DEMO/home/$f" --as "demo/$f" --store "$DEMO/store" >/dev/null 2>&1
    done

    # A tree for the Encrypt section to find something in.
    printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key\n' > "$DEMO/scan/.ssh/id_rsa"
    printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key\n' > "$DEMO/scan/.ssh/id_ecdsa"
    printf 'aws_access_key_id = PLACEHOLDER\n' > "$DEMO/scan/.aws/credentials"
    printf 'API_TOKEN=placeholder\n' > "$DEMO/scan/projects/api/.env"
    printf 'API_TOKEN=your-token-here\n' > "$DEMO/scan/projects/api/.env.example"
    printf 'machine example.com login placeholder\n' > "$DEMO/scan/.netrc"

    HOME="$DEMO/home" \
        sh -c 'exec 9<"$1"; shift; exec "$@" --passphrase-fd 9' _ "$DEMO/pw" \
        "$ang" agent start --ttl 10m --store "$DEMO/store" >/dev/null 2>&1 &
    sleep 2
}

demo_cleanup() {
    [ -n "$DEMO" ] || return 0
    HOME="$DEMO/home" "$REPO_DIR/angou" agent stop --store "$DEMO/store" >/dev/null 2>&1 || true
    rm -rf "$DEMO"
}

if [ "$all" -eq 1 ]; then
    # Force a scheme unless one was asked for. Without this the set inherits
    # whatever the person running it last picked in Appearance, so two refreshes
    # on two machines produce differently-coloured images for no reason.
    : "${scheme:=Breeze Dark}"
    mkdir -p "${REPO_DIR}/assets"
    demo
    trap demo_cleanup EXIT
    for s in Store Encrypt Doctor Machine; do
        low=$(printf '%s' "$s" | tr '[:upper:]' '[:lower:]')
        if [ "$s" = "Encrypt" ]; then
            capture "$s" "${REPO_DIR}/assets/screenshot-${low}.png" "$DEMO/scan"
        else
            capture "$s" "${REPO_DIR}/assets/screenshot-${low}.png"
        fi
    done
    echo
    echo "Now check the alt text in README.md still describes what is in each image."
    exit 0
fi

[ -n "$out" ] || { usage >&2; exit 2; }
[ -n "$section" ] || { echo "--section is required (or use --all)" >&2; exit 2; }
demo
trap demo_cleanup EXIT
capture "$section" "$out" "$DEMO/scan"
