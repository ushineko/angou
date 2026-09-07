#!/usr/bin/env bash
#
# Build a macOS .icns from an SVG. Each icon size is rendered straight from the
# vector by tools/svg2png (oksvg/rasterx, the stack fyne uses for the in-app
# icon), then iconutil assembles them. This needs only the Go toolchain the build
# already requires — no ImageMagick, no librsvg.
#
# It does NOT use qlmanage: that produces a Quick Look thumbnail, which drew the
# logo at roughly its native 64px in a 1024px canvas, so the app icon came out
# tiny. Rendering from the vector at each size fills the canvas and stays sharp
# down to 16px.

set -euo pipefail

SVG="${1:?usage: make-icns.sh <svg> <out.icns>}"
OUT="${2:?usage: make-icns.sh <svg> <out.icns>}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Build the rasteriser once, then run it per size.
go build -o "$tmp/svg2png" "${here}/tools/svg2png"

iconset="$tmp/angou.iconset"
mkdir -p "$iconset"

# The exact names and sizes iconutil expects, including the @2x doublings.
for pair in "16:icon_16x16" "32:icon_16x16@2x" "32:icon_32x32" "64:icon_32x32@2x" \
            "128:icon_128x128" "256:icon_128x128@2x" "256:icon_256x256" \
            "512:icon_256x256@2x" "512:icon_512x512" "1024:icon_512x512@2x"; do
    px="${pair%%:*}"
    name="${pair#*:}"
    "$tmp/svg2png" "$SVG" "$iconset/${name}.png" "$px"
done

iconutil -c icns "$iconset" -o "$OUT"
echo "wrote $OUT"
