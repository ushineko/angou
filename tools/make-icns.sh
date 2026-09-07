#!/usr/bin/env bash
#
# Build a macOS .icns from an SVG using only tools a stock Mac already has —
# qlmanage to rasterise the vector, sips to scale, iconutil to assemble. No
# ImageMagick or librsvg dependency, so `make build-app` needs nothing installed.

set -euo pipefail

SVG="${1:?usage: make-icns.sh <svg> <out.icns>}"
OUT="${2:?usage: make-icns.sh <svg> <out.icns>}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# qlmanage renders the vector to a large master PNG; every icon size scales down
# from that one master so the small sizes stay sharp.
qlmanage -t -s 1024 -o "$tmp" "$SVG" >/dev/null 2>&1 || true
master="$tmp/$(basename "$SVG").png"
if [ ! -f "$master" ]; then
    echo "make-icns: qlmanage produced no PNG for $SVG" >&2
    exit 1
fi

iconset="$tmp/angou.iconset"
mkdir -p "$iconset"

# The exact names and sizes iconutil expects, including the @2x doublings.
for pair in "16:icon_16x16" "32:icon_16x16@2x" "32:icon_32x32" "64:icon_32x32@2x" \
            "128:icon_128x128" "256:icon_128x128@2x" "256:icon_256x256" \
            "512:icon_256x256@2x" "512:icon_512x512" "1024:icon_512x512@2x"; do
    px="${pair%%:*}"
    name="${pair#*:}"
    sips -z "$px" "$px" "$master" --out "$iconset/${name}.png" >/dev/null
done

iconutil -c icns "$iconset" -o "$OUT"
echo "wrote $OUT"
