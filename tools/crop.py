"""Crop a full-desktop capture to a window's geometry.

kdotool reports logical coordinates while the capture is in device pixels, so the crop
needs the factor between them. It is read per-output from kscreen-doctor rather than
hardcoded: a mixed-scale multi-monitor setup has no single answer.
"""

import re
import subprocess
import sys

from PIL import Image


def scale_at(px, py):
    """The scale factor of the output containing logical point (px, py)."""
    try:
        raw = subprocess.run(["kscreen-doctor", "-o"], capture_output=True,
                             text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return 1.0
    raw = re.sub(r"\x1b\[[0-9;]*m", "", raw)          # strip the colour codes
    best, geo = 1.0, None
    for line in raw.splitlines():
        m = re.search(r"Geometry:\s*(-?\d+),(-?\d+)\s+(\d+)x(\d+)", line)
        if m:
            geo = tuple(int(v) for v in m.groups())
            continue
        m = re.search(r"Scale:\s*([\d.]+)", line)
        if m and geo:
            gx, gy, gw, gh = geo
            if gx <= px < gx + gw and gy <= py < gy + gh:
                return float(m.group(1))
            best = float(m.group(1))                   # fall back to the last seen
            geo = None
    return best


def main():
    src, out, pos, dim = sys.argv[1:5]
    x, y = (float(v) for v in pos.split(","))
    w, h = (float(v) for v in dim.split("x"))
    im = Image.open(src)
    scale = scale_at(x, y)
    box = (round(x * scale), round(y * scale), round((x + w) * scale), round((y + h) * scale))
    box = (max(0, box[0]), max(0, box[1]), min(im.width, box[2]), min(im.height, box[3]))
    im.crop(box).save(out)


if __name__ == "__main__":
    main()
