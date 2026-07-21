#!/usr/bin/env python3
"""Regenerate the Universal Clipboard app icon set (REL-1).

Draws a simple, clean clipboard glyph — two rounded rectangles (the board and
the clip/tab on top) on a rounded-square background — then emits every asset the
Tauri bundler needs:

    apps/ucb-gui/icons/
      icon.png            1024x1024 master (Tauri picks this up as `icon.png`)
      32x32.png
      128x128.png
      128x128@2x.png      (256x256)
      icon-128.png        (kept for backwards-compat with the old config)
      512x512.png
      icon.icns           (macOS, via `iconutil` when on macOS)
      icon.ico            (Windows, multi-resolution)

Committed outputs live under apps/ucb-gui/icons/. Re-run after changing the
glyph:

    python3 scripts/gen-icons.py

Requires Pillow (`pip install pillow`). `iconutil` (macOS only) is used for the
.icns; on other platforms the .icns step is skipped with a note.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

try:
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover - operator guidance
    sys.exit("Pillow is required: pip install pillow")

HERE = os.path.dirname(os.path.abspath(__file__))
ICONS_DIR = os.path.normpath(os.path.join(HERE, "..", "apps", "ucb-gui", "icons"))

# Palette: a calm indigo backdrop with an off-white board and a mid-grey clip.
BG_TOP = (79, 92, 214)      # indigo
BG_BOTTOM = (58, 66, 168)   # deeper indigo (subtle vertical gradient)
BOARD = (246, 247, 251)     # off-white
BOARD_LINE = (203, 210, 227)  # faint ruled lines
CLIP = (120, 130, 158)      # grey clip
CLIP_INNER = (79, 92, 214)  # indigo notch inside the clip


def _rounded_rect(draw: "ImageDraw.ImageDraw", box, radius, fill):
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def render_master(size: int = 1024) -> "Image.Image":
    """Render the clipboard glyph at `size`x`size` with 4x supersampling."""
    ss = 4
    S = size * ss
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background: rounded square with a soft vertical gradient.
    grad = Image.new("RGBA", (1, S), (0, 0, 0, 255))
    for y in range(S):
        t = y / (S - 1)
        r = round(BG_TOP[0] + (BG_BOTTOM[0] - BG_TOP[0]) * t)
        g = round(BG_TOP[1] + (BG_BOTTOM[1] - BG_TOP[1]) * t)
        b = round(BG_TOP[2] + (BG_BOTTOM[2] - BG_TOP[2]) * t)
        grad.putpixel((0, y), (r, g, b, 255))
    grad = grad.resize((S, S))

    mask = Image.new("L", (S, S), 0)
    mdraw = ImageDraw.Draw(mask)
    mdraw.rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * 0.22), fill=255)
    img.paste(grad, (0, 0), mask)

    # Board (the paper): a rounded rectangle centred, portrait-ish.
    bw, bh = int(S * 0.52), int(S * 0.60)
    bx = (S - bw) // 2
    by = int(S * 0.30)
    _rounded_rect(draw, [bx, by, bx + bw, by + bh], radius=int(S * 0.05), fill=BOARD)

    # Ruled lines on the board.
    line_w = max(1, int(S * 0.012))
    inset = int(bw * 0.16)
    for i, frac in enumerate((0.26, 0.42, 0.58, 0.74)):
        ly = by + int(bh * frac)
        # Last line is shorter, like a signature line.
        right = bx + bw - inset - (int(bw * 0.25) if i == 3 else 0)
        draw.rounded_rectangle(
            [bx + inset, ly, right, ly + line_w],
            radius=line_w // 2,
            fill=BOARD_LINE,
        )

    # Clip / tab on top: a rounded rectangle straddling the board's top edge,
    # with an indigo notch so it reads as a bulldog clip.
    cw, ch = int(S * 0.26), int(S * 0.14)
    cx = (S - cw) // 2
    cy = by - int(ch * 0.55)
    _rounded_rect(draw, [cx, cy, cx + cw, cy + ch], radius=int(ch * 0.35), fill=CLIP)
    nw, nh = int(cw * 0.42), int(ch * 0.34)
    nx = (S - nw) // 2
    ny = cy + int(ch * 0.16)
    _rounded_rect(draw, [nx, ny, nx + nw, ny + nh], radius=int(nh * 0.45), fill=CLIP_INNER)

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    os.makedirs(ICONS_DIR, exist_ok=True)
    master = render_master(1024)

    def out(name: str) -> str:
        return os.path.join(ICONS_DIR, name)

    # Master + Tauri's expected PNG names.
    master.save(out("icon.png"))
    sizes = {
        "32x32.png": 32,
        "128x128.png": 128,
        "128x128@2x.png": 256,
        "512x512.png": 512,
        "icon-128.png": 128,  # legacy name referenced by the old config
    }
    for name, sz in sizes.items():
        master.resize((sz, sz), Image.LANCZOS).save(out(name))

    # Windows .ico (multi-resolution).
    master.save(
        out("icon.ico"),
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )

    # macOS .icns via iconutil (macOS only).
    if shutil.which("iconutil"):
        with tempfile.TemporaryDirectory() as tmp:
            iconset = os.path.join(tmp, "icon.iconset")
            os.makedirs(iconset)
            icns_map = {
                "icon_16x16.png": 16,
                "icon_16x16@2x.png": 32,
                "icon_32x32.png": 32,
                "icon_32x32@2x.png": 64,
                "icon_128x128.png": 128,
                "icon_128x128@2x.png": 256,
                "icon_256x256.png": 256,
                "icon_256x256@2x.png": 512,
                "icon_512x512.png": 512,
                "icon_512x512@2x.png": 1024,
            }
            for name, sz in icns_map.items():
                master.resize((sz, sz), Image.LANCZOS).save(os.path.join(iconset, name))
            subprocess.run(
                ["iconutil", "-c", "icns", iconset, "-o", out("icon.icns")],
                check=True,
            )
        print("wrote icon.icns")
    else:
        print("iconutil not found (non-macOS): skipped icon.icns")

    print(f"icons written to {ICONS_DIR}")


if __name__ == "__main__":
    main()
