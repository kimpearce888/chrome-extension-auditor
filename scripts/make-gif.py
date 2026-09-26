#!/usr/bin/env python3
"""Assemble the README demo GIF from the timeline captured by demo-gif.mjs.

Reads .demo/gif-frames/timeline.json, then:
  1. drops consecutive visually-identical frames (merging their durations)
  2. downscales 1440x900 -> 900px wide
  3. draws a synthetic cursor (the headless browser has none) with a soft
     shadow, pressed state, and click ripples at recorded click points
  4. quantizes every frame to ONE shared adaptive palette (no dither, no
     palette flicker) and writes an optimized, looping GIF

Usage: python3 scripts/make-gif.py [output.gif]
Output defaults to docs/screenshots/demo.gif
"""
import hashlib
import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
FRAMES_DIR = ROOT / ".demo" / "gif-frames"
DEFAULT_OUT = ROOT / "docs" / "screenshots" / "demo.gif"

VIEW_W, VIEW_H = 1440, 900
TARGET_W = 900
SCALE = TARGET_W / VIEW_W
TARGET_H = round(VIEW_H * SCALE)

# classic arrow cursor, tip at (0,0), ~17px tall at unit scale
CURSOR_POLY = [(0, 0), (0, 17), (4.4, 12.6), (7.4, 19.0), (9.6, 17.9), (6.7, 11.6), (11.8, 11.6)]
CURSOR_SCALE = 1.32  # -> ~22px tall on a 900px-wide frame
RIPPLE_RADII = [10, 17, 24]
RIPPLE_ALPHA = [200, 130, 60]
RIPPLE_COLOR = (46, 108, 162)


def load_small(name: str) -> Image.Image:
    return Image.open(FRAMES_DIR / name).convert("RGB").resize((TARGET_W, TARGET_H), Image.LANCZOS)


def draw_cursor(img: Image.Image, cx: float, cy: float, pressed: bool) -> None:
    """Draw the cursor (with shadow) onto img in place."""
    sx, sy = cx * SCALE, cy * SCALE
    k = CURSOR_SCALE * (0.88 if pressed else 1.0)
    poly = [(sx + x * k, sy + y * k) for x, y in CURSOR_POLY]

    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)
    # soft drop shadow
    sh = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ImageDraw.Draw(sh).polygon([(x + 2.0, y + 3.0) for x, y in poly], fill=(0, 0, 0, 80))
    sh = sh.filter(ImageFilter.GaussianBlur(1.6))
    overlay = Image.alpha_composite(overlay, sh)
    d = ImageDraw.Draw(overlay)
    fill = (222, 228, 236, 255) if pressed else (252, 252, 252, 255)
    d.polygon(poly, fill=fill, outline=(28, 32, 38, 255), width=2)
    img.paste(Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB"), (0, 0))


def draw_ripple(img: Image.Image, cx: float, cy: float, step: int) -> None:
    r = RIPPLE_RADII[step]
    a = RIPPLE_ALPHA[step]
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ImageDraw.Draw(overlay).ellipse(
        [cx * SCALE - r, cy * SCALE - r, cx * SCALE + r, cy * SCALE + r],
        outline=RIPPLE_COLOR + (a,), width=3 if step == 0 else 2)
    img.paste(Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB"), (0, 0))


def build_palette(frames_meta) -> Image.Image:
    """One shared palette, sampled across the whole timeline."""
    picks = frames_meta[:: max(1, len(frames_meta) // 12)][:12]
    cols, rows = 3, (len(picks) + 2) // 3
    tw, th = TARGET_W // 2, TARGET_H // 2
    montage = Image.new("RGB", (tw * cols, th * rows), "white")
    for i, f in enumerate(picks):
        montage.paste(load_small(f["file"]).resize((tw, th), Image.LANCZOS), ((i % cols) * tw, (i // cols) * th))
    return montage.quantize(colors=255, method=Image.MEDIANCUT)


def assemble(out_path: Path, colors: int, width: int, drop_alt: bool) -> None:
    global TARGET_W, TARGET_H, SCALE
    TARGET_W = width
    SCALE = width / VIEW_W
    TARGET_H = round(VIEW_H * SCALE)

    tl = json.loads((FRAMES_DIR / "timeline.json").read_text())
    clicks = {c["frame"]: c for c in tl["clicks"]}

    # 1. dedupe consecutive identical frames (pixels AND cursor state)
    merged = []
    hashes = []
    for f in tl["frames"]:
        h = hashlib.md5(load_small(f["file"]).tobytes()).hexdigest()
        state = (round(f["cx"]), round(f["cy"]), f["pressed"])
        if merged and hashes[-1] == h and merged[-1]["_state"] == state:
            merged[-1]["ms"] += f["ms"]
            continue
        f["_state"] = state
        merged.append(f)
        hashes.append(h)

    if drop_alt:  # crude slowdown fallback: drop every other motion frame
        kept = []
        for f in merged:
            if kept and f["ms"] <= 100 and kept[-1]["ms"] <= 100 and f["ms"] == kept[-1]["ms"]:
                kept[-1]["ms"] += f["ms"]
                continue
            kept.append(f)
        merged = kept

    # 2. shared palette
    master = build_palette(merged)
    if colors < 255:
        master = master.quantize(colors=colors, method=Image.MEDIANCUT)

    # 3. render frames
    out_frames, durations = [], []
    for i, f in enumerate(merged):
        img = load_small(f["file"])
        draw_cursor(img, f["cx"], f["cy"], f["pressed"])
        if i in clicks:
            draw_ripple(img, clicks[i]["x"], clicks[i]["y"], 0)
        elif i - 1 in clicks:
            draw_ripple(img, clicks[i - 1]["x"], clicks[i - 1]["y"], 1)
        elif i - 2 in clicks:
            draw_ripple(img, clicks[i - 2]["x"], clicks[i - 2]["y"], 2)
        out_frames.append(img.quantize(palette=master, dither=Image.Dither.NONE))
        durations.append(max(30, f["ms"]))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_frames[0].save(
        out_path, save_all=True, append_images=out_frames[1:],
        duration=durations, loop=0, optimize=False, disposal=1)

    total = sum(durations) / 1000
    print(f"[gif] {out_path.name}: {len(out_frames)} frames, {total:.1f}s, "
          f"{out_path.stat().st_size / 1e6:.2f} MB, {width}px wide, {colors} colors")


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    # primary pass, then size-guarded fallbacks
    assemble(out, colors=255, width=900, drop_alt=False)
    if out.stat().st_size > 9.5e6:
        assemble(out, colors=127, width=900, drop_alt=False)
    if out.stat().st_size > 9.5e6:
        assemble(out, colors=127, width=840, drop_alt=True)


if __name__ == "__main__":
    main()
