#!/usr/bin/env python3
"""Generates original extension icons (shield + magnifier motif) — §143: local,
original assets only, no icon CDNs."""
from PIL import Image, ImageDraw
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "extension", "public", "icons")
os.makedirs(OUT, exist_ok=True)

def draw_icon(size):
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # background rounded square, deep slate
    pad = int(s * 0.04)
    d.rounded_rectangle([pad, pad, s - pad, s - pad], radius=int(s * 0.18),
                        fill=(28, 36, 48, 255))
    # shield
    cx = s * 0.46
    top = s * 0.18
    bot = s * 0.62
    w = s * 0.26
    shield = [(cx, top), (cx + w, top + s * 0.10), (cx + w * 0.92, bot),
              (cx, s * 0.80), (cx - w * 0.92, bot), (cx - w, top + s * 0.10)]
    d.polygon(shield, fill=(46, 108, 162, 255), outline=(120, 180, 230, 255), width=max(1, s // 32))
    # checkmark inside shield
    cw = max(2, s // 22)
    d.line([(cx - s * 0.10, s * 0.44), (cx - s * 0.02, s * 0.53), (cx + s * 0.13, s * 0.33)],
           fill=(230, 240, 250, 255), width=cw)
    # magnifier
    mx, my, mr = s * 0.68, s * 0.68, s * 0.14
    lw = max(2, s // 20)
    d.ellipse([mx - mr, my - mr, mx + mr, my + mr], outline=(240, 200, 90, 255), width=lw)
    d.line([(mx + mr * 0.72, my + mr * 0.72), (mx + mr * 1.55, my + mr * 1.55)],
           fill=(240, 200, 90, 255), width=lw + 1)
    return img

for px in (16, 32, 48, 128):
    icon = draw_icon(px)
    icon.save(os.path.join(OUT, f"icon{px}.png"))
    print(f"icon{px}.png written")
print("done")
