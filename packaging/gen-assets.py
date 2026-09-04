#!/usr/bin/env python3
"""T-156 (Батч 3.8): generates the placeholder MSIX tile/logo assets
AppxManifest.template.xml references. Deterministic (no randomness) so the
committed PNGs are exactly reproducible from this script — re-run it after
editing to regenerate, don't hand-edit the PNGs.

Flat accent-color square with a simple funnel/filter glyph in white — a
placeholder, not a final brand asset. Replace by re-running this script with
different colours/glyph, or by swapping the three PNGs directly, whichever
comes first: a real logo, or a Microsoft Store submission's own asset
requirements.
"""

from pathlib import Path
from PIL import Image, ImageDraw

ACCENT = (0x2F, 0x6F, 0xED)  # a plain blue, no brand meaning yet
GLYPH = (255, 255, 255)

SIZES = {
    "Square44x44Logo.png": 44,
    "Square150x150Logo.png": 150,
    "StoreLogo.png": 50,
}


def draw_filter_glyph(draw: ImageDraw.ImageDraw, size: int) -> None:
    """A simple funnel: a wide triangle tapering into a narrow stem —
    "filter" as a literal funnel, legible at 44px."""
    top_w = size * 0.62
    stem_w = size * 0.14
    top_y = size * 0.28
    mid_y = size * 0.60
    bottom_y = size * 0.78
    cx = size / 2
    draw.polygon(
        [
            (cx - top_w / 2, top_y),
            (cx + top_w / 2, top_y),
            (cx + stem_w / 2, mid_y),
            (cx + stem_w / 2, bottom_y),
            (cx - stem_w / 2, bottom_y),
            (cx - stem_w / 2, mid_y),
        ],
        fill=GLYPH,
    )


def main() -> None:
    out_dir = Path(__file__).parent / "assets"
    out_dir.mkdir(exist_ok=True)
    for name, size in SIZES.items():
        img = Image.new("RGBA", (size, size), (*ACCENT, 255))
        draw = ImageDraw.Draw(img)
        draw_filter_glyph(draw, size)
        img.save(out_dir / name)
        print(f"wrote {out_dir / name} ({size}x{size})")


if __name__ == "__main__":
    main()
