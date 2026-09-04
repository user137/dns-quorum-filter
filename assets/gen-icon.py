#!/usr/bin/env python3
"""Single source for the project's app icon (a wireframe hexagon with small
dots on each vertex — a shield-like shape for "filtering requests") and its
horizontal wordmark. Deterministic (no randomness), so every PNG under
assets/icon/ is exactly reproducible from this script — re-run it after
editing rather than hand-editing a PNG.

This icon is not MSIX-specific: it's the app's icon wherever one is needed —
the MSIX tile (packaging/pack-msix.ps1 copies the three named files below
into the package), a future Microsoft Store listing, README/site use via the
wordmark, and a future Linux desktop icon (Фаза 6, freedesktop icon theme
sizes). One drawing function, one palette, every consumer stays visually
consistent without redrawing the glyph per platform.

Palette (revised from a first navy/cyan/white pass that read as low-contrast
and muddy at tile size): two tones only — Windows' own system accent blue
(#0078D4, reads as "a Windows system app" rather than an arbitrary brand
colour) and pure white, the highest-contrast pairing at small sizes.

A placeholder, not a final brand asset — replace by re-running this script
with different colours/geometry, or by swapping the PNGs directly, whichever
comes first: a real logo, or a Microsoft Store submission's own asset
requirements.
"""

import math
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ACCENT = (0x00, 0x78, 0xD4)  # Windows system accent blue
WHITE = (0xFF, 0xFF, 0xFF)

OUT_DIR = Path(__file__).parent / "icon"

# freedesktop hicolor theme's standard sizes (for a future Фаза 6 Linux
# desktop icon) plus the MSIX tile sizes this project needs today.
ICON_SIZES = [16, 32, 44, 48, 50, 64, 128, 150, 256, 512]

# The three files packaging/pack-msix.ps1 copies into the MSIX package,
# named exactly as AppxManifest.template.xml references them.
MSIX_NAMES = {
    "Square44x44Logo.png": 44,
    "Square150x150Logo.png": 150,
    "StoreLogo.png": 50,
}

FONT_CANDIDATES = [
    r"C:\Windows\Fonts\segoeuib.ttf",  # Segoe UI Bold — the common case
]


def hexagon_vertices(cx: float, cy: float, radius: float) -> list[tuple[float, float]]:
    """Flat-top regular hexagon — 6 vertices starting at the top-right edge,
    going clockwise."""
    return [
        (cx + radius * math.cos(math.radians(angle)), cy + radius * math.sin(math.radians(angle)))
        for angle in range(-60, 300, 60)
    ]


def draw_hex_shield(draw: ImageDraw.ImageDraw, cx: float, cy: float, radius: float, colour) -> None:
    """The glyph alone, at an arbitrary centre/radius/colour — shared by the
    filled-tile icon and the transparent-background wordmark glyph."""
    stroke_width = max(1, round(radius * 0.10))
    dot_radius = max(2, round(radius * 0.24))
    vertices = hexagon_vertices(cx, cy, radius)
    draw.polygon(vertices, outline=colour, width=stroke_width)
    # Dots share the wireframe's colour but are noticeably larger, so at
    # small sizes they read as "joints" on the hex rather than blending into
    # the stroke.
    for x, y in vertices:
        draw.ellipse(
            [x - dot_radius, y - dot_radius, x + dot_radius, y + dot_radius],
            fill=colour,
        )


def make_tile(size: int) -> Image.Image:
    """A filled accent-colour square with the white glyph — the MSIX tile /
    generic app-icon shape."""
    img = Image.new("RGBA", (size, size), (*ACCENT, 255))
    draw = ImageDraw.Draw(img)
    draw_hex_shield(draw, size / 2, size / 2, size * 0.34, WHITE)
    return img


def load_bold_font(size: int) -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    # No bundled fallback font ships with this repo (avoids a font-licensing
    # question for a placeholder asset) - regenerate on a machine with Segoe
    # UI installed (any current Windows install has it) if this raises.
    raise FileNotFoundError(
        "no bold font found - install Segoe UI (any Windows machine has it) or "
        "edit FONT_CANDIDATES to point at another .ttf"
    )


def make_wordmark(glyph_size: int = 96, text: str = "DNS Quorum Filter") -> Image.Image:
    """Horizontal lockup for contexts with their own (typically light)
    background - README, a site, a Store listing description - transparent
    background, glyph and text both drawn in the accent colour rather than
    white-on-fill."""
    font = load_bold_font(round(glyph_size * 0.44))
    padding = round(glyph_size * 0.18)
    gap = round(glyph_size * 0.35)

    scratch = Image.new("RGBA", (1, 1))
    text_bbox = ImageDraw.Draw(scratch).textbbox((0, 0), text, font=font)
    text_w = text_bbox[2] - text_bbox[0]
    text_h = text_bbox[3] - text_bbox[1]

    width = padding * 2 + glyph_size + gap + text_w
    height = padding * 2 + max(glyph_size, text_h)
    img = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cy = height / 2
    draw_hex_shield(draw, padding + glyph_size / 2, cy, glyph_size * 0.42, ACCENT)

    text_x = padding + glyph_size + gap
    text_y = cy - text_h / 2 - text_bbox[1]
    draw.text((text_x, text_y), text, font=font, fill=ACCENT)
    return img


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for size in ICON_SIZES:
        path = OUT_DIR / f"icon-{size}.png"
        make_tile(size).save(path)
        print(f"wrote {path} ({size}x{size})")

    for name, size in MSIX_NAMES.items():
        path = OUT_DIR / name
        make_tile(size).save(path)
        print(f"wrote {path} ({size}x{size}, MSIX)")

    wordmark_path = OUT_DIR / "wordmark.png"
    make_wordmark().save(wordmark_path)
    print(f"wrote {wordmark_path}")


if __name__ == "__main__":
    main()
