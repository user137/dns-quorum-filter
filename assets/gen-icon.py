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


# Sizes packed into the multi-resolution app.ico that build.rs (T-177)
# embeds into each dnsqb-*.exe — what Windows shows in Task Manager,
# Explorer, Alt-Tab and the title bar. Each frame is drawn at its own
# native size (crisper small icons than downscaling one 256 frame).
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]

# Raw 32x32 RGBA bytes for dnsqb-tray's runtime tray icon — one blob per
# status colour (T-191, extending T-183's single white glyph).
# `tray_icon::Icon::from_rgba` wants pixels, not an encoded image, so the tray
# compiles these blobs in via `include_bytes!` — no runtime file read, no
# image-decode dependency (the same "everything in, no runtime asset I/O"
# choice `admin_ui.rs` makes for the embedded web UI). Regenerate by re-running
# this script; never hand-edit a .bin.
TRAY_ICON_SIZE = 32
TRAY_RGBA_DIR = Path(__file__).parent.parent / "crates" / "dnsqb-tray" / "icons"

# GitHub Primer state palette (success / attention / neutral / danger) — an
# existing UI palette already vetted for light+dark legibility, not a hand-mix.
# amber leans orange so green↔amber stay ≥90° apart in hue on the ~7px vertex
# dots that carry nearly all of a 32px glyph's colour (the 1px outline is
# almost incidental). Mapped from TrayStatus by `status::icon_colour`.
TRAY_GLYPH_COLOURS = {
    "green": (0x3F, 0xB9, 0x50),
    "amber": (0xF5, 0xA6, 0x23),
    "grey": (0x8B, 0x94, 0x9E),
    "red": (0xF8, 0x51, 0x49),
}


def make_tray_glyph(size: int, colour) -> Image.Image:
    """Wireframe hexagon in `colour` on a fully transparent background. A filled
    square would read as a clumsy block on a (usually dark) Windows taskbar next
    to the other transparent tray glyphs — so, unlike make_tile, no fill."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw_hex_shield(ImageDraw.Draw(img), size / 2, size / 2, size * 0.36, colour)
    return img


# T-229 (2026-09-13): a small, borderless, auto-dismissing popup near the
# tray icon, nudging the user once that no browser appears to be using the
# local DoH endpoint yet. Pre-rendered as a static RGBA image — the copy is
# fixed and one language today (T-151 i18n is unstarted) — rather than
# rendered at runtime, so `dnsqb-tray` needs no font/text-layout dependency
# of its own, only a pixel blit (`softbuffer`): the same "everything in, no
# runtime asset I/O" choice as the tray glyphs above.
POPUP_WIDTH = 540
POPUP_HEIGHT = 108
POPUP_TEXT = (
    "Жоден браузер ще не використовує DNS Quorum Filter.\n"
    "Відкрийте налаштування, щоб це виправити."
)
# A dark neutral slate, not the accent colour — this is a passive notice, not
# a brand moment, and it must read clearly against any desktop wallpaper.
POPUP_BG = (0x20, 0x2A, 0x33)


def make_browser_nudge_popup(
    width: int = POPUP_WIDTH, height: int = POPUP_HEIGHT, text: str = POPUP_TEXT
) -> Image.Image:
    """A small, fully-opaque notice card — no transparency: this is its own
    borderless top-level window, not composited over anything else."""
    img = Image.new("RGBA", (width, height), (*POPUP_BG, 255))
    draw = ImageDraw.Draw(img)
    padding = round(width * 0.05)
    glyph_radius = height * 0.24
    draw_hex_shield(draw, padding + glyph_radius, height / 2, glyph_radius, ACCENT)

    font = load_bold_font(round(height * 0.14))
    text_x = padding * 2 + glyph_radius * 2
    text_bbox = draw.multiline_textbbox((0, 0), text, font=font, spacing=round(height * 0.10))
    text_h = text_bbox[3] - text_bbox[1]
    draw.multiline_text(
        (text_x, (height - text_h) / 2 - text_bbox[1]),
        text,
        font=font,
        fill=WHITE,
        spacing=round(height * 0.10),
    )
    return img


def make_ico(path: Path) -> None:
    """Multi-resolution Windows .ico for the executables' embedded icon.
    The base frame must be the largest — Pillow's ICO writer drops any
    entry in `sizes` bigger than the base image."""
    frames = sorted((make_tile(size) for size in ICO_SIZES), key=lambda f: -f.width)
    frames[0].save(
        path,
        format="ICO",
        sizes=[(size, size) for size in ICO_SIZES],
        append_images=frames[1:],
    )


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

    ico_path = OUT_DIR / "app.ico"
    make_ico(ico_path)
    print(f"wrote {ico_path} ({'/'.join(str(s) for s in ICO_SIZES)})")

    wordmark_path = OUT_DIR / "wordmark.png"
    make_wordmark().save(wordmark_path)
    print(f"wrote {wordmark_path}")

    TRAY_RGBA_DIR.mkdir(parents=True, exist_ok=True)
    for name, rgb in TRAY_GLYPH_COLOURS.items():
        blob = make_tray_glyph(TRAY_ICON_SIZE, rgb).tobytes()
        path = TRAY_RGBA_DIR / f"tray-32-{name}-rgba.bin"
        path.write_bytes(blob)
        print(
            f"wrote {path} ({len(blob)} bytes, "
            f"{TRAY_ICON_SIZE}x{TRAY_ICON_SIZE} RGBA, transparent bg)"
        )

    popup_path = TRAY_RGBA_DIR / "browser-nudge-rgba.bin"
    popup_blob = make_browser_nudge_popup().tobytes()
    popup_path.write_bytes(popup_blob)
    print(
        f"wrote {popup_path} ({len(popup_blob)} bytes, "
        f"{POPUP_WIDTH}x{POPUP_HEIGHT} RGBA, opaque bg)"
    )


if __name__ == "__main__":
    main()
