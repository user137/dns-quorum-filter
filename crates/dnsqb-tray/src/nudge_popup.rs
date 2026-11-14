//! T-229 (rendering half, 2026-09-13) — the actual on-screen popup for the
//! browser nudge `browser_nudge.rs` decides the *timing* of. User's own
//! constraint: small, near the tray icon, never fullscreen or centered —
//! which rules out `rfd`'s centered native dialogs (`onboarding`'s own
//! mechanism) and a Windows balloon tip (`tray-icon` 0.21 exposes the real
//! tray icon's `window_handle()` but not the private `uID` it registered
//! under, so a balloon can't attach to the existing icon without a second,
//! separate `Shell_NotifyIcon` registration — either a new crate or
//! hand-rolled `unsafe` FFI in a `#![forbid(unsafe_code)]` crate).
//!
//! What's built instead: a borderless, always-on-top, non-focusable `tao`
//! window created on the *same* event loop the tray already runs on
//! (`WindowBuilder::build` takes the `&EventLoopWindowTarget` the main loop's
//! closure already receives — no second event loop, no new thread), painted
//! once via `softbuffer` (a small, safe pixel-blit crate — no GPU, no
//! `unsafe` in this crate). The pixels are pre-rendered, so no font or
//! text-layout dependency is needed here: one RGBA base (background +
//! shield, `assets/gen-icon.py::make_browser_nudge_popup`) and, per tray
//! locale (T-151 Batch 5.7), an RLE'd 8-bit coverage mask of the
//! `nudge.popupText` dictionary string, rendered by
//! `assets/gen-nudge-text.ps1` with GDI+ (which shapes Arabic, Devanagari,
//! Thai and CJK) and blended in white here. A right-to-left locale gets the
//! base mirrored, so the shield sits on its leading side.
//! `main.rs` owns the popup's lifetime: creates it once the detection half
//! fires, drops it (destroying the native window) after [`POPUP_LIFETIME`]
//! or on a click, and **only then** calls
//! `browser_nudge::mark_browser_nudge_seen` — the marker means "actually
//! shown", not "decided to show".

use std::rc::Rc;
use std::time::{Duration, Instant};
use tao::dpi::{PhysicalPosition, PhysicalSize};
use tao::event_loop::EventLoopWindowTarget;
use tao::rwh_06::{DisplayHandle, HandleError, HasDisplayHandle, HasWindowHandle, WindowHandle};
use tao::window::{Window, WindowBuilder, WindowId};

#[cfg(windows)]
use tao::platform::windows::WindowBuilderExtWindows;

/// Must match `assets/gen-icon.py`'s `POPUP_WIDTH`/`POPUP_HEIGHT` exactly —
/// same contract as the tray glyphs' `TRAY_ICON_SIZE`.
const POPUP_WIDTH: u32 = 540;
const POPUP_HEIGHT: u32 = 108;

/// The text box inside the popup for a left-to-right locale. Must match
/// `assets/gen-icon.py`'s `POPUP_TEXT_*` exactly — the masks are this size.
const TEXT_LEFT: u32 = 106;
const TEXT_TOP: u32 = 10;
const TEXT_WIDTH: u32 = 418;
const TEXT_HEIGHT: u32 = 88;

/// Locales whose text runs right to left: the base is mirrored for them.
const RIGHT_TO_LEFT: &[&str] = &["ar", "he", "ur"];

/// Gap, in pixels, between the tray icon's rect and the popup placed above
/// it — a judgment call, not derived from anything.
const POPUP_GAP: f64 = 8.0;

/// How long the popup stays up before `main.rs` auto-closes it.
pub const POPUP_LIFETIME: Duration = Duration::from_secs(8);

const POPUP_RGBA: &[u8] = include_bytes!("../icons/browser-nudge-rgba.bin");

/// One text mask per tray locale, the same code list as `i18n.rs`'s own
/// table (a test keeps the two equal). Each blob is the FNV-1a of the source
/// text (u32 LE) followed by the zero-run-encoded mask, see [`decode_mask`].
macro_rules! nudge_texts {
    ($($code:literal),+ $(,)?) => {
        const NUDGE_TEXTS: &[(&str, &[u8])] = &[
            $(($code, include_bytes!(concat!("../icons/nudge-text/", $code, ".bin")))),+
        ];
    };
}
nudge_texts!(
    "ar", "bg", "cs", "da", "de", "el", "en", "es", "et", "fi", "fr", "he", "hi", "hr", "hu", "id",
    "it", "ja", "ko", "lt", "lv", "nb", "nl", "pl", "pt", "ro", "sk", "sl", "sr-Latn", "sv", "sw",
    "th", "tr", "uk", "ur", "vi", "zh",
);

/// 32-bit FNV-1a, the same function `gen-icon.py` stamps each mask with: a
/// drift check between a committed mask and the dictionary text it shows,
/// not a security hash. Only the drift test needs it.
#[cfg(test)]
fn fnv1a32(data: &[u8]) -> u32 {
    data.iter().fold(0x811C_9DC5, |hash, &byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    })
}

/// Splits a mask blob into its source-text hash and the decoded
/// `TEXT_WIDTH * TEXT_HEIGHT` coverage bytes. Encoding: `0, n` is a run of
/// `n` (1..=255) zero pixels, any other byte one literal pixel. `None` for a
/// blob that is too short, has a zero or dangling run, or decodes to any
/// other size — the blobs are compiled in, so this only guards against a
/// broken regeneration, never untrusted input.
fn decode_mask(blob: &[u8]) -> Option<(u32, Vec<u8>)> {
    let expected = usize::try_from(TEXT_WIDTH * TEXT_HEIGHT).ok()?;
    let (hash, body) = blob.split_first_chunk::<4>()?;
    let mut mask = Vec::with_capacity(expected);
    let mut bytes = body.iter();
    while let Some(&byte) = bytes.next() {
        let run = if byte == 0 {
            match bytes.next() {
                Some(&count) if count > 0 => usize::from(count),
                _ => return None,
            }
        } else {
            1
        };
        if mask.len() + run > expected {
            return None;
        }
        if byte == 0 {
            mask.resize(mask.len() + run, 0);
        } else {
            mask.push(byte);
        }
    }
    (mask.len() == expected).then(|| (u32::from_le_bytes(*hash), mask))
}

/// `locale`'s decoded mask, or `en`'s when that locale has none or it does
/// not decode; `None` only if `en`'s is broken too (then no popup at all —
/// never a card without its text).
fn text_mask(locale: &str) -> Option<(&'static str, Vec<u8>)> {
    let lookup = |code: &str| {
        NUDGE_TEXTS
            .iter()
            .find(|(candidate, _)| *candidate == code)
            .and_then(|&(code, blob)| decode_mask(blob).map(|(_, mask)| (code, mask)))
    };
    lookup(locale).or_else(|| lookup("en"))
}

/// One channel of white blended over `base` at `coverage` (0..=255).
fn blend_white(base: u8, coverage: u8) -> u8 {
    let (base, coverage) = (u32::from(base), u32::from(coverage));
    let mixed = base + (255 - base) * coverage / 255;
    // `mixed` is at most 255: (255 - base) * coverage / 255 <= 255 - base.
    u8::try_from(mixed).unwrap_or(u8::MAX)
}

/// The popup's pixels as `0x00RRGGBB` (softbuffer's format), row-major:
/// the base (mirrored for a right-to-left locale) with the text blended in.
fn popup_pixels(locale: &str) -> Option<Vec<u32>> {
    let (code, mask) = text_mask(locale)?;
    let rtl = RIGHT_TO_LEFT.contains(&code);
    let width = usize::try_from(POPUP_WIDTH).ok()?;
    let text_width = usize::try_from(TEXT_WIDTH).ok()?;
    let text_left = usize::try_from(if rtl {
        POPUP_WIDTH - TEXT_LEFT - TEXT_WIDTH
    } else {
        TEXT_LEFT
    })
    .ok()?;
    let text_top = usize::try_from(TEXT_TOP).ok()?;
    let (base, _remainder) = POPUP_RGBA.as_chunks::<4>();
    let mut pixels = Vec::with_capacity(base.len());
    for (index, _) in base.iter().enumerate() {
        let (row, column) = (index / width, index % width);
        let source = if rtl {
            row * width + (width - 1 - column)
        } else {
            index
        };
        let &[red, green, blue, _alpha] = base.get(source)?;
        let coverage = match (row.checked_sub(text_top), column.checked_sub(text_left)) {
            (Some(y), Some(x)) if x < text_width => {
                mask.get(y * text_width + x).copied().unwrap_or(0)
            }
            _ => 0,
        };
        pixels.push(
            (u32::from(blend_white(red, coverage)) << 16)
                | (u32::from(blend_white(green, coverage)) << 8)
                | u32::from(blend_white(blue, coverage)),
        );
    }
    Some(pixels)
}

/// Thin `Clone`-able wrapper so both the [`softbuffer::Context`] and
/// [`softbuffer::Surface`] can each hold their own owning handle to the same
/// window (`Surface::new`/`Context::new` both take their handle by value) —
/// delegation only, no `unsafe` needed since the underlying trait methods
/// are already safe.
#[derive(Clone)]
struct SharedWindow(Rc<Window>);

impl HasWindowHandle for SharedWindow {
    fn window_handle(&self) -> Result<WindowHandle<'_>, HandleError> {
        self.0.window_handle()
    }
}

impl HasDisplayHandle for SharedWindow {
    fn display_handle(&self) -> Result<DisplayHandle<'_>, HandleError> {
        self.0.display_handle()
    }
}

/// Where to place the popup's top-left corner (screen coordinates) so it
/// sits just above the tray icon's rect, clamped to stay fully on-screen.
/// Pure — no I/O, trivially testable without a real window or monitor.
fn popup_position(tray_rect: (f64, f64, f64, f64), monitor_size: (u32, u32)) -> (i32, i32) {
    let (tray_x, tray_y, tray_w, _tray_h) = tray_rect;
    let (monitor_w, monitor_h) = (f64::from(monitor_size.0), f64::from(monitor_size.1));
    let x = tray_x + tray_w / 2.0 - f64::from(POPUP_WIDTH) / 2.0;
    let y = tray_y - f64::from(POPUP_HEIGHT) - POPUP_GAP;
    let clamped_x = x.clamp(0.0, (monitor_w - f64::from(POPUP_WIDTH)).max(0.0));
    let clamped_y = y.clamp(0.0, (monitor_h - f64::from(POPUP_HEIGHT)).max(0.0));
    // Both values are clamped into [0, monitor_{w,h}] just above — a real
    // monitor's pixel dimensions are far below `i32::MAX`, so this never
    // truncates; the clamp is what makes that provable, not a hand-traced
    // assumption about the caller.
    #[allow(clippy::cast_possible_truncation)]
    {
        (clamped_x.round() as i32, clamped_y.round() as i32)
    }
}

/// A short-lived popup window. `main.rs` holds this in an `Option`, checking
/// [`Self::is_expired`] each tick and matching [`Self::id`] against incoming
/// `WindowEvent`s to close it early on a click.
pub struct NudgePopup {
    window: Rc<Window>,
    // Kept alive only so the surface's own registration isn't torn down
    // early; never read again after the one paint in `spawn`.
    _surface: softbuffer::Surface<SharedWindow, SharedWindow>,
    opened_at: Instant,
}

impl NudgePopup {
    #[must_use]
    pub fn id(&self) -> WindowId {
        self.window.id()
    }

    #[must_use]
    pub fn is_expired(&self, lifetime: Duration) -> bool {
        self.opened_at.elapsed() >= lifetime
    }

    /// Whether this tick's event means the popup should close now — a click
    /// anywhere on it (there's no decoration/close button to click, since
    /// it's borderless) or its lifetime elapsing.
    #[must_use]
    pub fn should_close(&self, event: &tao::event::Event<'_, ()>, lifetime: Duration) -> bool {
        let clicked = matches!(
            event,
            tao::event::Event::WindowEvent {
                window_id,
                event: tao::event::WindowEvent::MouseInput {
                    state: tao::event::ElementState::Pressed,
                    ..
                },
                ..
            } if *window_id == self.id()
        );
        clicked || self.is_expired(lifetime)
    }
}

/// Build and paint the popup on the given event loop, positioned near
/// `tray_rect` (falling back to the primary monitor's bottom-right corner if
/// the tray icon's own rect isn't available yet — e.g. the very first poll
/// tick). Returns `None` on any failure (window creation, surface creation,
/// no monitor detected): this is a best-effort nudge, never worth crashing
/// the tray over.
pub fn spawn<T>(
    event_loop: &EventLoopWindowTarget<T>,
    tray_rect: Option<tray_icon::Rect>,
    locale: &str,
) -> Option<NudgePopup> {
    let pixels = popup_pixels(locale)?;
    let monitor = event_loop.primary_monitor()?;
    let monitor_size = monitor.size();

    let (popup_x, popup_y) = match tray_rect {
        Some(rect) => popup_position(
            (
                rect.position.x,
                rect.position.y,
                f64::from(rect.size.width),
                f64::from(rect.size.height),
            ),
            (monitor_size.width, monitor_size.height),
        ),
        // No tray rect yet -- anchor to the bottom-right corner directly,
        // the same corner the tray icon itself almost always occupies.
        None => popup_position(
            (
                f64::from(monitor_size.width),
                f64::from(monitor_size.height),
                0.0,
                0.0,
            ),
            (monitor_size.width, monitor_size.height),
        ),
    };

    // The title is never drawn (no decorations); it is the window's
    // accessible name for a screen reader.
    let mut builder = WindowBuilder::new()
        .with_title(crate::i18n::t(locale, "nudge.popupText"))
        .with_inner_size(PhysicalSize::new(POPUP_WIDTH, POPUP_HEIGHT))
        .with_position(PhysicalPosition::new(popup_x, popup_y))
        .with_decorations(false)
        .with_always_on_top(true)
        .with_resizable(false)
        .with_visible(true)
        .with_focused(false);
    #[cfg(windows)]
    {
        builder = builder.with_skip_taskbar(true);
    }
    let window = Rc::new(builder.build(event_loop).ok()?);
    let shared = SharedWindow(Rc::clone(&window));

    let context = softbuffer::Context::new(shared.clone()).ok()?;
    let mut surface = softbuffer::Surface::new(&context, shared).ok()?;
    surface
        .resize(
            std::num::NonZeroU32::new(POPUP_WIDTH)?,
            std::num::NonZeroU32::new(POPUP_HEIGHT)?,
        )
        .ok()?;

    let mut buffer = surface.buffer_mut().ok()?;
    for (target, pixel) in buffer.iter_mut().zip(pixels) {
        *target = pixel;
    }
    buffer.present().ok()?;

    Some(NudgePopup {
        window,
        _surface: surface,
        opened_at: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        blend_white, decode_mask, fnv1a32, popup_pixels, popup_position, text_mask, NUDGE_TEXTS,
        POPUP_HEIGHT, POPUP_WIDTH, TEXT_HEIGHT, TEXT_WIDTH,
    };

    fn mask_len() -> usize {
        usize::try_from(TEXT_WIDTH * TEXT_HEIGHT).unwrap_or(usize::MAX)
    }

    fn blob(body: &[u8]) -> Vec<u8> {
        let mut blob = vec![0, 0, 0, 0];
        blob.extend_from_slice(body);
        blob
    }

    /// A body of all-zero runs covering exactly `pixels` pixels.
    fn zero_runs(pixels: usize) -> Vec<u8> {
        let mut body = Vec::new();
        let mut left = pixels;
        while left > 0 {
            let run = left.min(255);
            body.extend_from_slice(&[0, u8::try_from(run).unwrap_or(255)]);
            left -= run;
        }
        body
    }

    // Happy path: every shipped mask decodes to the full box and draws text.
    #[test]
    fn every_locale_mask_decodes_to_the_whole_box_with_some_text() {
        for &(code, blob) in NUDGE_TEXTS {
            let Some((_, mask)) = decode_mask(blob) else {
                panic!("{code}: mask does not decode");
            };
            assert_eq!(mask.len(), mask_len(), "{code}");
            assert!(mask.iter().any(|&a| a > 128), "{code}: no text drawn");
        }
    }

    // The masks and the dictionaries cover the same locales.
    #[test]
    fn the_mask_table_matches_the_dictionary_table() {
        let masks: Vec<&str> = NUDGE_TEXTS.iter().map(|&(code, _)| code).collect();
        let dicts: Vec<&str> = crate::i18n::I18N_DICTS
            .iter()
            .map(|&(code, _)| code)
            .collect();
        assert_eq!(masks, dicts);
    }

    // Drift guard: a translation edited without regenerating the masks.
    #[test]
    fn every_mask_was_rendered_from_the_current_dictionary_text() {
        for &(code, json) in crate::i18n::I18N_DICTS {
            let value: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
            let Some(text) = value.get("nudge.popupText").and_then(|v| v.as_str()) else {
                panic!("{code}.json has no nudge.popupText");
            };
            let Some(&(_, blob)) = NUDGE_TEXTS.iter().find(|(c, _)| *c == code) else {
                panic!("{code}: no mask");
            };
            let Some((hash, _)) = decode_mask(blob) else {
                panic!("{code}: mask does not decode");
            };
            assert_eq!(
                hash,
                fnv1a32(text.as_bytes()),
                "{code}: nudge.popupText changed since its mask was rendered - re-run assets/gen-icon.py"
            );
        }
    }

    #[test]
    fn fnv1a32_matches_the_published_test_vectors() {
        assert_eq!(fnv1a32(b""), 0x811C_9DC5);
        assert_eq!(fnv1a32(b"a"), 0xE40C_292C);
        assert_eq!(fnv1a32(b"foobar"), 0xBF9C_F968);
    }

    // Security/boundary: a run that would overflow the box is rejected, and
    // the exact size is accepted.
    #[test]
    fn a_mask_one_pixel_too_long_is_rejected() {
        assert!(decode_mask(&blob(&zero_runs(mask_len()))).is_some());
        let mut body = zero_runs(mask_len());
        body.push(7);
        assert!(decode_mask(&blob(&body)).is_none());
    }

    // Misuse/fool: zero-length runs, a dangling run marker, a short blob.
    #[test]
    fn malformed_masks_are_rejected() {
        assert!(decode_mask(&[0, 0, 0]).is_none(), "no room for the hash");
        let mut zero_count = zero_runs(mask_len());
        zero_count.extend_from_slice(&[0, 0]);
        assert!(
            decode_mask(&blob(&zero_count)).is_none(),
            "a zero-length run"
        );
        let mut dangling = zero_runs(mask_len() - 1);
        dangling.push(0);
        assert!(
            decode_mask(&blob(&dangling)).is_none(),
            "a run with no count"
        );
    }

    // Error path: a mask one pixel short is rejected; an unknown locale falls
    // back to English rather than to no text.
    #[test]
    fn a_short_mask_is_rejected_and_an_unknown_locale_falls_back_to_english() {
        assert!(decode_mask(&blob(&zero_runs(mask_len() - 1))).is_none());
        assert_eq!(text_mask("xx").map(|(code, _)| code), Some("en"));
        assert_eq!(text_mask("uk").map(|(code, _)| code), Some("uk"));
    }

    #[test]
    fn blending_white_spans_base_to_white() {
        assert_eq!(blend_white(0x20, 0), 0x20);
        assert_eq!(blend_white(0x20, 255), 0xFF);
        assert_eq!(blend_white(0, 128), 128);
    }

    // A right-to-left locale mirrors the base: the shield's accent pixels
    // move from the left third to the right third.
    #[test]
    fn a_right_to_left_popup_puts_the_shield_on_the_right() {
        let width = usize::try_from(POPUP_WIDTH).unwrap_or(0);
        let height = usize::try_from(POPUP_HEIGHT).unwrap_or(0);
        let accent_columns = |pixels: &[u32]| -> Vec<usize> {
            (0..width)
                .filter(|&x| (0..height).any(|y| pixels[y * width + x] == 0x0000_78D4))
                .collect()
        };
        let (Some(ltr), Some(rtl)) = (popup_pixels("en"), popup_pixels("ar")) else {
            panic!("popups must render");
        };
        assert_eq!(ltr.len(), width * height);
        assert!(accent_columns(&ltr).iter().all(|&x| x < width / 3));
        assert!(accent_columns(&rtl).iter().all(|&x| x > width * 2 / 3));
    }

    // Happy path: room on every side, the popup centers above the tray icon.
    #[test]
    fn centers_above_the_tray_icon_when_there_is_room() {
        let (x, y) = popup_position((1000.0, 1000.0, 32.0, 32.0), (1920, 1080));
        assert_eq!(x, 1000 + 16 - 540 / 2);
        assert_eq!(y, 1000 - 108 - 8);
    }

    // Security/boundary: a tray icon flush against the right edge must not
    // push the popup off-screen.
    #[test]
    fn clamps_to_the_right_edge() {
        let (x, _y) = popup_position((1900.0, 1000.0, 32.0, 32.0), (1920, 1080));
        assert_eq!(x, 1920 - 540);
    }

    // Misuse/fool: a tray icon at (0, 0) (a malformed or minimized-taskbar
    // reading) must not push the popup to a negative, off-screen coordinate.
    #[test]
    fn clamps_to_the_top_left_edge() {
        let (x, y) = popup_position((0.0, 0.0, 32.0, 32.0), (1920, 1080));
        assert_eq!(x, 0);
        assert_eq!(y, 0);
    }

    // Error path: a monitor narrower than the popup itself must not produce
    // a negative clamp range (max(0.0) is what guards this).
    #[test]
    fn does_not_invert_the_clamp_range_on_a_too_small_monitor() {
        let (x, y) = popup_position((10.0, 10.0, 32.0, 32.0), (100, 100));
        assert_eq!(x, 0);
        assert_eq!(y, 0);
    }
}
