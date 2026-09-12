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
//! `unsafe` in this crate) with a pre-rendered static RGBA image
//! (`assets/gen-icon.py::make_browser_nudge_popup`, fixed Ukrainian copy —
//! T-151 i18n is unstarted, so no text-layout dependency is needed here).
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

/// Gap, in pixels, between the tray icon's rect and the popup placed above
/// it — a judgment call, not derived from anything.
const POPUP_GAP: f64 = 8.0;

/// How long the popup stays up before `main.rs` auto-closes it.
pub const POPUP_LIFETIME: Duration = Duration::from_secs(8);

const POPUP_RGBA: &[u8] = include_bytes!("../icons/browser-nudge-rgba.bin");

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
) -> Option<NudgePopup> {
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

    let mut builder = WindowBuilder::new()
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
    let (rgba_pixels, _remainder) = POPUP_RGBA.as_chunks::<4>();
    for (pixel, &[red, green, blue, _alpha]) in buffer.iter_mut().zip(rgba_pixels) {
        *pixel = (u32::from(red) << 16) | (u32::from(green) << 8) | u32::from(blue);
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
    use super::popup_position;

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
