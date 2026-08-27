#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `dnsqb-tray` (T-149) — a lightweight background tray icon replacing the
//! Tauri desktop window (T-52, `dnsqb-ui`, deleted alongside this crate's
//! introduction). Unlike `dnsqb-ui`, this is a genuine long-running
//! background process (SERVICES.md), started once (manually today — T-150
//! tracks real autostart, separately) and then left running: its whole job
//! is showing live resolver status in the tray tooltip and giving a
//! mouse-only user five actions without ever opening a terminal. Full
//! configuration moved to the browser (`dnsqb-service`'s own embedded
//! `/admin/ui`, T-149) — this crate has no window of its own.
//!
//! "Закрити" and "Зупинити фільтрацію" are deliberately two separate menu
//! items, not one (advisor-caught during the T-149 plan review): this tray
//! never owns `dnsqb-service` as a child process (T-150's own scoping
//! reasoning — a headless target can't depend on a graphical tray
//! supervisor to launch it), so a single "close = stop everything" action
//! would leave DNS silently unfiltered with no on-screen indication at all
//! once the tray itself is gone — the Три Б failure mode by name. "Закрити"
//! only exits this process; `dnsqb-service` keeps running. "Зупинити
//! фільтрацію" is the one action that actually calls `POST
//! /admin/shutdown`, gated behind a native confirm dialog naming that
//! consequence.
//!
//! Threading model (T-149 Крок 0, confirmed against a throwaway scratch
//! probe before writing this crate for real): `tao`'s [`EventLoop::run`]
//! hijacks the calling thread forever and is not itself `async` — so
//! polling `dnsqb-service`'s admin channel lives on a separate OS thread
//! with its own single-threaded `tokio` runtime ([`status::spawn`]),
//! publishing results the main thread reads without ever blocking on
//! network I/O itself. `muda`'s [`MenuEvent`] channel is a plain
//! lock-free queue, not wired into `tao`'s own event delivery on Windows
//! (only macOS/Linux integrate it via the native run loop, per `tray-icon`'s
//! own docs) — this loop drains it on a short fixed [`EVENT_POLL_INTERVAL`]
//! tick via `ControlFlow::WaitUntil` instead.

mod browser;
mod status;

use dnsqb_service::{app_data_dir, AdminClient, AdminClientError, ResolverConfig};
use status::TrayStatus;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tao::event_loop::{ControlFlow, EventLoop};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

// Raw 32x32 RGBA pixels (4096 bytes, no header) - deliberately not the
// original `.ico` file (`tray_icon::Icon::from_rgba` takes raw pixels, not
// an encoded image, and this avoids both a runtime filesystem read and a
// new image-decode dependency - the same "compile everything in, no
// runtime asset I/O" choice `admin_ui.rs` already made for the embedded web
// UI). Generated once from the pre-existing `crates/dnsqb-ui/icons/icon.ico`
// (itself already 32x32 RGBA), via:
//   python -c "from PIL import Image; \
//     Image.open(r'crates\dnsqb-ui\icons\icon.ico').convert('RGBA') \
//     .tobytes()" written to this file.
// `crates/dnsqb-ui` is deleted in T-149's third commit - this comment is
// the asset's only remaining provenance after that, since there is no
// build-time regeneration step.
const ICON_RGBA: &[u8] = include_bytes!("../icons/icon_32x32_rgba.bin");
const ICON_SIZE: u32 = 32;

const OPEN_SETTINGS_ID: &str = "open-settings";
const RESTART_ID: &str = "restart";
const ABOUT_ID: &str = "about";
const STOP_FILTERING_ID: &str = "stop-filtering";
const CLOSE_ID: &str = "close";

/// Re-check cadence for `muda`'s global menu-event channel (see the module
/// doc comment for why this loop drives it rather than `tao` itself) —
/// independent of [`status::spawn`]'s own 2s poll interval; this tick only
/// governs how quickly a menu click gets noticed.
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);

fn main() {
    tracing_subscriber::fmt::init();

    let app_data = match app_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            tracing::error!("no app-data directory available, dnsqb-tray cannot run: {err}");
            std::process::exit(1);
        }
    };
    let port = match ResolverConfig::load(&app_data.join("resolver_config.toml")) {
        Ok(config) => config.port,
        Err(err) => {
            tracing::error!("failed to load resolver_config.toml: {err}");
            std::process::exit(1);
        }
    };

    let status_handle = status::spawn(app_data.clone(), port);

    let Ok(icon) = Icon::from_rgba(ICON_RGBA.to_vec(), ICON_SIZE, ICON_SIZE) else {
        tracing::error!(
            "embedded tray icon failed to decode - this is a build-time asset, not user input"
        );
        std::process::exit(1);
    };
    let tray_icon = match TrayIconBuilder::new()
        .with_menu(Box::new(build_menu()))
        .with_icon(icon)
        .with_tooltip(TrayStatus::Unreachable.tooltip())
        .build()
    {
        Ok(tray_icon) => tray_icon,
        Err(err) => {
            tracing::error!("failed to create the tray icon: {err}");
            std::process::exit(1);
        }
    };

    let menu_channel = MenuEvent::receiver();
    let mut last_status = TrayStatus::Unreachable;

    let event_loop: EventLoop<()> = EventLoop::new();
    event_loop.run(move |_event, _target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + EVENT_POLL_INTERVAL);

        let observed = status_handle.current();
        if observed != last_status {
            if let Err(err) = tray_icon.set_tooltip(Some(observed.tooltip())) {
                tracing::warn!("failed to update tray tooltip: {err}");
            }
            last_status = observed;
        }

        if let Ok(event) = menu_channel.try_recv() {
            handle_menu_event(event.id().as_ref(), &app_data, port, control_flow);
        }
    });
}

fn build_menu() -> Menu {
    let menu = Menu::new();
    let open_settings = MenuItem::with_id(OPEN_SETTINGS_ID, "Відкрити налаштування", true, None);
    let restart = MenuItem::with_id(RESTART_ID, "Перезапустити", true, None);
    let about = MenuItem::with_id(ABOUT_ID, "Про програму", true, None);
    let stop_filtering = MenuItem::with_id(STOP_FILTERING_ID, "Зупинити фільтрацію", true, None);
    let close = MenuItem::with_id(CLOSE_ID, "Закрити", true, None);
    if let Err(err) = menu.append_items(&[
        &open_settings,
        &restart,
        &about,
        &PredefinedMenuItem::separator(),
        &stop_filtering,
        &close,
    ]) {
        tracing::warn!("failed to build the full tray menu: {err}");
    }
    menu
}

fn handle_menu_event(id: &str, app_data: &Path, port: u16, control_flow: &mut ControlFlow) {
    match id {
        OPEN_SETTINGS_ID => {
            browser::open_in_default_browser(&format!("https://127.0.0.1:{port}/admin/ui"));
        }
        RESTART_ID => {
            spawn_admin_action(app_data.to_path_buf(), port, "reset", |client| async move {
                client.reset().await.map(|_response| ())
            });
        }
        ABOUT_ID => show_about_dialog(),
        STOP_FILTERING_ID => {
            if confirm_stop_filtering() {
                spawn_admin_action(
                    app_data.to_path_buf(),
                    port,
                    "shutdown",
                    |client| async move { client.shutdown().await },
                );
            }
        }
        // "Закрити" only exits this process - dnsqb-service is never
        // touched (see the module doc comment for why these two menu items
        // are deliberately separate).
        CLOSE_ID => *control_flow = ControlFlow::Exit,
        _ => {}
    }
}

/// Runs one admin-channel action (`reset`/`shutdown`) on its own throwaway
/// OS thread with its own tiny runtime — these are rare, user-initiated
/// clicks, not a hot path, so building a fresh [`AdminClient`] per call is
/// fine here (same cadence the old `dnsqb-ui` Tauri commands already used) —
/// unlike [`status::spawn`]'s ~30x/minute poll, which specifically must not
/// rebuild one every tick.
fn spawn_admin_action<F, Fut>(app_data: PathBuf, port: u16, action_name: &'static str, action: F)
where
    F: FnOnce(AdminClient) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), AdminClientError>>,
{
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            tracing::error!("failed to start a runtime for the {action_name} action");
            return;
        };
        runtime.block_on(async move {
            match AdminClient::new(&app_data, port) {
                Ok(client) => match action(client).await {
                    Ok(()) => tracing::info!("{action_name} succeeded"),
                    Err(err) => tracing::warn!("{action_name} failed: {err}"),
                },
                Err(err) => {
                    tracing::warn!("{action_name} failed to build an admin client: {err}");
                }
            }
        });
    });
}

fn show_about_dialog() {
    rfd::MessageDialog::new()
        .set_title("dns-quorum-filter")
        .set_description(format!(
            "dnsqb-tray {}\nЛіцензія: Apache-2.0\nЛокальний DoH quorum-фільтр \u{2014} \
             https://127.0.0.1/admin/ui",
            env!("CARGO_PKG_VERSION")
        ))
        .set_level(rfd::MessageLevel::Info)
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

/// Native confirm dialog naming the actual consequence before
/// `/admin/shutdown` is ever called — see the module doc comment for why
/// this exists as a separate step from "Закрити".
fn confirm_stop_filtering() -> bool {
    let result = rfd::MessageDialog::new()
        .set_title("Зупинити фільтрацію")
        .set_description(
            "DNS піде нефільтрованим, доки ви вручну не перезапустите dnsqb-service. \
             Продовжити?",
        )
        .set_level(rfd::MessageLevel::Warning)
        .set_buttons(rfd::MessageButtons::YesNo)
        .show();
    result == rfd::MessageDialogResult::Yes
}
