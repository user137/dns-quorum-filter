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

use dnsqb_service::{
    acquire_instance_guard, app_data_dir, write_pid_file, AdminClient, AdminClientError,
    GuardError, InstanceRole, ResolverConfig,
};
use dnsqb_service::{
    ensure_installed, remove_all_local_state, rotate_certificate,
    uninstall as uninstall_trust_store, ArtifactOutcome, UninstallReport,
};
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
const INSTALL_CERT_ID: &str = "install-cert";
const UNINSTALL_CERT_ID: &str = "uninstall-cert";
const ROTATE_CERT_ID: &str = "rotate-cert";
const REMOVE_ALL_ID: &str = "remove-all-local-state";

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

    // SPEC.md §7.1 #2/#3: one tray per app-data directory, and a `tray.pid`
    // the watcher's launcher reads to decide whether to spawn one (T-150) —
    // without it, every watcher (re)start would spawn another tray. A second
    // instance (a double-clicked shortcut, the watcher relaunching) just
    // exits; that is the idempotent-launcher behaviour, not an error. `tao`'s
    // event loop never returns, so the guard is released by the OS on exit
    // (its whole `share_mode(0)` design) rather than by `Drop`.
    let _guard = match acquire_instance_guard(&app_data, InstanceRole::Tray) {
        Ok(guard) => guard,
        Err(GuardError::AlreadyRunning(_)) => {
            tracing::info!("another dnsqb-tray instance is already running, exiting");
            return;
        }
        Err(err) => {
            tracing::error!("could not acquire the tray single-instance lock: {err}");
            std::process::exit(1);
        }
    };
    if let Err(err) = write_pid_file(&app_data, InstanceRole::Tray) {
        tracing::warn!("could not write the tray pid file: {err}");
    }

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
    let install_cert = MenuItem::with_id(INSTALL_CERT_ID, "Встановити сертифікат", true, None);
    let uninstall_cert = MenuItem::with_id(UNINSTALL_CERT_ID, "Видалити сертифікат", true, None);
    let rotate_cert = MenuItem::with_id(ROTATE_CERT_ID, "Перевипустити сертифікат", true, None);
    let remove_all = MenuItem::with_id(REMOVE_ALL_ID, "Повністю видалити", true, None);
    let stop_filtering = MenuItem::with_id(STOP_FILTERING_ID, "Зупинити фільтрацію", true, None);
    let close = MenuItem::with_id(CLOSE_ID, "Закрити", true, None);
    if let Err(err) = menu.append_items(&[
        &open_settings,
        &restart,
        &about,
        &PredefinedMenuItem::separator(),
        &install_cert,
        &uninstall_cert,
        &rotate_cert,
        &PredefinedMenuItem::separator(),
        &remove_all,
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
        INSTALL_CERT_ID => {
            if confirm_install_cert() {
                let cert_path = app_data.join("cert.pem");
                spawn_trust_store_action(
                    "install",
                    "Встановити сертифікат",
                    move || ensure_installed(&cert_path).map(|outcome| format!("{outcome:?}")),
                );
            }
        }
        UNINSTALL_CERT_ID => {
            if confirm_uninstall_cert() {
                spawn_trust_store_action(
                    "uninstall",
                    "Видалити сертифікат",
                    || uninstall_trust_store().map(|()| "removed".to_string()),
                );
            }
        }
        ROTATE_CERT_ID => {
            if confirm_rotate_cert() {
                spawn_trust_store_action(
                    "rotate",
                    "Перевипустити сертифікат",
                    || rotate_certificate().map(|report| report.to_string()),
                );
            }
        }
        REMOVE_ALL_ID => {
            if confirm_remove_all_local_state() {
                let app_data = app_data.to_path_buf();
                spawn_trust_store_action(
                    "remove-all-local-state",
                    "Повністю видалити",
                    move || -> Result<String, std::convert::Infallible> {
                        Ok(format_uninstall_report(&remove_all_local_state(Some(
                            &app_data,
                        ))))
                    },
                );
            }
        }
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

/// Runs one trust-store action (`install`/`uninstall`) on its own throwaway
/// OS thread — unlike [`spawn_admin_action`], this is a synchronous local
/// `certutil` call, not an admin-HTTP-channel round trip, so no `tokio`
/// runtime is needed at all. Reports the outcome **both** ways: logged (as
/// every other action here does) and via a native dialog on this same
/// thread — this crate builds with `windows_subsystem = "windows"` (no
/// console), so a log line alone is invisible to a user who clicked a menu
/// item and is watching for a result. A silent failure here would leave the
/// user believing a trust-store change succeeded when it didn't — exactly
/// the "no on-screen indication" failure class this crate's own module doc
/// comment already names for "Зупинити фільтрацію" (advisor-caught before
/// commit, not written this way from the start).
fn spawn_trust_store_action<F, E>(action_name: &'static str, dialog_title: &'static str, action: F)
where
    F: FnOnce() -> Result<String, E> + Send + 'static,
    E: std::fmt::Display,
{
    std::thread::spawn(move || match action() {
        Ok(outcome) => {
            tracing::info!("{action_name} succeeded: {outcome}");
            rfd::MessageDialog::new()
                .set_title(dialog_title)
                .set_description(format!("Успішно: {outcome}"))
                .set_level(rfd::MessageLevel::Info)
                .set_buttons(rfd::MessageButtons::Ok)
                .show();
        }
        Err(err) => {
            tracing::warn!("{action_name} failed: {err}");
            rfd::MessageDialog::new()
                .set_title(dialog_title)
                .set_description(format!("Не вдалося: {err}"))
                .set_level(rfd::MessageLevel::Error)
                .set_buttons(rfd::MessageButtons::Ok)
                .show();
        }
    });
}

/// Native confirm dialog before `certutil -addstore` — this pops the OS's
/// own confirmation dialog too (a second, separate prompt) unless/until
/// T-49's open "is certutil silent?" question is settled by a real run; see
/// `trust_store.rs`'s module doc comment.
fn confirm_install_cert() -> bool {
    let result = rfd::MessageDialog::new()
        .set_title("Встановити сертифікат")
        .set_description(
            "Локальний сертифікат dns-quorum-filter буде додано до довірених кореневих \
             сертифікатів поточного користувача (CurrentUser\\Root). Це прибирає попередження \
             браузера про недовірений сертифікат на сторінці налаштувань. Windows може показати \
             власний діалог підтвердження. Продовжити?",
        )
        .set_level(rfd::MessageLevel::Info)
        .set_buttons(rfd::MessageButtons::YesNo)
        .show();
    result == rfd::MessageDialogResult::Yes
}

/// Native confirm dialog before `certutil -delstore` — names the real
/// consequence (browser warning returns), same pattern as
/// [`confirm_stop_filtering`].
fn confirm_uninstall_cert() -> bool {
    let result = rfd::MessageDialog::new()
        .set_title("Видалити сертифікат")
        .set_description(
            "Локальний сертифікат dns-quorum-filter буде видалено з довірених кореневих \
             сертифікатів. Браузер знову покаже попередження про недовірений сертифікат на \
             сторінці налаштувань, доки сертифікат не буде встановлено повторно. Продовжити?",
        )
        .set_level(rfd::MessageLevel::Warning)
        .set_buttons(rfd::MessageButtons::YesNo)
        .show();
    result == rfd::MessageDialogResult::Yes
}

/// Native confirm dialog before certificate rotation — names every consequence
/// *before* the user acts: the old `CurrentUser\Root` entries are removed, a
/// fresh key is generated and the new certificate installed in their place, and
/// the running `dnsqb-service` keeps serving the *previous* certificate (it
/// holds its TLS config from startup) until it is restarted. In that window the
/// browser shows an untrusted-certificate warning on `/admin/ui` because the
/// certificate on the wire is no longer in the trust store; restarting
/// `dnsqb-service` clears it. (The tray's own status poll is unaffected —
/// [`status::spawn`] keeps its cached client, still pinned to and matching the
/// still-served previous certificate.)
fn confirm_rotate_cert() -> bool {
    let result = rfd::MessageDialog::new()
        .set_title("Перевипустити сертифікат")
        .set_description(
            "Буде згенеровано новий локальний сертифікат dns-quorum-filter із новим ключем. \
             Старі записи цього проєкту прибираються з довірених кореневих сертифікатів \
             (CurrentUser\\Root), новий сертифікат встановлюється замість них. \
             dnsqb-service потрібно перезапустити, щоб новий сертифікат почав діяти — до \
             перезапуску сервіс віддає попередній сертифікат, і браузер показуватиме \
             попередження про недовірений сертифікат на сторінці налаштувань. Після \
             перезапуску воно зникає. Продовжити?",
        )
        .set_level(rfd::MessageLevel::Warning)
        .set_buttons(rfd::MessageButtons::YesNo)
        .show();
    result == rfd::MessageDialogResult::Yes
}

/// Native confirm dialog before T-70's full local-state removal — names
/// every artifact it touches (the trusted certificate *and* all three
/// Credential Manager secrets) and the one thing it deliberately does
/// **not** do: MSIX (T-156) gives this app no code to run at uninstall
/// time, so removing the app itself is still a separate, manual step in
/// Windows Settings.
fn confirm_remove_all_local_state() -> bool {
    let result = rfd::MessageDialog::new()
        .set_title("Повністю видалити")
        .set_description(
            "Буде видалено локальний сертифікат dns-quorum-filter із довірених кореневих \
             сертифікатів, а також TLS-ключ, ключ шифрування журналу/кешу та збережені \
             креденшели MaxMind (якщо є) зі сховища облікових даних Windows. Це НЕ видаляє \
             сам застосунок — після цього кроку видаліть dns-quorum-filter у Параметрах \
             Windows окремо. Продовжити?",
        )
        .set_level(rfd::MessageLevel::Warning)
        .set_buttons(rfd::MessageButtons::YesNo)
        .show();
    result == rfd::MessageDialogResult::Yes
}

/// One line per artifact, never a single collapsed pass/fail — the same
/// discipline [`UninstallReport`] itself follows.
fn format_uninstall_report(report: &UninstallReport) -> String {
    fn line(label: &str, outcome: ArtifactOutcome) -> String {
        let text = match outcome {
            ArtifactOutcome::Removed => "видалено",
            ArtifactOutcome::NotPresent => "не було встановлено",
            ArtifactOutcome::Failed(_) => "НЕ ВДАЛОСЯ видалити",
        };
        format!("{label}: {text}")
    }
    [
        line("Сертифікат", report.cert),
        line("TLS-ключ", report.tls_key),
        line("Ключ шифрування", report.persistence_key),
        line("Креденшели MaxMind", report.maxmind_creds),
    ]
    .join("\n")
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
