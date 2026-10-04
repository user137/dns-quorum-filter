//! T-185 — deliberate stop / pause of the whole app, as two flag files in the
//! app-data directory.
//!
//! `/admin/shutdown` only terminates the `dnsqb-service` process; the watchdog
//! then respawns it within ~40 s. That is correct for a crash but wrong for a
//! user who meant "stop filtering" or "quit". These flags let the tray express
//! that intent to `dnsqb-watcher`:
//!
//! - **`stop.flag`** — pause. **Since T-193** (revising the original T-185
//!   design — see `DECISIONS.md` 2026-09-08) this no longer shuts the service
//!   down: `dnsqb-service` observes the flag itself (`pause_watch::
//!   run_pause_watcher` → `AppState::filtering_paused`) and serves every A/AAAA
//!   query through the **unfiltered baseline** while it exists — the service
//!   stays up, the watchdog keeps supervising it normally. The tray's
//!   "Призупинити фільтрацію" only *writes* the flag; "Відновити фільтрацію"
//!   removes it. The user's own allow/blocklist still apply during a pause;
//!   only quorum + `GeoIP` are bypassed.
//! - **`quit.flag`** — exit. On its next tick the watcher stops the service
//!   and exits the process itself, then the tray exits — the whole app is
//!   down until the next tile / login launch.
//!
//! **Who clears them:** the **entry-point process on startup** — `dnsqb-watcher`
//! `main` clears both, so a fresh launch is a clean slate (a pause does not
//! survive an app restart). The watchdog's heartbeat loop no longer special-
//! cases `stop.flag` at all (T-193) — the service staying up during a pause
//! makes the loop a no-op. A tile re-click that hits an already-running watcher
//! clears `quit.flag` only (the user relaunched → cancel a pending quit) but
//! leaves `stop.flag` (don't silently un-pause).
//!
//! **Хвиля 13b** adds two more one-shot flags, same "presence is the signal"
//! shape, for recovering from a service that will not start (DECISIONS.md
//! 2026-10-04):
//!
//! - **`retry.flag`** — written by the tray («Спробувати ще раз») or by a
//!   tile re-click while the watchdog is in `GaveUp`; the running watcher
//!   consumes it, resets its restart budget and starts the service again.
//! - **`reset-config.flag`** — written by the tray («Скинути налаштування»,
//!   together with `retry.flag`); `dnsqb-service` consumes it on startup and
//!   moves `resolver_config.toml` aside **only** when the previous attempt
//!   failed on an invalid config (`startup_failure::should_reset_config`).
//!
//! No flag here is `watchdog-state.json` — that file keeps its single-writer
//! invariant (§7.1 #7). A flag's *presence* is the whole signal; its contents
//! are not read.

use std::path::{Path, PathBuf};

/// File name of the pause flag under the app-data directory.
pub const STOP_FLAG_NAME: &str = "stop.flag";
/// File name of the quit flag under the app-data directory.
pub const QUIT_FLAG_NAME: &str = "quit.flag";

/// File name of the retry flag (хвиля 13b) under the app-data directory.
pub const RETRY_FLAG_NAME: &str = "retry.flag";
/// File name of the reset-config flag (хвиля 13b) under the app-data directory.
pub const RESET_CONFIG_FLAG_NAME: &str = "reset-config.flag";

fn flag_path(app_data_dir: &Path, name: &str) -> PathBuf {
    app_data_dir.join(name)
}

/// Create `stop.flag` (pause). The worst case of a failure is the watchdog
/// respawning a service the user asked to pause, which the user can retry —
/// so the caller logs and continues rather than aborting.
///
/// # Errors
///
/// The underlying [`std::fs::write`] error if the file cannot be created.
pub fn set_stop_flag(app_data_dir: &Path) -> std::io::Result<()> {
    std::fs::write(flag_path(app_data_dir, STOP_FLAG_NAME), [])
}

/// Remove `stop.flag` (resume). Absent is success.
pub fn clear_stop_flag(app_data_dir: &Path) {
    remove_if_present(&flag_path(app_data_dir, STOP_FLAG_NAME));
}

/// Whether `stop.flag` currently exists.
#[must_use]
pub fn stop_flag_is_set(app_data_dir: &Path) -> bool {
    flag_path(app_data_dir, STOP_FLAG_NAME).exists()
}

/// Create `quit.flag` (exit the whole app).
///
/// # Errors
///
/// The underlying [`std::fs::write`] error if the file cannot be created.
pub fn set_quit_flag(app_data_dir: &Path) -> std::io::Result<()> {
    std::fs::write(flag_path(app_data_dir, QUIT_FLAG_NAME), [])
}

/// Remove `quit.flag`. Absent is success.
pub fn clear_quit_flag(app_data_dir: &Path) {
    remove_if_present(&flag_path(app_data_dir, QUIT_FLAG_NAME));
}

/// Whether `quit.flag` currently exists.
#[must_use]
pub fn quit_flag_is_set(app_data_dir: &Path) -> bool {
    flag_path(app_data_dir, QUIT_FLAG_NAME).exists()
}

/// Create `retry.flag` — ask the running watcher to reset its restart budget
/// and start the service again.
///
/// # Errors
///
/// The underlying [`std::fs::write`] error if the file cannot be created.
pub fn set_retry_flag(app_data_dir: &Path) -> std::io::Result<()> {
    std::fs::write(flag_path(app_data_dir, RETRY_FLAG_NAME), [])
}

/// Consume `retry.flag`: `true` if it was present (and is now removed).
#[must_use]
pub fn take_retry_flag(app_data_dir: &Path) -> bool {
    take(&flag_path(app_data_dir, RETRY_FLAG_NAME))
}

/// Create `reset-config.flag` — ask the next service start to move an invalid
/// `resolver_config.toml` aside.
///
/// # Errors
///
/// The underlying [`std::fs::write`] error if the file cannot be created.
pub fn set_reset_config_flag(app_data_dir: &Path) -> std::io::Result<()> {
    std::fs::write(flag_path(app_data_dir, RESET_CONFIG_FLAG_NAME), [])
}

/// Consume `reset-config.flag`: `true` if it was present (and is now removed).
#[must_use]
pub(crate) fn take_reset_config_flag(app_data_dir: &Path) -> bool {
    take(&flag_path(app_data_dir, RESET_CONFIG_FLAG_NAME))
}

/// One-shot consume. A flag that exists but cannot be removed counts as **not**
/// taken (logged): acting on it would repeat every tick — for `retry.flag` a
/// silent restart loop, exactly what SPEC §7 forbids — while ignoring it only
/// leaves the user's click without effect, which they can see and retry.
fn take(path: &Path) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => {
            tracing::warn!("could not remove {}, ignoring it: {err}", path.display());
            false
        }
    }
}

fn remove_if_present(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        // A flag we can't remove would trap the app paused / quitting — loud,
        // but there is nothing to return it to.
        Err(err) => tracing::warn!("could not remove {}: {err}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        clear_quit_flag, clear_stop_flag, quit_flag_is_set, set_quit_flag, set_reset_config_flag,
        set_retry_flag, set_stop_flag, stop_flag_is_set, take_reset_config_flag, take_retry_flag,
    };

    #[test]
    fn retry_and_reset_config_flags_are_one_shot_and_independent() {
        let dir = tempdir();
        assert!(!take_retry_flag(dir.path()));
        if let Err(err) = set_retry_flag(dir.path()) {
            panic!("set: {err}");
        }
        assert!(
            !take_reset_config_flag(dir.path()),
            "retry does not imply reset"
        );
        assert!(take_retry_flag(dir.path()));
        assert!(!take_retry_flag(dir.path()), "consumed");
        if let Err(err) = set_reset_config_flag(dir.path()) {
            panic!("set: {err}");
        }
        assert!(take_reset_config_flag(dir.path()));
        assert!(!take_reset_config_flag(dir.path()), "consumed");
    }

    fn tempdir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("tempdir: {err}"),
        }
    }

    #[test]
    fn stop_flag_round_trips() {
        let dir = tempdir();
        assert!(!stop_flag_is_set(dir.path()));
        if let Err(err) = set_stop_flag(dir.path()) {
            panic!("set: {err}");
        }
        assert!(stop_flag_is_set(dir.path()));
        clear_stop_flag(dir.path());
        assert!(!stop_flag_is_set(dir.path()));
    }

    #[test]
    fn quit_flag_round_trips_and_the_two_are_independent() {
        let dir = tempdir();
        if let Err(err) = set_quit_flag(dir.path()) {
            panic!("set: {err}");
        }
        assert!(quit_flag_is_set(dir.path()));
        assert!(!stop_flag_is_set(dir.path()), "quit does not imply stop");
        clear_quit_flag(dir.path());
        assert!(!quit_flag_is_set(dir.path()));
    }

    #[test]
    fn clearing_an_absent_flag_is_not_an_error() {
        let dir = tempdir();
        clear_stop_flag(dir.path()); // must not panic
        clear_quit_flag(dir.path());
    }
}
