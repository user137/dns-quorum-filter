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
//! **Хвиля 14** adds the first flag in the other direction, **service → tray**:
//!
//! - **`remove-all.flag`** — written only by `POST /admin/request-remove-all`
//!   (the `/admin/ui` danger-zone button) and consumed only by the tray, which
//!   shows its own native confirm and then runs the same «Повністю видалити»
//!   path as its menu item. Its mtime is the request time: only a flag younger
//!   than [`REMOVE_ALL_FLAG_WINDOW`] is acted on, an older one is discarded.
//!
//! No flag here is `watchdog-state.json` — that file keeps its single-writer
//! invariant (§7.1 #7). A flag's *presence* is the whole signal; its contents
//! are not read.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// File name of the pause flag under the app-data directory.
pub const STOP_FLAG_NAME: &str = "stop.flag";
/// File name of the quit flag under the app-data directory.
pub const QUIT_FLAG_NAME: &str = "quit.flag";

/// File name of the retry flag (хвиля 13b) under the app-data directory.
pub const RETRY_FLAG_NAME: &str = "retry.flag";
/// File name of the reset-config flag (хвиля 13b) under the app-data directory.
pub const RESET_CONFIG_FLAG_NAME: &str = "reset-config.flag";
/// File name of the remove-all request flag (хвиля 14) under the app-data
/// directory.
pub const REMOVE_ALL_FLAG_NAME: &str = "remove-all.flag";
/// How long a `remove-all.flag` stays actionable. The tray checks once a
/// second, so a live tray consumes it well inside this window.
pub const REMOVE_ALL_FLAG_WINDOW: Duration = Duration::from_secs(30);

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

/// Create (or re-stamp) `remove-all.flag` — ask the running tray to confirm and
/// run «Повністю видалити». The mtime is set explicitly: it is the request's
/// timestamp, and truncating an existing empty file need not update it.
///
/// # Errors
///
/// The underlying I/O error if the file cannot be created or stamped.
pub fn set_remove_all_flag(app_data_dir: &Path) -> std::io::Result<()> {
    std::fs::File::create(flag_path(app_data_dir, REMOVE_ALL_FLAG_NAME))?
        .set_modified(SystemTime::now())
}

/// What [`take_remove_all_flag`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveAllTake {
    /// No flag (or one that could not be removed — acting on it would prompt
    /// again every tick).
    Absent,
    /// A flag younger than [`REMOVE_ALL_FLAG_WINDOW`], now removed — act on it.
    Fresh,
    /// A flag that is too old, from the future, or without a readable mtime,
    /// now removed — ignore it.
    Stale,
}

/// Consume `remove-all.flag`. Only a [`RemoveAllTake::Fresh`] one may raise
/// the destructive confirm: a leftover from a click minutes ago must never pop
/// up later, and "no prompt" is the safe error — the user just clicks again.
#[must_use]
pub fn take_remove_all_flag(app_data_dir: &Path, now: SystemTime) -> RemoveAllTake {
    let path = flag_path(app_data_dir, REMOVE_ALL_FLAG_NAME);
    let mtime = match std::fs::metadata(&path).and_then(|meta| meta.modified()) {
        Ok(mtime) => Some(mtime),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return RemoveAllTake::Absent,
        Err(_) => None,
    };
    if !take(&path) {
        return RemoveAllTake::Absent;
    }
    match mtime {
        Some(mtime) if is_fresh(now, mtime, REMOVE_ALL_FLAG_WINDOW) => RemoveAllTake::Fresh,
        _ => {
            tracing::info!("ignored a stale {REMOVE_ALL_FLAG_NAME}");
            RemoveAllTake::Stale
        }
    }
}

/// `mtime` is at most `window` old as of `now`; a future `mtime` is not fresh.
fn is_fresh(now: SystemTime, mtime: SystemTime, window: Duration) -> bool {
    now.duration_since(mtime)
        .is_ok_and(|elapsed| elapsed <= window)
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
        clear_quit_flag, clear_stop_flag, quit_flag_is_set, set_quit_flag, set_remove_all_flag,
        set_reset_config_flag, set_retry_flag, set_stop_flag, stop_flag_is_set,
        take_remove_all_flag, take_reset_config_flag, take_retry_flag, RemoveAllTake,
        REMOVE_ALL_FLAG_WINDOW,
    };
    use std::time::{Duration, SystemTime};

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

    fn remove_all_mtime(dir: &std::path::Path) -> SystemTime {
        match std::fs::metadata(dir.join(super::REMOVE_ALL_FLAG_NAME)).and_then(|m| m.modified()) {
            Ok(mtime) => mtime,
            Err(err) => panic!("mtime: {err}"),
        }
    }

    #[test]
    fn a_fresh_remove_all_flag_is_taken_once() {
        let dir = tempdir();
        assert_eq!(
            take_remove_all_flag(dir.path(), SystemTime::now()),
            RemoveAllTake::Absent
        );
        if let Err(err) = set_remove_all_flag(dir.path()) {
            panic!("set: {err}");
        }
        let now = remove_all_mtime(dir.path()) + Duration::from_secs(1);
        assert_eq!(take_remove_all_flag(dir.path(), now), RemoveAllTake::Fresh);
        assert_eq!(
            take_remove_all_flag(dir.path(), now),
            RemoveAllTake::Absent,
            "consumed"
        );
    }

    #[test]
    fn an_old_remove_all_flag_is_removed_but_never_acted_on() {
        let dir = tempdir();
        if let Err(err) = set_remove_all_flag(dir.path()) {
            panic!("set: {err}");
        }
        let now = remove_all_mtime(dir.path()) + REMOVE_ALL_FLAG_WINDOW + Duration::from_secs(1);
        assert_eq!(take_remove_all_flag(dir.path(), now), RemoveAllTake::Stale);
        assert_eq!(
            take_remove_all_flag(dir.path(), now),
            RemoveAllTake::Absent,
            "a stale flag is removed too"
        );
    }

    #[test]
    fn a_remove_all_flag_from_the_future_is_not_fresh() {
        let dir = tempdir();
        if let Err(err) = set_remove_all_flag(dir.path()) {
            panic!("set: {err}");
        }
        let now = remove_all_mtime(dir.path()) - Duration::from_secs(60);
        assert_eq!(take_remove_all_flag(dir.path(), now), RemoveAllTake::Stale);
    }

    #[test]
    fn rewriting_the_remove_all_flag_refreshes_its_mtime() {
        let dir = tempdir();
        let path = dir.path().join(super::REMOVE_ALL_FLAG_NAME);
        if let Err(err) = std::fs::write(&path, []) {
            panic!("write: {err}");
        }
        let old = SystemTime::now() - Duration::from_secs(3600);
        match std::fs::File::options().write(true).open(&path) {
            Ok(file) => {
                if let Err(err) = file.set_modified(old) {
                    panic!("set_modified: {err}");
                }
            }
            Err(err) => panic!("open: {err}"),
        }
        if let Err(err) = set_remove_all_flag(dir.path()) {
            panic!("set: {err}");
        }
        assert_eq!(
            take_remove_all_flag(dir.path(), SystemTime::now()),
            RemoveAllTake::Fresh
        );
    }

    #[test]
    fn clearing_an_absent_flag_is_not_an_error() {
        let dir = tempdir();
        clear_stop_flag(dir.path()); // must not panic
        clear_quit_flag(dir.path());
    }
}
