//! T-185 — deliberate stop / pause of the whole app, as two flag files in the
//! app-data directory.
//!
//! `/admin/shutdown` only terminates the `dnsqb-service` process; the watchdog
//! then respawns it within ~40 s. That is correct for a crash but wrong for a
//! user who meant "stop filtering" or "quit". These flags let the tray express
//! that intent to `dnsqb-watcher`:
//!
//! - **`stop.flag`** — pause. While it exists, the watchdog does **not**
//!   respawn a dead `dnsqb-service`. The tray's "Призупинити фільтрацію" writes
//!   it (then asks the service to shut down); "Відновити фільтрацію" removes it
//!   (then relaunches the service).
//! - **`quit.flag`** — exit. On its next tick the watcher stops the service
//!   and exits the process itself, then the tray exits — the whole app is
//!   down until the next tile / login launch.
//!
//! **Who clears them:** the **entry-point process on startup** — `dnsqb-watcher`
//! `main` clears both, so a fresh launch is a clean slate. The watchdog's
//! heartbeat loop only *reads* `stop.flag` (never clears it there — otherwise a
//! headless `dnsqb-watcher.exe` launch could never stay paused). A tile
//! re-click that hits an already-running watcher clears `quit.flag` only (the
//! user relaunched → cancel a pending quit) but leaves `stop.flag` (don't
//! silently un-pause).
//!
//! Neither flag is `watchdog-state.json` — that file keeps its single-writer
//! invariant (§7.1 #7). A flag's *presence* is the whole signal; its contents
//! are not read.

use std::path::{Path, PathBuf};

/// File name of the pause flag under the app-data directory.
pub const STOP_FLAG_NAME: &str = "stop.flag";
/// File name of the quit flag under the app-data directory.
pub const QUIT_FLAG_NAME: &str = "quit.flag";

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
        clear_quit_flag, clear_stop_flag, quit_flag_is_set, set_quit_flag, set_stop_flag,
        stop_flag_is_set,
    };

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
