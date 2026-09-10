//! T-184 — file logging for the three `dnsqb-*` binaries.
//!
//! `windows_subsystem = "windows"` (T-181) removed the console, so a release
//! build otherwise produces no diagnostics at all. [`init`] points `tracing`
//! at one INFO-level file per binary — `<app-data>/logs/<role>.log` — rotated
//! to `.log.old` once at each process start if it already exceeds
//! [`MAX_LOG_BYTES`]. There is no in-process ceiling: a binary that runs for
//! days (the watcher) keeps appending to one `<role>.log` until it next
//! restarts — acceptable only because every log site in this workspace is a
//! rare lifecycle/error event, not a hot path. Debug builds additionally keep
//! stdout, so `cargo run` is unchanged.
//!
//! **No domain names reach `tracing`** anywhere in this workspace — every
//! network-path error site logs a coarse `error_kind()` label, never a raw
//! `reqwest::Error` whose `Display` embeds the `DoH` request URL (i.e. the
//! queried domain). Re-checked at T-184 before this file sink landed. So the
//! log file carries lifecycle/error events only and is safe to keep on disk
//! unencrypted (unlike `query-log.enc`, which is the domain history).

use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::sync::Arc;

/// Size threshold checked **once, at process start** (from [`init`] via
/// `prepare_log_file`): if `<role>.log` already exceeds it, rename to
/// `<role>.log.old` (replacing any previous `.old`) and open fresh. Not a
/// live cap — nothing re-checks the size while the process runs, so a
/// long-lived binary's `<role>.log` grows unbounded until its next restart.
pub const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

/// Install the process-global `tracing` subscriber for a binary.
///
/// `role` is the log-file stem (`"dnsqb-service"` / `"dnsqb-watcher"` /
/// `"dnsqb-tray"`). `app_data_dir` is `None` only when `%LOCALAPPDATA%` could
/// not be resolved — then this degrades to a plain stdout subscriber (which,
/// under `windows_subsystem = "windows"`, simply goes nowhere) rather than
/// failing.
///
/// Best-effort throughout: a logging-setup problem must never stop the binary
/// from starting. Call exactly once, as early in `main` as the app-data path
/// is known.
pub fn init(role: &str, app_data_dir: Option<&Path>) {
    let file = app_data_dir
        .and_then(|dir| prepare_log_file(role, dir))
        .map(Arc::new);

    match file {
        Some(file) => {
            #[cfg(debug_assertions)]
            {
                use tracing_subscriber::fmt::writer::MakeWriterExt;
                tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_max_level(tracing::Level::INFO)
                    .with_writer(file.and(std::io::stdout))
                    .init();
            }
            #[cfg(not(debug_assertions))]
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(file)
                .init();
        }
        None => {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .init();
        }
    }
}

/// Ensure `<app-data>/logs/` exists, rotate an oversized `<role>.log`, and
/// return an append handle to it. `None` on any I/O failure — the caller then
/// falls back to a console subscriber.
fn prepare_log_file(role: &str, app_data_dir: &Path) -> Option<File> {
    let dir = app_data_dir.join("logs");
    fs::create_dir_all(&dir).ok()?;

    let path = dir.join(format!("{role}.log"));
    let too_big = fs::metadata(&path).map_or(0, |meta| meta.len()) > MAX_LOG_BYTES;
    if too_big {
        // Best-effort: if the rename fails we still append to the existing file.
        let _ = fs::rename(&path, dir.join(format!("{role}.log.old")));
    }

    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::{prepare_log_file, MAX_LOG_BYTES};
    use std::fs;

    fn tempdir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("could not create a tempdir: {err}"),
        }
    }

    // Happy path: a first run with no existing log just creates `logs/<role>.log`.
    #[test]
    fn creates_the_log_file_on_a_first_run() {
        let dir = tempdir();
        let file = prepare_log_file("dnsqb-test", dir.path());
        assert!(
            file.is_some(),
            "a writable app-data dir must yield a handle"
        );
        assert!(dir.path().join("logs").join("dnsqb-test.log").is_file());
        assert!(!dir.path().join("logs").join("dnsqb-test.log.old").exists());
    }

    // Boundary: a log already past the cap is rotated to `.old`, and the new
    // handle points at a fresh (empty) `.log`.
    #[test]
    fn rotates_an_oversized_log_to_old() {
        let dir = tempdir();
        let logs = dir.path().join("logs");
        if let Err(err) = fs::create_dir_all(&logs) {
            panic!("mkdir logs: {err}");
        }
        let log = logs.join("dnsqb-test.log");
        let oversized = vec![b'x'; usize::try_from(MAX_LOG_BYTES).unwrap_or(usize::MAX) + 1];
        if let Err(err) = fs::write(&log, &oversized) {
            panic!("seed oversized log: {err}");
        }

        let handle = prepare_log_file("dnsqb-test", dir.path());
        assert!(handle.is_some());
        assert!(
            logs.join("dnsqb-test.log.old").is_file(),
            "old log kept aside"
        );
        match fs::metadata(&log) {
            Ok(meta) => assert_eq!(meta.len(), 0, "the live log is fresh after rotation"),
            Err(err) => panic!("live log missing after rotation: {err}"),
        }
    }

    // Error path: an app-data path that can't hold a `logs/` dir (a file sits
    // where the dir would go) yields `None`, not a panic — the caller then
    // falls back to a console subscriber.
    #[test]
    fn returns_none_when_the_logs_dir_cannot_be_created() {
        let dir = tempdir();
        if let Err(err) = fs::write(dir.path().join("logs"), b"not a dir") {
            panic!("seed blocking file: {err}");
        }
        assert!(prepare_log_file("dnsqb-test", dir.path()).is_none());
    }
}
