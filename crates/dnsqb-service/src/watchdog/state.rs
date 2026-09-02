//! §7.1 #7 — `watchdog-state.json`: `dnsqb-watcher` is the single writer, the
//! tray and `/admin/status` are readers (Батч 3.3 / T-95). This module owns the
//! on-disk shape and its atomic read/write. The state machine that produces the
//! values is [`super::transition`]; `diagrams/watchdog-state.md` is the picture.

use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// How old `watchdog-state.json`'s mtime may be before a reader treats it as
/// "the watchdog is not running" and shows nothing rather than a stale state
/// (Три Б — never a fabricated `Healthy`). The watcher rewrites the file every
/// tick (`WATCHDOG_INTERVAL` = 5 s), so 3 missed rewrites is the threshold.
/// One definition, shared by every reader (`/admin/status`, the tray).
pub const WATCHDOG_STATE_STALE_AFTER: Duration = Duration::from_secs(15);

/// The watchdog automaton's state for one direction
/// (`diagrams/watchdog-state.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WatchdogState {
    /// Voting confirms the peer is alive.
    Healthy,
    /// At least one channel is over its miss threshold, but the vote rule is
    /// not met — "a channel failure, not a death".
    ChannelDegraded,
    /// The vote rule is met — the peer is suspected dead.
    SuspectDead,
    /// Checking the peer's PID before restarting (a heartbeat stall is not a
    /// death).
    VerifyingPid,
    /// Spawning the peer.
    Restarting,
    /// Waiting out the exponential backoff before the next check.
    BackoffWait,
    /// The restart budget for the window is spent — stopped, awaiting a manual
    /// recovery. Terminal.
    GaveUp,
}

/// Which peer a `watchdog-state.json` record is about (§7.1 #7). The watchdog
/// never targets the tray, so this is deliberately narrower than
/// [`super::instance::Role`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WatchdogTarget {
    /// The direction watching `dnsqb-service`.
    Service,
    /// The direction watching `dnsqb-watcher`.
    Watcher,
}

/// A coarse label for `last_error` — a closed enum, never free text, so a domain
/// name can never reach `watchdog-state.json` (§7.1 #7 "без доменів і без
/// чутливого"; same shape as `overrides::InvalidReason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WatchdogErrorLabel {
    /// The IPC pipe could not be reached this cycle.
    #[error("ipc pipe unavailable")]
    PipeUnavailable,
    /// The `/health` endpoint could not be reached this cycle.
    #[error("health endpoint unreachable")]
    HealthUnreachable,
    /// A restart spawn failed.
    #[error("spawn failed")]
    SpawnFailed,
    /// The PID check could not run.
    #[error("pid check failed")]
    PidCheckFailed,
    /// The restart budget for the window is exhausted.
    #[error("restart budget exhausted")]
    BudgetExhausted,
}

/// Schema version stamped into every written record.
pub const STATE_SCHEMA_VERSION: u32 = 1;

/// The `watchdog-state.json` file name under the app-data directory.
pub const STATE_FILE_NAME: &str = "watchdog-state.json";

/// The full on-disk record (§7.1 #7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchdogStateFile {
    /// On-disk schema version — [`STATE_SCHEMA_VERSION`] for anything this build
    /// wrote.
    pub schema_version: u32,
    /// The automaton's current state.
    pub state: WatchdogState,
    /// Which peer this record is about.
    pub target: WatchdogTarget,
    /// Restart attempts counted in the current budget window.
    pub restart_attempts_in_window: u32,
    /// When the current budget window opened, or `None` before the first
    /// restart.
    pub window_started_at: Option<SystemTime>,
    /// When `state` was last entered.
    pub last_transition_at: SystemTime,
    /// A coarse label for the most recent error, or `None`.
    pub last_error: Option<WatchdogErrorLabel>,
}

/// Write `file` to `<app_data_dir>/watchdog-state.json` atomically — a sibling
/// temp file plus a same-directory rename, so a reader never sees a
/// partially-written record (mirrors `geoip_updater::persist_atomically`).
///
/// # Errors
///
/// Propagates a serialisation or filesystem error.
pub fn write(app_data_dir: &Path, file: &WatchdogStateFile) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(file)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let target = app_data_dir.join(STATE_FILE_NAME);
    let tmp = app_data_dir.join(format!("{STATE_FILE_NAME}.tmp"));
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &target)
}

/// Read `<app_data_dir>/watchdog-state.json`.
///
/// # Errors
///
/// Propagates a filesystem error, or [`io::ErrorKind::InvalidData`] if the file
/// is not a valid record.
pub fn read(app_data_dir: &Path) -> io::Result<WatchdogStateFile> {
    let bytes = std::fs::read(app_data_dir.join(STATE_FILE_NAME))?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::{
        read, write, WatchdogErrorLabel, WatchdogState, WatchdogStateFile, WatchdogTarget,
        STATE_FILE_NAME, STATE_SCHEMA_VERSION,
    };
    use std::time::{Duration, SystemTime};

    fn temp_dir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        }
    }

    fn sample(last_error: Option<WatchdogErrorLabel>) -> WatchdogStateFile {
        WatchdogStateFile {
            schema_version: STATE_SCHEMA_VERSION,
            state: WatchdogState::BackoffWait,
            target: WatchdogTarget::Service,
            restart_attempts_in_window: 3,
            window_started_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            last_transition_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_042),
            last_error,
        }
    }

    // Happy path: a record round-trips through write then read unchanged —
    // pinning the on-disk format for T-95's readers.
    #[test]
    fn write_then_read_round_trips() {
        let dir = temp_dir();
        let original = sample(Some(WatchdogErrorLabel::HealthUnreachable));
        if let Err(err) = write(dir.path(), &original) {
            panic!("write must succeed: {err}");
        }
        match read(dir.path()) {
            Ok(loaded) => assert_eq!(loaded, original),
            Err(err) => panic!("read must succeed: {err}"),
        }
    }

    // Cross-module contract (advisor closing review): a spent RestartBudget goes
    // through the real write/read of watchdog-state.json and is reconstructed
    // via RestartBudget::restored from the two flat §7.1 #7 fields — the next
    // attempt in the same window must still be GaveUp, so a watcher restart does
    // not reset the budget.
    #[test]
    fn budget_survives_the_state_file_round_trip() {
        use crate::watchdog::budget::{BudgetVerdict, RestartBudget, MAX_RESTARTS_PER_WINDOW};

        let window_start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut budget = RestartBudget::default();
        for _ in 0..=MAX_RESTARTS_PER_WINDOW {
            budget.register_attempt(window_start);
        }

        let record = WatchdogStateFile {
            schema_version: STATE_SCHEMA_VERSION,
            state: WatchdogState::GaveUp,
            target: WatchdogTarget::Service,
            restart_attempts_in_window: budget.attempts_in_window(),
            window_started_at: budget.window_started_at(),
            last_transition_at: window_start,
            last_error: Some(WatchdogErrorLabel::BudgetExhausted),
        };

        let dir = temp_dir();
        if let Err(err) = write(dir.path(), &record) {
            panic!("write must succeed: {err}");
        }
        let loaded = match read(dir.path()) {
            Ok(loaded) => loaded,
            Err(err) => panic!("read must succeed: {err}"),
        };

        let mut reloaded =
            RestartBudget::restored(loaded.window_started_at, loaded.restart_attempts_in_window);
        assert_eq!(
            reloaded.register_attempt(window_start + Duration::from_secs(1)),
            BudgetVerdict::GaveUp,
            "a watcher restart must not hand back a fresh budget"
        );
    }

    // Boundary: `last_error` both absent and present round-trips; every state and
    // target serialises to SCREAMING_SNAKE_CASE.
    #[test]
    fn optional_error_and_enum_encodings() {
        let dir = temp_dir();
        for record in [
            sample(None),
            sample(Some(WatchdogErrorLabel::BudgetExhausted)),
        ] {
            if let Err(err) = write(dir.path(), &record) {
                panic!("write must succeed: {err}");
            }
            match read(dir.path()) {
                Ok(loaded) => assert_eq!(loaded, record),
                Err(err) => panic!("read must succeed: {err}"),
            }
        }

        for state in [
            WatchdogState::Healthy,
            WatchdogState::ChannelDegraded,
            WatchdogState::SuspectDead,
            WatchdogState::VerifyingPid,
            WatchdogState::Restarting,
            WatchdogState::BackoffWait,
            WatchdogState::GaveUp,
        ] {
            let encoded = match serde_json::to_string(&state) {
                Ok(text) => text,
                Err(err) => panic!("state must serialise: {err}"),
            };
            assert_eq!(
                encoded,
                encoded.to_uppercase(),
                "{state:?} not screaming-snake"
            );
        }
        match serde_json::to_string(&WatchdogTarget::Watcher) {
            Ok(text) => assert_eq!(text, "\"WATCHER\""),
            Err(err) => panic!("target must serialise: {err}"),
        }
    }

    // Misuse & fool: a foreign / corrupt file is an InvalidData error, not a
    // panic.
    #[test]
    fn a_corrupt_file_is_invalid_data() {
        let dir = temp_dir();
        if let Err(err) = std::fs::write(dir.path().join(STATE_FILE_NAME), b"{ not json") {
            panic!("fixture write must succeed: {err}");
        }
        match read(dir.path()) {
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidData),
            Ok(_) => panic!("a corrupt file must not read as a record"),
        }
    }

    // Error & recovery: a write into a missing directory fails; a successful
    // write leaves no `.tmp` sibling behind.
    #[test]
    fn write_errors_and_leaves_no_temp_file() {
        let dir = temp_dir();
        assert!(
            write(&dir.path().join("nope"), &sample(None)).is_err(),
            "a missing directory must be an Err"
        );

        if let Err(err) = write(dir.path(), &sample(None)) {
            panic!("write must succeed: {err}");
        }
        assert!(
            !dir.path().join(format!("{STATE_FILE_NAME}.tmp")).exists(),
            "the temp file must not survive a successful write"
        );
    }

    // Privacy: every `WatchdogErrorLabel` Display is a fixed string with no
    // interpolation — structurally incapable of carrying a domain.
    #[test]
    fn error_labels_are_fixed_strings() {
        for label in [
            WatchdogErrorLabel::PipeUnavailable,
            WatchdogErrorLabel::HealthUnreachable,
            WatchdogErrorLabel::SpawnFailed,
            WatchdogErrorLabel::PidCheckFailed,
            WatchdogErrorLabel::BudgetExhausted,
        ] {
            let rendered = label.to_string();
            assert!(
                !rendered.contains('{'),
                "{label:?} interpolates: {rendered}"
            );
            assert!(!rendered.is_empty());
        }
    }
}
