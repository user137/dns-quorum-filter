//! Хвиля 13b (ARCH-03, T-266) — why `dnsqb-service` last failed to start.
//!
//! Every deterministic startup failure (port in use, broken config,
//! certificate/key store, upstream client, single-instance lock) used to be a
//! bare `exit(1)` that the watchdog could not tell apart from a crash: five
//! pointless restarts, then `GaveUp`, with the reason only in `service.log`.
//! Now the service records the reason here before exiting, as a **closed
//! enum** — no free text, so nothing from a config file or an OS error string
//! ever reaches this file (§7.1 #7: no domains, nothing sensitive).
//!
//! **Single writer:** only `dnsqb-service` writes or clears this file (it is
//! not `watchdog-state.json`, whose single writer stays the watcher). The
//! service clears it right after taking its single-instance guard, so its
//! presence always means "the latest start attempt failed deterministically".
//! Readers: the watcher (do not spend the restart budget) and the tray (show
//! the reason and the one action).

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::listener::BindError;

/// File name under the app-data directory.
pub const STARTUP_ERROR_FILE_NAME: &str = "startup-error.json";

const SCHEMA_VERSION: u32 = 1;

/// Why the last `dnsqb-service` start attempt failed. Closed — a new cause is
/// a new variant, never a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StartupFailure {
    /// The configured `DoH` port is bound by another process (SPEC.md §1 — no
    /// silent fallback to a different port).
    PortInUse {
        /// The port that was already in use.
        port: u16,
    },
    /// Any other listener bind failure.
    BindFailed,
    /// `resolver_config.toml` exists but is empty, unparsable, or fails
    /// validation — the one cause the tray's «Скинути налаштування» answers.
    ConfigInvalid,
    /// `resolver_config.toml` exists but could not be read.
    ConfigUnreadable,
    /// The TLS certificate or its private key (OS secret store) is unavailable.
    CertificateUnavailable,
    /// The upstream `DoH` HTTP client could not be built.
    UpstreamClientFailed,
    /// The single-instance lock could not be taken (other than "already
    /// running", which is not a failure).
    InstanceLockFailed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupErrorFile {
    schema_version: u32,
    reason: StartupFailure,
}

impl StartupFailure {
    /// Classifies a listener bind error.
    pub(crate) fn from_bind_error(err: &BindError) -> Self {
        match err {
            BindError::AddrInUse(port) => Self::PortInUse { port: *port },
            BindError::Other { .. } => Self::BindFailed,
        }
    }

    /// Classifies a `resolver_config.toml` load error: an I/O error is
    /// "unreadable", everything else is "invalid" (resettable).
    pub(crate) fn from_config_error(err: &ConfigError) -> Self {
        match err {
            ConfigError::Io(_) => Self::ConfigUnreadable,
            _ => Self::ConfigInvalid,
        }
    }
}

/// Whether a pending `reset-config.flag` may move `resolver_config.toml`
/// aside: only when the previous start attempt failed on an invalid config.
/// A stale flag (double click, the tray's 2 s status lag, a crash between the
/// tray's two flag writes) must never wipe a config that loads fine.
#[must_use]
pub(crate) fn should_reset_config(flag_present: bool, previous: Option<StartupFailure>) -> bool {
    flag_present && previous == Some(StartupFailure::ConfigInvalid)
}

/// Start of a new attempt, called right after the single-instance guard is
/// held (so a second instance on its way to "already running" never gets
/// here): read the previous failure, clear the record, then honour a pending
/// `reset-config.flag` only through [`should_reset_config`].
pub(crate) fn begin_attempt(app_data_dir: &Path) {
    let previous = read(app_data_dir).ok();
    clear(app_data_dir);
    let flag = crate::lifecycle::take_reset_config_flag(app_data_dir);
    if !should_reset_config(flag, previous) {
        if flag {
            tracing::info!("ignoring reset-config.flag: the last start did not fail on the config");
        }
        return;
    }
    match crate::log_persist::move_aside(&app_data_dir.join("resolver_config.toml")) {
        Ok(orphan) => tracing::warn!("reset-config: moved the invalid config aside to {orphan:?}"),
        Err(err) => tracing::warn!("reset-config: could not move the invalid config aside: {err}"),
    }
}

/// Records `reason` as the latest startup failure (atomic replace).
///
/// # Errors
///
/// A serialisation or filesystem error.
pub fn write(app_data_dir: &Path, reason: StartupFailure) -> io::Result<()> {
    let file = StartupErrorFile {
        schema_version: SCHEMA_VERSION,
        reason,
    };
    let json = serde_json::to_vec(&file).map_err(io::Error::other)?;
    crate::paths::write_atomic(&app_data_dir.join(STARTUP_ERROR_FILE_NAME), &json)
}

/// Reads the latest recorded startup failure.
///
/// # Errors
///
/// `NotFound` when no failure is recorded; `InvalidData` for a malformed or
/// foreign-schema file (callers treat it as "no known reason").
pub fn read(app_data_dir: &Path) -> io::Result<StartupFailure> {
    let bytes = std::fs::read(app_data_dir.join(STARTUP_ERROR_FILE_NAME))?;
    let file: StartupErrorFile = serde_json::from_slice(&bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if file.schema_version == SCHEMA_VERSION {
        Ok(file.reason)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported startup-error.json schema version",
        ))
    }
}

/// Removes the record. Absent is success; any other failure is logged — a
/// leftover file only makes the watcher stop retrying on the next real crash,
/// which the user can retry from the tray.
pub(crate) fn clear(app_data_dir: &Path) {
    match std::fs::remove_file(app_data_dir.join(STARTUP_ERROR_FILE_NAME)) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => tracing::warn!("could not remove {STARTUP_ERROR_FILE_NAME}: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        begin_attempt, clear, read, should_reset_config, write, StartupFailure,
        STARTUP_ERROR_FILE_NAME,
    };
    use crate::config::ConfigError;
    use crate::listener::BindError;

    fn tempdir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("tempdir: {err}"),
        }
    }

    #[test]
    fn bind_errors_classify_with_the_port_kept_only_for_addr_in_use() {
        assert_eq!(
            StartupFailure::from_bind_error(&BindError::AddrInUse(4443)),
            StartupFailure::PortInUse { port: 4443 }
        );
        assert_eq!(
            StartupFailure::from_bind_error(&BindError::Other {
                port: 4443,
                source: std::io::Error::other("x"),
            }),
            StartupFailure::BindFailed
        );
    }

    #[test]
    fn config_errors_split_into_unreadable_and_invalid() {
        assert_eq!(
            StartupFailure::from_config_error(&ConfigError::Io(std::io::Error::other("x"))),
            StartupFailure::ConfigUnreadable
        );
        for err in [
            ConfigError::Empty,
            ConfigError::ZeroPort,
            ConfigError::TooLarge,
        ] {
            assert_eq!(
                StartupFailure::from_config_error(&err),
                StartupFailure::ConfigInvalid
            );
        }
    }

    #[test]
    fn reset_config_runs_only_for_a_flag_after_an_invalid_config() {
        assert!(should_reset_config(
            true,
            Some(StartupFailure::ConfigInvalid)
        ));
        assert!(!should_reset_config(
            false,
            Some(StartupFailure::ConfigInvalid)
        ));
        assert!(!should_reset_config(true, None));
        for other in [
            StartupFailure::PortInUse { port: 1 },
            StartupFailure::BindFailed,
            StartupFailure::ConfigUnreadable,
            StartupFailure::CertificateUnavailable,
            StartupFailure::UpstreamClientFailed,
            StartupFailure::InstanceLockFailed,
        ] {
            assert!(!should_reset_config(true, Some(other)), "{other:?}");
        }
    }

    #[test]
    fn the_record_round_trips_and_clears() {
        let dir = tempdir();
        assert_eq!(
            read(dir.path()).map_err(|err| err.kind()),
            Err(std::io::ErrorKind::NotFound)
        );
        for reason in [
            StartupFailure::PortInUse { port: 65535 },
            StartupFailure::ConfigInvalid,
        ] {
            if let Err(err) = write(dir.path(), reason) {
                panic!("write: {err}");
            }
            assert_eq!(read(dir.path()).ok(), Some(reason));
        }
        clear(dir.path());
        assert!(read(dir.path()).is_err());
        clear(dir.path()); // absent: no panic
    }

    fn write_config(dir: &std::path::Path, body: &str) {
        if let Err(err) = std::fs::write(dir.join("resolver_config.toml"), body) {
            panic!("fixture: {err}");
        }
    }

    fn orphans(dir: &std::path::Path) -> usize {
        match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("resolver_config.toml.orphaned-")
                })
                .count(),
            Err(err) => panic!("read_dir: {err}"),
        }
    }

    #[test]
    fn begin_attempt_moves_an_invalid_config_aside_on_request() {
        let dir = tempdir();
        write_config(dir.path(), "port = \"broken\"\n");
        if let Err(err) = write(dir.path(), StartupFailure::ConfigInvalid) {
            panic!("write: {err}");
        }
        if let Err(err) = crate::lifecycle::set_reset_config_flag(dir.path()) {
            panic!("flag: {err}");
        }
        begin_attempt(dir.path());
        assert!(!dir.path().join("resolver_config.toml").exists());
        assert_eq!(orphans(dir.path()), 1);
        assert!(
            read(dir.path()).is_err(),
            "record cleared for the new attempt"
        );
        assert!(
            !crate::lifecycle::take_reset_config_flag(dir.path()),
            "flag consumed"
        );
    }

    #[test]
    fn begin_attempt_ignores_a_stale_reset_flag_and_keeps_the_config() {
        for previous in [None, Some(StartupFailure::PortInUse { port: 4443 })] {
            let dir = tempdir();
            write_config(dir.path(), "port = 4443\n");
            if let Some(reason) = previous {
                if let Err(err) = write(dir.path(), reason) {
                    panic!("write: {err}");
                }
            }
            if let Err(err) = crate::lifecycle::set_reset_config_flag(dir.path()) {
                panic!("flag: {err}");
            }
            begin_attempt(dir.path());
            assert!(
                dir.path().join("resolver_config.toml").exists(),
                "{previous:?}"
            );
            assert_eq!(orphans(dir.path()), 0);
            assert!(
                !crate::lifecycle::take_reset_config_flag(dir.path()),
                "flag consumed"
            );
            assert!(read(dir.path()).is_err(), "record cleared");
        }
    }

    #[test]
    fn a_malformed_or_foreign_record_reads_as_invalid_data() {
        let dir = tempdir();
        let path = dir.path().join(STARTUP_ERROR_FILE_NAME);
        for bytes in [
            &b"{ not json"[..],
            br#"{"schema_version":99,"reason":{"kind":"bind_failed"}}"#,
            br#"{"schema_version":1,"reason":{"kind":"something_new"}}"#,
        ] {
            if let Err(err) = std::fs::write(&path, bytes) {
                panic!("fixture: {err}");
            }
            assert_eq!(
                read(dir.path()).map_err(|err| err.kind()),
                Err(std::io::ErrorKind::InvalidData)
            );
        }
    }
}
