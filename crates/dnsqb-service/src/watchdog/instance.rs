//! T-92 — single-instance guard + per-role pid file (SPEC.md §7.1 #2 / #3).
//!
//! The guard is an advisory lockfile opened with a fully exclusive share mode
//! (`share_mode(0)`): a second process opening the same `<role>.lock` while the
//! first still holds it gets `ERROR_SHARING_VIOLATION`, and the OS closes the
//! handle on exit — a crash included — so the lock frees itself with no orphan
//! state and no cleanup step. A per-user `%LOCALAPPDATA%` directory already
//! gives per-session isolation, so no `Global\`/`Local\` namespace and no
//! elevated privilege is needed (unlike a named mutex). SPEC.md §7.1 #2 records
//! the crates weighed and rejected.
//!
//! The pid file (`<role>.pid`, `{ pid, exe_path, started_at }` as JSON) is the
//! only source of a peer's PID once both processes are launched independently
//! at login (T-150) and neither holds a child handle. It is rewritten on every
//! start and deliberately not removed on exit — a stale file from a dead or
//! recycled PID is filtered out by the identity check the reader adds in Батч
//! 3.2 (T-89), so no cleanup step (and its own failure mode) is needed.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Which binary a guard / pid file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `dnsqb-service` — the `DoH` listener + quorum resolver.
    Service,
    /// `dnsqb-watcher` — the watchdog process.
    Watcher,
    /// `dnsqb-tray` — the tray-icon UI.
    Tray,
}

impl Role {
    /// Stable lowercase token used in the `<role>.lock` / `<role>.pid` file
    /// names.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Service => "service",
            Role::Watcher => "watcher",
            Role::Tray => "tray",
        }
    }
}

/// Why [`acquire`] could not take the lock.
#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    /// Another process of the same role already holds the lock.
    #[error("another {0} instance is already running")]
    AlreadyRunning(&'static str),
    /// The lockfile could not be opened for a reason other than a share
    /// violation.
    #[error("failed to open the instance lockfile: {0}")]
    Io(#[source] io::Error),
    /// This platform has no guard implementation yet — non-Windows, where the
    /// Фаза 6 port replaces this with `flock(LOCK_EX | LOCK_NB)`.
    #[error("single-instance guard is not implemented on this platform")]
    UnsupportedPlatform,
}

/// A held single-instance lock. Dropping it — or the process exiting, cleanly
/// or not — releases the lock, because the OS closes the underlying handle
/// either way.
#[derive(Debug)]
#[must_use = "dropping the guard immediately releases the single-instance lock"]
pub struct InstanceGuard {
    _file: File,
    path: PathBuf,
}

impl InstanceGuard {
    /// The lockfile path this guard holds.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// `ERROR_SHARING_VIOLATION` — returned by `CreateFile` when another handle
/// with an incompatible share mode is already open on the path.
#[cfg(windows)]
const ERROR_SHARING_VIOLATION: i32 = 32;

/// Acquire the single-instance lock for `role` under `app_data_dir`.
///
/// The guard is often the first thing to touch the app-data directory (it runs
/// before cert/config load — SPEC.md §7.1 #2), so it creates the directory if
/// it doesn't exist.
///
/// # Errors
///
/// [`GuardError::AlreadyRunning`] if another same-role process holds it,
/// [`GuardError::Io`] for a directory-creation or other open failure, and — on
/// a non-Windows target — [`GuardError::UnsupportedPlatform`].
#[cfg(windows)]
pub fn acquire(app_data_dir: &Path, role: Role) -> Result<InstanceGuard, GuardError> {
    use std::os::windows::fs::OpenOptionsExt;

    std::fs::create_dir_all(app_data_dir).map_err(GuardError::Io)?;
    let path = app_data_dir.join(format!("{}.lock", role.as_str()));
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .share_mode(0)
        .open(&path)
        .map_err(|err| {
            if err.raw_os_error() == Some(ERROR_SHARING_VIOLATION) {
                GuardError::AlreadyRunning(role.as_str())
            } else {
                GuardError::Io(err)
            }
        })?;
    Ok(InstanceGuard { _file: file, path })
}

/// Non-Windows stub — see the Windows implementation. The Фаза 6 port replaces
/// this with an `flock`-based guard behind the same signature.
///
/// # Errors
///
/// Always [`GuardError::UnsupportedPlatform`].
#[cfg(not(windows))]
pub fn acquire(_app_data_dir: &Path, _role: Role) -> Result<InstanceGuard, GuardError> {
    Err(GuardError::UnsupportedPlatform)
}

/// The on-disk contents of a `<role>.pid` file (§7.1 #3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PidFile {
    /// OS process id at the time the file was written.
    pub pid: u32,
    /// Absolute path of the running executable — the identity half of the
    /// recycled-PID check (Батч 3.2 / T-89).
    pub exe_path: PathBuf,
    /// When the process wrote this file.
    pub started_at: SystemTime,
}

/// Write this process's pid file for `role` under `app_data_dir`, overwriting
/// any previous one.
///
/// # Errors
///
/// Propagates a filesystem error from resolving the current executable path or
/// writing the file.
pub fn write_pid_file(app_data_dir: &Path, role: Role) -> io::Result<()> {
    let record = PidFile {
        pid: std::process::id(),
        exe_path: std::env::current_exe()?,
        started_at: SystemTime::now(),
    };
    let json = serde_json::to_vec_pretty(&record)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    std::fs::write(app_data_dir.join(format!("{}.pid", role.as_str())), json)
}

/// Read the `<role>.pid` file under `app_data_dir`.
///
/// # Errors
///
/// Propagates a filesystem error, or [`io::ErrorKind::InvalidData`] if the file
/// is not the expected JSON shape.
pub fn read_pid_file(app_data_dir: &Path, role: Role) -> io::Result<PidFile> {
    let bytes = std::fs::read(app_data_dir.join(format!("{}.pid", role.as_str())))?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(all(test, windows))]
mod tests {
    use super::{acquire, read_pid_file, write_pid_file, GuardError, Role};

    fn temp_dir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        }
    }

    // Happy path — including creating the app-data directory when it's absent
    // (the guard runs before anything else touches it, SPEC.md §7.1 #2).
    #[test]
    fn acquire_creates_the_directory_and_the_lockfile() {
        let dir = temp_dir();
        let app_data = dir.path().join("not-yet-created");
        let guard = match acquire(&app_data, Role::Service) {
            Ok(guard) => guard,
            Err(err) => panic!("first acquire must succeed: {err}"),
        };
        assert!(app_data.is_dir(), "the app-data directory must be created");
        assert!(guard.path().exists(), "the .lock file must exist");
        assert_eq!(
            guard.path().file_name().and_then(|n| n.to_str()),
            Some("service.lock")
        );
    }

    // Security & boundary: distinct roles use distinct files, so they never
    // contend with each other.
    #[test]
    fn two_roles_in_one_directory_do_not_contend() {
        let dir = temp_dir();
        let service = acquire(dir.path(), Role::Service);
        let watcher = acquire(dir.path(), Role::Watcher);
        assert!(
            service.is_ok() && watcher.is_ok(),
            "different roles, no clash"
        );
    }

    // Misuse & fool: a second same-role acquire while the first is live.
    #[test]
    fn a_second_same_role_acquire_is_rejected_while_the_first_is_held() {
        let dir = temp_dir();
        let _first = match acquire(dir.path(), Role::Service) {
            Ok(guard) => guard,
            Err(err) => panic!("first acquire must succeed: {err}"),
        };
        match acquire(dir.path(), Role::Service) {
            Err(GuardError::AlreadyRunning("service")) => {}
            Ok(_) => panic!("a second same-role acquire must be rejected"),
            Err(other) => panic!("expected AlreadyRunning, got {other}"),
        }
    }

    // Error path: the app-data path exists but is a file, so it can't be
    // created as a directory — an `Io` error, not `AlreadyRunning`.
    #[test]
    fn acquire_where_the_app_data_path_is_a_file_is_an_io_error() {
        let dir = temp_dir();
        let not_a_dir = dir.path().join("i-am-a-file");
        if let Err(err) = std::fs::write(&not_a_dir, b"x") {
            panic!("fixture write must succeed: {err}");
        }
        match acquire(&not_a_dir, Role::Service) {
            Err(GuardError::Io(_)) => {}
            Ok(_) => panic!("acquire under a file path must fail"),
            Err(other) => panic!("expected Io, got {other}"),
        }
    }

    // Concurrency & recovery: releasing the first guard frees the lock.
    #[test]
    fn dropping_the_guard_releases_the_lock_for_the_next_acquire() {
        let dir = temp_dir();
        {
            let _guard = match acquire(dir.path(), Role::Service) {
                Ok(guard) => guard,
                Err(err) => panic!("first acquire must succeed: {err}"),
            };
        }
        match acquire(dir.path(), Role::Service) {
            Ok(_) => {}
            Err(err) => panic!("acquire after release must succeed: {err}"),
        }
    }

    // Happy path: the pid file round-trips through its own reader, pinning the
    // on-disk format for the Батч 3.2 identity check.
    #[test]
    fn pid_file_round_trips_through_write_then_read() {
        let dir = temp_dir();
        if let Err(err) = write_pid_file(dir.path(), Role::Service) {
            panic!("write_pid_file must succeed: {err}");
        }
        let record = match read_pid_file(dir.path(), Role::Service) {
            Ok(record) => record,
            Err(err) => panic!("read_pid_file must succeed: {err}"),
        };
        assert_eq!(record.pid, std::process::id());
        match std::env::current_exe() {
            Ok(exe) => assert_eq!(record.exe_path, exe),
            Err(err) => panic!("current_exe must resolve in the test: {err}"),
        }
    }

    // Error path: reading an absent pid file, and writing into a missing
    // directory, both surface as `Err` rather than a panic.
    #[test]
    fn pid_file_errors_are_returned_not_panicked() {
        let dir = temp_dir();
        assert!(
            read_pid_file(dir.path(), Role::Watcher).is_err(),
            "an absent pid file must be an Err"
        );
        assert!(
            write_pid_file(&dir.path().join("nope"), Role::Watcher).is_err(),
            "a missing directory must be an Err"
        );
    }
}
