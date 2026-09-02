//! T-85 — watchdog channel 2: a shared heartbeat file whose `mtime` is the
//! signal (SPEC.md §7.1 #4). Each side periodically re-touches its own
//! `<role>.hb`; the peer reads the other's `mtime` and applies the pure
//! [`is_stale`] predicate — `now - mtime > threshold`, nothing more (§7:
//! "the simplest"). The file body is a fixed marker (magic + schema version +
//! role); a fresh `mtime` on a file whose marker does not match is "no signal"
//! (channel 2 reports [`ChannelStatus::NoSignal`](super::channel::ChannelStatus)),
//! never a death.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::instance::Role;

/// Fixed marker prefix — `"dnsqb-heartbeat v<schema> "` — followed by the
/// writer's role and a newline.
const MAGIC: &str = "dnsqb-heartbeat";

/// On-disk schema version of the marker line.
const SCHEMA_VERSION: u32 = 1;

/// The fixed marker bytes a `<role>.hb` file carries.
fn marker_bytes(role: Role) -> Vec<u8> {
    format!("{MAGIC} v{SCHEMA_VERSION} {}\n", role.as_str()).into_bytes()
}

/// What [`read`] found in a heartbeat file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatFile {
    /// The `MAGIC` + schema-version prefix is present and current.
    pub marker_ok: bool,
    /// The role token that followed the prefix, if it named a known role.
    pub role: Option<Role>,
    /// The file's last-modification time — the actual liveness signal.
    pub mtime: SystemTime,
}

/// Re-touch this process's `<role>.hb` under `app_data_dir`, rewriting the
/// fixed marker (a plain overwrite — no atomic rename, §7.1 #4).
///
/// # Errors
///
/// Propagates any filesystem error from the write.
pub fn touch(app_data_dir: &Path, role: Role) -> io::Result<()> {
    fs::write(
        app_data_dir.join(format!("{}.hb", role.as_str())),
        marker_bytes(role),
    )
}

/// Read a heartbeat file's marker and `mtime`.
///
/// # Errors
///
/// Propagates any filesystem error from reading the file or its metadata.
pub fn read(path: &Path) -> io::Result<HeartbeatFile> {
    let mtime = fs::metadata(path)?.modified()?;
    let bytes = fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);

    let prefix = format!("{MAGIC} v{SCHEMA_VERSION} ");
    let (marker_ok, role) = match text.strip_prefix(&prefix) {
        Some(rest) => (true, parse_role(rest.trim_end())),
        None => (false, None),
    };
    Ok(HeartbeatFile {
        marker_ok,
        role,
        mtime,
    })
}

fn parse_role(token: &str) -> Option<Role> {
    [Role::Service, Role::Watcher, Role::Tray]
        .into_iter()
        .find(|role| role.as_str() == token)
}

/// Whether a heartbeat last written at `mtime` is stale as of `now`.
///
/// An `mtime` in the future — clock skew between the two processes — is
/// treated as *not* stale (`duration_since` returns `Err`, [`Result::is_ok_and`]
/// is `false`).
#[must_use]
pub fn is_stale(now: SystemTime, mtime: SystemTime, threshold: Duration) -> bool {
    now.duration_since(mtime)
        .is_ok_and(|elapsed| elapsed > threshold)
}

#[cfg(test)]
mod tests {
    use super::{is_stale, read, touch, Role};
    use std::time::{Duration, SystemTime};

    fn temp_dir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        }
    }

    // Happy path: a just-touched file reads back with a good marker, its role,
    // and is not stale.
    #[test]
    fn touch_then_read_is_fresh_and_well_formed() {
        let dir = temp_dir();
        if let Err(err) = touch(dir.path(), Role::Service) {
            panic!("touch must succeed: {err}");
        }
        let hb = match read(&dir.path().join("service.hb")) {
            Ok(hb) => hb,
            Err(err) => panic!("read must succeed: {err}"),
        };
        assert!(hb.marker_ok);
        assert_eq!(hb.role, Some(Role::Service));
        assert!(!is_stale(
            SystemTime::now(),
            hb.mtime,
            Duration::from_secs(5)
        ));
    }

    // Boundary: exactly at the threshold is not stale; a future mtime is not
    // stale; well past the threshold is stale.
    #[test]
    fn is_stale_threshold_future_and_past() {
        let now = SystemTime::now();
        let threshold = Duration::from_secs(5);

        assert!(!is_stale(now, now, threshold), "zero elapsed is not stale");

        let future = now + Duration::from_secs(10);
        assert!(!is_stale(now, future, threshold), "clock skew is not stale");

        let Some(past) = now.checked_sub(Duration::from_secs(6)) else {
            panic!("checked_sub must succeed for a recent SystemTime");
        };
        assert!(is_stale(now, past, threshold), "6s > 5s is stale");
    }

    // Misuse & fool: a foreign or truncated file with a perfectly fresh mtime
    // is "marker not ok" (→ NoSignal), never treated as a valid heartbeat.
    #[test]
    fn a_foreign_or_truncated_file_has_no_valid_marker() {
        let dir = temp_dir();

        let foreign = dir.path().join("service.hb");
        if let Err(err) = std::fs::write(&foreign, b"totally unrelated bytes") {
            panic!("fixture write must succeed: {err}");
        }
        match read(&foreign) {
            Ok(hb) => assert!(!hb.marker_ok && hb.role.is_none()),
            Err(err) => panic!("read must succeed: {err}"),
        }

        let truncated = dir.path().join("watcher.hb");
        if let Err(err) = std::fs::write(&truncated, b"dnsqb-hea") {
            panic!("fixture write must succeed: {err}");
        }
        match read(&truncated) {
            Ok(hb) => assert!(!hb.marker_ok),
            Err(err) => panic!("read must succeed: {err}"),
        }

        let unknown_role = dir.path().join("tray.hb");
        if let Err(err) = std::fs::write(&unknown_role, b"dnsqb-heartbeat v1 bogus\n") {
            panic!("fixture write must succeed: {err}");
        }
        match read(&unknown_role) {
            Ok(hb) => assert!(hb.marker_ok && hb.role.is_none(), "prefix ok, role unknown"),
            Err(err) => panic!("read must succeed: {err}"),
        }
    }

    // Error path: a missing file and a write into a missing directory both
    // return `Err` rather than panicking.
    #[test]
    fn missing_paths_are_errors_not_panics() {
        let dir = temp_dir();
        assert!(read(&dir.path().join("absent.hb")).is_err());
        assert!(touch(&dir.path().join("no-such-subdir"), Role::Service).is_err());
    }
}
