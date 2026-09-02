//! App-data directory resolution (T-50). Windows-only for now (DECISIONS.md,
//! 2026-08-25 — Phase 1 target platform); a cross-platform resolution (e.g.
//! via the `directories` crate) is Phase 2 scope (T-71), when a second
//! platform actually needs a different convention. Not `pub` — only
//! `cert.rs` needs this so far, but it's deliberately reusable for T-46/T-47
//! (override-list save), T-96/T-97 (log/cache persistence), and T-75
//! (`GeoIP` DB file) later, so those tasks don't each re-derive it.
//!
//! **`%LOCALAPPDATA%`, not `%APPDATA%`.** The former never roams across
//! machines/domain controllers; the latter can, by OS design, sync a
//! roaming profile's contents off the machine it was written on — the same
//! class of risk SPEC.md §2 already names for a rejected CA-based design
//! ("синхронізація папки в хмару" leaking a private key applies just as
//! much to a synced `%APPDATA%`).
//!
//! `app_data_dir`/`PathsError` are re-exported `pub` from `lib.rs` as of
//! T-143 — `main.rs` is a separate crate (the `[[bin]]` target) and needs a
//! real `pub` path to resolve the override-list file location, not just
//! `pub(crate)` visibility.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};

/// Errors resolving the app-data directory.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathsError {
    /// `%LOCALAPPDATA%` is not set in the environment.
    #[error("%LOCALAPPDATA% environment variable is not set")]
    LocalAppDataNotSet,
}

/// Pure decision logic, split out from [`app_data_dir`] so it's unit-testable
/// without mutating the real process environment — `std::env::set_var` is an
/// `unsafe fn` on this toolchain regardless of edition, which would conflict
/// with `#![forbid(unsafe_code)]` (applies to inline test modules too, same
/// crate).
pub(crate) fn resolve_app_data_dir(
    local_app_data: Option<OsString>,
) -> Result<PathBuf, PathsError> {
    let local_app_data = local_app_data.ok_or(PathsError::LocalAppDataNotSet)?;
    Ok(PathBuf::from(local_app_data).join("dns-quorum-filter"))
}

/// This app's local (non-roaming) app-data directory:
/// `%LOCALAPPDATA%\dns-quorum-filter`. Thin wrapper over
/// [`resolve_app_data_dir`] — not separately tested, trivial pass-through.
///
/// # Errors
///
/// Returns [`PathsError::LocalAppDataNotSet`] if `%LOCALAPPDATA%` isn't set
/// in the environment.
pub fn app_data_dir() -> Result<PathBuf, PathsError> {
    resolve_app_data_dir(env::var_os("LOCALAPPDATA"))
}

/// The first 8 bytes of `SHA-1(normalized app_data_dir)`, hex-encoded — the
/// per-install isolation suffix shared by the OS-secret-store entry names
/// ([`crate::key_store`]) and the watchdog IPC pipe name (SPEC.md §7.1 #1 / #6),
/// so a scratch instance in its own app-data directory never collides with a
/// real one.
///
/// The path is normalized before hashing — lowercased (Windows paths are
/// case-insensitive) and trailing separators stripped — so two processes that
/// resolve the same directory in slightly different textual forms
/// (`…\Local\dns-quorum-filter` vs `…\local\dns-quorum-filter\`) still derive the
/// same suffix. An 8.3 short path vs the long form would still diverge; every
/// caller resolves the directory from the same `%LOCALAPPDATA%` via
/// [`app_data_dir`], so that is a theoretical gap, not an observed one.
pub(crate) fn app_data_dir_hash(app_data_dir: &Path) -> String {
    use std::fmt::Write;

    let normalized = app_data_dir
        .to_string_lossy()
        .to_lowercase()
        .trim_end_matches(['/', '\\'])
        .to_owned();
    Sha1::digest(normalized.as_bytes()).iter().take(8).fold(
        String::with_capacity(16),
        |mut acc, byte| {
            // Writing a byte to a `String` via `write!` is infallible; the
            // `fmt::Error` branch is unreachable for this sink.
            let _ = write!(acc, "{byte:02x}");
            acc
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{app_data_dir_hash, resolve_app_data_dir, PathsError};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn resolves_under_the_given_local_app_data_root() {
        let resolved = resolve_app_data_dir(Some(OsString::from(r"C:\Users\x\AppData\Local")));
        assert_eq!(
            resolved,
            Ok(PathBuf::from(r"C:\Users\x\AppData\Local\dns-quorum-filter"))
        );
    }

    #[test]
    fn missing_local_app_data_is_an_explicit_error_not_a_guessed_fallback() {
        assert_eq!(
            resolve_app_data_dir(None),
            Err(PathsError::LocalAppDataNotSet)
        );
    }

    #[test]
    fn app_data_dir_hash_is_stable_case_and_trailing_separator_normalized() {
        let a = app_data_dir_hash(Path::new(r"C:\Users\x\AppData\Local\dns-quorum-filter"));
        let b = app_data_dir_hash(Path::new(r"c:\users\x\appdata\local\dns-quorum-filter\"));
        assert_eq!(a, b, "case and a trailing separator must normalize away");
        assert_eq!(a.len(), 16, "8 bytes, hex-encoded");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn app_data_dir_hash_differs_for_a_different_path() {
        assert_ne!(
            app_data_dir_hash(Path::new(r"C:\Users\x\AppData\Local\dns-quorum-filter")),
            app_data_dir_hash(Path::new(r"C:\Users\y\AppData\Local\dns-quorum-filter")),
        );
    }
}
