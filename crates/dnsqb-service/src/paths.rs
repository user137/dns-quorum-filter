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
use std::path::PathBuf;

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

#[cfg(test)]
mod tests {
    use super::{resolve_app_data_dir, PathsError};
    use std::ffi::OsString;
    use std::path::PathBuf;

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
}
