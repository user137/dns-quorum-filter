//! §7.1 #5 — spawn a sibling binary by absolute path. The watchdog restarts a
//! peer with the `dnsqb-service` / `dnsqb-watcher` / `dnsqb-tray` executable
//! sitting next to the running one — **never** a `PATH` lookup (`PATH` is
//! attacker-influenceable input, not a constant — "Наскрізні вимоги"), and
//! never a path resolved against the current directory.
//!
//! [`resolve_sibling_path`] is pure — the current-exe path is a parameter.
//! [`spawn_sibling`] is the thin impure shell: it reads `current_exe()` and
//! spawns.

use std::path::{Path, PathBuf};

use super::instance::Role;

/// Why a sibling could not be spawned. Messages carry no paths — coarse only.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// The running executable's path is not absolute — refusing to resolve a
    /// sibling relative to the current directory.
    #[error("the current executable path is not absolute")]
    NotAbsolute,
    /// The running executable has no parent directory.
    #[error("the current executable has no parent directory")]
    NoParentDir,
    /// No sibling binary for that role sits next to the running executable.
    #[error("no sibling binary found for that role")]
    NotFound,
    /// `std::env::current_exe()` failed.
    #[error("could not resolve the current executable: {0}")]
    CurrentExe(#[source] std::io::Error),
    /// The spawn call itself failed.
    #[error("could not spawn the sibling process: {0}")]
    Spawn(#[source] std::io::Error),
}

/// The absolute path of the `role` binary sitting next to `current_exe`.
///
/// Pure. `current_exe` must be absolute (it is, from `std::env::current_exe()`
/// on every supported platform); a relative one is rejected rather than
/// resolved against the current directory. The `dnsqb-` prefix matches this
/// workspace's binary names (`crates/dnsqb-*/Cargo.toml`).
///
/// # Errors
///
/// [`SpawnError::NotAbsolute`] or [`SpawnError::NoParentDir`].
pub fn resolve_sibling_path(current_exe: &Path, role: Role) -> Result<PathBuf, SpawnError> {
    if !current_exe.is_absolute() {
        return Err(SpawnError::NotAbsolute);
    }
    let dir = current_exe.parent().ok_or(SpawnError::NoParentDir)?;
    Ok(dir.join(format!(
        "dnsqb-{}{}",
        role.as_str(),
        std::env::consts::EXE_SUFFIX
    )))
}

/// Spawn the `role` binary sitting next to the running executable.
///
/// # Errors
///
/// [`SpawnError::CurrentExe`] if the running exe path can't be resolved;
/// [`SpawnError::NotAbsolute`] / [`SpawnError::NoParentDir`] from
/// [`resolve_sibling_path`]; [`SpawnError::NotFound`] if no such file sits
/// there; [`SpawnError::Spawn`] if the OS refuses the spawn.
pub fn spawn_sibling(role: Role) -> Result<std::process::Child, SpawnError> {
    let current_exe = std::env::current_exe().map_err(SpawnError::CurrentExe)?;
    let target = resolve_sibling_path(&current_exe, role)?;
    if !target.is_file() {
        return Err(SpawnError::NotFound);
    }
    std::process::Command::new(&target)
        .spawn()
        .map_err(SpawnError::Spawn)
}

#[cfg(test)]
mod tests {
    use super::{resolve_sibling_path, spawn_sibling, SpawnError};
    use crate::watchdog::instance::Role;
    use std::path::Path;

    // Happy path: an absolute watcher path resolves to the service binary in the
    // same directory, with the platform's exe suffix.
    #[test]
    fn resolves_a_sibling_in_the_same_directory() {
        let dir = std::env::temp_dir();
        let watcher = dir.join(format!("dnsqb-watcher{}", std::env::consts::EXE_SUFFIX));
        let resolved = match resolve_sibling_path(&watcher, Role::Service) {
            Ok(path) => path,
            Err(err) => panic!("an absolute path must resolve: {err}"),
        };
        assert_eq!(resolved.parent(), Some(dir.as_path()));
        assert_eq!(
            resolved.file_name().and_then(|n| n.to_str()),
            Some(format!("dnsqb-service{}", std::env::consts::EXE_SUFFIX).as_str())
        );
    }

    // Boundary: each role maps to its own binary name.
    #[test]
    fn each_role_maps_to_its_own_binary() {
        let base = std::env::temp_dir().join(format!("dnsqb-x{}", std::env::consts::EXE_SUFFIX));
        for (role, stem) in [
            (Role::Service, "dnsqb-service"),
            (Role::Watcher, "dnsqb-watcher"),
            (Role::Tray, "dnsqb-tray"),
        ] {
            let resolved = match resolve_sibling_path(&base, role) {
                Ok(path) => path,
                Err(err) => panic!("{role:?}: {err}"),
            };
            let expected = format!("{stem}{}", std::env::consts::EXE_SUFFIX);
            assert_eq!(
                resolved.file_name().and_then(|n| n.to_str()),
                Some(expected.as_str())
            );
        }
    }

    // Error: a relative current-exe path is rejected, not resolved against the
    // working directory — the CWD-relative-spawn class §7.1 #5 excludes.
    #[test]
    fn a_relative_path_is_not_absolute() {
        match resolve_sibling_path(Path::new("dnsqb-watcher"), Role::Service) {
            Err(SpawnError::NotAbsolute) => {}
            other => panic!("expected NotAbsolute, got {other:?}"),
        }
    }

    // Error: an absolute path with no parent (a bare drive root on Windows).
    #[cfg(windows)]
    #[test]
    fn an_absolute_root_has_no_parent() {
        match resolve_sibling_path(Path::new("C:\\"), Role::Service) {
            Err(SpawnError::NoParentDir) => {}
            other => panic!("expected NoParentDir, got {other:?}"),
        }
    }

    // Misuse & fool: from the test binary (in `target/debug/deps/`), no
    // `dnsqb-service` executable sits alongside — NotFound, never a PATH or
    // CWD-relative spawn, never a bare Spawn error.
    #[test]
    fn spawn_from_the_test_binary_is_not_found() {
        match spawn_sibling(Role::Service) {
            Err(SpawnError::NotFound) => {}
            other => panic!("expected NotFound next to the test binary, got {other:?}"),
        }
    }
}
