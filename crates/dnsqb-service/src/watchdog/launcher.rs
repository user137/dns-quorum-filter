//! T-150 — the idempotent launcher decision: on startup `dnsqb-watcher` brings
//! up any sibling (`dnsqb-service`, `dnsqb-tray`) that isn't already running.
//! Pure: given the sibling's `<role>.pid` file (if any) and the PID-identity
//! check on it, decide whether to spawn. Idempotency comes from doing this
//! check **before** every spawn — a re-run of the autostart shortcut takes the
//! same path and duplicates nothing (SPEC.md §7). The final backstop against a
//! spawn race is the sibling's own single-instance guard in its `main`.

use super::instance::PidFile;
use super::pid_check::PidCheck;

/// What [`plan_launch`] decided for one sibling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchAction {
    /// A live process with a matching identity already holds this role — do
    /// nothing.
    AlreadyRunning,
    /// No live matching process — spawn the sibling.
    Spawn,
}

/// Decide whether to spawn a sibling, given its `<role>.pid` file (`None` if
/// absent/unreadable) and the [`PidCheck`] run against that file's PID and exe
/// identity (`None` if the check could not run).
///
/// Only a present pid file **and** a confirmed-[`PidCheck::Alive`] identity
/// counts as "already running"; every other combination — no file, a
/// [`PidCheck::Gone`] PID, a recycled [`PidCheck::IdentityMismatch`], or a
/// check that didn't run — resolves to [`LaunchAction::Spawn`]. Erring toward a
/// redundant spawn (which the sibling's own guard rejects harmlessly) is safer
/// than erring toward a missing service.
#[must_use]
pub fn plan_launch(pid_file: Option<&PidFile>, pid_check: Option<PidCheck>) -> LaunchAction {
    match (pid_file, pid_check) {
        (Some(_), Some(PidCheck::Alive)) => LaunchAction::AlreadyRunning,
        _ => LaunchAction::Spawn,
    }
}

#[cfg(test)]
mod tests {
    use super::{plan_launch, LaunchAction};
    use crate::watchdog::instance::PidFile;
    use crate::watchdog::pid_check::PidCheck;
    use std::path::PathBuf;
    use std::time::SystemTime;

    fn pid_file() -> PidFile {
        PidFile {
            pid: 4321,
            exe_path: PathBuf::from(r"C:\Program Files\dns-quorum-filter\dnsqb-service.exe"),
            started_at: SystemTime::UNIX_EPOCH,
        }
    }

    // Happy path: a present pid file plus a live, identity-matching process →
    // nothing to do.
    #[test]
    fn live_matching_sibling_is_already_running() {
        assert_eq!(
            plan_launch(Some(&pid_file()), Some(PidCheck::Alive)),
            LaunchAction::AlreadyRunning
        );
    }

    // Boundary: no pid file at all (first run, or it was never written) → spawn.
    #[test]
    fn absent_pid_file_means_spawn() {
        assert_eq!(plan_launch(None, None), LaunchAction::Spawn);
        assert_eq!(
            plan_launch(None, Some(PidCheck::Alive)),
            LaunchAction::Spawn,
            "a stray Alive with no pid file is still a spawn"
        );
    }

    // Misuse & fool: a pid file survives from a dead or PID-recycled process —
    // it must not block the sibling from coming back up.
    #[test]
    fn stale_or_recycled_pid_file_means_spawn() {
        assert_eq!(
            plan_launch(Some(&pid_file()), Some(PidCheck::Gone)),
            LaunchAction::Spawn
        );
        assert_eq!(
            plan_launch(Some(&pid_file()), Some(PidCheck::IdentityMismatch)),
            LaunchAction::Spawn
        );
    }

    // Error path: the PID check itself could not run — spawn rather than assume
    // the sibling is up (a redundant spawn is rejected by its own guard).
    #[test]
    fn pid_check_that_did_not_run_means_spawn() {
        assert_eq!(plan_launch(Some(&pid_file()), None), LaunchAction::Spawn);
    }
}
