//! T-89 — verify a peer PID before restarting it (SPEC.md §7 "перед
//! перезапуском — перевірити, чи процес реально мертвий (за PID, не тільки за
//! відсутністю heartbeat)"; §7.1 #3). Thin shell over `sysinfo`: reads the OS
//! process table without an `unsafe` FFI call of our own.
//!
//! Both the PID *and* the identity are checked. A bare "is PID N alive?" would
//! read a recycled PID — the OS handed our dead service's number to an
//! unrelated process — as "alive forever", and the watchdog would never restart
//! a service that really died: a silent permanent failure, worse than the
//! restart loop §7 devotes its failure-mode section to.

use std::ffi::OsStr;
use std::path::Path;

use sysinfo::{Pid, ProcessesToUpdate, System};

/// Result of [`verify_pid_alive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidCheck {
    /// A process with this PID is running and its executable matches the
    /// expected one — the heartbeat stall was a false alarm, do not restart.
    Alive,
    /// No process with this PID is running — restart.
    Gone,
    /// A process with this PID is running, but a *different* executable — a
    /// recycled PID (§7.1 #3) — restart.
    IdentityMismatch,
}

/// Check whether `pid` is a live process running `expected_exe`.
///
/// `expected_exe` is the absolute path recorded in the peer's `<role>.pid` file
/// (§7.1 #3). Identity is matched on the full executable path when the OS
/// exposes it; when it does not (`Process::exe()` can be `None` on Windows for
/// some processes), the file name is compared as a fallback.
#[must_use]
pub fn verify_pid_alive(pid: u32, expected_exe: &Path) -> PidCheck {
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[Pid::from_u32(pid)]), true);

    let Some(process) = system.process(Pid::from_u32(pid)) else {
        return PidCheck::Gone;
    };

    match process.exe() {
        Some(exe) if exe == expected_exe => PidCheck::Alive,
        Some(_) => PidCheck::IdentityMismatch,
        None => {
            let expected_name = expected_exe.file_name().unwrap_or(OsStr::new(""));
            if process.name() == expected_name {
                PidCheck::Alive
            } else {
                PidCheck::IdentityMismatch
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{verify_pid_alive, PidCheck};
    use std::path::{Path, PathBuf};

    fn current_exe() -> PathBuf {
        match std::env::current_exe() {
            Ok(path) => path,
            Err(err) => panic!("the test runner must have a resolvable exe path: {err}"),
        }
    }

    // Happy path: this very process, checked against its own exe path, is Alive.
    // (If the OS withholds the full path, the file-name fallback still matches.)
    #[test]
    fn own_process_against_own_exe_is_alive() {
        assert_eq!(
            verify_pid_alive(std::process::id(), &current_exe()),
            PidCheck::Alive
        );
    }

    // Error / boundary: a PID that is almost certainly not in use is Gone, not a
    // panic.
    #[test]
    fn an_unused_pid_is_gone() {
        assert_eq!(
            verify_pid_alive(u32::MAX - 1, Path::new("does-not-matter")),
            PidCheck::Gone
        );
    }

    // Misuse & fool: a live PID (our own) checked against a foreign exe path is
    // an IdentityMismatch — the recycled-PID case §7.1 #3 exists for.
    #[test]
    fn live_pid_with_a_foreign_exe_is_a_mismatch() {
        assert_eq!(
            verify_pid_alive(std::process::id(), Path::new("Z:\\nowhere\\other.exe")),
            PidCheck::IdentityMismatch
        );
    }

    // Concurrency & recovery: two back-to-back checks give the same answer — the
    // fresh `System` per call carries no stale state.
    #[test]
    fn repeated_checks_are_stable() {
        let pid = std::process::id();
        let exe = current_exe();
        assert_eq!(verify_pid_alive(pid, &exe), verify_pid_alive(pid, &exe));
    }
}
