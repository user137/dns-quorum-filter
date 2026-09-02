//! T-87 / T-88 — liveness voting over the per-channel [`ChannelStatus`] signals
//! (SPEC.md §7, `diagrams/watchdog-state.md`). Pure: given each channel's
//! current signal state, decide whether the peer counts as alive or dead for
//! this direction.
//!
//! Two fixed-arity functions, not one over `&[ChannelStatus]` — a slice plus an
//! internal `.is_empty()` check is the T-41 "config subset" footgun (a single
//! silent channel passed as a one-element slice could declare death, exactly the
//! false-positive restart the whole of §7 exists to prevent). With fixed
//! parameters, "couldn't read channel 2" has to be written at the call site as
//! [`ChannelStatus::NoSignal`] — visible, not vanished into a shorter slice.

use super::channel::ChannelStatus;

/// The voted verdict for one direction of the mutual watchdog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// The direction's vote rule is not met — the peer counts as alive.
    Alive,
    /// The direction's vote rule is met — the peer counts as dead.
    Dead,
}

/// Watcher → service: all three channels exist (IPC, heartbeat file, `/health`),
/// so the rule is **2-of-3** (SPEC.md §7). [`Liveness::Dead`] iff at least two
/// of the three report [`ChannelStatus::NoSignal`].
#[must_use]
pub fn vote_watcher_checks_service(
    ipc: ChannelStatus,
    file: ChannelStatus,
    health: ChannelStatus,
) -> Liveness {
    let silent = [ipc, file, health]
        .into_iter()
        .filter(|&status| status == ChannelStatus::NoSignal)
        .count();
    if silent >= 2 {
        Liveness::Dead
    } else {
        Liveness::Alive
    }
}

/// Service → watcher: only channels 1 and 2 exist (`/health` lives in the
/// service), so a 2-of-2 majority would trip on any single channel failure. The
/// rule is **unanimous** (SPEC.md §7): [`Liveness::Dead`] iff both channels
/// report [`ChannelStatus::NoSignal`].
#[must_use]
pub fn vote_service_checks_watcher(ipc: ChannelStatus, file: ChannelStatus) -> Liveness {
    if ipc == ChannelStatus::NoSignal && file == ChannelStatus::NoSignal {
        Liveness::Dead
    } else {
        Liveness::Alive
    }
}

#[cfg(test)]
mod tests {
    use super::super::channel::ChannelStatus::{NoSignal, Signal};
    use super::{vote_service_checks_watcher, vote_watcher_checks_service, Liveness};

    // Happy path: every channel reports a signal → alive, both directions.
    #[test]
    fn all_channels_signalling_is_alive() {
        assert_eq!(
            vote_watcher_checks_service(Signal, Signal, Signal),
            Liveness::Alive
        );
        assert_eq!(vote_service_checks_watcher(Signal, Signal), Liveness::Alive);
    }

    // T-94, 2-of-3 branch: two or three silent channels → dead; one silent, two
    // alive → not a restart.
    #[test]
    fn watcher_checks_service_is_two_of_three() {
        assert_eq!(
            vote_watcher_checks_service(NoSignal, NoSignal, Signal),
            Liveness::Dead
        );
        assert_eq!(
            vote_watcher_checks_service(NoSignal, NoSignal, NoSignal),
            Liveness::Dead
        );
        assert_eq!(
            vote_watcher_checks_service(NoSignal, Signal, Signal),
            Liveness::Alive
        );
    }

    // T-94, unanimous branch: both silent → dead; either one still signalling →
    // alive (the difference from a 2-of-2 majority, which would trip here).
    #[test]
    fn service_checks_watcher_is_unanimous() {
        assert_eq!(
            vote_service_checks_watcher(NoSignal, NoSignal),
            Liveness::Dead
        );
        assert_eq!(
            vote_service_checks_watcher(NoSignal, Signal),
            Liveness::Alive
        );
        assert_eq!(
            vote_service_checks_watcher(Signal, NoSignal),
            Liveness::Alive
        );
    }

    // Boundary: every arrangement of exactly two silent channels among three is
    // Dead — the `>= 2` rule is symmetric in the three positions.
    #[test]
    fn any_two_silent_of_three_is_dead() {
        for verdict in [
            vote_watcher_checks_service(NoSignal, NoSignal, Signal),
            vote_watcher_checks_service(NoSignal, Signal, NoSignal),
            vote_watcher_checks_service(Signal, NoSignal, NoSignal),
        ] {
            assert_eq!(verdict, Liveness::Dead);
        }
    }
}
