//! §7 / `diagrams/watchdog-state.md` — the liveness/restart automaton as one
//! pure function. Given the current state and this cycle's observations, return
//! the next state. Side effects (spawn, sleep, PID check) are **not** here — the
//! Батч 3.3 loop derives them from the returned state, which keeps that loop
//! pure wiring.

use super::budget::BudgetVerdict;
use super::pid_check::PidCheck;
use super::state::WatchdogState;
use super::vote::Liveness;

/// This cycle's observations, fed to [`transition`]. Each field is consulted
/// only in the state(s) that can act on it.
#[derive(Debug, Clone, Copy)]
pub struct TransitionInput {
    /// The direction's voted verdict (`vote_watcher_checks_service` /
    /// `vote_service_checks_watcher`).
    pub vote: Liveness,
    /// Whether at least one channel is over its miss threshold while the vote
    /// rule is *not* met — the `ChannelDegraded` condition.
    pub any_channel_degraded: bool,
    /// The PID check result — consulted only in [`WatchdogState::VerifyingPid`];
    /// `None` means "not run yet".
    pub pid: Option<PidCheck>,
    /// The restart-budget verdict for this attempt — consulted in
    /// [`WatchdogState::Restarting`] and [`WatchdogState::BackoffWait`]; `None`
    /// means "not registered yet".
    pub budget: Option<BudgetVerdict>,
    /// Whether the backoff wait has elapsed — consulted only in
    /// [`WatchdogState::BackoffWait`].
    pub backoff_elapsed: bool,
}

/// The next automaton state, given `current` and this cycle's `input`. Total —
/// every `(state, input)` returns a state, never panics. Each arm traces to an
/// edge of `diagrams/watchdog-state.md`.
#[must_use]
pub fn transition(current: WatchdogState, input: &TransitionInput) -> WatchdogState {
    use WatchdogState as S;
    match current {
        // Healthy / ChannelDegraded: the vote decides. Dead → suspect; else a
        // still-degraded channel holds us in ChannelDegraded, otherwise Healthy.
        S::Healthy | S::ChannelDegraded => match input.vote {
            Liveness::Dead => S::SuspectDead,
            Liveness::Alive if input.any_channel_degraded => S::ChannelDegraded,
            Liveness::Alive => S::Healthy,
        },
        // SuspectDead: always verify the PID before a restart (§7 "перед
        // перезапуском — перевірити, чи процес реально мертвий").
        S::SuspectDead => S::VerifyingPid,
        // VerifyingPid: a live matching PID is a false alarm; a gone or
        // mismatched (recycled) PID means restart; no result yet → keep waiting.
        S::VerifyingPid => match input.pid {
            Some(PidCheck::Alive) => {
                if input.vote == Liveness::Dead || input.any_channel_degraded {
                    S::ChannelDegraded
                } else {
                    S::Healthy
                }
            }
            Some(PidCheck::Gone | PidCheck::IdentityMismatch) => S::Restarting,
            None => S::VerifyingPid,
        },
        // Restarting: the budget verdict routes to backoff or the terminal
        // GaveUp; no verdict yet → still restarting.
        S::Restarting => match input.budget {
            Some(BudgetVerdict::Allowed) => S::BackoffWait,
            Some(BudgetVerdict::GaveUp) => S::GaveUp,
            None => S::Restarting,
        },
        // BackoffWait: the peer coming back ends it early; a budget already
        // spent goes terminal (the diagram's direct BackoffWait → GaveUp edge);
        // otherwise wait out the backoff, then re-verify.
        S::BackoffWait => {
            if input.vote == Liveness::Alive {
                S::Healthy
            } else if input.budget == Some(BudgetVerdict::GaveUp) {
                S::GaveUp
            } else if input.backoff_elapsed {
                S::VerifyingPid
            } else {
                S::BackoffWait
            }
        }
        // GaveUp is terminal — only a manual recovery leaves it (§7).
        S::GaveUp => S::GaveUp,
    }
}

#[cfg(test)]
mod tests {
    use super::{transition, TransitionInput};
    use crate::watchdog::budget::BudgetVerdict;
    use crate::watchdog::channel::ChannelStatus::{NoSignal, Signal};
    use crate::watchdog::pid_check::PidCheck;
    use crate::watchdog::state::WatchdogState as S;
    use crate::watchdog::vote::{vote_watcher_checks_service, Liveness};

    fn input() -> TransitionInput {
        TransitionInput {
            vote: Liveness::Alive,
            any_channel_degraded: false,
            pid: None,
            budget: None,
            backoff_elapsed: false,
        }
    }

    // Healthy / ChannelDegraded out-edges: the vote decides.
    #[test]
    fn healthy_and_degraded_follow_the_vote() {
        assert_eq!(transition(S::Healthy, &input()), S::Healthy);
        assert_eq!(
            transition(
                S::Healthy,
                &TransitionInput {
                    any_channel_degraded: true,
                    ..input()
                }
            ),
            S::ChannelDegraded
        );
        assert_eq!(
            transition(
                S::Healthy,
                &TransitionInput {
                    vote: Liveness::Dead,
                    ..input()
                }
            ),
            S::SuspectDead
        );
        assert_eq!(
            transition(
                S::ChannelDegraded,
                &TransitionInput {
                    any_channel_degraded: false,
                    ..input()
                }
            ),
            S::Healthy
        );
    }

    // T-93 end-to-end: one channel silent, two alive → the vote is Alive and the
    // automaton never advances toward a restart. This is the "no restart"
    // assertion, observable on the returned state (not just on `vote`).
    #[test]
    fn one_silent_channel_never_restarts() {
        let vote = vote_watcher_checks_service(NoSignal, Signal, Signal);
        assert_eq!(vote, Liveness::Alive);
        let observed = TransitionInput {
            vote,
            any_channel_degraded: true,
            ..input()
        };
        for from in [S::Healthy, S::ChannelDegraded] {
            let next = transition(from, &observed);
            assert_eq!(next, S::ChannelDegraded);
            assert!(!matches!(
                next,
                S::SuspectDead | S::VerifyingPid | S::Restarting | S::GaveUp
            ));
        }
    }

    // T-94 through the automaton: the vote rule met → SuspectDead, from either
    // Healthy or ChannelDegraded.
    #[test]
    fn vote_dead_reaches_suspect_dead() {
        let dead = TransitionInput {
            vote: Liveness::Dead,
            ..input()
        };
        assert_eq!(transition(S::Healthy, &dead), S::SuspectDead);
        assert_eq!(transition(S::ChannelDegraded, &dead), S::SuspectDead);
    }

    // SuspectDead always goes to VerifyingPid, whatever else is observed.
    #[test]
    fn suspect_dead_always_verifies_pid() {
        assert_eq!(transition(S::SuspectDead, &input()), S::VerifyingPid);
        assert_eq!(
            transition(
                S::SuspectDead,
                &TransitionInput {
                    vote: Liveness::Dead,
                    pid: Some(PidCheck::Gone),
                    ..input()
                }
            ),
            S::VerifyingPid
        );
    }

    // VerifyingPid out-edges: alive+matching is a false alarm (Healthy, or
    // ChannelDegraded if a channel is still silent); gone / mismatch → Restarting;
    // no result yet → stay.
    #[test]
    fn verifying_pid_routes_on_the_check_result() {
        assert_eq!(
            transition(
                S::VerifyingPid,
                &TransitionInput {
                    pid: Some(PidCheck::Alive),
                    ..input()
                }
            ),
            S::Healthy
        );
        assert_eq!(
            transition(
                S::VerifyingPid,
                &TransitionInput {
                    pid: Some(PidCheck::Alive),
                    any_channel_degraded: true,
                    ..input()
                }
            ),
            S::ChannelDegraded
        );
        assert_eq!(
            transition(
                S::VerifyingPid,
                &TransitionInput {
                    pid: Some(PidCheck::Gone),
                    ..input()
                }
            ),
            S::Restarting
        );
        assert_eq!(
            transition(
                S::VerifyingPid,
                &TransitionInput {
                    pid: Some(PidCheck::IdentityMismatch),
                    ..input()
                }
            ),
            S::Restarting
        );
        assert_eq!(
            transition(
                S::VerifyingPid,
                &TransitionInput {
                    pid: None,
                    ..input()
                }
            ),
            S::VerifyingPid
        );
    }

    // Restarting out-edges: the budget verdict routes to backoff, terminal, or
    // stay.
    #[test]
    fn restarting_routes_on_the_budget_verdict() {
        assert_eq!(
            transition(
                S::Restarting,
                &TransitionInput {
                    budget: Some(BudgetVerdict::Allowed),
                    ..input()
                }
            ),
            S::BackoffWait
        );
        assert_eq!(
            transition(
                S::Restarting,
                &TransitionInput {
                    budget: Some(BudgetVerdict::GaveUp),
                    ..input()
                }
            ),
            S::GaveUp
        );
        assert_eq!(
            transition(
                S::Restarting,
                &TransitionInput {
                    budget: None,
                    ..input()
                }
            ),
            S::Restarting
        );
    }

    // BackoffWait out-edges: peer back → Healthy; budget spent → GaveUp; backoff
    // elapsed → re-verify; otherwise keep waiting.
    #[test]
    fn backoff_wait_out_edges() {
        assert_eq!(transition(S::BackoffWait, &input()), S::Healthy);
        assert_eq!(
            transition(
                S::BackoffWait,
                &TransitionInput {
                    vote: Liveness::Dead,
                    budget: Some(BudgetVerdict::GaveUp),
                    ..input()
                }
            ),
            S::GaveUp
        );
        assert_eq!(
            transition(
                S::BackoffWait,
                &TransitionInput {
                    vote: Liveness::Dead,
                    backoff_elapsed: true,
                    ..input()
                }
            ),
            S::VerifyingPid
        );
        assert_eq!(
            transition(
                S::BackoffWait,
                &TransitionInput {
                    vote: Liveness::Dead,
                    ..input()
                }
            ),
            S::BackoffWait
        );
    }

    // GaveUp is terminal — every input holds it there.
    #[test]
    fn gave_up_is_terminal() {
        for observed in [
            input(),
            TransitionInput {
                vote: Liveness::Alive,
                pid: Some(PidCheck::Alive),
                budget: Some(BudgetVerdict::Allowed),
                backoff_elapsed: true,
                any_channel_degraded: false,
            },
        ] {
            assert_eq!(transition(S::GaveUp, &observed), S::GaveUp);
        }
    }
}
