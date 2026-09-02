//! §7 / `diagrams/watchdog-state.md` — one direction's heartbeat loop as a
//! pure, time-injected state owner. [`LoopDriver::tick`] takes this cycle's raw
//! channel observations and returns the next [`WatchdogState`] plus the
//! side-effects the caller must run ([`Effect`]). It owns the per-channel miss
//! counters, the per-target [`RestartBudget`], the backoff deadline and the
//! spawn-once latch; it composes [`channel_status`] → [`vote_watcher_checks_service`]
//! / [`vote_service_checks_watcher`] → [`transition`]. No I/O — the pipe, the
//! heartbeat files, the PID check, the spawn and the `watchdog-state.json` write
//! all live in the two `main.rs` shells that drive this.
//!
//! Батч 3.2 built `transition` (one automaton step) and deliberately left the
//! loop-level T-93 / T-94 assertions to this batch; they live in this module's
//! tests.

use std::time::SystemTime;

use super::backoff::next_backoff;
use super::budget::{BudgetVerdict, RestartBudget};
use super::channel::{channel_status, ChannelStatus};
use super::pid_check::PidCheck;
use super::state::{
    WatchdogErrorLabel, WatchdogState, WatchdogStateFile, WatchdogTarget, STATE_SCHEMA_VERSION,
};
use super::transition::{transition, TransitionInput};
use super::vote::{vote_service_checks_watcher, vote_watcher_checks_service, Liveness};

/// Which peer this driver instance watches — decides the channel count and the
/// vote rule (`diagrams/watchdog-state.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Watcher → service: three channels (IPC, file, `/health`), **2-of-3**
    /// vote. This direction persists `watchdog-state.json` (§7.1 #7).
    WatcherToService,
    /// Service → watcher: two channels (IPC, file), **unanimous** vote. This
    /// direction runs in-memory only — the service is not a writer of
    /// `watchdog-state.json` (§7.1 #7).
    ServiceToWatcher,
}

impl Direction {
    fn target(self) -> WatchdogTarget {
        match self {
            Direction::WatcherToService => WatchdogTarget::Service,
            Direction::ServiceToWatcher => WatchdogTarget::Watcher,
        }
    }
}

/// This cycle's raw per-channel observations, gathered by the I/O shell.
#[derive(Debug, Clone, Copy)]
pub struct ChannelObs {
    /// Channel 1 (IPC): a heartbeat frame was exchanged this cycle.
    pub ipc_signal: bool,
    /// Channel 2 (file): the peer's `<role>.hb` `mtime` is within the freshness
    /// threshold this cycle.
    pub file_signal: bool,
    /// Channel 3 (`/health`): a 2xx decoded this cycle. `None` for
    /// [`Direction::ServiceToWatcher`], where the channel does not exist.
    pub health_signal: Option<bool>,
    /// The PID-check result the shell ran because last cycle's state was
    /// [`WatchdogState::VerifyingPid`]. `None` at every other time.
    pub pid: Option<PidCheck>,
}

/// A side-effect [`LoopDriver::tick`] asks the I/O shell to run this cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Run `verify_pid_alive` against the peer and feed the result back in
    /// [`ChannelObs::pid`] next cycle.
    VerifyPid,
    /// Spawn the peer's sibling binary now. Emitted at most once per
    /// `Restarting` episode (the spawn-once latch).
    Spawn,
    /// Persist this record to `watchdog-state.json` (only ever emitted for
    /// [`Direction::WatcherToService`]). Emitted **every** tick so the file's
    /// `mtime` stays fresh — readers treat a stale file as "watchdog not
    /// running", never as the recorded state.
    WriteState(WatchdogStateFile),
    /// Log, once, that the restart budget is spent and manual recovery is
    /// needed (`GaveUp`).
    LogGaveUp,
}

/// The result of one [`LoopDriver::tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickOutcome {
    /// The automaton state after this cycle.
    pub state: WatchdogState,
    /// Side-effects to run, in order.
    pub effects: Vec<Effect>,
}

/// One direction's running heartbeat loop. Construct with [`Self::new`] (fresh)
/// or [`Self::restored`] (resuming from a persisted `watchdog-state.json`, so a
/// watcher restart does not silently reset the restart budget — the same reason
/// [`RestartBudget::restored`] exists).
#[derive(Debug)]
pub struct LoopDriver {
    direction: Direction,
    miss_ipc: u32,
    miss_file: u32,
    miss_health: u32,
    state: WatchdogState,
    budget: RestartBudget,
    /// 1-indexed count of restart attempts in the current incident — the
    /// [`next_backoff`] argument. Reset to 1 on a return to `Healthy`.
    restart_attempt: u32,
    backoff_deadline: Option<SystemTime>,
    /// Set when `Effect::Spawn` has been emitted for the current `Restarting`
    /// episode; cleared on leaving `Restarting`. Guards a double spawn if
    /// `Restarting` is ever ticked more than once.
    spawn_issued: bool,
    last_transition_at: Option<SystemTime>,
    last_error: Option<WatchdogErrorLabel>,
}

impl LoopDriver {
    /// A fresh driver for `direction`, starting in [`WatchdogState::Healthy`].
    #[must_use]
    pub fn new(direction: Direction) -> Self {
        Self {
            direction,
            miss_ipc: 0,
            miss_file: 0,
            miss_health: 0,
            state: WatchdogState::Healthy,
            budget: RestartBudget::default(),
            restart_attempt: 1,
            backoff_deadline: None,
            spawn_issued: false,
            last_transition_at: None,
            last_error: None,
        }
    }

    /// A driver resuming from a persisted `watchdog-state.json` record — the
    /// state and the restart budget are carried over (§7.1 #7); the miss
    /// counters and the backoff deadline start fresh (the process was just
    /// (re)started, it has no channel history).
    #[must_use]
    pub fn restored(direction: Direction, file: &WatchdogStateFile) -> Self {
        Self {
            direction,
            miss_ipc: 0,
            miss_file: 0,
            miss_health: 0,
            state: file.state,
            budget: RestartBudget::restored(
                file.window_started_at,
                file.restart_attempts_in_window,
            ),
            restart_attempt: 1,
            backoff_deadline: None,
            spawn_issued: false,
            last_transition_at: Some(file.last_transition_at),
            last_error: file.last_error,
        }
    }

    /// The current automaton state.
    #[must_use]
    pub fn state(&self) -> WatchdogState {
        self.state
    }

    /// Advance one cycle. `now` is injected — this function reads no clock.
    pub fn tick(&mut self, now: SystemTime, obs: &ChannelObs) -> TickOutcome {
        if self.last_transition_at.is_none() {
            self.last_transition_at = Some(now);
        }

        bump(&mut self.miss_ipc, obs.ipc_signal);
        bump(&mut self.miss_file, obs.file_signal);
        bump(&mut self.miss_health, obs.health_signal.unwrap_or(false));

        let ipc_status = channel_status(self.miss_ipc);
        let file_status = channel_status(self.miss_file);
        let health_status = channel_status(self.miss_health);

        let (vote, any_silent) = match self.direction {
            Direction::WatcherToService => (
                vote_watcher_checks_service(ipc_status, file_status, health_status),
                [ipc_status, file_status, health_status].contains(&ChannelStatus::NoSignal),
            ),
            Direction::ServiceToWatcher => (
                vote_service_checks_watcher(ipc_status, file_status),
                [ipc_status, file_status].contains(&ChannelStatus::NoSignal),
            ),
        };
        let any_channel_degraded = vote == Liveness::Alive && any_silent;

        let pid = if self.state == WatchdogState::VerifyingPid {
            obs.pid
        } else {
            None
        };
        let budget = if self.state == WatchdogState::Restarting {
            Some(self.budget.register_attempt(now))
        } else {
            None
        };
        let backoff_elapsed = self.state == WatchdogState::BackoffWait
            && self.backoff_deadline.is_none_or(|deadline| now >= deadline);

        let input = TransitionInput {
            vote,
            any_channel_degraded,
            pid,
            budget,
            backoff_elapsed,
        };
        let next = transition(self.state, &input);

        let mut effects = Vec::new();

        // Spawn-once: we entered this tick already in `Restarting` and just
        // computed an `Allowed` verdict — issue the spawn, latch it.
        if self.state == WatchdogState::Restarting
            && budget == Some(BudgetVerdict::Allowed)
            && !self.spawn_issued
        {
            effects.push(Effect::Spawn);
            self.spawn_issued = true;
        }

        if next == WatchdogState::VerifyingPid {
            effects.push(Effect::VerifyPid);
        }

        // Entering the backoff wait: arm the deadline for this attempt, advance
        // the attempt index, clear the spawn latch for the next episode.
        if next == WatchdogState::BackoffWait && self.state == WatchdogState::Restarting {
            let wait = next_backoff(self.restart_attempt);
            self.backoff_deadline = now.checked_add(wait);
            self.restart_attempt = self.restart_attempt.saturating_add(1);
            self.spawn_issued = false;
        }

        if next == WatchdogState::GaveUp && self.state != WatchdogState::GaveUp {
            effects.push(Effect::LogGaveUp);
        }

        // A clean return to Healthy ends the incident — reset backoff tracking
        // (not the budget: its own 600s window is the circuit breaker).
        if next == WatchdogState::Healthy && self.state != WatchdogState::Healthy {
            self.restart_attempt = 1;
            self.backoff_deadline = None;
            self.spawn_issued = false;
        }

        if next != self.state {
            self.last_transition_at = Some(now);
        }
        self.state = next;
        self.last_error = derive_last_error(next, ipc_status, health_status);

        if self.direction == Direction::WatcherToService {
            effects.push(Effect::WriteState(self.state_file(now)));
        }

        TickOutcome {
            state: next,
            effects,
        }
    }

    fn state_file(&self, now: SystemTime) -> WatchdogStateFile {
        WatchdogStateFile {
            schema_version: STATE_SCHEMA_VERSION,
            state: self.state,
            target: self.direction.target(),
            restart_attempts_in_window: self.budget.attempts_in_window(),
            window_started_at: self.budget.window_started_at(),
            last_transition_at: self.last_transition_at.unwrap_or(now),
            last_error: self.last_error,
        }
    }
}

/// A successful signal resets a channel's consecutive-miss count; a missed one
/// increments it (saturating — the count only ever feeds a `>= MISS_THRESHOLD`
/// test).
fn bump(counter: &mut u32, signalled: bool) {
    *counter = if signalled {
        0
    } else {
        counter.saturating_add(1)
    };
}

/// A coarse [`WatchdogErrorLabel`] for the persisted record — closed enum, never
/// free text (§7.1 #7: no domains, nothing sensitive). `file`-channel silence
/// has no label of its own; it surfaces through `state` alone.
fn derive_last_error(
    state: WatchdogState,
    ipc: ChannelStatus,
    health: ChannelStatus,
) -> Option<WatchdogErrorLabel> {
    match state {
        WatchdogState::Healthy => None,
        WatchdogState::GaveUp => Some(WatchdogErrorLabel::BudgetExhausted),
        _ => {
            if ipc == ChannelStatus::NoSignal {
                Some(WatchdogErrorLabel::PipeUnavailable)
            } else if health == ChannelStatus::NoSignal {
                Some(WatchdogErrorLabel::HealthUnreachable)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ChannelObs, Direction, Effect, LoopDriver};
    use crate::watchdog::pid_check::PidCheck;
    use crate::watchdog::state::{
        WatchdogErrorLabel, WatchdogState, WatchdogStateFile, WatchdogTarget, STATE_SCHEMA_VERSION,
    };
    use std::time::{Duration, SystemTime};

    fn base() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    fn at(offset_secs: u64) -> SystemTime {
        base() + Duration::from_secs(offset_secs)
    }

    fn all_signal() -> ChannelObs {
        ChannelObs {
            ipc_signal: true,
            file_signal: true,
            health_signal: Some(true),
            pid: None,
        }
    }

    fn all_silent_w2s(pid: Option<PidCheck>) -> ChannelObs {
        ChannelObs {
            ipc_signal: false,
            file_signal: false,
            health_signal: Some(false),
            pid,
        }
    }

    fn spawns(outcome: &super::TickOutcome) -> usize {
        outcome
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::Spawn))
            .count()
    }

    fn write_states(outcome: &super::TickOutcome) -> usize {
        outcome
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::WriteState(_)))
            .count()
    }

    // Happy path: every channel signalling holds Healthy forever, writes the
    // state file once per tick, never spawns or verifies.
    #[test]
    fn all_channels_signalling_stays_healthy_and_writes_every_tick() {
        let mut driver = LoopDriver::new(Direction::WatcherToService);
        for i in 0..10 {
            let out = driver.tick(at(i * 5), &all_signal());
            assert_eq!(out.state, WatchdogState::Healthy);
            assert_eq!(write_states(&out), 1, "one WriteState per tick");
            assert!(
                out.effects
                    .iter()
                    .all(|e| !matches!(e, Effect::Spawn | Effect::VerifyPid | Effect::LogGaveUp)),
                "no restart-path effects while Healthy"
            );
        }
    }

    // T-93 loop level: one channel silent, the other two alive → the vote stays
    // Alive and the automaton never advances toward a restart. No Spawn, ever.
    #[test]
    fn one_silent_channel_degrades_but_never_restarts() {
        let mut driver = LoopDriver::new(Direction::WatcherToService);
        let ipc_silent = ChannelObs {
            ipc_signal: false,
            file_signal: true,
            health_signal: Some(true),
            pid: None,
        };
        let mut total_spawns = 0;
        for i in 0..8 {
            let out = driver.tick(at(i * 5), &ipc_silent);
            total_spawns += spawns(&out);
            assert!(
                !matches!(
                    out.state,
                    WatchdogState::SuspectDead
                        | WatchdogState::VerifyingPid
                        | WatchdogState::Restarting
                        | WatchdogState::GaveUp
                ),
                "tick {i}: a single silent channel must not reach a restart state"
            );
        }
        assert_eq!(driver.state(), WatchdogState::ChannelDegraded);
        assert_eq!(total_spawns, 0);
    }

    // T-94 loop level (2-of-3): two channels silent → SuspectDead → VerifyingPid
    // (VerifyPid emitted) → pid Gone → Restarting → exactly one Spawn across the
    // restart episode → BackoffWait. Then pid Alive on a re-verify returns to
    // Healthy with no further spawn.
    #[test]
    fn two_silent_channels_restart_once_then_recover() {
        let mut driver = LoopDriver::new(Direction::WatcherToService);
        let dead = ChannelObs {
            ipc_signal: false,
            file_signal: false,
            health_signal: Some(true),
            pid: None,
        };
        for i in 0..3 {
            driver.tick(at(i * 5), &dead);
        }
        assert_eq!(driver.state(), WatchdogState::SuspectDead, "2-of-3 silent");

        let out = driver.tick(at(15), &dead);
        assert_eq!(out.state, WatchdogState::VerifyingPid);
        assert!(out.effects.contains(&Effect::VerifyPid));

        let mut total_spawns = 0;
        let out = driver.tick(
            at(20),
            &ChannelObs {
                pid: Some(PidCheck::Gone),
                ..dead
            },
        );
        assert_eq!(out.state, WatchdogState::Restarting);
        total_spawns += spawns(&out);

        let out = driver.tick(at(25), &dead);
        assert_eq!(out.state, WatchdogState::BackoffWait);
        total_spawns += spawns(&out);
        assert_eq!(total_spawns, 1, "exactly one Spawn per restart episode");

        // Peer comes back: a re-verify finds it Alive → Healthy, no new spawn.
        let out = driver.tick(at(60), &all_signal());
        assert_eq!(out.state, WatchdogState::Healthy);
        assert_eq!(spawns(&out), 0);
    }

    // T-94 loop level (unanimous, service → watcher): exactly one of two
    // channels silent never leaves ChannelDegraded; both silent reaches
    // SuspectDead. This direction never emits WriteState.
    #[test]
    fn service_to_watcher_is_unanimous_and_never_persists() {
        let mut driver = LoopDriver::new(Direction::ServiceToWatcher);
        let one_silent = ChannelObs {
            ipc_signal: false,
            file_signal: true,
            health_signal: None,
            pid: None,
        };
        for i in 0..6 {
            let out = driver.tick(at(i * 5), &one_silent);
            assert_eq!(
                write_states(&out),
                0,
                "service → watcher never writes state"
            );
            assert_ne!(out.state, WatchdogState::SuspectDead);
        }
        assert_eq!(driver.state(), WatchdogState::ChannelDegraded);

        let both_silent = ChannelObs {
            file_signal: false,
            ..one_silent
        };
        // `file` needs three consecutive misses to cross the threshold; the
        // third tick is where the unanimous rule is finally met.
        for i in 6..9 {
            driver.tick(at(i * 5), &both_silent);
        }
        assert_eq!(driver.state(), WatchdogState::SuspectDead);
    }

    // Boundary: the backoff deadline armed on each successive restart follows
    // 1 → 2 → 4 → 8 → 16 s.
    #[test]
    fn backoff_schedule_is_one_two_four_eight_sixteen() {
        let mut driver = LoopDriver::new(Direction::WatcherToService);
        let dead = all_silent_w2s(Some(PidCheck::Gone));
        let mut seen = Vec::new();
        let mut t = 0_u64;
        while driver.restart_attempt <= 5 && t < 4000 {
            let before = driver.restart_attempt;
            driver.tick(at(t), &dead);
            if driver.restart_attempt > before {
                if let Some(deadline) = driver.backoff_deadline {
                    seen.push(deadline.duration_since(at(t)).unwrap_or_default().as_secs());
                }
            }
            t += 5;
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16]);
    }

    // Misuse & recovery: an unbroken restart storm spends the 5/600s budget,
    // logs GaveUp exactly once, then never spawns again — the terminal state
    // §7 requires instead of a silent infinite loop.
    #[test]
    fn budget_exhaustion_gives_up_once_and_stops_spawning() {
        let mut driver = LoopDriver::new(Direction::WatcherToService);
        let dead = all_silent_w2s(Some(PidCheck::Gone));
        let mut total_spawns = 0;
        let mut gaveup_logs = 0;
        for i in 0..40 {
            let out = driver.tick(at(i * 5), &dead);
            total_spawns += spawns(&out);
            gaveup_logs += out
                .effects
                .iter()
                .filter(|e| matches!(e, Effect::LogGaveUp))
                .count();
        }
        assert_eq!(driver.state(), WatchdogState::GaveUp);
        assert_eq!(total_spawns, 5, "budget is 5 restarts per 600s window");
        assert_eq!(gaveup_logs, 1, "GaveUp is logged exactly once");

        let out = driver.tick(at(250), &dead);
        assert!(
            out.effects
                .iter()
                .all(|e| !matches!(e, Effect::Spawn | Effect::LogGaveUp)),
            "no restart activity after GaveUp"
        );
        assert!(
            write_states(&out) == 1,
            "still writes state so the file stays fresh"
        );
    }

    // Recovery: a driver restored from a persisted record with the budget
    // already spent gives up on its first restart rather than handing back a
    // fresh allowance (a watcher restart must not reset the service's budget).
    #[test]
    fn restored_with_a_spent_budget_gives_up_immediately() {
        let file = WatchdogStateFile {
            schema_version: STATE_SCHEMA_VERSION,
            state: WatchdogState::Restarting,
            target: WatchdogTarget::Service,
            restart_attempts_in_window: 6,
            window_started_at: Some(at(0)),
            last_transition_at: at(0),
            last_error: Some(WatchdogErrorLabel::BudgetExhausted),
        };
        let mut driver = LoopDriver::restored(Direction::WatcherToService, &file);
        let out = driver.tick(at(10), &all_silent_w2s(Some(PidCheck::Gone)));
        assert_eq!(out.state, WatchdogState::GaveUp);
        assert_eq!(spawns(&out), 0);
    }

    // The persisted record carries the coarse error label and the live budget
    // fields, and its state matches the driver.
    #[test]
    fn written_state_file_reflects_the_live_driver() {
        let mut driver = LoopDriver::new(Direction::WatcherToService);
        let out = driver.tick(at(0), &all_signal());
        let Some(Effect::WriteState(file)) = out
            .effects
            .iter()
            .find(|e| matches!(e, Effect::WriteState(_)))
            .cloned()
        else {
            panic!("watcher direction must emit WriteState");
        };
        assert_eq!(file.schema_version, STATE_SCHEMA_VERSION);
        assert_eq!(file.state, WatchdogState::Healthy);
        assert_eq!(file.target, WatchdogTarget::Service);
        assert_eq!(file.last_error, None);
    }
}
