//! T-91 — restart budget: at most [`MAX_RESTARTS_PER_WINDOW`] restarts in a
//! rolling [`RESTART_WINDOW`], then [`BudgetVerdict::GaveUp`] (SPEC.md §7 "ліміт
//! спроб у вікні часу … далі зупинитись … не продовжувати цикл"; numbers §7.1
//! #8: 5 / 600 s, per-target). Pure: the caller owns one [`RestartBudget`] per
//! target and passes `now` in — wall time is never read here.

use std::time::{Duration, SystemTime};

/// Restart attempts allowed within one [`RESTART_WINDOW`] before the budget is
/// spent (SPEC.md §7.1 #8).
pub const MAX_RESTARTS_PER_WINDOW: u32 = 5;

/// Rolling window over which [`MAX_RESTARTS_PER_WINDOW`] is counted (SPEC.md
/// §7.1 #8).
pub const RESTART_WINDOW: Duration = Duration::from_secs(600);

/// Verdict from [`RestartBudget::register_attempt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetVerdict {
    /// This attempt is within budget — proceed with the restart.
    Allowed,
    /// The budget for the current window is spent — stop, do not loop. Drives
    /// the terminal `GaveUp` state in `diagrams/watchdog-state.md`.
    GaveUp,
}

/// One target's rolling restart budget. `Default` is a fresh, unopened window.
#[derive(Debug, Clone, Copy, Default)]
pub struct RestartBudget {
    window_started_at: Option<SystemTime>,
    attempts_in_window: u32,
}

impl RestartBudget {
    /// When the current window opened, or `None` before the first attempt. For
    /// serialising into `watchdog-state.json` (§7.1 #7).
    #[must_use]
    pub fn window_started_at(&self) -> Option<SystemTime> {
        self.window_started_at
    }

    /// Attempts counted in the current window. For serialising into
    /// `watchdog-state.json` (§7.1 #7).
    #[must_use]
    pub fn attempts_in_window(&self) -> u32 {
        self.attempts_in_window
    }

    /// Record a restart attempt at `now` and report whether it is within budget.
    ///
    /// A window older than [`RESTART_WINDOW`] — or a `window_started_at` in the
    /// future, which a `watchdog-state.json` read back after a clock jump can
    /// produce — resets the window: `duration_since` yields `Err` for a future
    /// start, mapped here to `Duration::MAX`, so the reset path is taken.
    /// Erring toward "allow restarts" rather than "wedge in `GaveUp` forever" is
    /// the same don't-do-the-drastic-thing call as `is_stale`'s future-`mtime`
    /// case in [`super::heartbeat_file`].
    pub fn register_attempt(&mut self, now: SystemTime) -> BudgetVerdict {
        let elapsed = self.window_started_at.map_or(Duration::MAX, |start| {
            now.duration_since(start).unwrap_or(Duration::MAX)
        });
        if elapsed > RESTART_WINDOW {
            self.window_started_at = Some(now);
            self.attempts_in_window = 1;
            return BudgetVerdict::Allowed;
        }
        self.attempts_in_window = self.attempts_in_window.saturating_add(1);
        if self.attempts_in_window > MAX_RESTARTS_PER_WINDOW {
            BudgetVerdict::GaveUp
        } else {
            BudgetVerdict::Allowed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BudgetVerdict, RestartBudget, MAX_RESTARTS_PER_WINDOW, RESTART_WINDOW};
    use std::time::{Duration, SystemTime};

    fn base() -> SystemTime {
        // Well clear of the epoch, so `checked_sub` in the clock-skew tests
        // always has room.
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    fn at(offset_secs: u64) -> SystemTime {
        base() + Duration::from_secs(offset_secs)
    }

    // Happy path + T-91 headline: five attempts inside one window are all
    // Allowed; the sixth is GaveUp.
    #[test]
    fn five_allowed_then_gave_up() {
        let mut budget = RestartBudget::default();
        for n in 0..MAX_RESTARTS_PER_WINDOW {
            assert_eq!(
                budget.register_attempt(at(u64::from(n))),
                BudgetVerdict::Allowed,
                "attempt {n}"
            );
        }
        assert_eq!(budget.register_attempt(at(10)), BudgetVerdict::GaveUp);
        assert_eq!(budget.attempts_in_window(), MAX_RESTARTS_PER_WINDOW + 1);
    }

    // Boundary: the fifth attempt exactly at the window edge is still Allowed;
    // an attempt one second past the edge opens a fresh window.
    #[test]
    fn window_edge_and_reset() {
        let mut budget = RestartBudget::default();
        for _ in 0..MAX_RESTARTS_PER_WINDOW - 1 {
            assert_eq!(budget.register_attempt(at(0)), BudgetVerdict::Allowed);
        }
        assert_eq!(
            budget.register_attempt(base() + RESTART_WINDOW),
            BudgetVerdict::Allowed,
            "fifth attempt on the window edge is still in budget"
        );
        let past_edge = base() + RESTART_WINDOW + Duration::from_secs(1);
        assert_eq!(budget.register_attempt(past_edge), BudgetVerdict::Allowed);
        assert_eq!(budget.attempts_in_window(), 1, "window reset");
    }

    // Misuse: once the budget is spent, further attempts in the same window keep
    // reporting GaveUp — the terminal state is held by the caller's state
    // machine, this function just keeps saying so.
    #[test]
    fn gave_up_is_sticky_within_the_window() {
        let mut budget = RestartBudget::default();
        for _ in 0..=MAX_RESTARTS_PER_WINDOW {
            budget.register_attempt(at(0));
        }
        assert_eq!(budget.register_attempt(at(1)), BudgetVerdict::GaveUp);
        assert_eq!(budget.register_attempt(at(2)), BudgetVerdict::GaveUp);
    }

    // Concurrency & recovery: a `now` earlier than `window_started_at` — a
    // momentary backward clock step, or a future timestamp read back from
    // `watchdog-state.json` — resets the window rather than wedging in GaveUp,
    // and never panics.
    #[test]
    fn now_before_window_start_resets_not_panics() {
        let mut budget = RestartBudget::default();
        for _ in 0..MAX_RESTARTS_PER_WINDOW {
            budget.register_attempt(at(3600));
        }
        assert_eq!(budget.register_attempt(at(3600)), BudgetVerdict::GaveUp);

        let Some(earlier) = at(3600).checked_sub(Duration::from_secs(7200)) else {
            panic!("fixture time must have room to subtract");
        };
        assert_eq!(budget.register_attempt(earlier), BudgetVerdict::Allowed);
        assert_eq!(budget.attempts_in_window(), 1);
    }

    // Per-target: two independent budgets do not share a window or a counter.
    #[test]
    fn two_budgets_are_independent() {
        let mut service = RestartBudget::default();
        let mut watcher = RestartBudget::default();
        for _ in 0..=MAX_RESTARTS_PER_WINDOW {
            service.register_attempt(at(0));
        }
        assert_eq!(service.register_attempt(at(1)), BudgetVerdict::GaveUp);
        assert_eq!(watcher.register_attempt(at(1)), BudgetVerdict::Allowed);
        assert_eq!(watcher.attempts_in_window(), 1);
    }
}
