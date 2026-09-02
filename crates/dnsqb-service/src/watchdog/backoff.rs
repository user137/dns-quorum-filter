//! T-90 — exponential backoff between restart attempts (SPEC.md §7 "експо-
//! ненційний backoff", numbers fixed in §7.1 #8). Pure: attempt number in,
//! wait duration out. The state machine in `diagrams/watchdog-state.md` moves
//! `Restarting → BackoffWait` and waits this long before the next
//! `VerifyingPid` check.

use std::time::Duration;

/// The backoff wait per restart attempt, 1-indexed: attempt 1 waits
/// `BACKOFF_STEPS[0]`, and so on (SPEC.md §7.1 #8 — `1 → 2 → 4 → 8 → 16 s`).
pub const BACKOFF_STEPS: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];

/// The wait for any attempt past the end of [`BACKOFF_STEPS`] — the schedule
/// caps here rather than growing without bound (SPEC.md §7.1 #8).
pub const BACKOFF_CAP: Duration = Duration::from_secs(16);

/// Backoff wait before the `attempt`-th restart, 1-indexed. `attempt == 0` is
/// treated as `1`; any attempt beyond the schedule returns [`BACKOFF_CAP`].
#[must_use]
pub fn next_backoff(attempt: u32) -> Duration {
    let index = attempt.saturating_sub(1) as usize;
    BACKOFF_STEPS.get(index).copied().unwrap_or(BACKOFF_CAP)
}

#[cfg(test)]
mod tests {
    use super::{next_backoff, BACKOFF_CAP};
    use std::time::Duration;

    // Happy path: the 1-indexed schedule is 1, 2, 4, 8, 16 seconds.
    #[test]
    fn schedule_is_one_two_four_eight_sixteen() {
        let seconds: Vec<u64> = (1..=5).map(|n| next_backoff(n).as_secs()).collect();
        assert_eq!(seconds, [1, 2, 4, 8, 16]);
    }

    // Boundary: attempt 0 clamps up to the first step; anything past the schedule
    // (including the saturated count) returns the cap, with no panic or overflow.
    #[test]
    fn clamps_below_one_and_caps_above_the_schedule() {
        assert_eq!(next_backoff(0), Duration::from_secs(1));
        assert_eq!(next_backoff(6), BACKOFF_CAP);
        assert_eq!(next_backoff(u32::MAX), BACKOFF_CAP);
    }

    // Misuse: the sequence is monotonically non-decreasing across its whole
    // domain — a caller that feeds attempt numbers out of order never gets a
    // shorter wait for a later attempt.
    #[test]
    fn sequence_never_decreases() {
        let mut previous = Duration::ZERO;
        for attempt in 0..20 {
            let wait = next_backoff(attempt);
            assert!(
                wait >= previous,
                "attempt {attempt}: {wait:?} < {previous:?}"
            );
            previous = wait;
        }
    }

    // Error path: n/a — `next_backoff` is total, every `u32` maps to a duration.
}
