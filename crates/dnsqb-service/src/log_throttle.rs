//! ARCH-21 — rate-limits one repeated warning to a line per window, so a
//! browser retrying against a not-yet-trusted cert (≈30 `TLS handshake
//! failed` per minute, measured) can't grow `dnsqb-service.log` without bound
//! between restarts — rotation only runs at startup (`logging`).
//!
//! Pure: the caller injects `now`. The suppressed count is reported on the
//! *next* line that gets through, so a burst followed by silence never
//! reports its tail count.

use std::time::{Duration, Instant};

/// How long one logged line covers before the next one may be logged.
pub(crate) const WARN_THROTTLE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub(crate) struct WarnThrottle {
    last_logged: Option<Instant>,
    suppressed: u64,
}

impl WarnThrottle {
    /// One occurrence at `now`. `Some(n)` — log it, mentioning the `n`
    /// occurrences suppressed since the last logged one; `None` — skip it.
    pub(crate) fn admit(&mut self, now: Instant) -> Option<u64> {
        if let Some(last) = self.last_logged {
            if now.saturating_duration_since(last) < WARN_THROTTLE_WINDOW {
                self.suppressed = self.suppressed.saturating_add(1);
                return None;
            }
        }
        self.last_logged = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

#[cfg(test)]
mod tests {
    use super::{WarnThrottle, WARN_THROTTLE_WINDOW};
    use std::time::{Duration, Instant};

    #[test]
    fn the_first_occurrence_is_logged_with_nothing_suppressed() {
        let mut t = WarnThrottle::default();
        assert_eq!(t.admit(Instant::now()), Some(0));
    }

    #[test]
    fn thirty_occurrences_in_a_minute_log_one_line() {
        let mut t = WarnThrottle::default();
        let start = Instant::now();
        let logged = (0..30u64)
            .filter_map(|i| t.admit(start + Duration::from_secs(i * 2)))
            .count();
        assert_eq!(logged, 1);
    }

    #[test]
    fn the_next_line_after_the_window_carries_the_suppressed_count() {
        let mut t = WarnThrottle::default();
        let start = Instant::now();
        t.admit(start);
        for i in 1..=5 {
            assert_eq!(t.admit(start + Duration::from_secs(i)), None);
        }
        assert_eq!(t.admit(start + WARN_THROTTLE_WINDOW), Some(5));
        assert_eq!(
            t.admit(start + WARN_THROTTLE_WINDOW + Duration::from_secs(1)),
            None
        );
    }

    #[test]
    fn a_clock_that_goes_backwards_suppresses_instead_of_panicking() {
        let mut t = WarnThrottle::default();
        let earlier = Instant::now();
        t.admit(earlier + Duration::from_secs(10));
        assert_eq!(t.admit(earlier), None);
    }
}
