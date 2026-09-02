//! T-154(b): which baseline (non-filtering) resolver URL to use right now,
//! and when to probe the primary again after a failover. Pure — time is a
//! parameter and there is no I/O here.
//!
//! The running side lives in the reachability prober task (`main.rs`,
//! T-152): once per cycle it health-checks the active URL (and, when on an
//! alternate past the retry deadline, the primary too), folds the result in
//! with [`BaselineSelector::record`], and swaps the shared `Arc` on
//! `AppState`. `dispatch::resolve_doh_request` only *reads* the selector —
//! it snapshots [`current`](BaselineSelector::current) and passes it down as
//! `pipeline::UpstreamContext::baseline_url`. So failover is between-query
//! and at probe granularity (SPEC.md §3.6: baseline is a tiebreaker and an
//! answer source, not a voter — a ~one-probe-cycle lag before switching to
//! an alternate is acceptable, and per-query retry would fight the latency
//! budget since `combine` waits on the baseline outcome).
//!
//! SPEC.md §3.4 lists a primary baseline (`cloudflare-dns.com`) plus two
//! alternates (`dns10.quad9.net`, `dns.google`). The alternates are a
//! fallback for a total outage of the primary, **not** a new home and
//! **not** routine load-balancing — so this switches only after
//! [`SWITCH_THRESHOLD`] consecutive total failures, and after switching it
//! spends one request every [`RETRY_PRIMARY_AFTER`] probing the primary so
//! it returns as soon as the primary is healthy again.

use crate::upstream::BASELINE_DOH_URL;
use std::time::{Duration, SystemTime};

/// The baseline failover chain (SPEC.md §3.4 "Baseline" rows), tried in
/// order. `[0]` is the same [`BASELINE_DOH_URL`] every pre-T-154 call site
/// hardcoded, so the default path is byte-for-byte unchanged.
pub const BASELINE_CHAIN: [&str; 3] = [
    BASELINE_DOH_URL,
    "https://dns10.quad9.net/dns-query",
    "https://dns.google/dns-query",
];

/// Consecutive total failures of the active URL before failing over to the
/// next entry in [`BASELINE_CHAIN`]. A single blip must not move us.
pub const SWITCH_THRESHOLD: u32 = 3;

/// After a failover, how long to stay on the alternate before spending one
/// request probing the primary again.
pub const RETRY_PRIMARY_AFTER: Duration = Duration::from_secs(300);

/// One baseline round-trip's health, as the caller saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineHealth {
    /// A usable answer came back.
    Responded,
    /// Timeout, or a connection/transport error — no answer at all. A
    /// SERVFAIL *response* is still `Responded` here: the endpoint is up,
    /// which is all failover cares about.
    Failed,
}

/// A selector change worth logging (SPEC.md §3.4: baseline failover must be
/// explicit, never silent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineEvent {
    /// Failed over to `BASELINE_CHAIN[index]` after `SWITCH_THRESHOLD`
    /// consecutive failures of the previous entry.
    SwitchedTo {
        /// New active index into [`BASELINE_CHAIN`].
        index: usize,
    },
    /// A primary probe succeeded — back to `BASELINE_CHAIN[0]`.
    RecoveredToPrimary,
}

/// Health/rotation state for the baseline resolver URL. `Clone` so a reader
/// can snapshot it (`RwLock<Arc<_>>` pattern) and the writer mutates a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineSelector {
    active_index: usize,
    consecutive_failures: u32,
    /// `Some` only while `active_index > 0` — the earliest time a primary
    /// probe is allowed.
    retry_primary_after: Option<SystemTime>,
}

impl Default for BaselineSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl BaselineSelector {
    /// Fresh state: primary active, no failures, no probe pending.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active_index: 0,
            consecutive_failures: 0,
            retry_primary_after: None,
        }
    }

    /// The URL to use for an ordinary request. Bound is provable from the
    /// line — `min` clamps regardless of how `active_index` got its value.
    #[must_use]
    pub fn current(&self) -> &'static str {
        BASELINE_CHAIN[self.active_index.min(BASELINE_CHAIN.len() - 1)]
    }

    /// Whether the caller should use `BASELINE_CHAIN[0]` for *this one*
    /// request instead of [`current`](Self::current), to test if the primary
    /// has recovered. Only true while on an alternate and past the deadline.
    #[must_use]
    pub fn should_retry_primary(&self, now: SystemTime) -> bool {
        self.active_index > 0 && self.retry_primary_after.is_some_and(|at| now >= at)
    }

    /// Whether the primary is the active endpoint (nothing failed over).
    #[must_use]
    pub fn on_primary(&self) -> bool {
        self.active_index == 0
    }

    /// Active position in [`BASELINE_CHAIN`] (`0` = primary). For the
    /// `/admin/status` diagnostic view (T-152 indicator commit).
    #[must_use]
    pub fn active_index(&self) -> usize {
        self.active_index.min(BASELINE_CHAIN.len() - 1)
    }

    /// Fold one round-trip's outcome in. `url_used` is the URL the caller
    /// actually queried — either [`current`](Self::current) (ordinary) or
    /// `BASELINE_CHAIN[0]` when [`should_retry_primary`](Self::should_retry_primary)
    /// was honored (a primary probe). Returns an event when the active
    /// endpoint changed.
    pub fn record(
        &mut self,
        now: SystemTime,
        url_used: &str,
        health: BaselineHealth,
    ) -> Option<BaselineEvent> {
        let is_primary_probe = self.active_index > 0 && url_used == BASELINE_CHAIN[0];
        if is_primary_probe {
            return self.record_primary_probe(now, health);
        }
        match health {
            BaselineHealth::Responded => {
                self.consecutive_failures = 0;
                None
            }
            BaselineHealth::Failed => self.record_active_failure(now),
        }
    }

    fn record_primary_probe(
        &mut self,
        now: SystemTime,
        health: BaselineHealth,
    ) -> Option<BaselineEvent> {
        match health {
            BaselineHealth::Responded => {
                *self = Self::new();
                Some(BaselineEvent::RecoveredToPrimary)
            }
            BaselineHealth::Failed => {
                // Stay on the alternate; push the next probe out so a dead
                // primary isn't hammered every request.
                self.retry_primary_after = now.checked_add(RETRY_PRIMARY_AFTER);
                None
            }
        }
    }

    fn record_active_failure(&mut self, now: SystemTime) -> Option<BaselineEvent> {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures < SWITCH_THRESHOLD {
            return None;
        }
        // `>= len - 1` (not `== `) so this reads as safe without tracing the
        // increment history — already on the last entry, nowhere to go.
        if self.active_index >= BASELINE_CHAIN.len() - 1 {
            return None;
        }
        self.active_index += 1;
        self.consecutive_failures = 0;
        self.retry_primary_after = now.checked_add(RETRY_PRIMARY_AFTER);
        Some(BaselineEvent::SwitchedTo {
            index: self.active_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BaselineEvent, BaselineHealth, BaselineSelector, BASELINE_CHAIN, RETRY_PRIMARY_AFTER,
        SWITCH_THRESHOLD,
    };
    use std::time::{Duration, SystemTime};

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn fresh_selector_is_on_the_primary() {
        let s = BaselineSelector::new();
        assert_eq!(s.current(), BASELINE_CHAIN[0]);
        assert!(s.on_primary());
        assert!(!s.should_retry_primary(t0()));
    }

    #[test]
    fn steady_success_never_switches() {
        let mut s = BaselineSelector::new();
        for _ in 0..50 {
            let ev = s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Responded);
            assert_eq!(ev, None);
        }
        assert_eq!(s.current(), BASELINE_CHAIN[0]);
    }

    #[test]
    fn exactly_threshold_consecutive_failures_switches_to_the_next() {
        let mut s = BaselineSelector::new();
        for _ in 0..SWITCH_THRESHOLD - 1 {
            assert_eq!(
                s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Failed),
                None
            );
            assert!(s.on_primary(), "must not switch before the threshold");
        }
        let ev = s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Failed);
        assert_eq!(ev, Some(BaselineEvent::SwitchedTo { index: 1 }));
        assert_eq!(s.current(), BASELINE_CHAIN[1]);
        assert!(s.should_retry_primary(t0() + RETRY_PRIMARY_AFTER));
        assert!(!s.should_retry_primary(t0() + RETRY_PRIMARY_AFTER - Duration::from_secs(1)));
    }

    #[test]
    fn a_success_resets_the_failure_run() {
        let mut s = BaselineSelector::new();
        s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Failed);
        s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Failed);
        s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Responded);
        // Two more failures would be threshold-3 only if the run hadn't reset.
        assert_eq!(
            s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Failed),
            None
        );
        assert_eq!(
            s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Failed),
            None
        );
        assert!(s.on_primary());
    }

    #[test]
    fn primary_probe_success_recovers_to_primary() {
        let mut s = BaselineSelector::new();
        for _ in 0..SWITCH_THRESHOLD {
            s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Failed);
        }
        assert_eq!(s.current(), BASELINE_CHAIN[1]);
        let now = t0() + RETRY_PRIMARY_AFTER;
        assert!(s.should_retry_primary(now));
        let ev = s.record(now, BASELINE_CHAIN[0], BaselineHealth::Responded);
        assert_eq!(ev, Some(BaselineEvent::RecoveredToPrimary));
        assert_eq!(s.current(), BASELINE_CHAIN[0]);
        assert!(s.on_primary());
    }

    #[test]
    fn primary_probe_failure_stays_on_alternate_and_defers_next_probe() {
        let mut s = BaselineSelector::new();
        for _ in 0..SWITCH_THRESHOLD {
            s.record(t0(), BASELINE_CHAIN[0], BaselineHealth::Failed);
        }
        let now = t0() + RETRY_PRIMARY_AFTER;
        let ev = s.record(now, BASELINE_CHAIN[0], BaselineHealth::Failed);
        assert_eq!(ev, None);
        assert_eq!(s.current(), BASELINE_CHAIN[1], "still on the alternate");
        assert!(!s.should_retry_primary(now), "next probe deferred");
        assert!(s.should_retry_primary(now + RETRY_PRIMARY_AFTER));
    }

    #[test]
    fn failures_on_the_last_entry_saturate_without_going_out_of_bounds() {
        let mut s = BaselineSelector::new();
        // Walk all the way to the last chain entry.
        for _ in 0..BASELINE_CHAIN.len() - 1 {
            for _ in 0..SWITCH_THRESHOLD {
                s.record(t0(), s.current(), BaselineHealth::Failed);
            }
        }
        assert_eq!(s.current(), BASELINE_CHAIN[BASELINE_CHAIN.len() - 1]);
        // Many more failures — must stay put, no panic, no wrap.
        for _ in 0..20 {
            assert_eq!(s.record(t0(), s.current(), BaselineHealth::Failed), None);
        }
        assert_eq!(s.current(), BASELINE_CHAIN[BASELINE_CHAIN.len() - 1]);
    }
}
