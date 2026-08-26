//! In-memory query log (SPEC.md §6, §6.1 — T-42, T-43): a `VecDeque<LogEntry>`
//! behind a `parking_lot::RwLock`, not `tokio::sync::RwLock` — every
//! operation here is an instant in-memory read/mutate with no `.await`
//! inside the critical section, so a `tokio` lock would only add overhead
//! (SPEC.md §6.1). Two independent bounds apply, each via a different
//! mechanism, per §6.1: entry count (evict oldest on insert, once over
//! capacity) and age (filtered out on read via `retain`, no background sweep
//! task).
//!
//! This module's [`LogEntry`] is the **internal backend record**, narrower
//! than the Tauri IPC DTO of the same name (`diagrams/ui-dto-model.md`,
//! `UI-SPEC.md`): `decision_source` here only has the four values Phase 1
//! can actually produce (`ALLOWLIST`/`BLOCKLIST`/`CACHE`/`QUORUM`), and there
//! is no `voter_scope`/`geoip_country` field at all — TASKS.md's own T-43
//! text defers both to T-109 (Фаза 4) and T-79 (Фаза 2) respectively. The DTO
//! conversion (T-53/T-54) is expected to widen this into the seven-variant
//! DTO enum and fill `voter_scope`/`geoip_country` with their fixed Phase-1
//! placeholder values (`FULL`/`null`) — that widening doesn't exist yet, and
//! doesn't belong in this module (illegal states — a `decision_source` this
//! phase can't produce — stay unrepresentable here instead of being carried
//! as a dead enum variant).
//!
//! [`VoterRecord`] deliberately carries [`crate::upstream::Provider`] (two
//! variants: Quad9, `AdGuard`), not `quorum::Slot`'s three (which also
//! includes `Baseline`) — SPEC.md §3.1 only calls Quad9/`AdGuard` "voters";
//! baseline exists to break Quad9's NXDOMAIN tie and to source real answer
//! data, it never casts an OR-logic block/allow vote itself. Excluding it
//! from `voters` is a SPEC-silent choice made here, not a documented
//! requirement — flagged per this project's own rule for filling such gaps.
//!
//! **No producer yet.** `quorum::resolve` returns `QuorumOutcome { verdict,
//! answer }` only; the per-slot `VoterOutcome`s that would populate a
//! `LogEntry.voters` list are local to `resolve`'s loop and never leave it
//! (`log_canceled`'s `tracing::debug!` is the only trace of a canceled
//! voter today). Wiring `pipeline::handle_query` to build and push a
//! `LogEntry` per query is a later task — same "module ready, wiring later"
//! pattern as `cache.rs`/`overrides.rs` before T-39/T-40.

use crate::upstream::Provider;
use hickory_proto::rr::RecordType;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

/// SPEC.md §6: "останні 1000 записів" default entry-count bound. Not
/// re-exported at crate root — `QueryLog::default()` is the public way to
/// get these defaults, same pattern as `cache::CacheConfig::default()`.
pub(crate) const DEFAULT_MAX_ENTRIES: usize = 1000;
/// SPEC.md §6: "24 години" default age bound.
pub(crate) const DEFAULT_MAX_AGE: Duration = Duration::from_hours(24);

/// SPEC.md §6 `decision` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The query resolved to a real answer.
    Allowed,
    /// The query was blocked (NULL-answered for A/AAAA, NODATA otherwise —
    /// see `wire::build_block_response`).
    Blocked,
}

/// SPEC.md §6 `decision_source` column — Phase 1's four producible values
/// only (`CCTLD_BLOCK`/`RATING_FILTER`/`GEOIP` are later-phase pipeline
/// steps that don't exist yet, see this module's doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// Matched an allowlist entry.
    Allowlist,
    /// Matched a blocklist entry.
    Blocklist,
    /// Served from a cached quorum verdict.
    Cache,
    /// Decided by a fresh quorum resolution.
    Quorum,
}

/// SPEC.md §6 `voters` column, per-voter value — five variants, matching
/// SPEC.md §6's own list exactly (`Pending` in the Tauri DTO's `VoterStatus`
/// is a live-update-only transit state, per `diagrams/ui-dto-model.md`'s
/// resolved source discrepancy — it can never appear in an already-completed
/// backend `LogEntry`, so this internal type omits it, not just the DTO's
/// naming choice of `Timeout` over `TIMEOUT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoterVerdict {
    /// This voter's block signature matched.
    Block,
    /// This voter did not block.
    Allow,
    /// This voter did not respond within the configured timeout.
    Timeout,
    /// This voter's query failed (transport/decode error).
    Error,
    /// Not waited on — the decision was already reached before this voter
    /// settled (SPEC.md §3.6 early return).
    Canceled,
}

/// One provider's contribution to a completed query, for the log's `voters`
/// column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterRecord {
    /// Which provider this result belongs to.
    pub provider: Provider,
    /// That provider's outcome.
    pub verdict: VoterVerdict,
}

/// One query-log record (SPEC.md §6's field table minus the two fields this
/// module's doc comment explains are deferred to their own later phases).
///
/// **Carries the query domain** (SPEC.md, Наскрізні вимоги: no domain names
/// in *service* logs) — this ring buffer is the one deliberate, user-facing
/// exception that requirement carves out (SPEC.md §6's whole "Конфлікт із
/// вимогою приватності" section), not a leak. Still, never pass a `LogEntry`
/// (or a `QueryLog` snapshot) to `tracing`/`{:?}` in a *diagnostic*-log
/// context — same discipline as `PipelineOutcome::Response` and
/// `QuorumOutcome::answer`, just for a different reason: this data belongs
/// only in the in-memory ring buffer the user explicitly opted into by
/// running the product, never in an on-disk diagnostic log file.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// When the query was received.
    pub timestamp: SystemTime,
    /// The normalized query domain.
    pub domain: String,
    /// The query's record type.
    pub qtype: RecordType,
    /// Allowed or blocked.
    pub decision: Decision,
    /// Which pipeline step produced `decision`.
    pub decision_source: DecisionSource,
    /// Per-provider results — empty when `decision_source` isn't `Quorum`
    /// (an allowlist/blocklist/cache decision never consulted a voter).
    pub voters: Vec<VoterRecord>,
    /// Total response latency.
    pub latency_ms: u64,
}

/// SPEC.md §6/§6.1: in-memory ring buffer of [`LogEntry`] records, bounded
/// independently by entry count and age.
///
/// Deliberately does **not** derive `Debug` — unlike `LogEntry` itself,
/// `{:?}` on the whole buffer would dump the user's entire recent browsing
/// history in one shot, a strictly worse version of the domain-name leaks
/// `overrides::InvalidEntry` and `UpstreamError::Http` already guard against
/// (see this crate's gotchas notes). There is no legitimate reason to format
/// the whole buffer at once; format individual [`LogEntry`] values (from
/// [`QueryLog::snapshot`]) if a caller genuinely needs to.
pub struct QueryLog {
    entries: RwLock<VecDeque<LogEntry>>,
    max_entries: usize,
    max_age: Duration,
}

impl QueryLog {
    /// Constructs an empty log with the given bounds.
    #[must_use]
    pub fn new(max_entries: usize, max_age: Duration) -> Self {
        Self {
            entries: RwLock::new(VecDeque::new()),
            max_entries,
            max_age,
        }
    }

    /// Appends `entry`, then evicts the oldest record(s) if the buffer is
    /// now over capacity.
    ///
    /// The eviction loop's own negation is the post-condition — `guard.len()
    /// <= self.max_entries` holds after this call regardless of how many
    /// entries were present going in, not just because `push` happens to be
    /// the only inserter today (global CLAUDE.md: bounds safety provable
    /// from the line itself, not from an induction argument over callers).
    pub fn push(&self, entry: LogEntry) {
        let mut guard = self.entries.write();
        guard.push_back(entry);
        while guard.len() > self.max_entries {
            guard.pop_front();
        }
    }

    /// Returns every entry still within `max_age` of `now`, oldest first.
    ///
    /// Applies the age bound by calling `VecDeque::retain` on the live
    /// buffer under the write lock (SPEC.md §6.1: "фільтрація на читанні",
    /// not a separate background sweep task) — an aged-out entry is actually
    /// dropped here, not just excluded from this call's return value.
    #[must_use]
    pub fn snapshot(&self, now: SystemTime) -> Vec<LogEntry> {
        let mut guard = self.entries.write();
        guard.retain(|entry| {
            // `Err` means `entry.timestamp` is after `now` (clock skew, not
            // staleness) - keep it. Do not "simplify" this to
            // `is_ok_and(...)`, which would silently flip that case to
            // "evict" instead.
            now.duration_since(entry.timestamp)
                .map_or(true, |age| age <= self.max_age)
        });
        guard.iter().cloned().collect()
    }
}

impl Default for QueryLog {
    /// SPEC.md §6's own stated defaults: 1000 entries or 24 hours.
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES, DEFAULT_MAX_AGE)
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, DecisionSource, LogEntry, QueryLog, DEFAULT_MAX_ENTRIES};
    use hickory_proto::rr::RecordType;
    use std::time::{Duration, SystemTime};

    fn entry_at(timestamp: SystemTime) -> LogEntry {
        LogEntry {
            timestamp,
            domain: "example.com".to_string(),
            qtype: RecordType::A,
            decision: Decision::Allowed,
            decision_source: DecisionSource::Quorum,
            voters: Vec::new(),
            latency_ms: 5,
        }
    }

    #[test]
    fn push_evicts_the_oldest_entry_once_over_capacity() {
        let log = QueryLog::new(2, Duration::from_hours(24));
        let now = SystemTime::now();
        let mut oldest = entry_at(now);
        oldest.domain = "oldest.example".to_string();
        log.push(oldest);
        let mut middle = entry_at(now);
        middle.domain = "middle.example".to_string();
        log.push(middle);
        let mut newest = entry_at(now);
        newest.domain = "newest.example".to_string();
        log.push(newest);

        let snapshot = log.snapshot(now);
        assert_eq!(snapshot.len(), 2, "must stay within max_entries");
        let domains: Vec<&str> = snapshot.iter().map(|e| e.domain.as_str()).collect();
        assert_eq!(
            domains,
            vec!["middle.example", "newest.example"],
            "the oldest entry must be the one evicted, not an arbitrary one"
        );
    }

    #[test]
    fn zero_max_entries_keeps_the_buffer_empty() {
        // Discriminating case for the eviction loop's shape: a naive
        // `if len >= max { pop_front() }` before push still leaves exactly
        // one entry when max_entries == 0; only trimming *after* push
        // (looping until the post-condition holds) empties it back out.
        let log = QueryLog::new(0, Duration::from_hours(24));
        let now = SystemTime::now();
        log.push(entry_at(now));

        assert!(log.snapshot(now).is_empty());
    }

    #[test]
    fn snapshot_excludes_entries_older_than_max_age() {
        let log = QueryLog::new(super::DEFAULT_MAX_ENTRIES, Duration::from_hours(24));
        let now = SystemTime::now();
        let Some(stale_timestamp) = now.checked_sub(Duration::from_hours(25)) else {
            panic!("valid fixture timestamp");
        };
        let mut stale = entry_at(stale_timestamp);
        stale.domain = "stale.example".to_string();
        log.push(stale);
        let mut fresh = entry_at(now);
        fresh.domain = "fresh.example".to_string();
        log.push(fresh);

        let snapshot = log.snapshot(now);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].domain, "fresh.example");
    }

    #[test]
    fn snapshot_actually_evicts_aged_out_entries_from_the_buffer_not_just_the_output() {
        // Discriminating test: a version of snapshot() that filters into a
        // new Vec without mutating the live buffer would pass every other
        // test here too - this one proves the *buffer itself* shrinks, per
        // SPEC.md §6.1's "фільтрація на читанні" (filtering happens on the
        // live structure, not a read-only copy).
        let log = QueryLog::new(1, Duration::from_hours(24));
        let now = SystemTime::now();
        let Some(stale_timestamp) = now.checked_sub(Duration::from_hours(25)) else {
            panic!("valid fixture timestamp");
        };
        log.push(entry_at(stale_timestamp));
        assert!(log.snapshot(now).is_empty(), "stale entry filtered out");

        // With max_entries == 1, a fresh push only succeeds without evicting
        // anything else if the prior stale entry was actually removed from
        // the buffer (not just from the last snapshot's return value).
        let mut fresh = entry_at(now);
        fresh.domain = "fresh.example".to_string();
        log.push(fresh);
        let snapshot = log.snapshot(now);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].domain, "fresh.example");
    }

    #[test]
    fn future_timestamp_is_never_treated_as_aged_out() {
        // Clock-skew case: entry.timestamp after `now` must not be evicted -
        // `duration_since` returns Err there, and the predicate must map
        // that to "keep", not "drop" (the is_ok_and trap called out in this
        // module's snapshot() comment).
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let future = now + Duration::from_secs(60);
        log.push(entry_at(future));

        assert_eq!(log.snapshot(now).len(), 1);
    }

    #[test]
    fn default_matches_spec_bounds() {
        let log = QueryLog::default();
        assert_eq!(log.max_entries, DEFAULT_MAX_ENTRIES);
        assert_eq!(log.max_age, Duration::from_hours(24));
    }
}
