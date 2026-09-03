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
//! `UI-SPEC.md`): `decision_source` here has six of the values Phase 1
//! can actually produce (`ALLOWLIST`/`BLOCKLIST`/`CACHE`/`QUORUM`/`GEOIP`/
//! `BASELINE_FALLBACK`, `GEOIP` added at T-76, `BASELINE_FALLBACK` at
//! T-155), and there is still no `voter_scope` field at all —
//! TASKS.md's own T-43 text defers it to T-109 (Фаза 4). `geoip_country` (the
//! ISO code a `GEOIP` entry actually matched, distinct from *whether* one
//! matched) joined at T-79, the task right after `GEOIP` itself became
//! producible. The DTO conversion (T-53/T-54) is expected to widen this into
//! the seven-variant DTO enum and fill `voter_scope` with its fixed Phase-1
//! placeholder value (`FULL`) — that widening doesn't exist yet for the two
//! still-unbuilt sources, and doesn't belong in this module (illegal states
//! — a `decision_source` this phase can't produce — stay unrepresentable
//! here instead of being carried as a dead enum variant).
//!
//! [`VoterRecord`]/`VoterVerdict` moved to `quorum.rs` at T-147 — which
//! providers cast a vote and what their outcome means is quorum's own
//! domain, not the log's; this module just records it. See `quorum.rs`'s own
//! doc comment for why `VoterRecord` carries a `provider_id` string (a
//! configured voter) rather than the baseline slot (baseline never casts an
//! OR-logic vote).
//!
//! **Producer since T-147**: `dispatch::resolve_doh_request` builds and
//! pushes a [`LogEntry`] after every `pipeline::handle_query` call that
//! returns `Some(QueryLogMeta)` — see that module for exactly which branches
//! do (and don't yet — non-A/AAAA proxied queries are a named, still-open
//! gap).

use crate::quorum::{VoterRecord, VoterVerdict};
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
    /// Resolution failed (SERVFAIL) — no filtering decision was actually
    /// made (T-147, DECISIONS.md: SPEC.md/`UI-SPEC.md` originally fixed this
    /// field at two values, added before `handle_query`'s several genuine
    /// SERVFAIL paths — baseline timeout/error, every voter unresponsive —
    /// were ever checked against it).
    Failed,
}

/// SPEC.md §6 `decision_source` column — six of the seven values the DTO
/// (`admin::DecisionSourceView`) declares are producible so far
/// (`CCTLD_BLOCK`/`RATING_FILTER` are still later-phase pipeline steps that
/// don't exist yet). `Geoip` joined at T-76, `BaselineFallback` at T-155 —
/// see this module's doc comment.
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
    /// A quorum `Allow` (cached or fresh) was overridden by SPEC.md §3.5's
    /// live `GeoIP` filter (T-76) — the resolved IP matched a blocked
    /// country. `voters` is always empty here (see this module's own doc
    /// comment): `GeoIP` isn't a quorum vote, it applies *after* one.
    Geoip,
    /// Quorum was consulted but **every** enabled voter failed to answer
    /// (timeout/error), so the verdict rests on the baseline resolver / the
    /// timeout-mode policy, not on any filter (T-155). Emitted whether or
    /// not the `serve_baseline_when_filters_unreachable` toggle is on — it's
    /// a marker for *why* the decision looks the way it does, not gated by
    /// the toggle. Unlike every other variant, `voters` here is **not**
    /// empty: it carries the timeout/error record of each voter, which is
    /// the whole point of distinguishing this from a plain `Quorum` row.
    BaselineFallback,
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
    /// Per-provider results — populated for `Quorum` and `BaselineFallback`
    /// (T-155: the latter *is* the per-voter timeout record), empty for
    /// every other source (an allowlist/blocklist/cache/geoip decision never
    /// consulted a voter, or the result of one).
    pub voters: Vec<VoterRecord>,
    /// The ISO country code that triggered a `GeoIP` block (T-79) — `Some`
    /// only when `decision_source` is `Geoip`, `None` for every other
    /// source, the same "empty/absent except for the one source that
    /// produces it" rule `voters` follows one field up. An unenforced
    /// convention, not a type-level guarantee — same as `quorum::resolve`'s
    /// own documented-but-unenforced precondition (T-148's gotcha) — but
    /// with a single production writer today (`dispatch::resolve_doh_request`,
    /// which copies straight from `pipeline::QueryLogMeta`), a materially
    /// narrower blast radius than that precedent's multi-writer case.
    pub geoip_country: Option<String>,
    /// The ISO country code of the first resolved A/AAAA record (T-161) —
    /// `Some` whenever a real IP was actually resolved, regardless of
    /// `decision_source` or whether `GeoIP` blocking is even configured;
    /// `None` for a synthetic response (blocklist/quorum block) or no
    /// answer at all. Deliberately independent of `geoip_country` above,
    /// which can name a *different* IP when a response carries several and
    /// a later one is the one that matched the blocked-country list — see
    /// `pipeline::QueryLogMeta::resolved_ip_country`'s own doc comment.
    pub resolved_ip_country: Option<String>,
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
        self.age_filtered_entries(now, |_| true)
    }

    /// [`Self::snapshot`], narrowed to entries matching every facet `filter`
    /// sets (T-45, SPEC.md §6: "простий підрядковий фільтр по domain плюс
    /// фасети: тільки заблоковані / тільки дозволені / за конкретним
    /// voter'ом"). Applies the same age bound as `snapshot` — an entry that
    /// ages out is dropped from the buffer here too, filter or no filter.
    #[must_use]
    pub fn search(&self, now: SystemTime, filter: &LogFilter<'_>) -> Vec<LogEntry> {
        let needle = filter.domain_contains.map(str::to_ascii_lowercase);
        self.age_filtered_entries(now, |entry| {
            matches_filter(entry, filter, needle.as_deref())
        })
    }

    /// Empties the log immediately (SPEC.md §6's manual clear action, T-44 —
    /// same pattern as `Cache::clear`, T-137).
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Seeds the buffer from a previous run's persisted entries (T-146 —
    /// [`Self::snapshot`] output, decrypted from `query-log.enc`), oldest
    /// first, then re-applies **both** bounds against `now`: entries past
    /// `max_age` are dropped, and any excess over `max_entries` is evicted
    /// oldest-first. SPEC.md §6's "1000 записів або 24 години" window is not
    /// bypassed by restoring from disk. Called once at startup before the
    /// listener accepts traffic; a no-op on empty input.
    ///
    /// The two post-conditions (`guard.len() <= max_entries`, every kept
    /// entry within `max_age` of `now`) hold from the loops themselves, the
    /// same way `push`/`age_filtered_entries` establish them — not from an
    /// assumption about what the caller passed in.
    pub fn restore(&self, entries: Vec<LogEntry>, now: SystemTime) {
        if entries.is_empty() {
            return;
        }
        let mut guard = self.entries.write();
        for entry in entries {
            guard.push_back(entry);
        }
        guard.retain(|entry| {
            // Same clock-skew handling as `age_filtered_entries`: a
            // future-dated entry (`Err` from `duration_since`) is kept.
            now.duration_since(entry.timestamp)
                .map_or(true, |age| age <= self.max_age)
        });
        while guard.len() > self.max_entries {
            guard.pop_front();
        }
    }

    /// Shared implementation behind [`Self::snapshot`]/[`Self::search`]: one
    /// age-eviction pass under one write-lock acquisition, then `predicate`
    /// narrows what gets cloned into the returned `Vec` — the age bound is
    /// enforced in exactly one place regardless of which public method a
    /// caller uses.
    fn age_filtered_entries<F>(&self, now: SystemTime, mut predicate: F) -> Vec<LogEntry>
    where
        F: FnMut(&LogEntry) -> bool,
    {
        let mut guard = self.entries.write();
        guard.retain(|entry| {
            // `Err` means `entry.timestamp` is after `now` (clock skew, not
            // staleness) - keep it. Do not "simplify" this to
            // `is_ok_and(...)`, which would silently flip that case to
            // "evict" instead.
            now.duration_since(entry.timestamp)
                .map_or(true, |age| age <= self.max_age)
        });
        guard
            .iter()
            .filter(|entry| predicate(entry))
            .cloned()
            .collect()
    }
}

/// T-45 search/filter criteria for [`QueryLog::search`]. Every field is
/// independently optional and combined with AND — `None` means "don't
/// filter on this facet" (SPEC.md §6/`UI-SPEC.md` §3.2 name a substring
/// search box, a `{ALL,BLOCKED,ALLOWED}` segmented control, and a provider
/// dropdown — three independent controls, not one combined enum).
#[derive(Debug, Clone, Default)]
pub struct LogFilter<'a> {
    /// Case-insensitive substring match against `domain`. Compared via
    /// `to_ascii_lowercase` on both sides, not full Unicode case-folding —
    /// consistent with this crate's own `normalize_domain`, which stores
    /// `domain` as ASCII/punycode already; a Unicode needle still won't
    /// match its `xn--` stored spelling.
    pub domain_contains: Option<&'a str>,
    /// Restrict to this decision only (`UI-SPEC.md`'s `ALL/BLOCKED/ALLOWED`
    /// facet — `None` here is that facet's `ALL`).
    pub decision: Option<Decision>,
    /// Restrict to entries where this provider *appears* in `voters` and was
    /// actually eligible to vote — regardless of that voter's individual
    /// Block/Allow/Timeout/Error/Canceled verdict — SPEC.md §6/`UI-SPEC.md`
    /// §3.2 name this facet "за конкретним voter'ом" (by a specific voter),
    /// not "blocked by voter X"; this crate has no per-verdict facet
    /// requirement to model, so participation is the SPEC-silent choice made
    /// here (flagged per this project's own rule for filling such gaps, same
    /// as `VoterRecord`'s own doc comment above). `VoterVerdict::Disabled`
    /// (T-148) is explicitly excluded from "participation" — a provider the
    /// user administratively turned off was never asked to vote, so matching
    /// it here would contradict the facet's own "did this provider
    /// participate" intent.
    ///
    /// `voters` is empty for every non-`Quorum` `decision_source`
    /// (`ALLOWLIST`/`BLOCKLIST`/`CACHE`/`GEOIP` never populate it — see this
    /// module's own doc comment) — filtering by voter therefore only ever
    /// surfaces entries decided by a *fresh* quorum resolution. A domain
    /// this provider blocked that's now served from cache won't appear;
    /// that's the same "an aggregate rate looks lower than what the
    /// provider actually caught" ambiguity this project's T-66 benchmark
    /// entry already recorded for a different reason, not a bug in this
    /// filter.
    pub voter: Option<&'a str>,
}

/// `lowercased_needle` is `filter.domain_contains`, already lowercased once
/// by the caller ([`QueryLog::search`]) — `filter.domain_contains` itself is
/// deliberately unused below, don't read the un-lowered field here by
/// mistake.
fn matches_filter(
    entry: &LogEntry,
    filter: &LogFilter<'_>,
    lowercased_needle: Option<&str>,
) -> bool {
    if let Some(needle) = lowercased_needle {
        if !entry.domain.to_ascii_lowercase().contains(needle) {
            return false;
        }
    }
    if let Some(decision) = filter.decision {
        if entry.decision != decision {
            return false;
        }
    }
    if let Some(provider_id) = filter.voter {
        // T-148: Disabled excluded explicitly - that provider was never
        // asked to vote, so it must not count as "participated" (see
        // LogFilter::voter's own doc comment).
        if !entry
            .voters
            .iter()
            .any(|v| v.provider_id == provider_id && v.verdict != VoterVerdict::Disabled)
        {
            return false;
        }
    }
    true
}

impl Default for QueryLog {
    /// SPEC.md §6's own stated defaults: 1000 entries or 24 hours.
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES, DEFAULT_MAX_AGE)
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, DecisionSource, LogEntry, LogFilter, QueryLog, DEFAULT_MAX_ENTRIES};
    use crate::quorum::{VoterRecord, VoterVerdict};
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
            geoip_country: None,
            resolved_ip_country: None,
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

    #[test]
    fn clear_empties_the_log() {
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        log.push(entry_at(now));
        log.push(entry_at(now));

        log.clear();

        assert!(log.snapshot(now).is_empty());
    }

    #[test]
    fn restore_seeds_entries_and_reapplies_both_bounds() {
        let log = QueryLog::new(2, Duration::from_hours(24));
        let now = SystemTime::now();
        let Some(stale) = now.checked_sub(Duration::from_hours(25)) else {
            panic!("valid fixture timestamp");
        };
        let mut a = entry_at(stale);
        a.domain = "too-old.example".to_string();
        let mut b = entry_at(now);
        b.domain = "b.example".to_string();
        let mut c = entry_at(now);
        c.domain = "c.example".to_string();
        let mut d = entry_at(now);
        d.domain = "d.example".to_string();

        log.restore(vec![a, b, c, d], now);

        let snap = log.snapshot(now);
        let domains: Vec<&str> = snap.iter().map(|e| e.domain.as_str()).collect();
        assert_eq!(
            domains,
            vec!["c.example", "d.example"],
            "the stale entry is dropped and the count is trimmed to the newest max_entries"
        );
    }

    #[test]
    fn restore_of_an_empty_vec_is_a_no_op() {
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        log.push(entry_at(now));
        log.restore(Vec::new(), now);
        assert_eq!(log.snapshot(now).len(), 1);
    }

    #[test]
    fn restore_appends_after_existing_entries() {
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let mut live = entry_at(now);
        live.domain = "live.example".to_string();
        log.push(live);
        let mut restored = entry_at(now);
        restored.domain = "restored.example".to_string();
        log.restore(vec![restored], now);
        assert_eq!(log.snapshot(now).len(), 2);
    }

    #[test]
    fn search_domain_substring_matches_mid_string_against_a_normalized_domain() {
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let mut match_entry = entry_at(now);
        match_entry.domain = "sub.exampledomain.com".to_string();
        log.push(match_entry);
        let mut other = entry_at(now);
        other.domain = "unrelated.example".to_string();
        log.push(other);

        let results = log.search(
            now,
            &LogFilter {
                domain_contains: Some("exampledomain"),
                ..LogFilter::default()
            },
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "sub.exampledomain.com");
    }

    #[test]
    fn search_domain_substring_is_case_insensitive_on_a_mixed_case_needle() {
        // The real-world direction (UI-SPEC.md §3.2): a user types whatever
        // case they like into the search box against an already-normalized
        // (lowercase) stored `domain`.
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let mut match_entry = entry_at(now);
        match_entry.domain = "sub.exampledomain.com".to_string();
        log.push(match_entry);

        let results = log.search(
            now,
            &LogFilter {
                domain_contains: Some("ExampleDomain"),
                ..LogFilter::default()
            },
        );

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_domain_substring_still_matches_a_non_normalized_stored_domain() {
        // Defensive case: LogEntry has no producer yet (this module's own
        // doc comment), so "domain is always normalized/lowercase" is a
        // convention, not a type-level guarantee. matches_filter lowercases
        // both sides specifically so a future producer bug (a mixed-case
        // domain reaching the buffer) doesn't also break search.
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let mut match_entry = entry_at(now);
        match_entry.domain = "sub.ExampleDomain.com".to_string();
        log.push(match_entry);

        let results = log.search(
            now,
            &LogFilter {
                domain_contains: Some("exampledomain"),
                ..LogFilter::default()
            },
        );

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_decision_facet_narrows_to_only_that_decision() {
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let mut blocked = entry_at(now);
        blocked.domain = "blocked.example".to_string();
        blocked.decision = Decision::Blocked;
        log.push(blocked);
        let mut allowed = entry_at(now);
        allowed.domain = "allowed.example".to_string();
        allowed.decision = Decision::Allowed;
        log.push(allowed);

        let results = log.search(
            now,
            &LogFilter {
                decision: Some(Decision::Blocked),
                ..LogFilter::default()
            },
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "blocked.example");
    }

    #[test]
    fn search_voter_facet_narrows_to_entries_that_provider_participated_in() {
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let mut quad9_entry = entry_at(now);
        quad9_entry.domain = "quad9-voted.example".to_string();
        quad9_entry.voters = vec![VoterRecord {
            provider_id: "quad9".to_string(),
            verdict: VoterVerdict::Allow,
            allow_ip_count: Some(1),
            error_message: None,
        }];
        log.push(quad9_entry);
        let mut adguard_entry = entry_at(now);
        adguard_entry.domain = "adguard-voted.example".to_string();
        adguard_entry.voters = vec![VoterRecord {
            provider_id: "adguard".to_string(),
            verdict: VoterVerdict::Allow,
            allow_ip_count: Some(1),
            error_message: None,
        }];
        log.push(adguard_entry);

        let results = log.search(
            now,
            &LogFilter {
                voter: Some("quad9"),
                ..LogFilter::default()
            },
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "quad9-voted.example");
    }

    #[test]
    fn search_voter_facet_excludes_entries_with_no_voters_even_if_that_provider_would_have_blocked()
    {
        // Pins the documented LogFilter::voter semantic: a cache/allowlist/
        // blocklist decision never has voters, so filtering by voter can
        // never surface it - not an accident, see LogFilter's own doc
        // comment.
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let mut cached = entry_at(now);
        cached.domain = "cached.example".to_string();
        cached.decision_source = DecisionSource::Cache;
        cached.voters = Vec::new();
        log.push(cached);

        let results = log.search(
            now,
            &LogFilter {
                voter: Some("quad9"),
                ..LogFilter::default()
            },
        );

        assert!(results.is_empty());
    }

    #[test]
    fn search_voter_facet_excludes_entries_where_that_provider_was_administratively_disabled() {
        // T-148: VoterVerdict::Disabled means the provider was turned off,
        // never actually asked to vote - matching it here would contradict
        // the facet's own documented "did this provider participate" intent
        // (same class of gap as the no-voters test above, pinned with its
        // own dedicated test rather than left implicit).
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let mut disabled_entry = entry_at(now);
        disabled_entry.domain = "quad9-disabled.example".to_string();
        disabled_entry.voters = vec![
            VoterRecord {
                provider_id: "quad9".to_string(),
                verdict: VoterVerdict::Disabled,
                allow_ip_count: None,
                error_message: None,
            },
            VoterRecord {
                provider_id: "adguard".to_string(),
                verdict: VoterVerdict::Allow,
                allow_ip_count: Some(1),
                error_message: None,
            },
        ];
        log.push(disabled_entry);

        let results = log.search(
            now,
            &LogFilter {
                voter: Some("quad9"),
                ..LogFilter::default()
            },
        );

        assert!(results.is_empty());
    }

    #[test]
    fn search_combines_facets_with_and_not_or() {
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        // Matches the domain substring but not the decision facet.
        let mut wrong_decision = entry_at(now);
        wrong_decision.domain = "target.example".to_string();
        wrong_decision.decision = Decision::Allowed;
        log.push(wrong_decision);
        // Matches the decision facet but not the domain substring.
        let mut wrong_domain = entry_at(now);
        wrong_domain.domain = "other.example".to_string();
        wrong_domain.decision = Decision::Blocked;
        log.push(wrong_domain);
        // Matches both.
        let mut both = entry_at(now);
        both.domain = "target.example".to_string();
        both.decision = Decision::Blocked;
        log.push(both);

        let results = log.search(
            now,
            &LogFilter {
                domain_contains: Some("target"),
                decision: Some(Decision::Blocked),
                ..LogFilter::default()
            },
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, Decision::Blocked);
        assert_eq!(results[0].domain, "target.example");
    }

    #[test]
    fn search_with_default_filter_matches_everything_snapshot_would() {
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        log.push(entry_at(now));
        log.push(entry_at(now));

        assert_eq!(
            log.search(now, &LogFilter::default()).len(),
            log.snapshot(now).len()
        );
    }

    #[test]
    fn search_still_respects_the_age_bound() {
        let log = QueryLog::new(10, Duration::from_hours(24));
        let now = SystemTime::now();
        let Some(stale_timestamp) = now.checked_sub(Duration::from_hours(25)) else {
            panic!("valid fixture timestamp");
        };
        let mut stale = entry_at(stale_timestamp);
        stale.domain = "stale.example".to_string();
        log.push(stale);

        let results = log.search(
            now,
            &LogFilter {
                domain_contains: Some("stale"),
                ..LogFilter::default()
            },
        );

        assert!(results.is_empty());
    }
}
