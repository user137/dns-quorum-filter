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
//! than the admin-channel DTO of the same name (`diagrams/ui-dto-model.md`,
//! `UI-SPEC.md`): `decision_source` here has six of the values Phase 1
//! can actually produce (`ALLOWLIST`/`BLOCKLIST`/`CACHE`/`QUORUM`/`GEOIP`/
//! `BASELINE_FALLBACK`, `GEOIP` added at T-76, `BASELINE_FALLBACK` at
//! T-155). `geoip_country` (the ISO code a `GEOIP` entry actually matched,
//! distinct from *whether* one matched) joined at T-79, the task right after
//! `GEOIP` itself became producible. The DTO conversion (T-53/T-54) widens
//! this into the seven-variant DTO enum — that widening doesn't exist yet for
//! the still-unbuilt sources, and doesn't belong in this module (illegal
//! states — a `decision_source` this phase can't produce — stay
//! unrepresentable here instead of being carried as a dead enum variant).
//! The `voter_scope` field was removed everywhere at T-179 (SPEC.md §5.1
//! dropped — nothing narrows the voter set).
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
use parking_lot::{RwLock, RwLockWriteGuard};
use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

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

/// SPEC.md §6 `decision_source` column — all eight values the DTO
/// (`admin::DecisionSourceView`) declares are now producible. `Geoip` joined
/// at T-76, `BaselineFallback` at T-155, `RatingFilter` at T-124,
/// `CctldBlock` at Фаза 5/T-116 — see this module's doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// Matched an allowlist entry.
    Allowlist,
    /// Matched a blocklist entry.
    Blocklist,
    /// Matched a public blocklist-bundle entry (T-218 Фаза 7, Батч 7.4,
    /// SPEC.md §5 step 2). Composes with `Blocklist`'s own pipeline slot —
    /// step 2 doesn't distinguish a manual entry from a bundle one, this
    /// variant only exists so the log/admin surfaces can still tell them
    /// apart. `voters` is always empty; never cached (the bundle can change
    /// under the next `blocklist_updater::run_blocklist_updater` cycle,
    /// same reasoning `RatingFilter` already has).
    BlocklistBundle,
    /// Blocked by the ccTLD-suffix step (Фаза 5, T-115/T-116, SPEC.md §5.2)
    /// — pipeline step 3, right after `Blocklist`/`BlocklistBundle` and
    /// before `Cache`. `voters` is always empty; never cached (a local,
    /// dependency-free check, same reasoning as `BlocklistBundle`).
    CctldBlock,
    /// Served from a cached quorum verdict.
    Cache,
    /// Decided by a fresh quorum resolution.
    Quorum,
    /// Blocked by the rating filter «bubble» (T-124, SPEC.md §5.3 step 5):
    /// the domain was outside every active availability zone, so quorum was
    /// never consulted. `voters` is always empty. Not cached — the zone can
    /// change under a toggle or lazy hygiene.
    RatingFilter,
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

/// How long the query log keeps entries (T-291, SPEC.md §6) — a closed set
/// the user picks from in `/admin/ui`, never a free-form duration. Serialized
/// by explicit stable name (`resolver_config.toml`'s `query_log_retention`
/// and the admin DTO), never by declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum LogRetention {
    /// 24 hours — the default, in memory only unless `persist_query_log` is on.
    #[default]
    #[serde(rename = "24h")]
    Day,
    /// 3 days — needs `persist_query_log` (a reboot would drop it otherwise).
    #[serde(rename = "3d")]
    ThreeDays,
    /// 7 days — needs `persist_query_log`.
    #[serde(rename = "7d")]
    SevenDays,
    /// 30 days — needs `persist_query_log`.
    #[serde(rename = "30d")]
    ThirtyDays,
}

impl LogRetention {
    /// The age bound.
    #[must_use]
    pub const fn max_age(self) -> Duration {
        Duration::from_hours(24 * self.days())
    }

    /// The entry-count bound — sized so a typical day (~2 200 queries,
    /// measured 2026-11-13) fits the age bound with room to spare, and capped
    /// at [`MAX_LOG_ENTRIES`] however long the age bound is.
    #[must_use]
    pub const fn max_entries(self) -> usize {
        match self {
            Self::Day => 10_000,
            Self::ThreeDays => 30_000,
            Self::SevenDays => 70_000,
            Self::ThirtyDays => MAX_LOG_ENTRIES,
        }
    }

    /// Whole days covered — also the on-disk segment window.
    #[must_use]
    pub const fn days(self) -> u64 {
        match self {
            Self::Day => 1,
            Self::ThreeDays => 3,
            Self::SevenDays => 7,
            Self::ThirtyDays => 30,
        }
    }

    /// Whether this window outlives a service restart only with
    /// `persist_query_log` on — every choice past the default.
    #[must_use]
    pub const fn needs_disk(self) -> bool {
        !matches!(self, Self::Day)
    }
}

/// The live query-log policy (T-291): how long entries are kept and whether
/// they are sealed to disk. Changed only together, under the admin
/// `persist_lock`, so the "past 24 h needs the disk" rule is checked against
/// one consistent pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueryLogPolicy {
    /// The retention window.
    pub retention: LogRetention,
    /// Whether the log is persisted (`persist_query_log`).
    pub persist: bool,
}

/// The hard ceiling on entries any [`LogRetention`] may keep (~35–40 MB at
/// the measured ~350 B per entry).
pub(crate) const MAX_LOG_ENTRIES: usize = 100_000;

/// One log entry plus its position in arrival order — the pager's cursor
/// (T-291). Not a timestamp: many queries share a millisecond, so a
/// timestamp cursor would skip entries at a page boundary.
#[derive(Debug, Clone)]
pub struct PagedEntry {
    /// Strictly increasing in arrival order for this process's lifetime;
    /// never persisted.
    pub seq: u64,
    /// The entry itself.
    pub entry: LogEntry,
}

/// One `GET /admin/log` page: the newest matches, oldest-first, and whether
/// older matches exist past it.
#[derive(Debug, Clone)]
pub struct LogPage {
    /// Up to `limit` matching entries, oldest first.
    pub entries: Vec<PagedEntry>,
    /// `true` when at least one more (older) matching entry was not returned.
    pub truncated: bool,
}

/// The buffer plus its bounds, all behind one lock so a bounds change and
/// the trim it implies are one atomic step.
struct Ring {
    entries: VecDeque<LogEntry>,
    max_entries: usize,
    max_age: Duration,
    /// Bumped on every push/clear/restore/bounds change — the persister
    /// compares it to skip a flush when nothing changed. Age eviction does
    /// not bump it: it only drops entries, which the disk copy loses on its
    /// own bounded restore.
    generation: u64,
    /// The sequence number the next pushed entry gets. Entry `i` (from the
    /// front) has `next_seq - len + i`: pushes append, every eviction pops
    /// the front, so the numbering needs no per-entry storage. `restore`
    /// (the one non-front removal) renumbers strictly upward.
    next_seq: u64,
}

impl Ring {
    fn is_live(&self, entry: &LogEntry, now: SystemTime) -> bool {
        // `Err` means `entry.timestamp` is after `now` (clock skew, not
        // staleness) - keep it. Do not "simplify" this to
        // `is_ok_and(...)`, which would silently flip that case to
        // "evict" instead.
        now.duration_since(entry.timestamp)
            .map_or(true, |age| age <= self.max_age)
    }

    /// Drops aged-out entries from the head. The buffer is in arrival order,
    /// so this is O(dropped), not a full scan; a future-dated head (clock
    /// skew) stops it, and readers skip any stale entry left behind it.
    fn evict_aged(&mut self, now: SystemTime) {
        while self
            .entries
            .front()
            .is_some_and(|entry| !self.is_live(entry, now))
        {
            self.entries.pop_front();
        }
    }

    fn trim_to_capacity(&mut self) {
        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }

    /// The sequence number of the front entry.
    fn head_seq(&self) -> u64 {
        self.next_seq.saturating_sub(self.entries.len() as u64)
    }

    fn bump(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }
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
    ring: RwLock<Ring>,
}

impl QueryLog {
    /// Constructs an empty log with the given bounds.
    #[must_use]
    pub fn new(max_entries: usize, max_age: Duration) -> Self {
        Self {
            ring: RwLock::new(Ring {
                entries: VecDeque::new(),
                max_entries,
                max_age,
                generation: 0,
                next_seq: 0,
            }),
        }
    }

    /// Constructs an empty log bounded by `retention` (T-291).
    #[must_use]
    pub fn with_retention(retention: LogRetention) -> Self {
        Self::new(retention.max_entries(), retention.max_age())
    }

    /// Switches to `retention`'s bounds live (T-291); a smaller window trims
    /// the buffer immediately.
    pub fn set_retention(&self, retention: LogRetention, now: SystemTime) {
        let mut ring = self.ring.write();
        ring.max_entries = retention.max_entries();
        ring.max_age = retention.max_age();
        ring.evict_aged(now);
        ring.trim_to_capacity();
        ring.bump();
    }

    /// The change counter (see [`Ring::generation`]).
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.ring.read().generation
    }

    /// The sequence number the next pushed entry will get — every entry
    /// already in the log has a smaller one. The persister records it after
    /// a flush to know which entries arrived since.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.ring.read().next_seq
    }

    /// `key(entry)` for every entry whose sequence number is `>= since`
    /// (T-291: the UTC days the persister must rewrite). Walks from the tail
    /// and stops at the first older entry — O(new entries), not O(log).
    #[must_use]
    pub fn keys_since<K: Ord>(
        &self,
        since: u64,
        mut key: impl FnMut(&LogEntry) -> K,
    ) -> std::collections::BTreeSet<K> {
        let ring = self.ring.read();
        let head_seq = ring.head_seq();
        let first = usize::try_from(since.saturating_sub(head_seq)).unwrap_or(usize::MAX);
        ring.entries.iter().skip(first).map(&mut key).collect()
    }

    /// Appends `entry`, then evicts the oldest record(s) if the buffer is
    /// now over capacity.
    ///
    /// The eviction loop's own negation is the post-condition — `len <=
    /// max_entries` holds after this call regardless of how many entries
    /// were present going in, not just because `push` happens to be the only
    /// inserter today (global CLAUDE.md: bounds safety provable from the
    /// line itself, not from an induction argument over callers).
    pub fn push(&self, entry: LogEntry) {
        let mut ring = self.ring.write();
        ring.entries.push_back(entry);
        ring.next_seq = ring.next_seq.saturating_add(1);
        ring.trim_to_capacity();
        ring.bump();
    }

    /// Returns every entry still within `max_age` of `now`, oldest first.
    ///
    /// Drops aged-out entries from the live buffer first (SPEC.md §6.1:
    /// "фільтрація на читанні", not a separate background sweep task). This
    /// clones the whole window — `GET /admin/log` uses [`Self::search`] and
    /// the status path [`Self::inspect`] instead.
    #[must_use]
    pub fn snapshot(&self, now: SystemTime) -> Vec<LogEntry> {
        self.entries_matching(now, |_| true)
    }

    /// Clones the live entries `predicate` accepts, oldest first — the
    /// persister's per-day segment read (T-291) clones one day, not the
    /// whole window.
    #[must_use]
    pub fn entries_matching<F>(&self, now: SystemTime, mut predicate: F) -> Vec<LogEntry>
    where
        F: FnMut(&LogEntry) -> bool,
    {
        let mut ring = self.ring.write();
        ring.evict_aged(now);
        let ring = RwLockWriteGuard::downgrade(ring);
        ring.entries
            .iter()
            .filter(|entry| ring.is_live(entry, now) && predicate(entry))
            .cloned()
            .collect()
    }

    /// Runs `f` over the live buffer (oldest first) without cloning it —
    /// the status path's whole-window counters (T-291: a 100 000-entry
    /// window cloned once a second for the SSE sampler was the alternative).
    /// `f` may see a stale entry left behind a future-dated head (see
    /// [`Ring::evict_aged`]); every caller only counts, so that is harmless.
    pub fn inspect<R>(&self, now: SystemTime, f: impl FnOnce(&VecDeque<LogEntry>) -> R) -> R {
        let mut ring = self.ring.write();
        ring.evict_aged(now);
        let ring = RwLockWriteGuard::downgrade(ring);
        f(&ring.entries)
    }

    /// The newest `limit` entries matching every facet `filter` sets and
    /// arrived before sequence number `before_seq` (when set), oldest first
    /// (T-45, SPEC.md §6: "простий підрядковий фільтр по domain плюс
    /// фасети"). Walks from the tail and clones at most `limit` entries,
    /// however many match (T-291).
    #[must_use]
    pub fn search(
        &self,
        now: SystemTime,
        filter: &LogFilter<'_>,
        limit: usize,
        before_seq: Option<u64>,
    ) -> LogPage {
        let needle = filter.domain_contains.map(str::to_ascii_lowercase);
        let mut ring = self.ring.write();
        ring.evict_aged(now);
        let ring = RwLockWriteGuard::downgrade(ring);
        let head_seq = ring.head_seq();
        let mut matches = ring
            .entries
            .iter()
            .enumerate()
            .rev()
            .map(|(index, entry)| (head_seq.saturating_add(index as u64), entry))
            .filter(|(seq, entry)| {
                before_seq.is_none_or(|cutoff| *seq < cutoff)
                    && ring.is_live(entry, now)
                    && matches_filter(entry, filter, needle.as_deref())
            });
        let mut entries: Vec<PagedEntry> = matches
            .by_ref()
            .take(limit)
            .map(|(seq, entry)| PagedEntry {
                seq,
                entry: entry.clone(),
            })
            .collect();
        let truncated = matches.next().is_some();
        entries.reverse();
        LogPage { entries, truncated }
    }

    /// Empties the log immediately (SPEC.md §6's manual clear action, T-44 —
    /// same pattern as `Cache::clear`, T-137).
    pub fn clear(&self) {
        let mut ring = self.ring.write();
        ring.entries.clear();
        ring.bump();
    }

    /// Seeds the buffer from a previous run's persisted entries (T-146 —
    /// [`Self::snapshot`] output, decrypted from disk), oldest first, then
    /// re-applies **both** bounds against `now`: entries past `max_age` are
    /// dropped, and any excess over `max_entries` is evicted oldest-first.
    /// The configured window is not bypassed by restoring from disk. Called
    /// once at startup before the listener accepts traffic; a no-op on empty
    /// input.
    ///
    /// A full `retain` here, not [`Ring::evict_aged`]: restored input can
    /// interleave segments, so arrival order is not guaranteed. The merged
    /// buffer is then sorted by timestamp (stable), so restored history sits
    /// behind live entries, never after them — T-291 restores into a live
    /// log when persistence is switched on at runtime. The two
    /// post-conditions (`len <= max_entries`, every kept entry within
    /// `max_age` of `now`) hold from the loops themselves.
    pub fn restore(&self, entries: Vec<LogEntry>, now: SystemTime) {
        if entries.is_empty() {
            return;
        }
        let mut ring = self.ring.write();
        // Every surviving entry is renumbered at or above the old
        // `next_seq`, so a cursor handed out before this never lands inside
        // the new numbering.
        let old_next = ring.next_seq;
        ring.entries.extend(entries);
        let max_age = ring.max_age;
        ring.entries.retain(|entry| {
            now.duration_since(entry.timestamp)
                .map_or(true, |age| age <= max_age)
        });
        ring.entries
            .make_contiguous()
            .sort_by_key(|entry| entry.timestamp);
        ring.trim_to_capacity();
        ring.next_seq = old_next.saturating_add(ring.entries.len() as u64);
        ring.bump();
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
    /// [`LogRetention::default`]'s bounds (24 hours).
    fn default() -> Self {
        Self::with_retention(LogRetention::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Decision, DecisionSource, LogEntry, LogFilter, LogRetention, QueryLog, MAX_LOG_ENTRIES,
    };
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

    /// The pre-T-291 "every match" read, for the facet tests below.
    fn search_all(log: &QueryLog, now: SystemTime, filter: &LogFilter<'_>) -> Vec<LogEntry> {
        log.search(now, filter, usize::MAX, None)
            .entries
            .into_iter()
            .map(|paged| paged.entry)
            .collect()
    }

    fn page_domains(page: &super::LogPage) -> Vec<&str> {
        page.entries
            .iter()
            .map(|p| p.entry.domain.as_str())
            .collect()
    }

    fn named(timestamp: SystemTime, domain: &str) -> LogEntry {
        let mut entry = entry_at(timestamp);
        entry.domain = domain.to_string();
        entry
    }

    fn domains(entries: &[LogEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.domain.as_str()).collect()
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
        let log = QueryLog::new(1000, Duration::from_hours(24));
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
        let ring = log.ring.read();
        assert_eq!(ring.max_entries, LogRetention::Day.max_entries());
        assert_eq!(ring.max_age, Duration::from_hours(24));
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

        let results = search_all(
            &log,
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

        let results = search_all(
            &log,
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

        let results = search_all(
            &log,
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

        let results = search_all(
            &log,
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

        let results = search_all(
            &log,
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

        let results = search_all(
            &log,
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

        let results = search_all(
            &log,
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

        let results = search_all(
            &log,
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
            search_all(&log, now, &LogFilter::default()).len(),
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

        let results = search_all(
            &log,
            now,
            &LogFilter {
                domain_contains: Some("stale"),
                ..LogFilter::default()
            },
        );

        assert!(results.is_empty());
    }

    // T-291: retention choices.

    #[test]
    fn every_retention_has_its_age_and_a_capped_entry_bound() {
        let cases = [
            (LogRetention::Day, 1, false),
            (LogRetention::ThreeDays, 3, true),
            (LogRetention::SevenDays, 7, true),
            (LogRetention::ThirtyDays, 30, true),
        ];
        for (retention, days, needs_disk) in cases {
            assert_eq!(retention.max_age(), Duration::from_hours(24 * days));
            assert_eq!(retention.days(), days);
            assert_eq!(retention.needs_disk(), needs_disk);
            assert!(retention.max_entries() <= MAX_LOG_ENTRIES);
        }
        assert!(
            LogRetention::Day.max_entries() > 1000,
            "1000 held only ~11 h of real traffic"
        );
        assert_eq!(LogRetention::default(), LogRetention::Day);
    }

    #[test]
    fn retention_serializes_by_stable_name() {
        for (retention, wire) in [
            (LogRetention::Day, "\"24h\""),
            (LogRetention::ThreeDays, "\"3d\""),
            (LogRetention::SevenDays, "\"7d\""),
            (LogRetention::ThirtyDays, "\"30d\""),
        ] {
            assert_eq!(
                serde_json::to_string(&retention).ok().as_deref(),
                Some(wire)
            );
            assert_eq!(
                serde_json::from_str::<LogRetention>(wire).ok(),
                Some(retention)
            );
        }
        assert!(serde_json::from_str::<LogRetention>("\"2d\"").is_err());
        assert!(serde_json::from_str::<LogRetention>("\"Day\"").is_err());
    }

    #[test]
    fn a_longer_retention_keeps_entries_the_default_would_drop() {
        let now = SystemTime::now();
        let Some(three_days_ago) = now.checked_sub(Duration::from_hours(72)) else {
            panic!("valid fixture timestamp");
        };
        let log = QueryLog::with_retention(LogRetention::SevenDays);
        log.restore(
            vec![
                named(three_days_ago, "old.example"),
                named(now, "new.example"),
            ],
            now,
        );
        assert_eq!(
            domains(&log.snapshot(now)),
            vec!["old.example", "new.example"]
        );

        let day = QueryLog::default();
        day.restore(
            vec![
                named(three_days_ago, "old.example"),
                named(now, "new.example"),
            ],
            now,
        );
        assert_eq!(domains(&day.snapshot(now)), vec!["new.example"]);
    }

    #[test]
    fn shrinking_the_retention_trims_the_buffer_at_once() {
        let now = SystemTime::now();
        let Some(two_days_ago) = now.checked_sub(Duration::from_hours(48)) else {
            panic!("valid fixture timestamp");
        };
        let log = QueryLog::with_retention(LogRetention::SevenDays);
        log.push(named(two_days_ago, "old.example"));
        log.push(named(now, "new.example"));
        let before = log.generation();

        log.set_retention(LogRetention::Day, now);

        assert_ne!(log.generation(), before, "a bounds change is a change");
        assert_eq!(log.inspect(now, std::collections::VecDeque::len), 1);
        assert_eq!(domains(&log.snapshot(now)), vec!["new.example"]);
    }

    #[test]
    fn shrinking_the_entry_bound_keeps_the_newest() {
        let now = SystemTime::now();
        let log = QueryLog::with_retention(LogRetention::ThreeDays);
        for i in 0..LogRetention::Day.max_entries() + 5 {
            log.push(named(now, &format!("d{i}.example")));
        }
        log.set_retention(LogRetention::Day, now);
        let kept = log.snapshot(now);
        assert_eq!(kept.len(), LogRetention::Day.max_entries());
        assert_eq!(kept.first().map(|e| e.domain.as_str()), Some("d5.example"));
    }

    #[test]
    fn the_buffer_never_outgrows_the_hard_ceiling() {
        let now = SystemTime::now();
        let log = QueryLog::with_retention(LogRetention::ThirtyDays);
        for _ in 0..MAX_LOG_ENTRIES + 10 {
            log.push(entry_at(now));
        }
        assert_eq!(
            log.inspect(now, std::collections::VecDeque::len),
            MAX_LOG_ENTRIES
        );
    }

    #[test]
    fn generation_moves_on_push_clear_and_restore() {
        let now = SystemTime::now();
        let log = QueryLog::default();
        let g0 = log.generation();
        log.push(entry_at(now));
        let g1 = log.generation();
        log.clear();
        let g2 = log.generation();
        log.restore(vec![entry_at(now)], now);
        let g3 = log.generation();
        assert!(g0 != g1 && g1 != g2 && g2 != g3);
        let _ = log.snapshot(now);
        assert_eq!(log.generation(), g3, "a read is not a change");
    }

    #[test]
    fn search_returns_the_newest_limit_matches_oldest_first() {
        let now = SystemTime::now();
        let log = QueryLog::default();
        for name in ["a.example", "b.example", "c.example", "d.example"] {
            log.push(named(now, name));
        }
        let page = log.search(now, &LogFilter::default(), 2, None);
        assert_eq!(page_domains(&page), vec!["c.example", "d.example"]);
        assert!(page.truncated);

        let whole = log.search(now, &LogFilter::default(), 4, None);
        assert!(!whole.truncated, "exactly `limit` matches is not truncated");
    }

    /// Walks every page with the `before_seq` cursor and returns what it saw.
    fn walk_pages(log: &QueryLog, now: SystemTime, limit: usize) -> Vec<String> {
        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let page = log.search(now, &LogFilter::default(), limit, cursor);
            let mut names: Vec<String> = page
                .entries
                .iter()
                .map(|p| p.entry.domain.clone())
                .collect();
            names.extend(seen);
            seen = names;
            if !page.truncated {
                return seen;
            }
            cursor = page.entries.first().map(|p| p.seq);
        }
    }

    #[test]
    fn paging_with_the_cursor_neither_skips_nor_duplicates() {
        let now = SystemTime::now();
        let log = QueryLog::default();
        // Same instant for all - a millisecond cursor would lose some at
        // every page boundary - and one pushed out of timestamp order.
        for i in 0..7 {
            log.push(named(now, &format!("d{i}.example")));
        }
        let Some(earlier) = now.checked_sub(Duration::from_secs(5)) else {
            panic!("valid fixture timestamp");
        };
        log.push(named(earlier, "late.example"));
        let expected: Vec<String> = (0..7)
            .map(|i| format!("d{i}.example"))
            .chain(std::iter::once("late.example".to_string()))
            .collect();
        for limit in 1..=9 {
            assert_eq!(walk_pages(&log, now, limit), expected, "limit {limit}");
        }
    }

    #[test]
    fn the_cursor_survives_evictions_from_the_front() {
        let now = SystemTime::now();
        let log = QueryLog::new(3, Duration::from_hours(24));
        for name in ["a", "b", "c"] {
            log.push(named(now, name));
        }
        let page = log.search(now, &LogFilter::default(), 1, None);
        let Some(cursor) = page.entries.first().map(|p| p.seq) else {
            panic!("page is not empty");
        };
        log.push(named(now, "d")); // evicts "a"
        let older = log.search(now, &LogFilter::default(), 10, Some(cursor));
        assert_eq!(
            page_domains(&older),
            vec!["b"],
            "still older than the cursor's own entry"
        );
    }

    #[test]
    fn restore_renumbers_above_every_earlier_cursor() {
        let now = SystemTime::now();
        let log = QueryLog::default();
        log.push(named(now, "live"));
        let before = log.search(now, &LogFilter::default(), 1, None);
        let Some(old_seq) = before.entries.first().map(|p| p.seq) else {
            panic!("page is not empty");
        };
        log.restore(vec![named(now, "restored")], now);
        let page = log.search(now, &LogFilter::default(), 10, None);
        assert!(page.entries.iter().all(|p| p.seq > old_seq));
        let seqs: Vec<u64> = page.entries.iter().map(|p| p.seq).collect();
        assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    }

    #[test]
    fn restore_into_a_live_log_keeps_timestamp_order() {
        let now = SystemTime::now();
        let Some(hour_ago) = now.checked_sub(Duration::from_hours(1)) else {
            panic!("valid fixture timestamp");
        };
        let log = QueryLog::default();
        log.push(named(now, "live"));
        log.restore(vec![named(hour_ago, "old")], now);
        assert_eq!(domains(&log.snapshot(now)), vec!["old", "live"]);
        let page = log.search(now, &LogFilter::default(), 1, None);
        assert_eq!(
            page_domains(&page),
            vec!["live"],
            "the newest page is the live entry"
        );
    }

    #[test]
    fn keys_since_sees_only_entries_pushed_after_the_mark() {
        let now = SystemTime::now();
        let log = QueryLog::new(3, Duration::from_hours(24));
        log.push(named(now, "a"));
        let mark = log.next_seq();
        log.push(named(now, "b"));
        log.push(named(now, "c"));
        let keys = log.keys_since(mark, |e| e.domain.clone());
        assert_eq!(keys.into_iter().collect::<Vec<_>>(), vec!["b", "c"]);
        log.push(named(now, "d")); // evicts "a"
        log.push(named(now, "e")); // evicts "b"
        let keys = log.keys_since(mark, |e| e.domain.clone());
        assert_eq!(keys.into_iter().collect::<Vec<_>>(), vec!["c", "d", "e"]);
        assert!(log
            .keys_since(log.next_seq(), |e| e.domain.clone())
            .is_empty());
    }

    #[test]
    fn search_skips_a_stale_entry_left_behind_a_future_dated_head() {
        let now = SystemTime::now();
        let Some(stale) = now.checked_sub(Duration::from_hours(25)) else {
            panic!("valid fixture timestamp");
        };
        let log = QueryLog::default();
        log.push(named(now + Duration::from_secs(60), "future.example"));
        log.push(named(stale, "stale.example"));
        let page = log.search(now, &LogFilter::default(), 10, None);
        assert_eq!(page_domains(&page), vec!["future.example"]);
    }
}
