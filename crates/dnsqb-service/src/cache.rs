//! Per-entry-TTL quorum-verdict cache (SPEC.md §4, §4.1 — T-32, T-34, T-36).
//!
//! Wired into the live request pipeline since T-39 (`pipeline::handle_query`
//! branches positive-answer `chain_cache_ttl` vs. NXDOMAIN/NODATA
//! `negative_cache_ttl` there). `CacheConfig` itself was still startup-
//! hardcoded to [`CacheConfig::default`] until T-153, which added
//! [`CacheConfig::from_secs`] as the validated boundary a live admin-channel
//! write goes through — see that function's own doc comment.

use crate::normalize_domain;
use hickory_proto::rr::{Record, RecordType};
use hickory_proto::ProtoError;
use moka::future::Cache as MokaCache;
use moka::policy::Expiry;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Cache key — `domain` always passed through [`normalize_domain`] (T-38),
/// so cache and override-list lookups can never desync over case/IDNA
/// formatting (SPEC.md §4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    domain: String,
    qtype: RecordType,
}

impl CacheKey {
    /// # Errors
    ///
    /// Returns `Err` if `domain` is not a syntactically valid domain name.
    pub fn new(domain: &str, qtype: RecordType) -> Result<Self, ProtoError> {
        Ok(Self {
            domain: normalize_domain(domain)?,
            qtype,
        })
    }

    /// The normalized domain this key matches — needed by T-97 to serialize a
    /// cache snapshot. Restore goes back through [`Self::new`], not a struct
    /// literal, so the `normalize_domain` invariant still holds on the way in.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The record type this key matches (T-97, paired with [`Self::domain`]).
    #[must_use]
    pub fn qtype(&self) -> RecordType {
        self.qtype
    }
}

/// A cached quorum verdict (SPEC.md §4) — never `quorum::QuorumVerdict::
/// NotApplicable`, which bypasses quorum (and therefore caching) entirely
/// (HTTPS/SVCB etc., SPEC.md §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Domain resolved; the IPs a fresh quorum answer carried.
    Allow(Vec<IpAddr>),
    /// At least one provider's block signature matched.
    Block,
}

/// One cache slot: the verdict, its TTL, and the instant it was computed to
/// go stale. `expires_at` — not `moka`'s own per-entry removal time — is the
/// real freshness boundary this project reads (see [`Cache`]'s doc comment).
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cached verdict.
    pub verdict: Verdict,
    /// The TTL this entry was inserted with.
    pub ttl: Duration,
    /// `created_at + ttl`, computed once at construction.
    pub expires_at: Instant,
}

impl CacheEntry {
    /// Constructs an entry, computing `expires_at` as `Instant::now() + ttl`.
    #[must_use]
    pub fn new(verdict: Verdict, ttl: Duration) -> Self {
        Self {
            verdict,
            ttl,
            expires_at: Instant::now() + ttl,
        }
    }

    /// `true` if `now` is still before `expires_at` — an entry can be
    /// present in the cache (within `moka`'s `ttl + stale_grace` window) and
    /// still not fresh; that's exactly the stale-if-error case (T-28).
    #[must_use]
    pub fn is_fresh(&self, now: Instant) -> bool {
        now < self.expires_at
    }
}

/// Three independently-sourced TTL kinds this module deals with at once
/// (SPEC.md §4.1 addendum) — bundled into one config so `clamp_ttl` can take
/// the whole thing instead of two bare `Duration` parameters that would
/// invite passing the wrong kind in the wrong slot:
/// - `clamp_min`/`clamp_max` — bounds for upstream-controlled raw TTLs
///   (`chain_cache_ttl`/`negative_cache_ttl` output). RFC-silent on the
///   exact numbers; SPEC.md §4.1 already names sensible defaults.
/// - `block_verdict_ttl` — project-chosen constant, not upstream-derived,
///   never passed through `clamp_ttl`.
/// - `stale_grace` — RFC 8767 §5's stale-timer window (T-28).
/// - `max_capacity` — project-chosen entry-count bound for `moka`'s LRU-like
///   eviction (SPEC.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfig {
    /// Lower clamp bound for upstream-derived TTLs.
    pub clamp_min: Duration,
    /// Upper clamp bound for upstream-derived TTLs.
    pub clamp_max: Duration,
    /// Cache lifetime for a `Block` verdict — not upstream-derived.
    pub block_verdict_ttl: Duration,
    /// RFC 8767 §5 stale-timer grace window, layered on top of `ttl`.
    pub stale_grace: Duration,
    /// Maximum number of entries `moka` will hold before LRU-like eviction.
    pub max_capacity: u64,
}

impl Default for CacheConfig {
    /// SPEC.md §4.1: clamp defaults are the spec's own stated numbers
    /// (min 30s, max 24h). `block_verdict_ttl` reuses `clamp_max` rather than
    /// inventing a fourth number — "block decisions update less often than
    /// individual A records" (SPEC.md §4) is satisfied by any value at least
    /// that long. `stale_grace` defaults to the conservative (lower) end of
    /// RFC 8767 §5's suggested 1–3 day range. `max_capacity` is a project
    /// choice with no RFC or SPEC number behind it (typical single-user
    /// daily unique-domain count), configurable.
    fn default() -> Self {
        let clamp_max = Duration::from_hours(24);
        Self {
            clamp_min: Duration::from_secs(30),
            clamp_max,
            block_verdict_ttl: clamp_max,
            stale_grace: Duration::from_hours(24),
            max_capacity: 10_000,
        }
    }
}

/// Errors validating raw seconds/count into a [`CacheConfig`] (T-153).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CacheConfigError {
    /// `clamp_min_secs > clamp_max_secs` — rejected here rather than left to
    /// surface as a panic in [`clamp_ttl`] (which is itself made
    /// structurally non-panicking regardless, see its own doc comment; this
    /// is the loud, honest rejection at the boundary, not the only defense).
    #[error("cache clamp_min must not exceed clamp_max")]
    ClampMinExceedsMax,
}

impl CacheConfig {
    /// The *only* validated path from untrusted raw integers (a
    /// `resolver_config.toml` `[cache]` table, an admin-channel POST body)
    /// into a `CacheConfig` (T-153). `config.rs`'s `ResolverConfig::load` and
    /// `dispatch.rs`'s `POST /admin/cache-config/apply` handler both call
    /// this rather than each re-implementing the `clamp_min <= clamp_max`
    /// check — two independent copies of that check would risk drifting,
    /// which matters here because [`clamp_ttl`] depends on it holding.
    /// Struct-literal construction (used throughout this crate's own tests)
    /// is unaffected — this is additive, not a replacement.
    ///
    /// # Errors
    ///
    /// Returns [`CacheConfigError::ClampMinExceedsMax`] if
    /// `clamp_min_secs > clamp_max_secs`.
    pub fn from_secs(
        clamp_min_secs: u64,
        clamp_max_secs: u64,
        block_verdict_ttl_secs: u64,
        stale_grace_secs: u64,
        max_capacity: u64,
    ) -> Result<Self, CacheConfigError> {
        if clamp_min_secs > clamp_max_secs {
            return Err(CacheConfigError::ClampMinExceedsMax);
        }
        Ok(Self {
            clamp_min: Duration::from_secs(clamp_min_secs),
            clamp_max: Duration::from_secs(clamp_max_secs),
            block_verdict_ttl: Duration::from_secs(block_verdict_ttl_secs),
            stale_grace: Duration::from_secs(stale_grace_secs),
            max_capacity,
        })
    }

    /// The reverse of [`Self::from_secs`] — whole-second counts for
    /// persisting back to TOML or echoing in an admin-channel response.
    /// Sub-second precision is never produced by `from_secs`, so this is a
    /// lossless round trip for any `CacheConfig` built that way (not
    /// necessarily for one built via a struct literal with a non-whole-second
    /// `Duration`, which nothing in this crate does).
    #[must_use]
    pub fn to_secs(&self) -> CacheConfigSecs {
        CacheConfigSecs {
            clamp_min_secs: self.clamp_min.as_secs(),
            clamp_max_secs: self.clamp_max.as_secs(),
            block_verdict_ttl_secs: self.block_verdict_ttl.as_secs(),
            stale_grace_secs: self.stale_grace.as_secs(),
            max_capacity: self.max_capacity,
        }
    }
}

/// Whole-second view of a [`CacheConfig`], returned by [`CacheConfig::to_secs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfigSecs {
    /// See [`CacheConfig::clamp_min`].
    pub clamp_min_secs: u64,
    /// See [`CacheConfig::clamp_max`].
    pub clamp_max_secs: u64,
    /// See [`CacheConfig::block_verdict_ttl`].
    pub block_verdict_ttl_secs: u64,
    /// See [`CacheConfig::stale_grace`].
    pub stale_grace_secs: u64,
    /// See [`CacheConfig::max_capacity`].
    pub max_capacity: u64,
}

/// RFC 2181/2308-derived TTL clamping (T-34, SPEC.md §4.1) — applied only to
/// upstream-controlled raw seconds (`chain_cache_ttl`/`negative_cache_ttl`
/// output), never to `block_verdict_ttl` or `stale_grace`. Takes the whole
/// [`CacheConfig`] rather than bare `min`/`max: Duration` parameters so the
/// signature itself can't be handed the wrong one of this module's three TTL
/// kinds.
///
/// `raw_seconds == 0` is passed through as `Duration::ZERO`, **not** raised
/// to `clamp_min` — SPEC.md §4.1 is explicit that TTL=0 means "don't cache
/// at all," a sentinel distinct from "cache briefly." Clamping it up would
/// make [`is_cacheable`]/[`Cache::insert`]'s zero-TTL guard unreachable from
/// any real upstream-derived value, since this function is the last place
/// that sees the raw `0` before it becomes a `Duration`. Callers must treat
/// a `Duration::ZERO` return the same way as any other zero TTL: skip
/// caching and answer the client directly from the fresh response
/// (`Cache::insert` already does this itself; `is_cacheable` is there for
/// callers who want to branch earlier).
///
/// Deliberately `.max(min).min(max)`, not `std::cmp::Ord::clamp` (T-153) —
/// `Ord::clamp` asserts `min <= max` unconditionally (release builds
/// included) and panics otherwise. `CacheConfig::from_secs` already rejects
/// an inverted `clamp_min`/`clamp_max` at every validated construction path,
/// but relying on that alone would make this line's own safety a fact
/// provable only by tracing every caller, not from the line itself — exactly
/// the bounds-safety shape this project avoids elsewhere. `.max(min).min
/// (max)` gives identical output to `.clamp()` for any valid config, and for
/// an inverted one deterministically returns `max` instead of panicking
/// (`x.max(min) >= min > max`, then `.min(max) == max`).
#[must_use]
pub fn clamp_ttl(raw_seconds: u32, config: &CacheConfig) -> Duration {
    if raw_seconds == 0 {
        return Duration::ZERO;
    }
    Duration::from_secs(u64::from(raw_seconds))
        .max(config.clamp_min)
        .min(config.clamp_max)
}

/// SPEC.md §4.1 (T-36): minimum TTL across the whole answer section — every
/// CNAME hop plus the final `RRset`, not just the final record's TTL.
/// Deliberately does **not** group by `(name, type)` — the global minimum
/// over the section is a safe (conservative) superset of the RFC 2181
/// same-`RRset` requirement too, since that `RRset` is itself part of the
/// section. Distinct from [`crate::min_rrset_ttl`] (T-33), which requires
/// pre-grouped, single-RRset input — conflating the two would pass both
/// their conformance tests while correctly implementing neither.
#[must_use]
pub fn chain_cache_ttl(records: &[Record]) -> Option<u32> {
    records.iter().map(|r| r.ttl).min()
}

/// T-32 (SPEC.md §4.1): TTL=0 must never enter the cache, not even
/// momentarily — a TTL=0 entry participates in concurrent-read races the
/// instant it exists. [`Cache::insert`] enforces this itself; this is
/// exposed separately for callers who want to branch (e.g. skip building a
/// `CacheEntry` at all) before ever reaching `insert`.
#[must_use]
pub fn is_cacheable(ttl: Duration) -> bool {
    ttl > Duration::ZERO
}

/// `moka`'s own per-entry eviction clock — deliberately set to
/// `ttl + stale_grace`, not bare `ttl`. RFC 8767 stale-if-error (T-28) needs
/// to read an already-expired-but-still-cached entry; if `moka` evicted at
/// exactly `ttl`, the very data stale-if-error exists to serve would already
/// be gone by the time `should_serve_stale` says to use it. RFC 8767 §5
/// itself specifies a maximum stale-timer window ("suggested value is
/// between 1 and 3 days") — `stale_grace` is that window, not a workaround.
/// The real freshness boundary stays [`CacheEntry::expires_at`], checked on
/// read, never `moka`'s own clock.
struct CacheExpiry {
    stale_grace: Duration,
}

impl Expiry<CacheKey, CacheEntry> for CacheExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CacheEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl + self.stale_grace)
    }
}

/// SPEC.md §4: concurrent, per-entry-TTL quorum-verdict cache.
pub struct Cache {
    inner: MokaCache<CacheKey, CacheEntry>,
}

impl Cache {
    /// Builds an empty cache from `config` — bounded capacity, `Expiry`
    /// wired to `config.stale_grace`.
    #[must_use]
    pub fn new(config: &CacheConfig) -> Self {
        let inner = MokaCache::builder()
            .max_capacity(config.max_capacity)
            .expire_after(CacheExpiry {
                stale_grace: config.stale_grace,
            })
            .support_invalidation_closures()
            .build();
        Self { inner }
    }

    /// Looks up `key` — may return an entry whose `is_fresh` is `false`
    /// (present but stale, within `moka`'s grace window; see the module and
    /// [`CacheExpiry`] docs).
    pub async fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        self.inner.get(key).await
    }

    /// No-op if `entry.ttl` is zero (T-32) — `insert` doesn't rely on the
    /// caller having checked [`is_cacheable`] first; the failure mode for
    /// forgetting that at a future call site would otherwise be silent.
    pub async fn insert(&self, key: CacheKey, entry: CacheEntry) {
        if !is_cacheable(entry.ttl) {
            return;
        }
        self.inner.insert(key, entry).await;
    }

    /// SPEC.md §5 (T-40): invalidate every cached A/AAAA entry matching any
    /// of `entries` — each `(domain, is_wildcard)` pair uses the same
    /// suffix-match semantics as `overrides::rule_matches`: exact match
    /// always, plus any subdomain when `is_wildcard`. Every `domain` must
    /// already be normalized (same precondition as `CacheKey::new`).
    ///
    /// One `moka` predicate registration for the whole batch, not one per
    /// entry — `moka` applies every live predicate on every `get()` until
    /// its own maintenance task sweeps it away, so registering N separate
    /// predicates for an N-domain override-list reload would put N closures
    /// on the DNS read path. A single predicate closing over the whole list
    /// keeps that cost at one, however many entries changed. No-op on an
    /// empty `entries` — skips registering a predicate that could never
    /// match anything.
    pub fn invalidate_matching(&self, entries: Vec<(String, bool)>) {
        if entries.is_empty() {
            return;
        }
        let matchers: Vec<(String, Option<String>)> = entries
            .into_iter()
            .map(|(domain, is_wildcard)| {
                let suffix = is_wildcard.then(|| format!(".{domain}"));
                (domain, suffix)
            })
            .collect();
        let matched = self.inner.invalidate_entries_if(move |key, _entry| {
            matchers.iter().any(|(domain, suffix)| {
                key.domain == *domain
                    || suffix
                        .as_ref()
                        .is_some_and(|s| key.domain.ends_with(s.as_str()))
            })
        });
        if matched.is_err() {
            // The only failure mode is `PredicateError::InvalidationClosuresDisabled`
            // (verified by reading moka 0.12.16's `common/error.rs` in full — it has
            // exactly one variant) — unreachable here since `Cache::new` always calls
            // `support_invalidation_closures()`. Warned, not silently swallowed: a
            // future moka upgrade changing that invariant should be observable, not
            // a cache that quietly stops honoring override-list changes.
            tracing::warn!(
                "override-list cache invalidation rejected: cache built without invalidation-closure support"
            );
        }
    }

    /// T-97: a point-in-time copy of every currently-held `(key, entry)` pair,
    /// for the encrypted `cache.enc` snapshot. `moka`'s `iter()` is a
    /// best-effort concurrent scan — an entry inserted after the scan begins
    /// may be missed (the next flush picks it up), and a logically-expired but
    /// not-yet-swept entry may be yielded (`cache_persist_dto`'s own freshness
    /// filter drops it). Neither matters for a cache.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(CacheKey, CacheEntry)> {
        self.inner
            .iter()
            .map(|(key, entry)| (key.as_ref().clone(), entry))
            .collect()
    }

    /// T-97: re-inserts entries restored from `cache.enc`, once at startup
    /// before the listener accepts traffic. Each entry's `moka` eviction
    /// window is derived from its (already downtime-adjusted) `ttl` exactly as
    /// a fresh insert's is; a zero-TTL entry is a no-op ([`Self::insert`]).
    pub async fn restore(&self, entries: Vec<(CacheKey, CacheEntry)>) {
        for (key, entry) in entries {
            self.insert(key, entry).await;
        }
    }

    /// T-137: manual full-cache clear, exposed as a one-click UI action —
    /// unlike [`Self::invalidate_matching`], this doesn't need a predicate
    /// (`moka`'s own `invalidate_all` marks every current entry stale as of
    /// now, no `support_invalidation_closures` involved). `moka`'s own docs
    /// say retrieval won't return entries inserted "before or at" the
    /// invalidation time — read alone that's ambiguous about whether a
    /// same-tick re-insert of a just-cleared key would also be swallowed;
    /// verified empirically, not just by reading the doc, that it isn't
    /// (`tests::clear_does_not_block_a_re_insert_of_the_same_key_afterward`).
    pub fn clear(&self) {
        self.inner.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        chain_cache_ttl, clamp_ttl, is_cacheable, Cache, CacheConfig, CacheConfigError, CacheEntry,
        CacheExpiry, CacheKey, Verdict,
    };
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use moka::policy::Expiry;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    fn fixture_name() -> Name {
        let Ok(name) = Name::from_str("example.com.") else {
            panic!("valid fixture name");
        };
        name
    }

    fn a_record(name: Name, ttl: u32) -> Record {
        Record::from_rdata(name, ttl, RData::A(A(Ipv4Addr::new(93, 184, 216, 34))))
    }

    #[test]
    fn cache_key_normalizes_domain() {
        let Ok(key) = CacheKey::new("Example.COM.", RecordType::A) else {
            panic!("valid domain");
        };
        assert_eq!(key.domain, "example.com");
    }

    #[test]
    fn clamp_ttl_below_minimum_is_raised() {
        let config = CacheConfig::default();
        assert_eq!(clamp_ttl(5, &config), config.clamp_min);
    }

    #[test]
    fn clamp_ttl_above_maximum_is_lowered() {
        let config = CacheConfig::default();
        assert_eq!(clamp_ttl(u32::MAX, &config), config.clamp_max);
    }

    #[test]
    fn clamp_ttl_within_range_is_unchanged() {
        let config = CacheConfig::default();
        assert_eq!(clamp_ttl(3600, &config), Duration::from_secs(3600));
    }

    #[test]
    fn clamp_ttl_of_zero_is_not_raised_to_minimum() {
        // TTL=0 is the "don't cache" sentinel (SPEC.md §4.1) — clamping it
        // up to clamp_min would make the zero-TTL guard downstream
        // unreachable from any real upstream-derived value.
        let config = CacheConfig::default();
        assert_eq!(clamp_ttl(0, &config), Duration::ZERO);
    }

    #[test]
    fn clamp_ttl_never_panics_on_an_inverted_config() {
        // Struct-literal construction deliberately bypasses `from_secs`'s own
        // validation, to prove `clamp_ttl` itself is safe regardless of
        // caller discipline (T-153) - not just that the validated
        // construction path rejects this shape (a separate test below).
        let inverted = CacheConfig {
            clamp_min: Duration::from_secs(100),
            clamp_max: Duration::from_secs(10),
            ..CacheConfig::default()
        };
        assert_eq!(clamp_ttl(50, &inverted), Duration::from_secs(10));
    }

    #[test]
    fn from_secs_rejects_an_inverted_clamp_range() {
        assert_eq!(
            CacheConfig::from_secs(100, 10, 100, 100, 10_000),
            Err(CacheConfigError::ClampMinExceedsMax)
        );
    }

    #[test]
    fn from_secs_then_to_secs_round_trips() {
        let config = match CacheConfig::from_secs(30, 3600, 3600, 86_400, 5_000) {
            Ok(config) => config,
            Err(err) => panic!("valid input must not be rejected: {err}"),
        };
        let secs = config.to_secs();
        assert_eq!(secs.clamp_min_secs, 30);
        assert_eq!(secs.clamp_max_secs, 3600);
        assert_eq!(secs.block_verdict_ttl_secs, 3600);
        assert_eq!(secs.stale_grace_secs, 86_400);
        assert_eq!(secs.max_capacity, 5_000);
    }

    #[test]
    fn is_cacheable_rejects_zero_ttl() {
        assert!(!is_cacheable(Duration::ZERO));
        assert!(is_cacheable(Duration::from_secs(1)));
    }

    #[test]
    fn chain_cache_ttl_takes_minimum_across_cname_hop_and_final_record() {
        let cname_name = fixture_name();
        let Ok(final_name) = Name::from_str("cdn.example.net.") else {
            panic!("valid fixture name");
        };
        let cname_record = Record::from_rdata(
            cname_name,
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(final_name.clone())),
        );
        let final_record = a_record(final_name, 60);
        assert_eq!(chain_cache_ttl(&[cname_record, final_record]), Some(60));
    }

    #[test]
    fn chain_cache_ttl_of_empty_answer_is_none() {
        assert_eq!(chain_cache_ttl(&[]), None);
    }

    #[tokio::test]
    async fn insert_then_get_round_trips_a_fresh_entry() {
        let cache = Cache::new(&CacheConfig::default());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let entry = CacheEntry::new(Verdict::Block, Duration::from_secs(60));
        cache.insert(key.clone(), entry).await;

        let Some(fetched) = cache.get(&key).await else {
            panic!("entry must be present after insert");
        };
        assert!(matches!(fetched.verdict, Verdict::Block));
        assert!(fetched.is_fresh(Instant::now()));
    }

    #[tokio::test]
    async fn insert_with_zero_ttl_is_a_no_op() {
        let cache = Cache::new(&CacheConfig::default());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(key.clone(), CacheEntry::new(Verdict::Block, Duration::ZERO))
            .await;
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn zero_raw_ttl_through_clamp_is_never_cached() {
        // The realistic path (raw upstream TTL -> clamp_ttl -> CacheEntry ->
        // insert), not a hand-built Duration::ZERO — proves the guard is
        // actually reachable from real input, not only from a fixture that
        // bypasses clamp_ttl.
        let config = CacheConfig::default();
        let cache = Cache::new(&config);
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let ttl = clamp_ttl(0, &config);
        cache
            .insert(key.clone(), CacheEntry::new(Verdict::Block, ttl))
            .await;
        assert!(cache.get(&key).await.is_none());
    }

    #[test]
    fn stale_but_present_entry_is_not_fresh() {
        let Some(expires_at) = Instant::now().checked_sub(Duration::from_secs(1)) else {
            panic!("Instant::now() must be at least 1s past the process epoch");
        };
        let entry = CacheEntry {
            verdict: Verdict::Block,
            ttl: Duration::from_secs(60),
            expires_at,
        };
        assert!(!entry.is_fresh(Instant::now()));
    }

    #[tokio::test]
    async fn invalidate_matching_exact_removes_only_that_domain() {
        let cache = Cache::new(&CacheConfig::default());
        let Ok(target) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let Ok(other) = CacheKey::new("other.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                target.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;
        cache
            .insert(
                other.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;

        cache.invalidate_matching(vec![("example.com".to_string(), false)]);

        assert!(cache.get(&target).await.is_none());
        assert!(cache.get(&other).await.is_some());
    }

    #[tokio::test]
    async fn invalidate_matching_removes_both_a_and_aaaa_for_the_domain() {
        let cache = Cache::new(&CacheConfig::default());
        let Ok(a_key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let Ok(aaaa_key) = CacheKey::new("example.com", RecordType::AAAA) else {
            panic!("valid domain");
        };
        cache
            .insert(
                a_key.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;
        cache
            .insert(
                aaaa_key.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;

        cache.invalidate_matching(vec![("example.com".to_string(), false)]);

        assert!(cache.get(&a_key).await.is_none());
        assert!(cache.get(&aaaa_key).await.is_none());
    }

    #[tokio::test]
    async fn invalidate_matching_wildcard_true_also_removes_subdomains() {
        let cache = Cache::new(&CacheConfig::default());
        let Ok(apex) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let Ok(sub) = CacheKey::new("sub.example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                apex.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;
        cache
            .insert(
                sub.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;

        cache.invalidate_matching(vec![("example.com".to_string(), true)]);

        assert!(cache.get(&apex).await.is_none());
        assert!(cache.get(&sub).await.is_none());
    }

    #[tokio::test]
    async fn invalidate_matching_wildcard_false_removes_exact_but_not_subdomain() {
        // Discriminating test (advisor review, T-40): a test that only
        // asserts the subdomain survives would pass identically if the
        // predicate silently never matched anything at all. Asserting both
        // halves in one test — exact gone, subdomain present — proves the
        // `is_wildcard: false` branch actually distinguishes the two.
        let cache = Cache::new(&CacheConfig::default());
        let Ok(apex) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let Ok(sub) = CacheKey::new("sub.example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                apex.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;
        cache
            .insert(
                sub.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;

        cache.invalidate_matching(vec![("example.com".to_string(), false)]);

        assert!(cache.get(&apex).await.is_none());
        assert!(cache.get(&sub).await.is_some());
    }

    #[tokio::test]
    async fn invalidate_matching_with_empty_entries_is_a_noop() {
        let cache = Cache::new(&CacheConfig::default());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                key.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;

        cache.invalidate_matching(Vec::new());

        assert!(cache.get(&key).await.is_some());
    }

    #[tokio::test]
    async fn clear_removes_every_previously_inserted_entry() {
        let cache = Cache::new(&CacheConfig::default());
        let Ok(a) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let Ok(b) = CacheKey::new("other.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                a.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;
        cache
            .insert(
                b.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;

        cache.clear();

        assert!(cache.get(&a).await.is_none());
        assert!(cache.get(&b).await.is_none());
    }

    #[tokio::test]
    async fn clear_does_not_block_a_re_insert_of_the_same_key_afterward() {
        // The production sequence: user clicks clear, the next DNS query for
        // the same domain resolves and re-inserts the same key. `moka`'s own
        // `invalidate_all` doc says retrieval won't return entries inserted
        // "before or at" the invalidation time — an inclusive cutoff — so
        // this can't be assumed safe from a doc read alone (advisor review:
        // a test that clears an *empty* cache before inserting proves
        // nothing about a real `clear()` call, since it'd pass even against
        // an empty-body no-op). This exercises the real insert-clear-insert
        // order and must observe the second insert surviving.
        let cache = Cache::new(&CacheConfig::default());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                key.clone(),
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;

        cache.clear();

        cache
            .insert(
                key.clone(),
                CacheEntry::new(
                    Verdict::Allow(vec![Ipv4Addr::new(93, 184, 216, 34).into()]),
                    Duration::from_secs(60),
                ),
            )
            .await;

        let Some(fetched) = cache.get(&key).await else {
            panic!("re-insert after clear must be observable, not swallowed by an inclusive invalidation cutoff");
        };
        assert!(matches!(fetched.verdict, Verdict::Allow(_)));
    }

    #[test]
    fn expiry_impl_returns_ttl_plus_stale_grace() {
        // Direct unit test on the Expiry impl itself, not an integration
        // test against moka's real clock: moka's eviction is lazy (runs
        // during periodic housekeeping, not the instant a TTL elapses), so a
        // short-sleep-then-get test would pass even if this impl returned
        // bare `ttl` instead of `ttl + stale_grace` — it wouldn't be testing
        // what it claims to. Calling `expire_after_create` directly removes
        // moka's scheduling from the picture entirely.
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let ttl = Duration::from_secs(60);
        let stale_grace = Duration::from_secs(500);
        let entry = CacheEntry::new(Verdict::Block, ttl);
        let expiry = CacheExpiry { stale_grace };

        let result = expiry.expire_after_create(&key, &entry, Instant::now());

        assert_eq!(result, Some(ttl + stale_grace));
    }
}
