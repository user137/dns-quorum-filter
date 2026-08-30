//! T-39: end-to-end request pipeline — allowlist → blocklist → cache →
//! quorum (SPEC.md §5 steps 1-3+5). Voter scope (step 4, top-N per country)
//! isn't implemented yet — Фаза 4. RFC 8767 stale-if-error integration
//! (`should_serve_stale` stays an unconsumed predicate here) is also
//! deferred — see TASKS.md. Not wired to any network listener yet
//! (T-48 waits on the self-signed certificate).
//!
//! T-40 adds a second, non-`handle_query` entry point: [`invalidate_changed`]
//! is the reload-event counterpart, called whenever the override lists
//! change rather than once per query — see its own doc comment.
//!
//! T-41 added a pass-through for SPEC.md §3/§8.1's "every quorum provider
//! disabled" case (originally a 2-variant `Voters` enum); T-148 replaced
//! that all-or-nothing switch with [`crate::quorum::EnabledProviders`], a
//! real per-provider toggle — see `handle_query`'s `enabled.any_enabled()`
//! branch.
//!
//! T-76 wires SPEC.md §3.5's `GeoIP` filter into the two points named there:
//! a cache-hit `Allow` replay ([`cache_hit_response_with_meta`]) and a fresh
//! quorum `Allow` ([`handle_allow`]'s return path). Both apply live, never
//! cache the `GeoIP` verdict itself (SPEC.md's own reasoning: a country-list
//! edit must take effect on the very next query, not wait out a TTL) — see
//! [`GeoipFilter`]/[`crate::geoip::blocking_country`]. **SPEC-silent choice, stated
//! here rather than left implicit**: the allowlist branch is exempt (SPEC.md
//! §3.5's own pipeline snippet says so explicitly — allowlisted domains never
//! consult quorum *or* `GeoIP`), and the every-provider-disabled pass-through
//! ([`baseline_passthrough_with_meta`]) is *also* exempt, by the same "no
//! filtering at all" reasoning T-41 already documented for that branch — both
//! share [`resolve_via_baseline`], so exempting one without the other would
//! need splitting that shared helper for no behavioral gain today. T-79
//! filled in `QueryLogMeta.geoip_country`/`LogEntry.geoip_country`
//! (`Some(code)` on a `DecisionSource::Geoip` entry, `None` otherwise) via
//! [`geoip::blocking_country`], widened from a bare `bool` at that same task.
//! Still a real, named gap: non-A/AAAA proxied queries (HTTPS/SVCB
//! `ipv4hint`/`ipv6hint`) never reach this filter — they already bypass
//! quorum entirely (SPEC.md §3), and `GeoIP` bypasses with it.

use crate::cache::{
    chain_cache_ttl, clamp_ttl, is_cacheable, Cache, CacheConfig, CacheEntry, CacheKey, Verdict,
};
use crate::geoip::{self, GeoipReader};
use crate::negative_cache_ttl;
use crate::overrides::{self, ListKind, OverrideLists};
use crate::query_log::{Decision, DecisionSource};
use crate::quorum::{requires_quorum, resolve, EnabledProviders, QuorumVerdict, VoterRecord};
use crate::timeout::{query_with_timeout, TimeoutConfig, VoterOutcome};
use crate::upstream::{DohClient, BASELINE_DOH_URL};
use crate::wire::{build_answer_response, build_block_response, build_servfail_response};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, SOA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// The cache and its config, bundled into one `handle_query` parameter
/// (T-76) — keeps the total parameter count under `clippy::too_many_arguments`
/// now that `geoip` is an eighth, the same "structural fix, not `#[allow]`"
/// precedent T-147/T-148 already established elsewhere in this file. Defined
/// here rather than reusing `dispatch::CacheState` (which owns the values,
/// not references, and importing it here would invert the crate's
/// `dispatch` → `pipeline` dependency direction).
pub struct CacheContext<'a> {
    /// The live cache.
    pub cache: &'a Cache,
    /// The config it was built from.
    pub config: &'a CacheConfig,
}

/// SPEC.md §3.5's live `GeoIP` filter inputs for one query (T-76) — bundled
/// into one `handle_query` parameter for the same `clippy::too_many_arguments`
/// reason as [`CacheContext`]. `reader: None` means no database has ever
/// loaded yet (a fresh install, before `geoip_updater`'s first successful
/// check) — see [`geoip::blocking_country`]'s own doc comment for why that's
/// a no-op, not an error.
pub struct GeoipFilter<'a> {
    /// The loaded `GeoIP` database, or `None` before the first successful
    /// download.
    pub reader: Option<&'a GeoipReader>,
    /// The user's blocked-country list — empty by default (SPEC.md §3.5).
    pub blocked_countries: &'a [String],
}

/// The result of running a query through the pipeline.
#[derive(Debug)]
pub enum PipelineOutcome {
    /// A fully resolved response, ready to send to the client.
    ///
    /// **Carries the query domain and its records** (SPEC.md, Наскрізні
    /// вимоги: no domain names in service logs) — never pass this variant's
    /// `Message` (or the whole `PipelineOutcome`, since it derives `Debug`)
    /// to `tracing`/`{:?}` in a diagnostic-log context, same discipline as
    /// `quorum::QuorumOutcome::answer` (T-39), `UpstreamError::error_kind()`
    /// (T-29), and `overrides::InvalidReason` (T-37).
    Response(Message),
    /// Neither override list matched and `query`'s type doesn't go through
    /// cache/quorum (RFC 9460 SVCB/HTTPS etc., T-25) — the caller must proxy
    /// this query to a single upstream directly. That dispatch itself is a
    /// deliberately separate, already-documented gap (TASKS.md T-21/T-25),
    /// not this module's job: choosing *which* upstream to proxy an
    /// arbitrary record type to is a type-dispatch decision, not a verdict
    /// this pipeline computes.
    ProxyToSingleUpstream,
}

/// Enough information to build a `query_log::LogEntry` for a completed
/// `handle_query` call (T-147) — kept separate from `PipelineOutcome` rather
/// than folded into its `Response` variant, so a caller that only wants the
/// response (every existing test, before this task) doesn't have to
/// destructure it, and so `ProxyToSingleUpstream`'s lack of metadata is
/// explicit (`None`) rather than a caller inventing a placeholder.
#[derive(Debug)]
pub struct QueryLogMeta {
    /// The normalized query domain (same string `handle_query` itself uses
    /// for the overrides/cache lookups).
    pub domain: String,
    /// The query's record type.
    pub qtype: RecordType,
    /// Allowed, blocked, or failed to resolve.
    pub decision: Decision,
    /// Which pipeline step produced `decision`.
    pub decision_source: DecisionSource,
    /// Always empty except for `DecisionSource::Quorum` — matches
    /// `LogEntry.voters`'s own documented rule.
    pub voters: Vec<VoterRecord>,
    /// The ISO country code that triggered a `GeoIP` block (T-79) —
    /// `Some` only when `decision_source` is `DecisionSource::Geoip`,
    /// `None` otherwise, matching `LogEntry.geoip_country`'s own rule.
    pub geoip_country: Option<String>,
}

/// `Decision::Allowed` vs `Decision::Failed` from a resolved [`Message`] —
/// only valid where `Decision::Blocked` isn't a reachable outcome of the
/// branch calling it (allowlist pass-through, every-provider-disabled
/// pass-through, quorum `Allow`): each of those three shapes is either a
/// real/forwarded answer or a synthesized/forwarded SERVFAIL, never a block
/// response — `build_block_response`/cache-replayed blocks never reach this
/// helper.
fn decision_from_response(message: &Message) -> Decision {
    if message.metadata.response_code == ResponseCode::ServFail {
        Decision::Failed
    } else {
        Decision::Allowed
    }
}

/// Shared shape of `handle_query`'s two baseline-pass-through branches
/// (allowlist match, every provider disabled): resolve unfiltered via
/// [`resolve_via_baseline`], then pair the result with `QueryLogMeta` —
/// `voters` is always empty here, nothing was actually consulted for either
/// caller. Pulled out purely to keep `handle_query` itself readable, not
/// reused for any other reason.
async fn baseline_passthrough_with_meta<C: DohClient + Sync>(
    client: &C,
    query: &Message,
    timeout_config: &TimeoutConfig,
    domain: String,
    qtype: RecordType,
    decision_source: DecisionSource,
) -> (PipelineOutcome, Option<QueryLogMeta>) {
    let message = resolve_via_baseline(client, query, timeout_config).await;
    let meta = QueryLogMeta {
        domain,
        qtype,
        decision: decision_from_response(&message),
        decision_source,
        voters: Vec::new(),
        geoip_country: None,
    };
    (PipelineOutcome::Response(message), Some(meta))
}

/// A blocklist match's response + metadata (T-147) — pulled out for the same
/// reason as [`baseline_passthrough_with_meta`]: keeping `handle_query`
/// itself short enough to read in one pass.
fn blocklist_response_with_meta(
    query: &Message,
    cache_config: &CacheConfig,
    domain: String,
    qtype: RecordType,
) -> (PipelineOutcome, Option<QueryLogMeta>) {
    let ttl = duration_to_ttl_secs(cache_config.block_verdict_ttl);
    let meta = QueryLogMeta {
        domain,
        qtype,
        decision: Decision::Blocked,
        decision_source: DecisionSource::Blocklist,
        voters: Vec::new(),
        geoip_country: None,
    };
    (
        PipelineOutcome::Response(build_block_response(query, ttl)),
        Some(meta),
    )
}

/// A fresh cache hit's response + metadata (T-147) — same reason as
/// [`blocklist_response_with_meta`].
///
/// SPEC.md §3.5: `GeoIP` applies live even on a cache-hit replay, checked
/// here (not baked into the cached [`CacheEntry`] itself) — see the module
/// doc comment for why the verdict is never cached. A `GeoIP`-blocked hit
/// still logs `DecisionSource::Geoip`, not `Cache` — the cached verdict was
/// `Allow`, but that's not what actually decided this response. The block
/// response's TTL is `cache_config.block_verdict_ttl`, the same constant
/// [`handle_allow`]'s own `GeoIP` block uses on the fresh-answer path — not
/// the *Allow* entry's own remaining TTL, which has no relationship to how
/// long a `GeoIP` block should be advertised and would leave the browser
/// holding a stale `0.0.0.0` for up to that remainder after a country is
/// removed from the list (advisor-caught before commit).
fn cache_hit_response_with_meta(
    query: &Message,
    entry: &CacheEntry,
    now: Instant,
    domain: String,
    qtype: RecordType,
    cache_config: &CacheConfig,
    geoip: &GeoipFilter<'_>,
) -> (PipelineOutcome, Option<QueryLogMeta>) {
    if let Verdict::Allow(ips) = &entry.verdict {
        if let Some(country) = geoip::blocking_country(geoip.reader, geoip.blocked_countries, ips) {
            let ttl = duration_to_ttl_secs(cache_config.block_verdict_ttl);
            let meta = QueryLogMeta {
                domain,
                qtype,
                decision: Decision::Blocked,
                decision_source: DecisionSource::Geoip,
                voters: Vec::new(),
                geoip_country: Some(country),
            };
            return (
                PipelineOutcome::Response(build_block_response(query, ttl)),
                Some(meta),
            );
        }
    }
    let decision = match entry.verdict {
        Verdict::Block => Decision::Blocked,
        Verdict::Allow(_) => Decision::Allowed,
    };
    let meta = QueryLogMeta {
        domain,
        qtype,
        decision,
        decision_source: DecisionSource::Cache,
        voters: Vec::new(),
        geoip_country: None,
    };
    (
        PipelineOutcome::Response(response_from_cache_entry(query, entry, now)),
        Some(meta),
    )
}

/// SPEC.md §5: run `query` through allowlist → blocklist → cache → quorum,
/// in that fixed order. Allowlist and blocklist apply regardless of query
/// type (an MX/TXT domain can be overridden too); cache and quorum apply
/// only to A/AAAA (`requires_quorum`).
///
/// # Panics
///
/// Never panics — see the individual step comments for how each fallible
/// path (a malformed-per-`normalize_domain` domain, a missing SOA, an
/// upstream error) degrades instead of unwrapping.
pub async fn handle_query<C: DohClient + Sync>(
    query: &Message,
    client: &C,
    overrides: &OverrideLists,
    enabled: EnabledProviders,
    cache: &CacheContext<'_>,
    timeout_config: &TimeoutConfig,
    geoip: &GeoipFilter<'_>,
) -> (PipelineOutcome, Option<QueryLogMeta>) {
    let Some(question) = query.queries.first() else {
        return (PipelineOutcome::ProxyToSingleUpstream, None);
    };
    // `Name::to_ascii()`, not `.to_string()`/`Display` — the same
    // transformation `normalize_domain` itself performs internally
    // (`Name::from_utf8(...).to_ascii()`), so this string round-trips
    // through `overrides.decision`/`CacheKey::new` (both call
    // `normalize_domain`) without an unnecessary punycode->Unicode->
    // punycode detour. Empirically verified (not assumed) that a label
    // containing a literal dot escapes and re-parses to one label, not two.
    let domain = question.name().to_ascii();
    let qtype = question.query_type();
    // `LogEntry.domain`'s documented invariant is `normalize_domain`'s output
    // (lowercase, no trailing dot) - `domain` above is deliberately the
    // to_ascii() intermediate form instead (see the comment on it), so the
    // log gets its own, separately normalized copy rather than the two
    // uses drifting apart.
    let log_domain = domain.trim_end_matches('.').to_ascii_lowercase();

    // `Err` here means `domain` doesn't round-trip through
    // `normalize_domain` — practically unreachable for a string sourced
    // from an already wire-decoded `Name` (see the round-trip test below),
    // but treated as "no override match" rather than propagated, so a
    // theoretical edge case degrades safely instead of panicking.
    match overrides.decision(&domain) {
        Ok(Some(ListKind::Allowlist)) => {
            return baseline_passthrough_with_meta(
                client,
                query,
                timeout_config,
                log_domain.clone(),
                qtype,
                DecisionSource::Allowlist,
            )
            .await;
        }
        Ok(Some(ListKind::Blocklist)) => {
            return blocklist_response_with_meta(query, cache.config, log_domain.clone(), qtype);
        }
        Ok(None) | Err(_) => {}
    }

    if !requires_quorum(qtype) {
        return (PipelineOutcome::ProxyToSingleUpstream, None);
    }

    if !enabled.any_enabled() {
        // SPEC.md §3, §8.1: explicit pass-through, not fail-closed, not a
        // silent no-op — OR-logic over an empty voter set is semantically
        // undefined, so resolution goes through the baseline resolver with
        // no filtering at all, the same path the allowlist branch above
        // already uses. A blocklist match still short-circuited above this
        // check regardless of `enabled` - disabling third-party voters does
        // not disable the user's own override rules, that's the pipeline's
        // fixed step order, not an inconsistency to "fix" later.
        //
        // Placed *before* the cache lookup below, not just before the
        // cache write - a fresh cache entry written while voters were
        // still enabled (e.g. a BLOCK verdict) must not be served here
        // either, or disabling every provider would silently keep
        // blocking via a stale cache hit instead of actually passing
        // through. Read and write both skip the cache for the same
        // reason: a cached record from a pass-through moment (or served
        // through one) would be indistinguishable from a genuinely-
        // filtered verdict once the user re-enables a provider and the
        // cache is later replayed.
        // SPEC-silent choice (T-147): none of the four Ф1 decision_source
        // values name "voters globally disabled" - `Quorum` is the closest
        // ("what quorum produces over zero active voters"), and `voters:
        // vec![]` (built by the shared helper below) makes clear nothing
        // was actually consulted, distinguishing this from a real quorum
        // resolution at a glance.
        return baseline_passthrough_with_meta(
            client,
            query,
            timeout_config,
            log_domain.clone(),
            qtype,
            DecisionSource::Quorum,
        )
        .await;
    }

    let Ok(key) = CacheKey::new(&domain, qtype) else {
        // Same practically-unreachable normalize_domain failure as the
        // overrides.decision() branch above, but on the A/AAAA path -
        // `ProxyToSingleUpstream` would be the wrong signal here (that
        // variant means "this type doesn't go through cache/quorum at all,"
        // not "an error occurred on the path that does"). An honest
        // SERVFAIL, consistent with this module's other no-usable-data
        // branches, not a routing decision that doesn't apply to A/AAAA.
        // Not logged (`None`): no decision_source value describes a
        // never-actually-attempted resolution, and this path is already
        // documented as practically unreachable.
        return (
            PipelineOutcome::Response(build_servfail_response(query)),
            None,
        );
    };

    let now = Instant::now();
    if let Some(entry) = cache.cache.get(&key).await {
        if entry.is_fresh(now) {
            return cache_hit_response_with_meta(
                query,
                &entry,
                now,
                log_domain.clone(),
                qtype,
                cache.config,
                geoip,
            );
        }
    }

    let outcome = resolve(client, query, timeout_config, enabled).await;
    match outcome.verdict {
        QuorumVerdict::NotApplicable => (PipelineOutcome::ProxyToSingleUpstream, None),
        QuorumVerdict::Block => {
            let ttl = cache.config.block_verdict_ttl;
            cache
                .cache
                .insert(key, CacheEntry::new(Verdict::Block, ttl))
                .await;
            let meta = QueryLogMeta {
                domain: log_domain.clone(),
                qtype,
                decision: Decision::Blocked,
                decision_source: DecisionSource::Quorum,
                voters: outcome.voters,
                geoip_country: None,
            };
            (
                PipelineOutcome::Response(build_block_response(query, duration_to_ttl_secs(ttl))),
                Some(meta),
            )
        }
        QuorumVerdict::Allow => {
            quorum_allow_response_with_meta(cache, key, query, outcome, log_domain, qtype, geoip)
                .await
        }
    }
}

/// The `QuorumVerdict::Allow` branch of `handle_query`'s quorum step —
/// pulled out only to keep `handle_query` itself under
/// `clippy::too_many_lines` (T-76 added a fourth branch's worth of `GeoIP`
/// handling), same "structural fix, not `#[allow]`" precedent T-147/T-148
/// already established for this file's other extracted helpers.
async fn quorum_allow_response_with_meta(
    cache: &CacheContext<'_>,
    key: CacheKey,
    query: &Message,
    outcome: crate::quorum::QuorumOutcome,
    log_domain: String,
    qtype: RecordType,
    geoip: &GeoipFilter<'_>,
) -> (PipelineOutcome, Option<QueryLogMeta>) {
    let voters = outcome.voters;
    let result = handle_allow(cache, key, query, outcome.answer, geoip).await;
    let (message, decision, decision_source, voters, geoip_country) = match result {
        AllowResult::Answer(message) => {
            let decision = decision_from_response(&message);
            (message, decision, DecisionSource::Quorum, voters, None)
        }
        // SPEC.md §3.5: the quorum verdict itself was Allow (and is cached
        // as such, unchanged — see handle_allow's own doc comment for why)
        // - GeoIP overrides only the response actually sent, and only this
        // log entry's own decision/decision_source/voters/geoip_country, not
        // the cached Verdict a later, country-list-edited query will re-read.
        AllowResult::GeoipBlocked { response, country } => (
            response,
            Decision::Blocked,
            DecisionSource::Geoip,
            Vec::new(),
            Some(country),
        ),
    };
    let meta = QueryLogMeta {
        domain: log_domain,
        qtype,
        decision,
        decision_source,
        voters,
        geoip_country,
    };
    (PipelineOutcome::Response(message), Some(meta))
}

/// SPEC.md §5 step 1: one direct query to the baseline resolver (T-22),
/// forwarded as-is — used both by the allowlist branch (an allowlisted
/// domain never consults quorum, but the client still needs a real answer,
/// not just a verdict) and by the every-provider-disabled pass-through, where
/// this is the entire resolution path for *every* A/AAAA query while
/// filtering is off.
///
/// Bounded by `timeout_config.duration` via [`query_with_timeout`] — a bare
/// unbounded `client.query(...)` here would let one hung baseline stall
/// every query the browser makes for as long as voters stay disabled,
/// worse than no filtering at all (Три Б, user safety). `timeout_config`'s
/// `mode` is deliberately ignored: this call isn't casting an OR-vote, it's
/// "get a real answer or fail honestly" — the same principle already
/// governing the `TimedOut`/`Errored` branch below.
async fn resolve_via_baseline<C: DohClient + Sync>(
    client: &C,
    query: &Message,
    timeout_config: &TimeoutConfig,
) -> Message {
    match query_with_timeout(client, BASELINE_DOH_URL, query, timeout_config.duration).await {
        VoterOutcome::Responded(response) => crate::wire::forward_response(query, &response),
        // Три Б (user safety): an honest failure, not a silent block-shaped
        // `0.0.0.0` on a domain the user just allowlisted, or on ordinary
        // traffic while filtering is off.
        VoterOutcome::TimedOut | VoterOutcome::Errored(_) => build_servfail_response(query),
    }
}

/// T-25's call-site half of [`PipelineOutcome::ProxyToSingleUpstream`] — proxies `query` to the
/// baseline resolver, unfiltered, via the same bounded path `handle_query`'s own allowlist and
/// every-provider-disabled branches already use ([`resolve_via_baseline`]). A separate `pub` name
/// rather than exposing `resolve_via_baseline` itself: this function's contract to callers is
/// "the non-A/AAAA proxy step," not "the allowlist helper" — the two happen to share an
/// implementation because SPEC.md §5 step 1 is genuinely the same action in both cases.
pub async fn proxy_to_single_upstream<C: DohClient + Sync>(
    client: &C,
    query: &Message,
    timeout_config: &TimeoutConfig,
) -> Message {
    resolve_via_baseline(client, query, timeout_config).await
}

/// [`handle_allow`]'s result — distinguishes a real answer (forwarded or
/// synthesized SERVFAIL, `Decision`/`DecisionSource` computed by the caller
/// the same way it always was) from a live `GeoIP` block (T-76), whose
/// `Decision`/`DecisionSource`/`voters` the caller must override outright
/// rather than derive from the response — see `handle_query`'s own match on
/// this type.
enum AllowResult {
    Answer(Message),
    /// A named struct variant (T-79), not a `(Message, String)` tuple — the
    /// caller destructures this by field name, so a future third field can't
    /// silently land at the wrong tuple position the way it could in a
    /// growing positional match.
    GeoipBlocked {
        response: Message,
        country: String,
    },
}

/// The `Allow`-verdict branch of `handle_query`'s quorum step — separated
/// out only because `handle_query` was otherwise growing past a readable
/// single function, not because this is reused elsewhere.
///
/// SPEC.md §3.5: `GeoIP` is checked on the *return* path, after the quorum
/// `Allow` verdict is cached exactly as it always was (unaffected by whether
/// `GeoIP` goes on to block this particular response) — never inside the
/// `is_cacheable(ttl)` branch below, which only runs for a positive answer
/// with a non-zero TTL and would silently skip the check for a TTL-0 answer.
/// This is also why the resolved `Verdict::Allow` is cached unchanged even
/// when this function returns [`AllowResult::GeoipBlocked`]: caching a
/// `Block` (or skipping the insert) would mean removing a country from the
/// blocked list doesn't take effect until the cache entry's TTL expires —
/// exactly what the module doc comment says `GeoIP` exists to avoid.
async fn handle_allow(
    cache: &CacheContext<'_>,
    key: CacheKey,
    query: &Message,
    answer: Option<Message>,
    geoip: &GeoipFilter<'_>,
) -> AllowResult {
    let Some(message) = answer else {
        // Every voter unresponsive under fail-open, or every Responded voter
        // had an unusable answer (SERVFAIL/REFUSED - representative_allow_
        // answer's is_usable_answer guard, quorum.rs, T-39) - either way, no
        // real data to hand back. Три Б: an honest SERVFAIL, not a
        // misleading empty NoError that a browser would read as "this
        // domain has no record" (SPEC.md §3.2's own reasoning about
        // misleading responses applies here too).
        return AllowResult::Answer(build_servfail_response(query));
    };

    if message.answers.is_empty() {
        // Genuine NXDOMAIN/NODATA (not a block - quorum already ruled that
        // out). RFC 2308 negative-caching TTL comes from the authority
        // section's SOA MINIMUM, not the same clamp source as a positive
        // answer's chain TTL. No IPs in an empty answer section, so GeoIP
        // has nothing to check here - falls straight through to the forward
        // below.
        let ttl = match find_soa(&message.authorities) {
            Some(soa) => clamp_ttl(negative_cache_ttl(soa), cache.config),
            // No SOA to derive a negative TTL from - Три Б: don't guess one,
            // just don't cache this answer.
            None => Duration::ZERO,
        };
        if is_cacheable(ttl) {
            cache
                .cache
                .insert(key, CacheEntry::new(Verdict::Allow(Vec::new()), ttl))
                .await;
        }
    } else {
        let ips = extract_ips(&message.answers);
        let ttl = match chain_cache_ttl(&message.answers) {
            Some(secs) => clamp_ttl(secs, cache.config),
            None => Duration::ZERO,
        };
        if is_cacheable(ttl) {
            cache
                .cache
                .insert(key, CacheEntry::new(Verdict::Allow(ips.clone()), ttl))
                .await;
        }
        if let Some(country) = geoip::blocking_country(geoip.reader, geoip.blocked_countries, &ips)
        {
            let block_ttl = duration_to_ttl_secs(cache.config.block_verdict_ttl);
            return AllowResult::GeoipBlocked {
                response: build_block_response(query, block_ttl),
                country,
            };
        }
    }

    // The fresh path always forwards the real upstream response verbatim -
    // including a genuine NXDOMAIN. SPEC.md §3.2 forbids only a
    // *synthesized* BLOCK-NXDOMAIN, not forwarding a real one (this is the
    // same `forward_response` the ordinary quorum-Allow path already uses).
    // Cache-hit replay is the one place that collapses NXDOMAIN into
    // NODATA-shaped (`response_from_cache_entry` below) - a deliberate,
    // documented difference between the two paths, not an inconsistency.
    AllowResult::Answer(crate::wire::forward_response(query, &message))
}

/// SPEC.md §5 (T-40): apply the `Cache` invalidation implied by an
/// override-list reload. `before`/`after` are two `OverrideLists` snapshots
/// — the one a caller was using, and the one `OverrideLists::load` just
/// produced. **Why this is needed at all, given `handle_query` always checks
/// overrides *before* cache:** while an override rule is active, no query
/// for a domain it covers can ever produce a new cache entry (the pipeline
/// short-circuits before touching the cache), so the only entry that can go
/// stale is one written *before* the rule existed. Invalidating at the
/// moment a rule is *added* clears that leftover immediately, so a later
/// removal of the same rule can't resurrect it from a still-fresh TTL.
/// Invalidation runs in both directions (added and removed entries alike),
/// not only newly-added ones — that doesn't rely on every prior reload
/// having gone through this exact path (e.g. the first reload after this
/// function existed, or a list edited by hand outside any diffing tool).
///
/// Not yet called from anywhere: no live file-watcher or UI writer exists
/// yet to trigger a reload in the first place (`overrides::OverrideLists`
/// itself has no file-write path — deferred to T-46/T-47) — same
/// "module ready, wiring task still pending" pattern as every prior slice's
/// modules before their own wiring task.
pub fn invalidate_changed(cache: &Cache, before: &OverrideLists, after: &OverrideLists) {
    let entries: Vec<(String, bool)> = overrides::changed_entries(before, after)
        .into_iter()
        .map(|entry| (entry.domain.clone(), entry.is_wildcard))
        .collect();
    cache.invalidate_matching(entries);
}

/// SOA record in `records` (RFC 2308, T-35's `negative_cache_ttl` input) —
/// `message.authorities`, not `answers`, per DNS convention for a negative
/// response.
fn find_soa(records: &[Record]) -> Option<&SOA> {
    records.iter().find_map(|record| match &record.data {
        RData::SOA(soa) => Some(soa),
        _ => None,
    })
}

/// The A/AAAA addresses in `records` — CNAME hops and any other record type
/// in the same answer section are skipped, not misinterpreted as an IP.
fn extract_ips(records: &[Record]) -> Vec<IpAddr> {
    records
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(A(ip)) => Some(IpAddr::V4(*ip)),
            RData::AAAA(AAAA(ip)) => Some(IpAddr::V6(*ip)),
            _ => None,
        })
        .collect()
}

/// Reconstruct a response directly from a cache hit — no upstream `Message`
/// survives a cache round-trip, only [`Verdict`] and a TTL.
///
/// The served TTL is `entry.expires_at`'s **remaining** time as of `now`,
/// never the full `entry.ttl` the entry was inserted with — otherwise every
/// repeated hit would hand the client a freshly-extended TTL and the
/// effective cache lifetime would never actually expire from the client's
/// point of view (the exact discipline T-33/T-34/T-36 exist to enforce,
/// just on the read side instead of the write side).
fn response_from_cache_entry(query: &Message, entry: &CacheEntry, now: Instant) -> Message {
    let remaining_ttl = duration_to_ttl_secs(entry.expires_at.saturating_duration_since(now));
    match &entry.verdict {
        Verdict::Block => build_block_response(query, remaining_ttl),
        Verdict::Allow(ips) => {
            let Some(question) = query.queries.first() else {
                return build_answer_response(query, Vec::new());
            };
            let records = ips
                .iter()
                .map(|ip| {
                    let rdata = match ip {
                        IpAddr::V4(v4) => RData::A(A(*v4)),
                        IpAddr::V6(v6) => RData::AAAA(AAAA(*v6)),
                    };
                    Record::from_rdata(question.name().clone(), remaining_ttl, rdata)
                })
                .collect();
            // An empty `ips` (genuine NXDOMAIN/NODATA on the fresh path,
            // SPEC.md §4's documented cache-hit compromise) naturally
            // produces an empty `records` here - no separate branch needed,
            // `build_answer_response` is already NODATA-shaped for that.
            build_answer_response(query, records)
        }
    }
}

fn duration_to_ttl_secs(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{handle_query, invalidate_changed, CacheContext, GeoipFilter, PipelineOutcome};
    use crate::cache::{Cache, CacheConfig, CacheEntry, CacheKey, Verdict};
    use crate::geoip::GeoipReader;
    use crate::overrides::{ListKind, OverrideEntry, OverrideLists};
    use crate::query_log::{Decision, DecisionSource};
    use crate::quorum::{EnabledProviders, VoterVerdict};
    use crate::timeout::{TimeoutConfig, TimeoutMode};
    use crate::upstream::{DohClient, Provider, UpstreamError};
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    // T-76: the same vendored MaxMind-DB test fixture geoip.rs's own tests
    // use (89.160.20.112 -> SE, maxmind/MaxMind-DB's own known-good
    // assertion) - loaded here too rather than a hand-rolled mock, so these
    // tests exercise a real GeoipReader::country lookup, not just the
    // pipeline's own plumbing around one.
    fn geoip_fixture() -> GeoipReader {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/geoip/GeoIP2-Country-Test.mmdb");
        let Ok(reader) = GeoipReader::open(&path) else {
            panic!("fixture must load");
        };
        reader
    }

    fn se_ip() -> Ipv4Addr {
        Ipv4Addr::new(89, 160, 20, 112)
    }

    /// TEST-NET-1 (RFC 5737) - never present in any real `GeoIP` database, see
    /// `geoip.rs`'s own tests for the same fixture-address choice.
    fn unmatched_ip() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn query_for(domain: &str, qtype: RecordType) -> Message {
        let Ok(name) = Name::from_str(domain) else {
            panic!("valid fixture domain");
        };
        let mut question = Query::new();
        question.set_name(name);
        question.set_query_type(qtype);
        let mut message = Message::query();
        message.add_query(question);
        message
    }

    fn allow_message_with_ip(ip: Ipv4Addr) -> Message {
        allow_message_with_ips(&[ip])
    }

    fn allow_message_with_ips(ips: &[Ipv4Addr]) -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NoError;
        for ip in ips {
            message
                .answers
                .push(Record::from_rdata(Name::root(), 300, RData::A(A(*ip))));
        }
        message
    }

    fn nxdomain_message_with_soa(minimum: u32) -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NXDomain;
        let soa = SOA::new(Name::root(), Name::root(), 1, 3600, 900, 604_800, minimum);
        message
            .authorities
            .push(Record::from_rdata(Name::root(), minimum, RData::SOA(soa)));
        message
    }

    fn nxdomain_message_without_soa() -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NXDomain;
        message
    }

    fn overrides_with(entries: Vec<OverrideEntry>) -> OverrideLists {
        OverrideLists::from_entries_for_test(entries)
    }

    #[derive(Clone)]
    enum MockResponse {
        Instant(Message),
        Error,
        Panic,
    }

    struct MockClient {
        quad9: MockResponse,
        adguard: MockResponse,
        baseline: MockResponse,
        calls: AtomicU32,
    }

    impl MockClient {
        fn all_panic() -> Self {
            Self {
                quad9: MockResponse::Panic,
                adguard: MockResponse::Panic,
                baseline: MockResponse::Panic,
                calls: AtomicU32::new(0),
            }
        }
    }

    impl DohClient for MockClient {
        fn query(
            &self,
            url: &str,
            _query: &Message,
        ) -> impl std::future::Future<Output = Result<Message, UpstreamError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let response = if url == Provider::Quad9.doh_url() {
                &self.quad9
            } else if url == Provider::AdGuard.doh_url() {
                &self.adguard
            } else {
                &self.baseline
            };
            let result = match response {
                MockResponse::Instant(message) => Ok(message.clone()),
                MockResponse::Error => Err(UpstreamError::Decode(
                    "mock decode failure".to_string().into(),
                )),
                MockResponse::Panic => panic!("unexpected upstream call to {url}"),
            };
            std::future::ready(result)
        }
    }

    struct PendingClient;

    impl DohClient for PendingClient {
        fn query(
            &self,
            _url: &str,
            _query: &Message,
        ) -> impl std::future::Future<Output = Result<Message, UpstreamError>> {
            std::future::pending()
        }
    }

    fn cache_config() -> CacheConfig {
        CacheConfig::default()
    }

    fn timeout_config() -> TimeoutConfig {
        TimeoutConfig::default()
    }

    // Design decision 2 (plan): `Name::to_ascii()` round-trips a label
    // containing a literal dot through `normalize_domain` without a false
    // override match or a panic - empirically verified, not assumed.
    #[tokio::test]
    async fn label_with_a_literal_dot_does_not_panic_or_false_match() {
        let Ok(odd_name) = Name::from_labels(vec![b"a.b".to_vec(), b"com".to_vec()]) else {
            panic!("valid fixture labels");
        };
        let mut question = Query::new();
        question.set_name(odd_name);
        question.set_query_type(RecordType::A);
        let mut query = Message::query();
        query.add_query(question);

        let overrides = overrides_with(vec![OverrideEntry {
            domain: "b.com".to_string(),
            is_wildcard: false,
            list: ListKind::Blocklist,
        }]);
        let cache = Cache::new(&cache_config());
        let client = MockClient {
            quad9: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 1, 1, 1))),
            adguard: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 1, 1, 1))),
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 1, 1, 1))),
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query,
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        // Must not match the "b.com" blocklist entry - "a.b.com" (one label
        // containing a literal dot, then "com") is not "b.com" nor a
        // subdomain of it. A false match would produce a NULL-blocked
        // (0.0.0.0) NoError answer, which is *also* NoError - so the
        // discriminating assertion is the IP itself (the mock's real
        // 1.1.1.1, not build_block_response's UNSPECIFIED), not the
        // response code alone.
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected one A answer");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[tokio::test]
    async fn allowlist_match_resolves_via_baseline_without_consulting_quorum() {
        let overrides = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Allowlist,
        }]);
        let cache = Cache::new(&cache_config());
        let baseline_ip = Ipv4Addr::new(93, 184, 216, 34);
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(baseline_ip)),
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        assert_eq!(response.answers, allow_message_with_ip(baseline_ip).answers);
    }

    #[tokio::test]
    async fn blocklist_match_never_consults_baseline_or_quorum() {
        let overrides = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Blocklist,
        }]);
        let cache = Cache::new(&cache_config());
        let client = MockClient::all_panic();

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected a NULL-blocked A answer");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == Ipv4Addr::UNSPECIFIED));
    }

    #[tokio::test]
    async fn allowlist_wins_when_domain_is_in_both_lists() {
        let overrides = overrides_with(vec![
            OverrideEntry {
                domain: "example.com".to_string(),
                is_wildcard: false,
                list: ListKind::Allowlist,
            },
            OverrideEntry {
                domain: "example.com".to_string(),
                is_wildcard: false,
                list: ListKind::Blocklist,
            },
        ]);
        let cache = Cache::new(&cache_config());
        let baseline_ip = Ipv4Addr::new(93, 184, 216, 34);
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(baseline_ip)),
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        assert_eq!(response.answers, allow_message_with_ip(baseline_ip).answers);
    }

    #[tokio::test]
    async fn non_a_aaaa_without_override_match_proxies_without_consulting_any_upstream() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let client = MockClient::all_panic();

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::MX),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        assert!(matches!(outcome, PipelineOutcome::ProxyToSingleUpstream));
    }

    #[tokio::test]
    async fn fresh_cache_hit_makes_no_network_call() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                key,
                CacheEntry::new(
                    Verdict::Allow(vec![Ipv4Addr::new(1, 2, 3, 4).into()]),
                    Duration::from_secs(60),
                ),
            )
            .await;
        let client = MockClient::all_panic();

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected one cached A answer");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[tokio::test]
    async fn cache_hit_serves_remaining_ttl_not_the_full_inserted_ttl() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        // Struct literal, not `CacheEntry::new` - directly places `expires_at`
        // ~30s in the future rather than relying on `tokio::time::advance`,
        // which moves tokio's virtual clock, not the `std::time::Instant`
        // `expires_at` is actually made of (advisor review: the paused-time
        // version of this test passed, but only via `Duration::as_secs`
        // sub-second truncation on an untouched ~60s value, not because 30s
        // had actually elapsed).
        cache
            .insert(
                key,
                CacheEntry {
                    verdict: Verdict::Allow(vec![Ipv4Addr::new(1, 2, 3, 4).into()]),
                    ttl: Duration::from_secs(60),
                    expires_at: Instant::now() + Duration::from_secs(30),
                },
            )
            .await;
        let client = MockClient::all_panic();

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected one cached A answer");
        };
        // Tight band around the ~30s remaining, not the full 60s inserted -
        // proves "remaining", not just "less than the full TTL".
        assert!(
            (25..=30).contains(&answer.ttl),
            "served TTL {} must reflect the ~30s remaining, not the full 60s entry.ttl",
            answer.ttl
        );
    }

    #[tokio::test]
    async fn cache_miss_allow_with_records_is_cached_and_reused() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let client = MockClient {
            quad9: MockResponse::Instant(allow_message_with_ip(ip)),
            adguard: MockResponse::Instant(allow_message_with_ip(ip)),
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected one A answer");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == ip));
        let calls_after_miss = client.calls.load(Ordering::SeqCst);
        assert!(calls_after_miss > 0);

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        assert!(matches!(outcome, PipelineOutcome::Response(_)));
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            calls_after_miss,
            "second call must be a cache hit, no additional upstream calls"
        );
    }

    #[tokio::test]
    async fn cache_miss_genuine_nxdomain_with_soa_is_cached_with_negative_ttl() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let response = nxdomain_message_with_soa(120);
        let client = MockClient {
            quad9: MockResponse::Instant(response.clone()),
            adguard: MockResponse::Instant(response.clone()),
            baseline: MockResponse::Instant(response),
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        assert!(matches!(outcome, PipelineOutcome::Response(_)));
        let calls_after_miss = client.calls.load(Ordering::SeqCst);

        // Directly inspect the cached entry's TTL (not just "it got cached")
        // - proves it came from the SOA's MINIMUM=120, not e.g. clamp_min's
        // 30s default, which would also make the entry cacheable and pass a
        // weaker assertion.
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let Some(cached) = cache.get(&key).await else {
            panic!("expected the negative answer to be cached");
        };
        assert_eq!(cached.ttl, Duration::from_secs(120));

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        assert!(matches!(outcome, PipelineOutcome::Response(_)));
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            calls_after_miss,
            "negative TTL from SOA must be enough to cache the entry"
        );
    }

    #[tokio::test]
    async fn cache_miss_genuine_nxdomain_without_soa_is_never_cached() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let response = nxdomain_message_without_soa();
        let client = MockClient {
            quad9: MockResponse::Instant(response.clone()),
            adguard: MockResponse::Instant(response.clone()),
            baseline: MockResponse::Instant(response),
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(fresh_response) = outcome else {
            panic!("expected a Response");
        };
        // Fresh path forwards the real upstream response verbatim, genuine
        // NXDOMAIN included - only the cache-hit replay collapses to NODATA.
        assert_eq!(
            fresh_response.metadata.response_code,
            ResponseCode::NXDomain
        );
        let calls_after_miss = client.calls.load(Ordering::SeqCst);

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        assert!(matches!(outcome, PipelineOutcome::Response(_)));
        assert!(
            client.calls.load(Ordering::SeqCst) > calls_after_miss,
            "without a SOA there is nothing to cache - the second call must go to quorum again"
        );
    }

    #[tokio::test]
    async fn cached_empty_allow_replays_as_nodata_not_literal_nxdomain() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                key,
                CacheEntry::new(Verdict::Allow(Vec::new()), Duration::from_secs(60)),
            )
            .await;
        let client = MockClient::all_panic();

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn all_voters_unresponsive_yields_servfail_not_cached() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let client = PendingClient;
        let config = TimeoutConfig {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_millis(5),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &config,
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);

        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        assert!(cache.get(&key).await.is_none(), "must not be cached");
    }

    #[tokio::test]
    async fn baseline_error_on_allowlist_path_yields_servfail() {
        let overrides = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Allowlist,
        }]);
        let cache = Cache::new(&cache_config());
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Error,
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn invalidate_changed_evicts_a_cache_entry_for_a_newly_blocklisted_domain() {
        let cache = Cache::new(&cache_config());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        // Simulates a pre-override quorum result already sitting in the
        // cache when the reload happens.
        cache
            .insert(
                key.clone(),
                CacheEntry::new(
                    Verdict::Allow(vec![Ipv4Addr::new(1, 2, 3, 4).into()]),
                    Duration::from_secs(300),
                ),
            )
            .await;

        let before = OverrideLists::empty();
        let after = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Blocklist,
        }]);

        invalidate_changed(&cache, &before, &after);

        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn invalidate_changed_wildcard_entry_evicts_a_subdomain_cache_entry() {
        let cache = Cache::new(&cache_config());
        let Ok(key) = CacheKey::new("sub.example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                key.clone(),
                CacheEntry::new(
                    Verdict::Allow(vec![Ipv4Addr::new(1, 2, 3, 4).into()]),
                    Duration::from_secs(300),
                ),
            )
            .await;

        let before = OverrideLists::empty();
        let after = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: true,
            list: ListKind::Blocklist,
        }]);

        invalidate_changed(&cache, &before, &after);

        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn invalidate_changed_handles_a_multi_entry_reload_in_one_predicate() {
        // Discriminating test (advisor review, T-40): every other test in
        // this module diffs to exactly 0 or 1 changed entries, so a wrong
        // quantifier in `Cache::invalidate_matching`'s `matchers.iter().any`
        // loop (e.g. `.all()`, or an early return after the first match)
        // would pass every one of them. Three cache entries, two changed
        // override entries (one exact, one wildcard), one entry that must
        // survive - this can't pass if the batch collapses to
        // first-entry-only, last-entry-only, or all-entries.
        let cache = Cache::new(&cache_config());
        let Ok(exact_key) = CacheKey::new("a.com", RecordType::A) else {
            panic!("valid domain");
        };
        let Ok(wildcard_sub_key) = CacheKey::new("sub.b.com", RecordType::A) else {
            panic!("valid domain");
        };
        let Ok(keep_key) = CacheKey::new("keep.com", RecordType::A) else {
            panic!("valid domain");
        };
        for key in [&exact_key, &wildcard_sub_key, &keep_key] {
            cache
                .insert(
                    key.clone(),
                    CacheEntry::new(
                        Verdict::Allow(vec![Ipv4Addr::new(1, 2, 3, 4).into()]),
                        Duration::from_secs(300),
                    ),
                )
                .await;
        }

        let before = OverrideLists::empty();
        let after = overrides_with(vec![
            OverrideEntry {
                domain: "a.com".to_string(),
                is_wildcard: false,
                list: ListKind::Blocklist,
            },
            OverrideEntry {
                domain: "b.com".to_string(),
                is_wildcard: true,
                list: ListKind::Blocklist,
            },
        ]);

        invalidate_changed(&cache, &before, &after);

        assert!(cache.get(&exact_key).await.is_none(), "a.com must be gone");
        assert!(
            cache.get(&wildcard_sub_key).await.is_none(),
            "sub.b.com must be gone (matches the *.b.com wildcard entry)"
        );
        assert!(
            cache.get(&keep_key).await.is_some(),
            "keep.com must survive - it matches neither changed entry"
        );
    }

    #[tokio::test]
    async fn invalidate_changed_is_a_noop_when_lists_are_unchanged() {
        let cache = Cache::new(&cache_config());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                key.clone(),
                CacheEntry::new(
                    Verdict::Allow(vec![Ipv4Addr::new(1, 2, 3, 4).into()]),
                    Duration::from_secs(300),
                ),
            )
            .await;

        let lists = overrides_with(vec![OverrideEntry {
            domain: "other.com".to_string(),
            is_wildcard: false,
            list: ListKind::Blocklist,
        }]);

        invalidate_changed(&cache, &lists, &lists);

        assert!(
            cache.get(&key).await.is_some(),
            "a reload diffing to no changes must not wipe unrelated cache entries"
        );
    }

    #[tokio::test]
    async fn voters_disabled_yields_pass_through_via_baseline_without_consulting_quorum() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let baseline_ip = Ipv4Addr::new(93, 184, 216, 34);
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(baseline_ip)),
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders {
                quad9: false,
                adguard: false,
            },
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        assert_eq!(response.answers, allow_message_with_ip(baseline_ip).answers);
    }

    #[tokio::test]
    async fn voters_disabled_is_never_cached() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 2, 3, 4))),
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders {
                quad9: false,
                adguard: false,
            },
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        assert!(matches!(outcome, PipelineOutcome::Response(_)));

        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        assert!(
            cache.get(&key).await.is_none(),
            "a pass-through answer must never be cached - it would be indistinguishable \
             from a genuinely-filtered Allow once the user re-enables a provider"
        );
    }

    #[tokio::test]
    async fn voters_disabled_baseline_error_yields_servfail() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Error,
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders {
                quad9: false,
                adguard: false,
            },
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }

    #[tokio::test(start_paused = true)]
    async fn voters_disabled_baseline_timeout_yields_servfail_not_a_hang() {
        // Advisor-review regression: resolve_via_baseline used to call the
        // baseline directly with no timeout - harmless for the handful of
        // allowlisted domains that path used to serve alone, but T-41 makes
        // it the entire resolution path for *every* A/AAAA query while
        // voters are disabled. An unbounded hang here would stall all
        // traffic, worse than no filtering at all. Paused time makes a
        // real hang observable without an actual wait (same technique as
        // quorum.rs's T-30 cancellation tests): if resolve_via_baseline
        // waited out PendingClient instead of being bounded by
        // timeout_config.duration, elapsed would jump to that duration
        // instead of staying near zero.
        let client = PendingClient;
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let config = TimeoutConfig {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_millis(5),
        };
        let started = tokio::time::Instant::now();

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders {
                quad9: false,
                adguard: false,
            },
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &config,
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;

        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        // Tied to `config.duration` itself (T-30's own precedent), not a
        // generous constant - a hardcoded fallback timeout inside
        // resolve_via_baseline that ignored `timeout_config` entirely would
        // still pass a "< 1s" assertion against this 5ms config.
        assert!(
            started.elapsed() < config.duration * 2,
            "resolve_via_baseline must be bounded by timeout_config.duration, not hang forever"
        );
    }

    #[tokio::test]
    async fn proxy_to_single_upstream_forwards_the_baseline_answer() {
        // T-143: proxy_to_single_upstream is a thin pub wrapper around
        // resolve_via_baseline (already fully covered above, including the
        // timeout-bound regression test) - this only proves the delegation
        // itself, not resolve_via_baseline's own behavior a second time.
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(9, 9, 9, 9))),
            calls: AtomicU32::new(0),
        };
        let query = query_for("example.com.", RecordType::TXT);

        let response = super::proxy_to_single_upstream(&client, &query, &timeout_config()).await;

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn voters_disabled_skips_a_stale_ready_block_cache_entry() {
        // Advisor-review regression: every-provider-disabled is checked *before*
        // the cache lookup, not just before the cache write - a BLOCK
        // verdict cached while voters were still enabled must not be
        // served here either, or disabling every provider would silently
        // keep blocking via a stale cache hit instead of actually passing
        // through (exactly the surprise SPEC.md §3 forbids). A test that
        // only proves the pass-through path is never *cached* (the
        // existing voters_disabled_is_never_cached) doesn't prove the
        // read side is skipped too - this one starts from a cache that's
        // already populated.
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                key,
                CacheEntry::new(Verdict::Block, Duration::from_secs(300)),
            )
            .await;
        let baseline_ip = Ipv4Addr::new(93, 184, 216, 34);
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(baseline_ip)),
            calls: AtomicU32::new(0),
        };

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders {
                quad9: false,
                adguard: false,
            },
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected the real baseline A answer, not a NULL-blocked one");
        };
        assert!(
            matches!(answer.data, RData::A(a) if a.0 == baseline_ip),
            "a stale cached BLOCK verdict must not be served while voters are disabled"
        );
    }

    #[tokio::test]
    async fn voters_disabled_still_honors_blocklist() {
        // Disabling third-party voters does not disable the user's own
        // override rules - blocklist must still short-circuit above the
        // every-provider-disabled branch, and baseline must never be consulted for
        // a blocked domain regardless of voter state.
        let overrides = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Blocklist,
        }]);
        let cache = Cache::new(&cache_config());
        let client = MockClient::all_panic();

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders {
                quad9: false,
                adguard: false,
            },
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected a NULL-blocked A answer");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == Ipv4Addr::UNSPECIFIED));
    }

    // T-147: QueryLogMeta - one test per branch that produces Some(meta),
    // plus the two branches that deliberately produce None.

    #[tokio::test]
    async fn allowlist_match_logs_allowed_via_allowlist_with_no_voters() {
        let overrides = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Allowlist,
        }]);
        let cache = Cache::new(&cache_config());
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 2, 3, 4))),
            calls: AtomicU32::new(0),
        };

        let (_outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.domain, "example.com");
        assert_eq!(meta.decision, Decision::Allowed);
        assert_eq!(meta.decision_source, DecisionSource::Allowlist);
        assert!(meta.voters.is_empty());
    }

    #[tokio::test]
    async fn baseline_error_on_allowlist_path_logs_failed_decision() {
        let overrides = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Allowlist,
        }]);
        let cache = Cache::new(&cache_config());
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Error,
            calls: AtomicU32::new(0),
        };

        let (_outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(
            meta.decision,
            Decision::Failed,
            "a SERVFAIL result must not be logged as Allowed"
        );
        assert_eq!(meta.decision_source, DecisionSource::Allowlist);
    }

    #[tokio::test]
    async fn blocklist_match_logs_blocked_via_blocklist_with_no_voters() {
        let overrides = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Blocklist,
        }]);
        let cache = Cache::new(&cache_config());
        let client = MockClient::all_panic();

        let (_outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Blocked);
        assert_eq!(meta.decision_source, DecisionSource::Blocklist);
        assert!(meta.voters.is_empty());
    }

    #[tokio::test]
    async fn cache_hit_logs_the_cached_verdicts_decision_via_cache() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let Ok(block_key) = CacheKey::new("blocked.example", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                block_key,
                CacheEntry::new(Verdict::Block, Duration::from_secs(60)),
            )
            .await;
        let Ok(allow_key) = CacheKey::new("allowed.example", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                allow_key,
                CacheEntry::new(
                    Verdict::Allow(vec![Ipv4Addr::new(1, 2, 3, 4).into()]),
                    Duration::from_secs(60),
                ),
            )
            .await;
        let client = MockClient::all_panic();

        let (_outcome, meta) = handle_query(
            &query_for("blocked.example.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Blocked);
        assert_eq!(meta.decision_source, DecisionSource::Cache);

        let (_outcome, meta) = handle_query(
            &query_for("allowed.example.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Allowed);
        assert_eq!(meta.decision_source, DecisionSource::Cache);
    }

    #[tokio::test]
    async fn quorum_block_logs_blocked_via_quorum_with_the_blocking_voter() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let client = MockClient {
            quad9: MockResponse::Instant(nxdomain_message_with_soa(120)),
            adguard: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 2, 3, 4))),
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 2, 3, 4))),
            calls: AtomicU32::new(0),
        };

        let (_outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Blocked);
        assert_eq!(meta.decision_source, DecisionSource::Quorum);
        assert_eq!(
            meta.voters.len(),
            2,
            "both Phase-1 providers must have a record, blocking or not"
        );
    }

    #[tokio::test]
    async fn quorum_allow_logs_allowed_via_quorum_with_both_voters() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let client = MockClient {
            quad9: MockResponse::Instant(allow_message_with_ip(ip)),
            adguard: MockResponse::Instant(allow_message_with_ip(ip)),
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };

        let (_outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Allowed);
        assert_eq!(meta.decision_source, DecisionSource::Quorum);
        assert_eq!(meta.voters.len(), 2);
    }

    #[tokio::test]
    async fn voters_disabled_logs_via_quorum_with_no_voters_consulted() {
        // SPEC-silent choice, documented in handle_query itself: no Ф1
        // decision_source value names "voters globally disabled", so this
        // uses Quorum with an empty voters list - distinguishable from a
        // real quorum resolution by the empty list, not by decision_source.
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 2, 3, 4))),
            calls: AtomicU32::new(0),
        };

        let (_outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders {
                quad9: false,
                adguard: false,
            },
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Allowed);
        assert_eq!(meta.decision_source, DecisionSource::Quorum);
        assert!(meta.voters.is_empty());
    }

    // T-148: disabling a single provider must still run real quorum over
    // whichever provider(s) remain enabled - it's not the every-provider-
    // disabled pass-through, and the disabled provider must never actually
    // be queried (MockClient::Panic on its URL would fail the test if it
    // were).
    #[tokio::test]
    async fn single_provider_disabled_still_runs_quorum_not_passthrough() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 2, 3, 4))),
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(1, 2, 3, 4))),
            calls: AtomicU32::new(0),
        };

        let (_outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders {
                quad9: false,
                adguard: true,
            },
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Allowed);
        assert_eq!(meta.decision_source, DecisionSource::Quorum);
        // Real quorum ran (not the every-provider-disabled pass-through,
        // which always logs an empty voters list) - and the disabled
        // provider's own entry actually carries VoterVerdict::Disabled, not
        // just "the list happens to have 2 entries" (a count-only assertion
        // would pass even if handle_query silently dropped the verdict on
        // its way from QuorumOutcome into QueryLogMeta).
        assert_eq!(meta.voters.len(), 2);
        let Some(quad9) = meta.voters.iter().find(|v| v.provider == Provider::Quad9) else {
            panic!("expected a Quad9 voter record");
        };
        assert_eq!(quad9.verdict, VoterVerdict::Disabled);
    }

    #[tokio::test]
    async fn non_a_aaaa_query_produces_no_log_metadata() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let client = MockClient::all_panic();

        let (_outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::MX),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        assert!(meta.is_none());
    }

    #[tokio::test]
    async fn a_query_with_no_question_produces_no_log_metadata() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let client = MockClient::all_panic();

        let (_outcome, meta) = handle_query(
            &Message::query(),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: None,
                blocked_countries: &[],
            },
        )
        .await;
        assert!(meta.is_none());
    }

    // T-76: GeoIP wiring at both of SPEC.md §3.5's named hook points (a
    // fresh quorum Allow and a cache-hit Allow replay). `nop_on_an_empty_
    // blocked_list` asserts the real answer, not just the response code -
    // `build_block_response` is also NoError for A/AAAA, the same trap
    // `label_with_a_literal_dot_does_not_panic_or_false_match` above already
    // documents.

    #[tokio::test]
    async fn geoip_nop_on_an_empty_blocked_list_serves_the_real_ip() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let ip = se_ip();
        let client = MockClient {
            quad9: MockResponse::Instant(allow_message_with_ip(ip)),
            adguard: MockResponse::Instant(allow_message_with_ip(ip)),
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let reader = geoip_fixture();

        let (outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: Some(&reader),
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected the real A answer, not a NULL-blocked one");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == ip));
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Allowed);
        assert_eq!(meta.decision_source, DecisionSource::Quorum);
    }

    #[tokio::test]
    async fn geoip_blocks_a_fresh_quorum_allow_when_a_non_first_ip_matches() {
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        // The matching IP is deliberately second - a "check only ips[0]"
        // bug would pass a first-IP-matching version of this test but fail
        // this one, same discipline as `geoip.rs`'s own `blocks_any_is_true_
        // when_a_non_first_ip_matches_a_blocked_country`.
        let message = allow_message_with_ips(&[unmatched_ip(), se_ip()]);
        let client = MockClient {
            quad9: MockResponse::Instant(message.clone()),
            adguard: MockResponse::Instant(message.clone()),
            baseline: MockResponse::Instant(message),
            calls: AtomicU32::new(0),
        };
        let reader = geoip_fixture();

        let (outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: Some(&reader),
                blocked_countries: &["SE".to_string()],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected a NULL-blocked A answer");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == Ipv4Addr::UNSPECIFIED));
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Blocked);
        assert_eq!(meta.decision_source, DecisionSource::Geoip);
        assert_eq!(meta.geoip_country, Some("SE".to_string()));
        assert!(
            meta.voters.is_empty(),
            "GeoIP isn't a quorum vote - voters must stay empty on a GeoIP-blocked entry"
        );
    }

    #[tokio::test]
    async fn geoip_blocked_fresh_allow_still_caches_the_underlying_allow_verdict() {
        // The one property SPEC.md §3.5 actually depends on: the quorum
        // Allow verdict is cached unchanged even when GeoIP blocks this
        // particular response - caching a Block (or skipping the insert)
        // would mean removing a country from the list doesn't take effect
        // until the cache entry's TTL expires, exactly what GeoIP not being
        // cached is supposed to avoid. This test proves both halves in one
        // place: first with the country blocked (response is BLOCK, but the
        // cache holds Allow), then with the country removed and no upstream
        // client available at all (so a second network round-trip would
        // panic) - the second call can only be a genuine cache hit serving
        // the real IP.
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let ip = se_ip();
        let client = MockClient {
            quad9: MockResponse::Instant(allow_message_with_ip(ip)),
            adguard: MockResponse::Instant(allow_message_with_ip(ip)),
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let reader = geoip_fixture();
        let cache_context = CacheContext {
            cache: &cache,
            config: &cache_config(),
        };

        let (outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &cache_context,
            &timeout_config(),
            &GeoipFilter {
                reader: Some(&reader),
                blocked_countries: &["SE".to_string()],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected a NULL-blocked A answer");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == Ipv4Addr::UNSPECIFIED));
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision_source, DecisionSource::Geoip);
        assert_eq!(meta.geoip_country, Some("SE".to_string()));

        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        let Some(cached) = cache.get(&key).await else {
            panic!("the underlying Allow verdict must still be cached");
        };
        assert_eq!(
            cached.verdict,
            Verdict::Allow(vec![ip.into()]),
            "the cached verdict must be the real Allow, never a Block, regardless of GeoIP"
        );

        // Second call: country removed, and a client that panics on any
        // call - if this weren't a genuine cache hit, the test would panic
        // here instead of asserting anything below.
        let (outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &MockClient::all_panic(),
            &overrides,
            EnabledProviders::default(),
            &cache_context,
            &timeout_config(),
            &GeoipFilter {
                reader: Some(&reader),
                blocked_countries: &[],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected the real A answer now that the country was removed");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == ip));
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Allowed);
        assert_eq!(
            meta.decision_source,
            DecisionSource::Cache,
            "a country-list edit must take effect on the very next query, no cache invalidation"
        );
        assert_eq!(meta.geoip_country, None);
    }

    #[tokio::test]
    async fn geoip_blocks_a_cache_hit_allow_without_ever_consulting_quorum() {
        // Independently exercises cache_hit_response_with_meta's own GeoIP
        // check (not just reached transitively via a prior quorum call, as
        // in the test above) - the cache is pre-populated directly, and the
        // client panics on any call, proving quorum is never consulted for
        // a fresh cache hit either way.
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let ip = se_ip();
        let Ok(key) = CacheKey::new("example.com", RecordType::A) else {
            panic!("valid domain");
        };
        cache
            .insert(
                key.clone(),
                CacheEntry::new(Verdict::Allow(vec![ip.into()]), Duration::from_secs(300)),
            )
            .await;
        let client = MockClient::all_panic();
        let reader = geoip_fixture();

        let (outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: Some(&reader),
                blocked_countries: &["SE".to_string()],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected a NULL-blocked A answer");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == Ipv4Addr::UNSPECIFIED));
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision, Decision::Blocked);
        assert_eq!(meta.decision_source, DecisionSource::Geoip);
        assert_eq!(meta.geoip_country, Some("SE".to_string()));

        // Unaffected by the GeoIP block - still the original Allow.
        let Some(cached) = cache.get(&key).await else {
            panic!("cache entry must survive a GeoIP-blocked read");
        };
        assert_eq!(cached.verdict, Verdict::Allow(vec![ip.into()]));
    }

    #[tokio::test]
    async fn voters_disabled_pass_through_is_exempt_from_geoip() {
        // SPEC-silent choice, stated in the module doc comment: the
        // every-provider-disabled pass-through shares resolve_via_baseline
        // with the allowlist branch and is documented as "no filtering at
        // all" - GeoIP (a filtering mechanism) is included in that scope by
        // the same reasoning. A blocked-country match here must not turn
        // into a BLOCK response.
        let overrides = OverrideLists::empty();
        let cache = Cache::new(&cache_config());
        let ip = se_ip();
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let reader = geoip_fixture();

        let (outcome, meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders {
                quad9: false,
                adguard: false,
            },
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: Some(&reader),
                blocked_countries: &["SE".to_string()],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected the real baseline A answer, not a NULL-blocked one");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == ip));
        let Some(meta) = meta else {
            panic!("expected Some(meta)");
        };
        assert_eq!(meta.decision_source, DecisionSource::Quorum);
    }

    #[tokio::test]
    async fn allowlist_match_is_exempt_from_geoip() {
        // SPEC.md §3.5's own pipeline snippet, step 1: "ALLOW, ні quorum,
        // ні GeoIP не опитуються" - an allowlisted domain's real answer must
        // never be overridden by a blocked-country match.
        let overrides = overrides_with(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Allowlist,
        }]);
        let cache = Cache::new(&cache_config());
        let ip = se_ip();
        let client = MockClient {
            quad9: MockResponse::Panic,
            adguard: MockResponse::Panic,
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let reader = geoip_fixture();

        let (outcome, _meta) = handle_query(
            &query_for("example.com.", RecordType::A),
            &client,
            &overrides,
            EnabledProviders::default(),
            &CacheContext {
                cache: &cache,
                config: &cache_config(),
            },
            &timeout_config(),
            &GeoipFilter {
                reader: Some(&reader),
                blocked_countries: &["SE".to_string()],
            },
        )
        .await;
        let PipelineOutcome::Response(response) = outcome else {
            panic!("expected a Response");
        };
        let Some(answer) = response.answers.first() else {
            panic!("expected the real baseline A answer, not a NULL-blocked one");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == ip));
    }
}
