//! Admin channel (T-52) — a minimal control-plane on the same loopback,
//! TLS-terminated listener `dispatch::serve` already owns (SPEC.md's
//! communication-matrix row 3 pattern: extend the existing port, no new
//! listener — the same reasoning already named for the future `/health`,
//! T-86). Lets a locally-running UI (the `dnsqb-ui` Tauri app) read live
//! stats from, and push live config into, an already-running
//! `dnsqb-service` — a gap that didn't exist before this slice (`config.rs`
//! previously only had startup-time `load()`; `query_log::QueryLog` is
//! in-memory-only, no external reader).
//!
//! `AdminClient` pins TLS trust to the exact self-signed leaf `cert.rs`
//! persists to `cert.pem` (T-48/T-50) via `reqwest::Certificate::from_pem` +
//! `.add_root_certificate()` — confirmed empirically (a throwaway scratch
//! probe, not assumed) that this validates against a cert built with
//! `IsCa::ExplicitNoCa`: a length-1 chain where the leaf is its own issuer
//! still passes rustls/webpki's path building, despite `cA=FALSE`. Real TLS
//! validation, not disabled cert verification — scoped to trust exactly the
//! one cert this service itself generated, the programmatic equivalent of
//! T-49's manual trust-store import for a first-party local client (a
//! browser can't do this for itself, which is exactly why T-49 is manual).
//!
//! `AdminClient` itself is deliberately **not** unit-tested here — it's thin
//! `reqwest` glue over a real TLS+TCP round trip, which the crate's other
//! "hardcoded real resource, untested by design" modules (`paths::
//! app_data_dir`, `tls::load_or_generate_server_config`) already establish
//! precedent for. The JSON/routing/live-apply logic it talks to is fully
//! covered at the `dispatch::serve` route level instead (hand-built
//! `Request`s, no real socket, same pattern as the existing `/dns-query`
//! tests) — `AdminClient`'s only genuinely novel risk, whether cert pinning
//! validates at all, was proven by the scratch probe above, not left
//! untested. The full chain is covered by T-52's manual end-to-end smoke
//! test (TASKS-DONE.md).

use crate::cache::{CacheConfig, CacheConfigError};
use crate::overrides::ListKind;
use crate::query_log::{Decision, DecisionSource, LogEntry};
use crate::quorum::{EnabledProviders, VoterRecord, VoterVerdict};
use crate::timeout::TimeoutMode;
use hickory_proto::rr::RecordType;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

/// Live resolver state plus a snapshot of log-derived stats — the body of
/// `GET /admin/status`, and echoed back by `POST /admin/config` after
/// applying an update.
///
/// **T-53 DTO audit (2026-08-29), verdict for this file as a whole:**
/// `providers`/`timeout_mode` below are the only two fields in this module
/// that reuse an internal domain type directly (`quorum::EnabledProviders`,
/// `timeout::TimeoutMode`) rather than going through a `*View` projection —
/// checked by re-reading every DTO in this file against the type it's built
/// from. Deliberate, not an oversight: both are already flat, `Serialize`-
/// carrying config *values* (T-144/T-148), not internal implementation
/// types with anything to leak (no `LogEntry`/`VoterRecord`-shaped payload,
/// neither derives `Serialize` at all — confirmed by grep, so neither can be
/// accidentally handed to `json_response` regardless). Wrapping them in a
/// parallel DTO would recreate exactly the drift risk T-148's own module
/// doc comment already named for `config::ResolverConfig::providers`
/// reusing `EnabledProviders` — a duplicate type could represent a
/// combination `quorum::resolve` doesn't actually honor. Every other DTO in
/// this file (`OverrideDomainView`, `CacheConfigView`, `QTypeView`,
/// `DecisionView`, `DecisionSourceView`, `VoterVerdictView`,
/// `VoterResultView`, `LogEntryView`) is a genuine projection with its own
/// `From` conversion, not a reuse — closes T-53's DTO half (the allowlist
/// half was already closed structurally, `dispatch::ROUTES`, TASKS-DONE.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminStatusResponse {
    /// Which providers are currently queried. Reuses `quorum::
    /// EnabledProviders` directly — see this struct's own doc comment for
    /// the T-53 reuse-vs-projection verdict.
    pub providers: EnabledProviders,
    /// Current timeout-interpretation mode. Reuses `timeout::TimeoutMode`
    /// directly — same verdict as `providers` above.
    pub timeout_mode: TimeoutMode,
    /// Current per-query timeout, in milliseconds. Not itself editable via
    /// this slice's `POST /admin/config` (TASKS.md's T-52 line only asks for
    /// timeout-*mode* selection) — carried here read-only so a full
    /// [`crate::ResolverConfig`] can still be reconstructed for
    /// [`crate::ResolverConfig::save`].
    pub timeout_ms: u32,
    /// The local `DoH` listener's port — read-only here (changing it needs a
    /// re-bind, out of scope for a live-apply admin call).
    pub port: u16,
    /// Counts from the current query-log window.
    pub stats: AdminStats,
    /// Whether the values above were also written to `resolver_config.toml`
    /// on this call. Always `true` for a plain `GET /admin/status` (nothing
    /// changed, so there's nothing to fail to persist). A `POST
    /// /admin/config` that live-applies but fails to persist to disk still
    /// returns `false` here rather than an error — the in-memory change
    /// already took effect and must not be reported as failed, but the
    /// caller needs to know it won't survive a restart.
    pub persisted: bool,
}

/// Counts derived from [`crate::QueryLog::snapshot`] — no new storage, same
/// principle SPEC.md §8 already names for the later T-139/T-140 UI stats.
/// **Not** a calendar-day count — the log is a bounded ring buffer
/// (1000-entries-or-24h, SPEC.md §6), so `total`/`blocked` describe "the
/// current log window," not "today." The `dnsqb-ui` frontend labels it that
/// way rather than "сьогодні" (same honesty correction T-66 already made
/// relabeling cache buckets "miss/hit" instead of "cold/warm").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminStats {
    /// Every logged query in the current window, any decision.
    pub total: u64,
    /// The subset of `total` with [`Decision::Blocked`] — [`Decision::
    /// Failed`] (SERVFAIL) is a separate outcome, not counted as blocked
    /// filtering (T-147).
    pub blocked: u64,
    /// How many requests are being resolved *right now* (T-149) — a live
    /// counter (`dispatch::AppState`'s `in_flight` field), not derived from
    /// [`crate::QueryLog`] like `total`/`blocked` above: a `LogEntry` is only
    /// written after a query finishes, so the log alone can never answer
    /// "how many are in flight." `compute_stats` itself can't fill this in
    /// (it only ever sees the log) — both call sites in `dispatch.rs`
    /// overwrite it with the live counter via struct-update syntax.
    pub in_flight: u64,
}

/// `POST /admin/config`'s body — always a full replace of both fields, never
/// a partial patch. Keeps parsing trivial and matches how the UI actually
/// uses it: the dashboard always has both controls' current values on hand
/// and sends them together, so there's no scenario needing
/// `Option<Option<T>>`-style patch semantics for this slice's two controls.
/// Also reuses `EnabledProviders`/`TimeoutMode` directly on the *input*
/// side — same T-53 verdict as [`AdminStatusResponse`]'s own doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminConfigUpdate {
    /// The desired provider toggles.
    pub providers: EnabledProviders,
    /// The desired timeout mode.
    pub timeout_mode: TimeoutMode,
}

/// One override-list entry as shown to a client (T-47) — a projection of
/// [`crate::overrides::OverrideEntry`], not a reuse of it directly: once an
/// entry is already split into `OverrideListsResponse::allowlist`/
/// `blocklist`, the internal type's `list` tag is redundant, so this is a
/// genuine shape change (same class of DTO as [`AdminStats`] above), not a
/// duplicate the T-53 open question (whether admin DTOs should ever reuse
/// internal types directly) is about — that question is left exactly as
/// open as it already was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideDomainView {
    /// Normalized domain (never carries a `*.` prefix — see `is_wildcard`).
    pub domain: String,
    /// Whether this entry also matches subdomains (suffix match).
    pub is_wildcard: bool,
}

/// The body of `GET /admin/overrides`, and echoed back by `POST
/// /admin/overrides/add`/`POST /admin/overrides/remove` after applying a
/// change (T-47) — same "always return the fresh live state" shape as
/// [`AdminStatusResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideListsResponse {
    /// Every current allowlist entry.
    pub allowlist: Vec<OverrideDomainView>,
    /// Every current blocklist entry.
    pub blocklist: Vec<OverrideDomainView>,
    /// Domains present as a literal entry in both lists (SPEC.md §5,
    /// UI-SPEC.md §3.3) — allowlist wins at resolution time, but the UI must
    /// show this, not silently apply it.
    pub conflicts: Vec<String>,
    /// Whether the change that produced this response was also written to
    /// `overrides.toml` on disk. Always `true` for a plain `GET`. A `POST
    /// /admin/overrides/add`/`remove` that live-applies but fails to persist
    /// still returns `false` here rather than an error — the in-memory
    /// change already took effect and must not be reported as failed, but
    /// the caller needs to know it won't survive a restart (advisor-caught
    /// before commit: the first draft omitted this field, the same silent-
    /// data-loss shape `AdminStatusResponse::persisted` already exists to
    /// prevent for `resolver_config.toml`).
    pub persisted: bool,
}

/// `POST /admin/overrides/add`'s body (T-47). `pattern` may carry a leading
/// `*.` (the same wildcard convention `overrides.toml`'s own file format
/// uses) — parsed and normalized server-side by
/// [`crate::overrides::OverrideLists::with_entry_added`], not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideAddRequest {
    /// A raw domain pattern, e.g. `"example.com"` or `"*.example.com"`.
    pub pattern: String,
    /// Which list to add it to.
    pub list: ListKind,
}

/// `POST /admin/overrides/remove`'s body (T-47) — identifies the entry by
/// the full `(domain, is_wildcard, list)` tuple, not just `domain`, since a
/// domain can legitimately have both an exact and a wildcard entry in the
/// same list at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideRemoveRequest {
    /// The normalized domain (as shown in [`OverrideDomainView::domain`]).
    pub domain: String,
    /// Whether the entry to remove is the wildcard one.
    pub is_wildcard: bool,
    /// Which list to remove it from.
    pub list: ListKind,
}

/// The body of `GET /admin/cache-config`, and echoed back by
/// `POST /admin/cache-config/apply` after applying a change (T-153) — same
/// "always return the fresh live state" shape as [`AdminStatusResponse`]/
/// [`OverrideListsResponse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheConfigView {
    /// Lower clamp bound for upstream-derived TTLs, in seconds.
    pub clamp_min_secs: u64,
    /// Upper clamp bound for upstream-derived TTLs, in seconds.
    pub clamp_max_secs: u64,
    /// Cache lifetime for a `Block` verdict, in seconds.
    pub block_verdict_ttl_secs: u64,
    /// RFC 8767 §5 stale-timer grace window, in seconds.
    pub stale_grace_secs: u64,
    /// Maximum number of entries the cache will hold.
    pub max_capacity: u64,
    /// Whether the values above were also written to `resolver_config.toml`
    /// on this call — same convention as [`AdminStatusResponse::persisted`]/
    /// [`OverrideListsResponse::persisted`].
    pub persisted: bool,
}

impl CacheConfigView {
    /// Builds a view from a live [`CacheConfig`] plus the caller's
    /// `persisted` verdict (the caller's to state — always `true` for a
    /// plain `GET`, same convention `admin_status`/`overrides_view` in
    /// `dispatch.rs` already use).
    #[must_use]
    pub(crate) fn from_config(config: &CacheConfig, persisted: bool) -> Self {
        let secs = config.to_secs();
        Self {
            clamp_min_secs: secs.clamp_min_secs,
            clamp_max_secs: secs.clamp_max_secs,
            block_verdict_ttl_secs: secs.block_verdict_ttl_secs,
            stale_grace_secs: secs.stale_grace_secs,
            max_capacity: secs.max_capacity,
            persisted,
        }
    }
}

/// `POST /admin/cache-config/apply`'s body (T-153) — same 5 fields as
/// [`CacheConfigView`] minus `persisted` (nothing to echo before the change
/// is applied).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheConfigUpdate {
    /// See [`CacheConfigView::clamp_min_secs`].
    pub clamp_min_secs: u64,
    /// See [`CacheConfigView::clamp_max_secs`].
    pub clamp_max_secs: u64,
    /// See [`CacheConfigView::block_verdict_ttl_secs`].
    pub block_verdict_ttl_secs: u64,
    /// See [`CacheConfigView::stale_grace_secs`].
    pub stale_grace_secs: u64,
    /// See [`CacheConfigView::max_capacity`].
    pub max_capacity: u64,
}

impl CacheConfigUpdate {
    /// Validates and converts this update into a live [`CacheConfig`] — the
    /// same [`CacheConfig::from_secs`] boundary `config.rs`'s file loader
    /// goes through, so an admin POST and a hand-edited TOML file are
    /// rejected by exactly the same rule (T-153).
    ///
    /// # Errors
    ///
    /// Returns [`CacheConfigError::ClampMinExceedsMax`] if
    /// `clamp_min_secs > clamp_max_secs`.
    pub(crate) fn into_config(self) -> Result<CacheConfig, CacheConfigError> {
        CacheConfig::from_secs(
            self.clamp_min_secs,
            self.clamp_max_secs,
            self.block_verdict_ttl_secs,
            self.stale_grace_secs,
            self.max_capacity,
        )
    }
}

/// SPEC.md §6 `qtype` column, DTO form (`diagrams/ui-dto-model.md`'s `QType`
/// enum, T-54) — four coarse buckets, not [`RecordType`]'s full range: an
/// unrecognized/unusual wire record type must never round-trip an arbitrary
/// numeric value into this response (advisor-caught during planning — the
/// same "an error/response type echoes untrusted input" shape this crate's
/// own gotchas already record for `toml::de::Error`/`reqwest::Error`,
/// applied here to a record-type number instead of a domain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QTypeView {
    A,
    Aaaa,
    HttpsSvcb,
    Other,
}

impl From<RecordType> for QTypeView {
    fn from(qtype: RecordType) -> Self {
        match qtype {
            RecordType::A => Self::A,
            RecordType::AAAA => Self::Aaaa,
            RecordType::HTTPS => Self::HttpsSvcb,
            _ => Self::Other,
        }
    }
}

/// SPEC.md §6 `decision` column, DTO form (T-54/T-147) — three values, not
/// the two `diagrams/ui-dto-model.md`'s draft `Decision` enum still lists;
/// `Failed` (SERVFAIL — no filtering decision was actually made) was added
/// to the internal [`Decision`] at T-147, after that diagram was drawn. This
/// is the ground-truth ritual catching up the diagram, not a new design
/// choice — see `diagrams/ui-dto-model.md`'s own update at this task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionView {
    Allowed,
    Blocked,
    Failed,
}

impl From<Decision> for DecisionView {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Allowed => Self::Allowed,
            Decision::Blocked => Self::Blocked,
            Decision::Failed => Self::Failed,
        }
    }
}

/// SPEC.md §6/§8 `decision_source` column, DTO form (T-54) — all seven
/// values `UI-SPEC.md` §1's "carry every field from day one" principle
/// requires, though only four (`Allowlist`/`Blocklist`/`Cache`/`Quorum`) are
/// producible before their own later-phase pipeline step exists (see
/// [`DecisionSourceView::from`] below — a total match over the internal
/// four-variant [`DecisionSource`], so the other three can never actually be
/// constructed by this conversion, only declared for the wire format).
///
/// `CcTldBlock`/`GeoIp` need an explicit `#[serde(rename)]` — automatic
/// `SCREAMING_SNAKE_CASE` conversion would produce `CC_TLD_BLOCK`/`GEO_IP`,
/// not SPEC.md's own `CCTLD_BLOCK`/`GEOIP` (verified by hand-tracing serde's
/// case-boundary algorithm before relying on the blanket `rename_all` for
/// these two, not assumed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionSourceView {
    Allowlist,
    Blocklist,
    #[serde(rename = "CCTLD_BLOCK")]
    CcTldBlock,
    Cache,
    RatingFilter,
    Quorum,
    #[serde(rename = "GEOIP")]
    GeoIp,
}

impl From<DecisionSource> for DecisionSourceView {
    fn from(source: DecisionSource) -> Self {
        match source {
            DecisionSource::Allowlist => Self::Allowlist,
            DecisionSource::Blocklist => Self::Blocklist,
            DecisionSource::Cache => Self::Cache,
            DecisionSource::Quorum => Self::Quorum,
        }
    }
}

/// SPEC.md §5.1/§6 `voter_scope` column, DTO form (T-54) — always [`Self::
/// Full`] this phase: T-109 (Фаза 4) hasn't built the top-N voter-scope
/// exemption yet, so every query gets the full enabled voter set. The field
/// exists from day one (`UI-SPEC.md` §1) so a future phase only has to start
/// *populating* it, never add a new wire field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoterScopeView {
    Full,
    SecurityOnly,
}

/// SPEC.md §6 `voters` column, per-voter value, DTO form (T-54) — seven
/// variants, resolving the SPEC.md §6-vs-§8 discrepancy `diagrams/
/// ui-dto-model.md` already documented and the user already confirmed
/// (DECISIONS.md 2026-08-25): `Pending` stays a legitimate variant, reserved
/// for a future *live*-updating log view this crate doesn't have yet — see
/// [`From<&VoterRecord>`](VoterVerdictView#impl-From<%26VoterRecord>-for-VoterVerdictView)
/// below for why it can never come from an already-completed [`VoterRecord`].
/// `#[serde(tag = "status")]` (internally tagged, T-53/T-54's own "mirror to
/// a discriminated union" ask) rather than the flat, payload-free style every
/// other DTO enum in this file uses — chosen specifically because `Allow`/
/// `Error` carry a payload today and the tagged form lets a future variant
/// gain its own payload later without changing the wire shape of the
/// variants that already exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoterVerdictView {
    Pending,
    Block,
    Allow { ip_count: u32 },
    Timeout,
    Error { message: String },
    Canceled,
    Disabled,
}

impl From<&VoterRecord> for VoterVerdictView {
    /// Total over every backend [`VoterVerdict`] variant, no wildcard arm —
    /// if a `Pending`-like transit state is ever added to the backend enum,
    /// this match stops compiling instead of silently falling through
    /// (advisor-caught during planning). `Pending` has no arm here at all:
    /// it's structurally unreachable from this conversion, not just
    /// documented as unused — see this type's own doc comment.
    fn from(record: &VoterRecord) -> Self {
        match record.verdict {
            VoterVerdict::Block => Self::Block,
            VoterVerdict::Allow => Self::Allow {
                ip_count: record.allow_ip_count.unwrap_or(0),
            },
            VoterVerdict::Timeout => Self::Timeout,
            VoterVerdict::Error => Self::Error {
                message: record.error_message.unwrap_or("unknown").to_string(),
            },
            VoterVerdict::Canceled => Self::Canceled,
            VoterVerdict::Disabled => Self::Disabled,
        }
    }
}

/// SPEC.md §8 `VoterResult` DTO (T-54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoterResultView {
    /// [`crate::upstream::Provider::as_str`] — the same lowercase identifier
    /// `EnabledProviders`'s own field names and the `GET /admin/log?voter=`
    /// facet use, so a client can round-trip a value from here straight back
    /// into that filter.
    pub provider_name: String,
    pub status: VoterVerdictView,
}

impl From<&VoterRecord> for VoterResultView {
    fn from(record: &VoterRecord) -> Self {
        Self {
            provider_name: record.provider.as_str().to_string(),
            status: VoterVerdictView::from(record),
        }
    }
}

/// Milliseconds since the Unix epoch, saturating rather than panicking on a
/// (practically unreachable) pre-epoch `SystemTime`.
fn unix_millis(time: SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

/// SPEC.md §6/§8 `LogEntry` DTO — the body of `GET /admin/log`'s `entries`
/// (T-54). Widens the internal, Phase-1-only [`LogEntry`] (four
/// `decision_source` values, no `voter_scope`/`geoip_country` fields at all)
/// into the full seven-value/placeholder-carrying shape `UI-SPEC.md` §1's
/// "carry every field from day one" principle calls for — `crate::query_log`'s
/// own module doc comment names this widening as this task's job, not
/// something to build into the internal type itself (an illegal state for
/// this phase — a `decision_source` this phase can't produce — stays
/// unrepresentable there).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntryView {
    pub timestamp_ms: u64,
    pub domain: String,
    pub qtype: QTypeView,
    pub decision: DecisionView,
    pub decision_source: DecisionSourceView,
    /// Always [`VoterScopeView::Full`] this phase — see that type's own doc
    /// comment.
    pub voter_scope: VoterScopeView,
    pub voters: Vec<VoterResultView>,
    /// Always `None` this phase — T-79 (Фаза 2) hasn't built `GeoIP` yet.
    pub geoip_country: Option<String>,
    pub latency_ms: u64,
}

impl LogEntryView {
    #[must_use]
    pub(crate) fn from_entry(entry: &LogEntry) -> Self {
        Self {
            timestamp_ms: unix_millis(entry.timestamp),
            domain: entry.domain.clone(),
            qtype: QTypeView::from(entry.qtype),
            decision: DecisionView::from(entry.decision),
            decision_source: DecisionSourceView::from(entry.decision_source),
            voter_scope: VoterScopeView::Full,
            voters: entry.voters.iter().map(VoterResultView::from).collect(),
            geoip_country: None,
            latency_ms: entry.latency_ms,
        }
    }
}

/// The body of `GET /admin/log` (T-54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogQueryResponse {
    /// Newest-matching-entries-last (chronological order within the kept
    /// window), capped at the request's `limit` (see `dispatch::
    /// parse_log_query`) — never the full, unbounded search result: every
    /// other input/output boundary in this crate is explicitly bounded
    /// (`MAX_MESSAGE_SIZE`, `MAX_ADMIN_BODY_SIZE`, `MAX_OVERRIDES_FILE_SIZE`),
    /// and a response whose size scales with live user traffic is no
    /// exception (advisor-caught during planning).
    pub entries: Vec<LogEntryView>,
    /// Whether more entries matched the filter than `entries` actually
    /// carries — lets the UI show an honest "showing latest N of M" instead
    /// of silently truncating with no indication.
    pub truncated: bool,
}

/// Reduces `entries` to [`AdminStats`]. `pub(crate)` — only `dispatch.rs`'s
/// `GET /admin/status`/`POST /admin/config` handlers call this.
#[must_use]
pub(crate) fn compute_stats(entries: &[LogEntry]) -> AdminStats {
    let total = entries.len();
    let blocked = entries
        .iter()
        .filter(|entry| entry.decision == Decision::Blocked)
        .count();
    AdminStats {
        total: u64::try_from(total).unwrap_or(u64::MAX),
        blocked: u64::try_from(blocked).unwrap_or(u64::MAX),
        // Filled in by the caller (`dispatch.rs`) from the live in-flight
        // counter, which this pure, log-only function has no access to.
        in_flight: 0,
    }
}

/// Errors building or using an [`AdminClient`].
#[derive(Debug, thiserror::Error)]
pub enum AdminClientError {
    /// Couldn't read the persisted TLS certificate (`cert.pem`) — most
    /// likely `dnsqb-service` hasn't been run yet, so no certificate has
    /// been generated.
    #[error("failed to read the persisted TLS certificate: {0}")]
    CertRead(#[source] std::io::Error),
    /// Failed to parse the certificate or build the underlying HTTP client.
    #[error("failed to build the admin HTTP client: {0}")]
    ClientBuild(#[source] reqwest::Error),
    /// The request itself failed (connection refused — the service isn't
    /// running — a non-2xx response, or a response that didn't decode as
    /// the expected JSON shape).
    #[error("admin request failed: {0}")]
    Request(#[source] reqwest::Error),
}

/// A small `reqwest`-based client for `dnsqb-service`'s admin channel,
/// pinned to the exact self-signed leaf certificate this service instance
/// persists (see the module doc comment for why that validates). The whole
/// public surface a caller (e.g. `dnsqb-ui`'s Tauri commands) needs —
/// `reqwest` itself never has to appear in that caller's own dependency
/// graph (T-52 plan: avoids two crates having to track matching `reqwest`
/// versions/features just to pass `Client`/`Certificate` values around).
#[derive(Debug, Clone)]
pub struct AdminClient {
    client: reqwest::Client,
    base_url: String,
}

impl AdminClient {
    /// Builds a client pinned to the certificate persisted at
    /// `app_data_dir/cert.pem`, targeting `https://127.0.0.1:<port>`.
    ///
    /// # Errors
    ///
    /// Returns [`AdminClientError::CertRead`] if `cert.pem` can't be read,
    /// or [`AdminClientError::ClientBuild`] if it doesn't parse as PEM or
    /// the underlying HTTP client fails to build.
    pub fn new(app_data_dir: &Path, port: u16) -> Result<Self, AdminClientError> {
        let cert_pem =
            fs::read(app_data_dir.join("cert.pem")).map_err(AdminClientError::CertRead)?;
        let cert =
            reqwest::Certificate::from_pem(&cert_pem).map_err(AdminClientError::ClientBuild)?;
        let client = reqwest::Client::builder()
            .add_root_certificate(cert)
            .build()
            .map_err(AdminClientError::ClientBuild)?;
        Ok(Self {
            client,
            base_url: format!("https://127.0.0.1:{port}"),
        })
    }

    /// Fetches the live resolver status.
    ///
    /// # Errors
    ///
    /// Returns [`AdminClientError::Request`] if the service isn't reachable
    /// or the response doesn't decode as [`AdminStatusResponse`].
    pub async fn status(&self) -> Result<AdminStatusResponse, AdminClientError> {
        let response = self
            .client
            .get(format!("{}/admin/status", self.base_url))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(AdminClientError::Request)?;
        response.json().await.map_err(AdminClientError::Request)
    }

    /// Applies `update` to the live resolver (and persists it, if the
    /// service has a config file to persist to — see [`AdminStatusResponse::
    /// persisted`]).
    ///
    /// # Errors
    ///
    /// Returns [`AdminClientError::Request`] if the service isn't reachable
    /// or the response doesn't decode as [`AdminStatusResponse`].
    pub async fn apply(
        &self,
        update: AdminConfigUpdate,
    ) -> Result<AdminStatusResponse, AdminClientError> {
        let response = self
            .client
            .post(format!("{}/admin/config", self.base_url))
            .json(&update)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(AdminClientError::Request)?;
        response.json().await.map_err(AdminClientError::Request)
    }

    /// Soft-resets the live resolver (T-149) — reloads `resolver_config.toml`/
    /// `overrides.toml` from disk and clears the cache and query log. Not a
    /// process restart (SPEC.md §7 leaves that to `dnsqb-watcher`).
    ///
    /// # Errors
    ///
    /// Returns [`AdminClientError::Request`] if the service isn't reachable,
    /// the reset itself failed server-side (a malformed on-disk file), or the
    /// response doesn't decode as [`AdminStatusResponse`].
    pub async fn reset(&self) -> Result<AdminStatusResponse, AdminClientError> {
        let response = self
            .client
            .post(format!("{}/admin/reset", self.base_url))
            .json(&serde_json::json!({}))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(AdminClientError::Request)?;
        response.json().await.map_err(AdminClientError::Request)
    }

    /// Requests a graceful shutdown of the whole `dnsqb-service` process
    /// (T-149) — the highest blast-radius call on this channel: after this
    /// returns `Ok`, `dnsqb-service` is draining and will exit, and DNS
    /// resolution for the whole machine stops until it's manually restarted
    /// (SPEC.md §7 leaves full process supervision to `dnsqb-watcher`, not
    /// this channel). The only caller is `dnsqb-tray`'s "Зупинити
    /// фільтрацію" menu item, behind a confirm dialog naming that
    /// consequence — never call this without an equivalent, explicit
    /// user confirmation.
    ///
    /// # Errors
    ///
    /// Returns [`AdminClientError::Request`] if the service isn't reachable
    /// or the response wasn't a success status. A success response here has
    /// no meaningful body (the process may already be exiting), unlike
    /// [`AdminClient::reset`]/[`AdminClient::apply`].
    pub async fn shutdown(&self) -> Result<(), AdminClientError> {
        self.client
            .post(format!("{}/admin/shutdown", self.base_url))
            .json(&serde_json::json!({}))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(AdminClientError::Request)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_stats, AdminStats};
    use crate::query_log::{Decision, DecisionSource, LogEntry};
    use hickory_proto::rr::RecordType;
    use std::time::SystemTime;

    fn entry(decision: Decision) -> LogEntry {
        LogEntry {
            timestamp: SystemTime::now(),
            domain: "example.com".to_string(),
            qtype: RecordType::A,
            decision,
            decision_source: DecisionSource::Quorum,
            voters: Vec::new(),
            latency_ms: 1,
        }
    }

    #[test]
    fn compute_stats_counts_blocked_separately_from_allowed_and_failed() {
        let entries = vec![
            entry(Decision::Allowed),
            entry(Decision::Blocked),
            entry(Decision::Blocked),
            entry(Decision::Failed),
        ];
        assert_eq!(
            compute_stats(&entries),
            AdminStats {
                total: 4,
                blocked: 2,
                in_flight: 0,
            }
        );
    }

    #[test]
    fn compute_stats_of_an_empty_log_is_all_zero() {
        assert_eq!(
            compute_stats(&[]),
            AdminStats {
                total: 0,
                blocked: 0,
                in_flight: 0,
            }
        );
    }

    // T-54: LogEntryView and its component enums. The DTO's exact wire
    // strings are asserted via `serde_json::to_string` (not just via the
    // enum variant's `Debug` form) - `SCREAMING_SNAKE_CASE`'s case-boundary
    // behavior on a mixed-case variant name (`CcTldBlock`, `GeoIp`) isn't
    // obvious from reading the derive alone, and this crate's own gotchas
    // record more than one case of an assumed-safe serde behavior turning
    // out wrong when actually run.

    use super::{
        DecisionSourceView, DecisionView, LogEntryView, QTypeView, VoterResultView, VoterScopeView,
        VoterVerdictView,
    };
    use crate::quorum::{VoterRecord, VoterVerdict};
    use crate::upstream::Provider;

    fn json_of<T: serde::Serialize>(value: &T) -> String {
        match serde_json::to_string(value) {
            Ok(json) => json,
            Err(err) => panic!("must serialize: {err}"),
        }
    }

    #[test]
    fn qtype_view_maps_a_aaaa_https_and_buckets_everything_else_as_other() {
        assert_eq!(json_of(&QTypeView::from(RecordType::A)), "\"A\"");
        assert_eq!(json_of(&QTypeView::from(RecordType::AAAA)), "\"AAAA\"");
        assert_eq!(
            json_of(&QTypeView::from(RecordType::HTTPS)),
            "\"HTTPS_SVCB\""
        );
        assert_eq!(json_of(&QTypeView::from(RecordType::TXT)), "\"OTHER\"");
        assert_eq!(json_of(&QTypeView::from(RecordType::MX)), "\"OTHER\"");
    }

    #[test]
    fn decision_view_wire_strings_match_spec() {
        assert_eq!(
            json_of(&DecisionView::from(Decision::Allowed)),
            "\"ALLOWED\""
        );
        assert_eq!(
            json_of(&DecisionView::from(Decision::Blocked)),
            "\"BLOCKED\""
        );
        assert_eq!(json_of(&DecisionView::from(Decision::Failed)), "\"FAILED\"");
    }

    #[test]
    fn decision_source_view_wire_strings_match_spec_including_the_two_renamed_variants() {
        assert_eq!(
            json_of(&DecisionSourceView::from(DecisionSource::Allowlist)),
            "\"ALLOWLIST\""
        );
        assert_eq!(
            json_of(&DecisionSourceView::from(DecisionSource::Blocklist)),
            "\"BLOCKLIST\""
        );
        assert_eq!(
            json_of(&DecisionSourceView::from(DecisionSource::Cache)),
            "\"CACHE\""
        );
        assert_eq!(
            json_of(&DecisionSourceView::from(DecisionSource::Quorum)),
            "\"QUORUM\""
        );
        // The two phase-5 variants aren't producible from the internal
        // 4-variant DecisionSource (see DecisionSourceView::from's own
        // exhaustive match) - constructed directly here purely to pin their
        // wire string, which the explicit #[serde(rename)] overrides exist
        // for.
        assert_eq!(json_of(&DecisionSourceView::CcTldBlock), "\"CCTLD_BLOCK\"");
        assert_eq!(json_of(&DecisionSourceView::GeoIp), "\"GEOIP\"");
        assert_eq!(
            json_of(&DecisionSourceView::RatingFilter),
            "\"RATING_FILTER\""
        );
    }

    #[test]
    fn voter_scope_view_wire_strings_match_spec() {
        assert_eq!(json_of(&VoterScopeView::Full), "\"FULL\"");
        assert_eq!(json_of(&VoterScopeView::SecurityOnly), "\"SECURITY_ONLY\"");
    }

    #[test]
    fn voter_verdict_view_is_internally_tagged_with_the_documented_status_key() {
        assert_eq!(json_of(&VoterVerdictView::Block), "{\"status\":\"BLOCK\"}");
        assert_eq!(
            json_of(&VoterVerdictView::Allow { ip_count: 2 }),
            "{\"status\":\"ALLOW\",\"ip_count\":2}"
        );
        assert_eq!(
            json_of(&VoterVerdictView::Error {
                message: "http".to_string()
            }),
            "{\"status\":\"ERROR\",\"message\":\"http\"}"
        );
        assert_eq!(
            json_of(&VoterVerdictView::Pending),
            "{\"status\":\"PENDING\"}"
        );
    }

    fn voter_record(verdict: VoterVerdict) -> VoterRecord {
        VoterRecord {
            provider: Provider::Quad9,
            verdict,
            allow_ip_count: match verdict {
                VoterVerdict::Allow => Some(3),
                _ => None,
            },
            error_message: match verdict {
                VoterVerdict::Error => Some("http"),
                _ => None,
            },
        }
    }

    #[test]
    fn voter_result_view_from_record_carries_the_provider_name_and_payload() {
        let view = VoterResultView::from(&voter_record(VoterVerdict::Allow));
        assert_eq!(view.provider_name, "quad9");
        assert_eq!(view.status, VoterVerdictView::Allow { ip_count: 3 });
    }

    #[test]
    fn voter_result_view_from_record_covers_every_backend_verdict() {
        // Every VoterVerdict variant must map to *some* VoterVerdictView
        // without panicking - a wildcard-free match (see
        // `impl From<&VoterRecord> for VoterVerdictView`) makes this provable
        // at compile time already; this test additionally pins the actual
        // mapping for each one.
        let cases = [
            (VoterVerdict::Block, VoterVerdictView::Block),
            (VoterVerdict::Allow, VoterVerdictView::Allow { ip_count: 3 }),
            (VoterVerdict::Timeout, VoterVerdictView::Timeout),
            (
                VoterVerdict::Error,
                VoterVerdictView::Error {
                    message: "http".to_string(),
                },
            ),
            (VoterVerdict::Canceled, VoterVerdictView::Canceled),
            (VoterVerdict::Disabled, VoterVerdictView::Disabled),
        ];
        for (verdict, expected) in cases {
            let record = voter_record(verdict);
            assert_eq!(VoterVerdictView::from(&record), expected);
        }
    }

    #[test]
    fn log_entry_view_from_entry_widens_decision_source_and_placeholders_the_rest() {
        let mut source_entry = entry(Decision::Blocked);
        source_entry.decision_source = DecisionSource::Blocklist;
        source_entry.voters = vec![voter_record(VoterVerdict::Block)];
        source_entry.qtype = RecordType::AAAA;
        source_entry.latency_ms = 42;

        let view = LogEntryView::from_entry(&source_entry);

        assert_eq!(view.domain, "example.com");
        assert_eq!(view.qtype, QTypeView::Aaaa);
        assert_eq!(view.decision, DecisionView::Blocked);
        assert_eq!(view.decision_source, DecisionSourceView::Blocklist);
        assert_eq!(
            view.voter_scope,
            VoterScopeView::Full,
            "always FULL until T-109 (Фаза 4)"
        );
        assert_eq!(view.geoip_country, None, "always None until T-79 (Фаза 2)");
        assert_eq!(view.voters.len(), 1);
        assert_eq!(view.latency_ms, 42);
    }
}
