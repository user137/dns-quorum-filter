#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
// This crate is never published - it's built only for `dnsqb-service`/`dnsqb-watcher` and its own
// docs are always generated with `--document-private-items` (CLAUDE.md). Doc comments on public
// items routinely cross-reference private helpers on purpose (the established habit for this
// crate); that's exactly what this lint flags, so it's not a real problem to fix at each site.
#![allow(rustdoc::private_intra_doc_links)]

//! `DoH` server + quorum resolver core (SPEC.md §1, §3). Фаза 1, чотирнадцятий
//! зріз (T-144): `main.rs`'s three MVP-hardcoded constants (port, timeout
//! mode/duration, whether voters are enabled) are now a real persisted
//! config — new module `config.rs`: `ResolverConfig`/`ResolverConfig::load`,
//! mirroring `overrides.rs`'s own load pattern (`ResolverConfigFile`,
//! struct-level `#[serde(default, deny_unknown_fields)]`, missing file →
//! `Ok(default())`, malformed file → `Err`). Deliberately **not** a per-
//! provider/category config (UI-SPEC.md §3.4's Security/Ads/Adult toggles
//! and preset checklist) — `quorum::resolve` hardcodes querying both
//! `Provider::Quad9` and `Provider::AdGuard` unconditionally, with no
//! parameter anywhere for "which providers to query," so persisting a
//! per-provider toggle the resolver can't act on would repeat T-41's own
//! `Voters`-design lesson (a config subset nothing downstream honors is a
//! footgun) — flagged as an open gap for whoever scopes T-52's config
//! surface for real, not silently invented here. Unlike `overrides.json`'s
//! own load errors (non-fatal, falls back to empty), a malformed
//! `resolver_config.json` is **fatal** at startup (`tracing::error!` +
//! `exit(1)`) — SPEC.md §1's "never a silent port fallback" rule means
//! silently substituting the default port for a corrupted file would be
//! exactly the forbidden behavior, just one step removed. `port == 0` /
//! `timeout_ms == 0` are rejected explicitly at load (`ConfigError::
//! ZeroPort`/`ZeroTimeout`) rather than silently clamped — a `0`ms timeout
//! would SERVFAIL every query instantly with no obvious cause (Три Б, user
//! safety; caught by advisor review of the plan, not a test). `TimeoutMode`
//! (`timeout.rs`) gained `Serialize`/`Deserialize` (`snake_case` on disk) —
//! reused directly rather than a parallel config-only copy of the same three
//! variants. Manually confirmed against the running binary: a
//! `resolver_config.json` with a non-default port actually changes which
//! port the listener binds (verified end-to-end with a real `DoH` query
//! against the new port), and a structurally-invalid file exits 1 with an
//! explicit error, not a silent fallback.
//!
//! Фаза 1, тринадцятий зріз (T-143): `main.rs` is no longer a stub — a real `hyper` TCP accept
//! loop + `rustls`/`tokio-rustls` TLS termination + `dispatch::serve`
//! (`GET`/`POST /dns-query` → `pipeline::handle_query`, RFC 8484) actually
//! resolves queries end to end, manually confirmed against the running
//! binary (200 OK with correctly encoded answers on GET and POST, 404 on
//! any other path, 405 on any other method). `dispatch.rs` is new: its pure
//! parsing helpers (`wire_bytes_from_get`, `content_type_is_dns_message`)
//! and `resolve_doh_request` (decode → `handle_query` →
//! `pipeline::proxy_to_single_upstream` for T-25's non-A/AAAA case → encode)
//! are `pub(crate)` and unit-tested directly; `serve` and `AppState` are
//! `pub` — `serve` is generic over the request body type specifically so it
//! can be unit-tested with `http_body_util::Full` instead of
//! `hyper::body::Incoming`, which only a live connection can produce.
//! `tls::build_server_config` now sets `alpn_protocols` (h2, then
//! http/1.1) — advisor review of the plan caught that an unset ALPN offer
//! doesn't guarantee predictable HTTP/2 negotiation. `paths::app_data_dir`/
//! `PathsError` are `pub` as of this slice — `main.rs` is a separate crate
//! (the `[[bin]]` target) and needed a real external path to resolve
//! `overrides.json`'s location, `cert.rs`'s `pub(crate)` access no longer
//! being enough. Port `8443`, timeout mode/duration, and `Voters::Enabled`
//! were MVP hardcoded defaults at the time of this slice — **superseded by
//! T-144** (see the fourteenth-slice paragraph above), which made all three
//! a real persisted config; per-provider toggling itself is still not
//! wired (`quorum::resolve` still hardcodes both Phase-1 providers
//! unconditionally). Query-log wiring (`query_log::LogEntry` still has no producer)
//! and graceful shutdown (no watcher yet, Фаза 3) stay out of scope, same as
//! every prior slice's "primitive ready, wiring later" pattern. On top of
//! the twelfth slice's (T-142) `tls::load_or_generate_server_config` — builds a
//! `rustls::ServerConfig` from the persisted cert/key, or generates and
//! persists a fresh one if none exists/usable (the load-vs-regenerate
//! decision T-50 explicitly left open). On top of the eleventh slice's (T-50)
//! `cert::write_cert_and_key_to_app_data` — disk persistence for T-48's
//! cert/key — and the tenth slice's (T-48) `cert::generate_self_signed_cert`
//! — the local listener's
//! self-signed leaf certificate (SPEC.md §2), SAN `IP:127.0.0.1`, `IP:::1`,
//! `DNS:localhost`, explicit 100-year validity window (not rcgen's raw
//! default), never a CA. On top of the ninth slice's (T-42, T-43) `query_log`
//! — the in-memory ring buffer query log
//! (SPEC.md §6, §6.1), a `VecDeque<LogEntry>` behind `parking_lot::RwLock`
//! bounded independently by entry count (evict-oldest-on-insert) and age
//! (`retain`-on-read). `LogEntry` here is the internal backend record, only
//! the four `decision_source` values Phase 1 can produce — narrower than
//! the eventual Tauri DTO of the same name (see `query_log`'s own module
//! doc comment for the full reasoning, including why `voters` carries only
//! `Provider`'s two filtering-voter variants, not baseline). No producer
//! yet (nothing in `pipeline::handle_query` builds or pushes a `LogEntry`),
//! same "module ready, wiring later" pattern as every prior slice's modules
//! before their own wiring task.
//!
//! On top of the eighth slice's (T-137) `Cache::clear()` — manual
//! one-click full-cache clear, wrapping `moka::future::Cache::invalidate_all`
//! directly (no predicate needed, unlike `invalidate_matching`) — the
//! seventh slice's (T-41) `pipeline::handle_query`'s `Voters` parameter
//! (every provider disabled is an explicit pass-through via the baseline
//! resolver, not `fail-closed` and not a silent no-op, SPEC.md §3, §8.1),
//! the sixth slice's (T-40) `pipeline::invalidate_changed` (cache eviction
//! on an override-list reload), and the fifth slice's (T-39) end-to-end
//! `pipeline::handle_query` (allowlist → blocklist → cache → quorum) and the
//! earlier slices' timeout-mode-aware OR-logic quorum with early
//! return/cancellation, `DoH` wire codec, baseline/upstream client with
//! HTTP/2 keep-alive, and `moka`-backed cache. `Cache::clear()` has no live
//! caller yet either (no Tauri command exists — T-53), same pattern as
//! `invalidate_matching`/`invalidate_changed`. Override lists have no
//! file-write path yet (`save()` — T-46/T-47, when a UI writer exists), so
//! nothing calls `invalidate_changed` yet either; likewise no real
//! per-provider toggle config exists yet (T-52), so nothing calls
//! `handle_query` with `Voters::Disabled` yet either. Tauri UI is a later
//! batch — see TASKS.md.
//!
//! T-148 replaced the seventh slice's `pipeline::Voters` (all-or-nothing)
//! with `quorum::EnabledProviders` — a real per-provider toggle
//! `quorum::resolve` actually honors (only pushes a query for a provider
//! that's enabled; a disabled provider's outcome is never coerced into
//! `TimedOut`, or `fail_closed` mode would treat "disabled" the same as
//! "unresponsive" and silently block every query). `config::ResolverConfig`
//! reuses the same type directly as its `providers` field (nested
//! `[providers]` TOML table) rather than a parallel config-only copy. Still
//! not wired to any UI (T-52, no longer blocked on this task).

mod admin;
mod admin_ui;
mod cache;
mod cert;
mod cert_rotation;
mod config;
mod dispatch;
mod geoip;
mod geoip_credentials;
mod geoip_download;
mod geoip_updater;
mod key_store;
mod listener;
mod overrides;
mod paths;
mod pipeline;
mod query_log;
mod quorum;
mod timeout;
mod tls;
mod trust_store;
mod upstream;
mod wire;

pub use admin::{
    AdminClient, AdminClientError, AdminConfigUpdate, AdminStats, AdminStatusResponse,
    DatabaseSource, MaxmindCredentialCheck, MaxmindCredentialsRequest, MaxmindCredentialsView,
    ProviderAddRequest, ProviderRemoveRequest, ProviderSetEnabledRequest, ProviderStatusView,
    ProviderView, ProvidersResponse,
};
pub use cache::{
    chain_cache_ttl, clamp_ttl, is_cacheable, Cache, CacheConfig, CacheConfigError,
    CacheConfigSecs, CacheEntry, CacheKey, Verdict,
};
pub use cert::{generate_self_signed_cert, write_cert_and_key_to_app_data, CertError, CertFiles};
pub use cert_rotation::{rotate_certificate, RotationError, RotationReport};
pub use config::{ConfigError, GeoipConfig, ResolverConfig};
pub use dispatch::{
    serve, AppState, CacheState, GeoipInit, GeoipState, OverridesState, PersistPaths,
    PersistTarget, RuntimeInit, RuntimeSettings,
};
pub use geoip::{GeoipError, GeoipReader};
pub use geoip_credentials::{
    load as load_maxmind_credentials, migrate_legacy_credentials_file, CredentialsError,
    LicenseKey, MaxmindCredentials,
};
pub use geoip_updater::{
    run_geoip_updater, GeoipSource, GeoipUpdateError, MaxmindHealth, GEOIP_CHECK_INTERVAL,
};
pub use listener::{bind_listener, BindError};
pub use overrides::{
    InvalidEntry, InvalidReason, ListKind, OverrideEntry, OverrideError, OverrideLists,
};
pub use paths::{app_data_dir, PathsError};
pub use pipeline::{
    handle_query, invalidate_changed, proxy_to_single_upstream, CacheContext, GeoipFilter,
    PipelineOutcome, QueryLogMeta,
};
pub use query_log::{Decision, DecisionSource, LogEntry, LogFilter, QueryLog};
pub use quorum::{
    is_blocked, requires_quorum, resolve, QuorumOutcome, QuorumVerdict, VoterRecord, VoterVerdict,
};
pub use timeout::{query_with_timeout, TimeoutConfig, TimeoutMode, VoterOutcome};
pub use tls::{load_or_generate_server_config, TlsError};
pub use trust_store::{ensure_installed, uninstall, TrustStoreError, TrustStoreOutcome};
pub use upstream::{
    all_builtin_presets, builtin_preset, doh_get_url, is_valid_provider_id, validate_provider_url,
    BlockSignature, Category, DohClient, ProviderEntry, ProviderSpec, ProviderUrlError,
    ReqwestDohClient, UpstreamError, BASELINE_DOH_URL, DEFAULT_PROVIDER_IDS,
};
pub use wire::{
    attach_edns, build_block_response, decode_wire_message, encode_wire_message, forward_response,
    EDNS_UDP_PAYLOAD_SIZE,
};

use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, Record};
use hickory_proto::ProtoError;

/// RFC 2181 §5.2 (T-33): minimum TTL across one `RRset` — `None` for an empty
/// set (SPEC.md §4.1). `hickory-proto` does not itself enforce that same-name/
/// same-type records share one TTL at decode time (verified empirically —
/// `wire::tests::hickory_proto_does_not_reconcile_rrset_ttls_on_decode`), so
/// this reconciliation is this project's own responsibility, not a passthrough
/// to an existing guarantee.
///
/// Callers must pass records already narrowed to one `(name, type)` `RRset` —
/// this function itself does no grouping. For the whole-answer-section
/// minimum (CNAME chain included), see `cache::chain_cache_ttl` (T-36)
/// instead, which is deliberately a different function with a different
/// precondition.
#[must_use]
pub fn min_rrset_ttl(records: &[Record]) -> Option<u32> {
    records.iter().map(|r| r.ttl).min()
}

/// RFC 2308 (T-35): negative-caching TTL is bounded by the zone's SOA MINIMUM,
/// not an arbitrary constant (SPEC.md §3.1, §4.1).
#[must_use]
pub fn negative_cache_ttl(soa: &SOA) -> u32 {
    soa.minimum
}

/// RFC 5891 IDNA2008 (T-38): normalize an override-list/cache-key domain —
/// lowercase, punycode, trailing dot trimmed (SPEC.md §5, §4).
///
/// Goes through `hickory_proto::rr::Name::from_utf8`/`to_ascii` — the exact
/// `idna::uts46::Uts46` path (`AsciiDenyList::STD3`, `Hyphens::Allow`,
/// `DnsLength::Ignore`) that `hickory-proto` itself uses to parse incoming
/// query names — rather than a second, directly-depended-on `idna` call.
/// Two independent IDNA code paths normalizing the same-looking domain
/// differently would mean a domain occasionally doesn't match itself between
/// override-list/cache lookups and incoming-query parsing; going through
/// `Name` makes that desync impossible by construction instead of by
/// version-pinning discipline.
///
/// # Errors
///
/// Returns `Err` if `input` is not a syntactically valid domain name.
pub fn normalize_domain(input: &str) -> Result<String, ProtoError> {
    let ascii = Name::from_utf8(input)?.to_ascii().to_ascii_lowercase();
    Ok(ascii.trim_end_matches('.').to_string())
}

/// RFC 8767 stale-if-error (T-10): serve a stale cache entry instead of a
/// fresh upstream error, layered on top of (not instead of) `fail-open` —
/// `fail-closed`/`degraded` don't get this fallback (SPEC.md §3.3, §4.1,
/// TASKS.md T-28).
#[must_use]
pub fn should_serve_stale(
    fail_open: bool,
    cache_entry_expired: bool,
    upstream_failed: bool,
) -> bool {
    fail_open && cache_entry_expired && upstream_failed
}
