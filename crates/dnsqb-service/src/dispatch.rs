//! `DoH` GET/POST → `pipeline::handle_query` request dispatch (T-143) — RFC 8484
//! (SPEC.md §1, §3). `main.rs`'s TCP accept loop and TLS handshake hand each
//! connection off to [`serve`], the piece of this module `main.rs`
//! (a separate crate — the `[[bin]]` target) calls directly; [`RuntimeSettings`]/
//! [`PersistTarget`] (T-52) are `pub` too, since `main.rs` constructs both to
//! build the [`AppState`] it hands to `serve`. Everything else here is
//! `pub(crate)` or private, independently unit-tested with a mock
//! [`DohClient`] and a hand-built [`Request`], no live TCP/TLS needed.
//! [`serve`] itself is generic over the request body type (not hardcoded to
//! `hyper::body::Incoming`, which can't be constructed outside a real
//! connection) for exactly that reason — `main.rs` calls it with `Incoming`,
//! tests call it with `http_body_util::Full`.
//!
//! Endpoint is fixed to `/dns-query` (SPEC.md §1 line 84) — any other path is
//! a 404, except `/admin/status`/`/admin/config` (T-52), `/admin/reset`
//! (T-149, soft reset — see `apply_admin_reset`), `/admin/shutdown` (T-149,
//! graceful process exit — see `serve_admin_shutdown` and `main.rs`'s accept
//! loop, its only consumer is the `dnsqb-tray` crate), and `/admin/ui`/
//! `/admin/ui/main.js`/`/admin/ui/style.css` (T-149, the embedded web UI —
//! see `admin_ui.rs`), all added on this same listener rather than a new
//! one, the same "extend the existing port" pattern. `/health` (T-86,
//! watchdog channel 3 — SPEC.md §7.1 #10) is on this listener too.

use crate::admin::{
    compute_stats, unix_millis, AdminConfigUpdate, AdminStats, AdminStatusResponse,
    BaselineEndpointView, CacheConfigUpdate, CacheConfigView, DatabaseSource,
    EncryptedPersistenceView, GeoipCountriesResponse, GeoipCountryRequest, HealthGeoip,
    HealthResponse, LogEntryView, LogQueryResponse, MaxmindCredentialCheck,
    MaxmindCredentialsRequest, MaxmindCredentialsView, NetworkStatusView, OverrideAddRequest,
    OverrideDomainView, OverrideListsResponse, OverrideRemoveRequest, ProviderStatusView,
    UninstallLocalStateResponse, WatchdogStatusView,
};
use crate::admin_ui;
use crate::baseline_selector::BaselineSelector;
use crate::cache::{Cache, CacheConfig, CacheConfigError, CacheEntry, CacheKey};
use crate::config::{validate_country_code, ConfigError, GeoipConfig, ResolverConfig};
use crate::geoip::GeoipReader;
use crate::geoip_credentials::{self, CredentialsError};
use crate::geoip_updater::{
    check_maxmind_credentials, GeoipSource, GeoipUpdateError, MaxmindHealth,
};
use crate::overrides::{InvalidEntry, InvalidReason, ListKind, OverrideError, OverrideLists};
use crate::pipeline::{
    handle_query, invalidate_changed, proxy_to_single_upstream, CacheContext, GeoipFilter,
    PipelineOutcome, UpstreamContext,
};
use crate::query_log::{Decision, LogEntry, LogFilter, QueryLog, DEFAULT_MAX_ENTRIES};
use crate::reachability::NetworkReachability;
use crate::timeout::TimeoutConfig;
use crate::upstream::{
    all_builtin_presets, builtin_preset, BlockSignature, DohClient, ProviderEntry, ProviderSpec,
};
use crate::watchdog::state::{WatchdogState, WATCHDOG_STATE_STALE_AFTER};
use crate::wire::{decode_wire_message, encode_wire_message};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use hickory_proto::rr::RecordType;
use hickory_proto::ProtoError;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Body;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{watch, Notify};

/// The largest a DNS wire message is allowed to be, GET or POST alike — the
/// classic DNS-over-TCP 2-byte length prefix this project doesn't use still
/// names the right upper bound (a real DNS message can't legally exceed it),
/// and rejecting anything larger here is what actually bounds allocation
/// (SPEC.md §8.1: "ліміт розміру, не необмежена алокація").
pub(crate) const MAX_MESSAGE_SIZE: usize = 65_535;

const DNS_QUERY_PATH: &str = "/dns-query";
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";
/// Watchdog channel 3 (T-86) — a peer of `/dns-query`, not an `/admin/*`
/// route.
const HEALTH_PATH: &str = "/health";
/// A syntactically valid name that can never resolve (RFC 2606 `.invalid`),
/// run through the local pipeline prefix by [`serve_health`] to prove that
/// path executes without a network call.
const HEALTH_SENTINEL_DOMAIN: &str = "health-probe.dnsqb.invalid";

const ADMIN_STATUS_PATH: &str = "/admin/status";
const ADMIN_CONFIG_PATH: &str = "/admin/config";
const ADMIN_RESET_PATH: &str = "/admin/reset";
const ADMIN_SHUTDOWN_PATH: &str = "/admin/shutdown";
const ADMIN_OVERRIDES_PATH: &str = "/admin/overrides";
const ADMIN_OVERRIDES_ADD_PATH: &str = "/admin/overrides/add";
const ADMIN_OVERRIDES_REMOVE_PATH: &str = "/admin/overrides/remove";
const ADMIN_CACHE_CONFIG_PATH: &str = "/admin/cache-config";
const ADMIN_CACHE_CONFIG_APPLY_PATH: &str = "/admin/cache-config/apply";
const ADMIN_GEOIP_PATH: &str = "/admin/geoip";
const ADMIN_GEOIP_ADD_PATH: &str = "/admin/geoip/add";
const ADMIN_GEOIP_REMOVE_PATH: &str = "/admin/geoip/remove";
const ADMIN_GEOIP_MAXMIND_PATH: &str = "/admin/geoip/maxmind";
const ADMIN_GEOIP_MAXMIND_CLEAR_PATH: &str = "/admin/geoip/maxmind/clear";
const ADMIN_PROVIDERS_PATH: &str = "/admin/providers";
const ADMIN_PROVIDERS_ADD_PATH: &str = "/admin/providers/add";
const ADMIN_PROVIDERS_REMOVE_PATH: &str = "/admin/providers/remove";
const ADMIN_PROVIDERS_SET_ENABLED_PATH: &str = "/admin/providers/set-enabled";
const ADMIN_LOG_PATH: &str = "/admin/log";
const ADMIN_LOG_CLEAR_PATH: &str = "/admin/log/clear";
const ADMIN_UNINSTALL_LOCAL_STATE_PATH: &str = "/admin/uninstall-local-state";
const ADMIN_UI_PATH: &str = "/admin/ui";
const ADMIN_UI_JS_PATH: &str = "/admin/ui/main.js";
const ADMIN_UI_CSS_PATH: &str = "/admin/ui/style.css";

/// T-53/T-59: the single source of truth for which paths [`serve`] routes at
/// all and which method(s) each one accepts — `serve` checks a request
/// against this table *before* the handler-dispatch `match` below ever runs,
/// so a path/method pair not listed here can never reach a handler no matter
/// what arm someone later adds to that `match`. This is what makes
/// `dispatch::tests::serve_matches_the_documented_admin_route_allowlist`
/// (an independent, hand-written copy of this same table) an actual proof
/// that the exposed surface is exactly this list, not just a test that
/// happens to pass today.
const ROUTES: &[(&str, &[Method])] = &[
    (DNS_QUERY_PATH, &[Method::GET, Method::POST]),
    (HEALTH_PATH, &[Method::GET]),
    (ADMIN_STATUS_PATH, &[Method::GET]),
    (ADMIN_CONFIG_PATH, &[Method::POST]),
    (ADMIN_RESET_PATH, &[Method::POST]),
    (ADMIN_SHUTDOWN_PATH, &[Method::POST]),
    (ADMIN_OVERRIDES_PATH, &[Method::GET]),
    (ADMIN_OVERRIDES_ADD_PATH, &[Method::POST]),
    (ADMIN_OVERRIDES_REMOVE_PATH, &[Method::POST]),
    (ADMIN_CACHE_CONFIG_PATH, &[Method::GET]),
    (ADMIN_CACHE_CONFIG_APPLY_PATH, &[Method::POST]),
    (ADMIN_GEOIP_PATH, &[Method::GET]),
    (ADMIN_GEOIP_ADD_PATH, &[Method::POST]),
    (ADMIN_GEOIP_REMOVE_PATH, &[Method::POST]),
    (ADMIN_GEOIP_MAXMIND_PATH, &[Method::GET, Method::POST]),
    (ADMIN_GEOIP_MAXMIND_CLEAR_PATH, &[Method::POST]),
    (ADMIN_PROVIDERS_PATH, &[Method::GET]),
    (ADMIN_PROVIDERS_ADD_PATH, &[Method::POST]),
    (ADMIN_PROVIDERS_REMOVE_PATH, &[Method::POST]),
    (ADMIN_PROVIDERS_SET_ENABLED_PATH, &[Method::POST]),
    (ADMIN_LOG_PATH, &[Method::GET]),
    (ADMIN_LOG_CLEAR_PATH, &[Method::POST]),
    (ADMIN_UNINSTALL_LOCAL_STATE_PATH, &[Method::POST]),
    (ADMIN_UI_PATH, &[Method::GET]),
    (ADMIN_UI_JS_PATH, &[Method::GET]),
    (ADMIN_UI_CSS_PATH, &[Method::GET]),
];

/// `POST /admin/config`'s body is two bools and a short enum — this bound
/// exists for the same reason `MAX_MESSAGE_SIZE` does (SPEC.md §8.1: "ліміт
/// розміру, не необмежена алокація"), just a much smaller one, since nothing
/// legitimate ever needs more than a few dozen bytes here.
const MAX_ADMIN_BODY_SIZE: usize = 4096;

/// A malformed `DoH` HTTP request — never carries the request's own bytes or
/// the decoded message, only a closed, coarse reason (same discipline as
/// `overrides::InvalidReason`/`upstream::UpstreamError::error_kind()`: no
/// domain names, and here, no arbitrary client-supplied bytes, in
/// logs/diagnostics).
#[derive(Debug, thiserror::Error)]
pub(crate) enum DohRequestError {
    /// GET request had no `dns=` query parameter (RFC 8484 §4.1.1).
    #[error("missing dns query parameter")]
    MissingDnsParam,
    /// The `dns=` parameter wasn't valid unpadded base64url.
    #[error("dns query parameter is not valid unpadded base64url")]
    InvalidBase64,
    /// Decoded/POSTed message exceeds [`MAX_MESSAGE_SIZE`].
    #[error("dns message exceeds the maximum allowed size")]
    MessageTooLarge,
    /// POST request's `Content-Type` wasn't `application/dns-message` (RFC
    /// 8484 §6).
    #[error("unsupported content-type for a DoH POST request")]
    UnsupportedContentType,
    /// Reading the POST body itself failed for a reason other than
    /// exceeding [`MAX_MESSAGE_SIZE`] (e.g. the client disconnected
    /// mid-body) — kept distinct from `MessageTooLarge` so a 413 always
    /// means what it says.
    #[error("failed to read the request body")]
    BodyReadError,
}

/// RFC 8484 §4.1.1: extract the wire message from a GET request's raw query
/// string. No percent-decoding — base64url's alphabet (`A-Za-z0-9-_`) is
/// already URL-safe, matching `upstream::doh_get_url`'s own encoder; a
/// client that percent-encodes anyway fails to decode safely rather than
/// being silently mishandled.
pub(crate) fn wire_bytes_from_get(query_string: &str) -> Result<Vec<u8>, DohRequestError> {
    let encoded = query_string
        .split('&')
        .find_map(|pair| pair.strip_prefix("dns="))
        .ok_or(DohRequestError::MissingDnsParam)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DohRequestError::InvalidBase64)?;
    if decoded.len() > MAX_MESSAGE_SIZE {
        return Err(DohRequestError::MessageTooLarge);
    }
    Ok(decoded)
}

/// RFC 7231: media-type comparison is ASCII-case-insensitive and may carry
/// parameters (`application/dns-message; charset=utf-8` is still
/// `application/dns-message`) — a byte-equality check would reject a
/// conforming client whose `Content-Type` isn't byte-identical to Chrome's.
fn content_type_matches(content_type: Option<&str>, expected: &str) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
}

/// Whether `content_type` is `application/dns-message` (RFC 8484 §6),
/// ignoring case and any trailing parameters.
pub(crate) fn content_type_is_dns_message(content_type: Option<&str>) -> bool {
    content_type_matches(content_type, DNS_MESSAGE_CONTENT_TYPE)
}

/// **Not** an implementation detail — this is the whole CSRF defense for
/// `POST /admin/config` (T-52). `application/json` is not a CORS "simple"
/// content type, so a cross-origin `fetch()` (e.g. from a page the browser
/// happens to be rendering once `cert.pem` is trust-store-installed, T-49)
/// must preflight; the preflight `OPTIONS` isn't routed to anything here and
/// gets a bare 404/405 with no CORS headers, so the browser never sends the
/// real request. Without this check, a `text/plain` (or missing)
/// `Content-Type` is a CORS *simple* request — no preflight — and the write
/// already lands before the browser even enforces same-origin on reading the
/// response: silent, persisted, unfiltered DNS with zero on-screen
/// indication, the Три Б failure mode by name. Caught by advisor review of
/// the diff before commit, not a test — `serve_dns_query`'s own
/// `content_type_is_dns_message` gate was the precedent this admin route
/// should have matched from the start.
///
/// **DNS rebinding is a separate obvious worry here and is already closed,
/// not by this check** — `cert.rs`'s leaf SANs are exactly `IP:127.0.0.1`/
/// `IP:::1`/`DNS:localhost` (T-48), so a rebound attacker-controlled hostname
/// fails TLS certificate validation before any request to this route could
/// even complete. Widening that SAN set in the future would reopen this —
/// don't, without re-litigating this comment.
fn content_type_is_json(content_type: Option<&str>) -> bool {
    content_type_matches(content_type, "application/json")
}

/// The admin-mutable timeout config (T-52). Since T-72/T-73 the provider
/// list is its own [`AppState::providers`] `RwLock<Arc<Vec<ProviderEntry>>>`
/// slice (edited via `/admin/providers/*`, not `/admin/config`), so this is
/// down to one field — kept as a struct for a stable `AppState` shape and in
/// case another admin-mutable scalar joins it.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeSettings {
    /// Current timeout mode/duration.
    pub timeout: TimeoutConfig,
    /// T-155 — serve the unfiltered baseline answer when *every* enabled
    /// voter failed to respond (`false` = the timeout mode decides, only
    /// the log label changes).
    pub serve_baseline_when_filters_unreachable: bool,
}

/// The admin-mutable resolver settings handed to [`AppState::new`] (T-72/T-73)
/// — bundles `timeout` with the configured `providers` list so the
/// constructor stays under `clippy::too_many_arguments`. `AppState::new`
/// immediately splits it: `timeout` into [`AppState::runtime`], `providers`
/// into [`AppState::providers`] (its own `RwLock<Arc<_>>`, swapped only by
/// `/admin/providers/*` and `/admin/reset`).
#[derive(Debug, Clone)]
pub struct RuntimeInit {
    /// Current timeout mode/duration.
    pub timeout: TimeoutConfig,
    /// T-155 — see [`RuntimeSettings::serve_baseline_when_filters_unreachable`].
    pub serve_baseline_when_filters_unreachable: bool,
    /// The configured voter list, in order.
    pub providers: Vec<ProviderEntry>,
}

impl Default for RuntimeInit {
    fn default() -> Self {
        Self {
            timeout: TimeoutConfig::default(),
            serve_baseline_when_filters_unreachable: false,
            providers: ProviderEntry::default_active_set(),
        }
    }
}

/// Where (if anywhere) admin-channel config changes should be persisted,
/// plus the immutable `port` / `persist_query_log` / `persist_cache` values
/// needed to reconstruct a full [`ResolverConfig`] for that write. None is
/// admin-mutable — `port` needs a listener re-bind, and the two persistence
/// flags (T-146 / T-97) are deliberately hand-edit-only (no admin route) —
/// but every route that re-serializes `resolver_config.toml` must carry their
/// live values or an unrelated toggle would blank them on save (the
/// cross-field-read bug class, T-57/T-139/T-149/T-47/T-77).
#[derive(Debug, Clone)]
pub struct PersistTarget {
    /// The local `DoH` listener's port (unchanging at runtime).
    pub port: u16,
    /// T-146 — whether the query log is persisted to `query-log.enc`
    /// (SPEC.md §6). Set once from `resolver_config.toml` at startup; carried
    /// through every config rewrite so an admin change doesn't wipe it.
    pub persist_query_log: bool,
    /// T-97 — whether the quorum-verdict cache is persisted to `cache.enc`
    /// (SPEC.md §4). Same hand-edit-only, carried-through-every-rewrite
    /// treatment as `persist_query_log`.
    pub persist_cache: bool,
    /// Where `resolver_config.toml`/`overrides.toml` live, or `None` if no
    /// app-data directory was available at startup (same tolerance
    /// `main.rs` already applies to loading them) — an admin write with no
    /// target still live-applies, just can't persist ([`AdminStatusResponse::
    /// persisted`] reports `false`) and `/admin/reset` (T-149) has nowhere
    /// to reload from (500).
    pub paths: Option<PersistPaths>,
}

/// The parsed override lists plus the raw lines that failed to parse when
/// they were last loaded from disk (T-47) — bundled so a swap into
/// [`AppState::overrides`] is atomic across both, and so [`OverrideLists::
/// save`] can write `invalid` back verbatim instead of silently deleting a
/// user's own (typo'd) filtering intent the next time any entry is added or
/// removed through the admin channel. `OverrideLists` alone only ever holds
/// successfully-parsed entries — without this bundle, nothing downstream of
/// `load()`/`/admin/reset` would even know an invalid line still exists.
///
/// `pub` (same reasoning as [`PersistTarget`]/[`RuntimeSettings`]): `main.rs`
/// builds one from [`OverrideLists::load`]'s own return value and hands it to
/// [`AppState::new`] — bundling it here is also what keeps that constructor
/// under `clippy::too_many_arguments` without an `#[allow(...)]`, same
/// structural fix T-147/T-148 already established for this file.
pub struct OverridesState {
    /// The successfully-parsed entries.
    pub lists: OverrideLists,
    /// Lines that failed to parse, kept only so a later [`OverrideLists::
    /// save`] can write them back verbatim.
    pub invalid: Vec<InvalidEntry>,
}

/// The live cache instance plus the config it was built from (T-153) —
/// bundled because a cache-config change can't be applied to an existing
/// `moka::Cache` in place: `moka::future::Cache::policy()` only exposes a
/// read-only snapshot (confirmed by reading `moka` 0.12.16's own source,
/// `policy.rs`/`future/cache.rs` — `Policy::max_capacity` is a getter, no
/// setter anywhere in the crate, and the `Expiry` policy is baked into the
/// `CacheBuilder` at construction with no equivalent live-swap API). A
/// config change always builds a brand-new `Cache` and swaps both fields
/// atomically (via [`AppState::cache`]'s `RwLock<Arc<_>>`), so the instance
/// and the config it reports via `/admin/cache-config` never disagree, and a
/// query holding an `Arc::clone` of the old value finishes safely against
/// the orphaned instance rather than racing a live mutation.
///
/// `pub` (same reasoning as [`PersistTarget`]/[`OverridesState`]): `main.rs`
/// builds one to hand to [`AppState::new`].
pub struct CacheState {
    /// The live cache.
    pub cache: Cache,
    /// The config it was built from.
    pub config: CacheConfig,
}

/// The currently-loaded `GeoIP` country database, if any, plus when it was
/// last (re)loaded (T-75). `reader: None` is the pre-first-download state
/// (a fresh install, before `geoip_updater`'s first successful check
/// completes) — same "empty ⇒ no-op, not disabled/error" framing SPEC.md
/// §3.5 already uses for an empty blocked-country list, extended here to
/// cover "no database at all" too, not just "database present but no
/// countries configured."
///
/// `pub` (same reasoning as [`CacheState`]/[`OverridesState`]): `main.rs`
/// builds the initial value (from an on-disk database a previous run left
/// behind, if any) to hand to [`AppState::new`], and
/// `geoip_updater::run_geoip_updater` builds each subsequent value after a
/// successful refresh.
#[derive(Default)]
pub struct GeoipState {
    /// The loaded database, or `None` before the first successful download.
    pub reader: Option<Arc<GeoipReader>>,
    /// When `reader` was last (re)loaded — `None` alongside `reader: None`.
    pub updated_at: Option<SystemTime>,
}

/// `AppState::new`'s `geoip` parameter (T-76) — pairs the initially-loaded
/// `GeoipState` with the initially-configured blocked-country list so the
/// constructor doesn't need an eighth parameter (same
/// `clippy::too_many_arguments` reasoning as `pipeline::CacheContext`/
/// `GeoipFilter`). `AppState::new` immediately splits this into two
/// independently-swappable fields — see [`AppState::geoip`]/
/// [`AppState::geoip_countries`]'s own doc comments for why they're kept
/// separate rather than one field: `geoip` is swapped only by
/// `geoip_updater::run_geoip_updater` after a database refresh,
/// `geoip_countries` only by config load / `/admin/reset` (and, once T-77
/// exists, an admin write route) — bundling them into one swappable value
/// would mean a database refresh could silently wipe the user's country
/// list, or vice versa.
pub struct GeoipInit {
    /// The initially-loaded `GeoIP` database state (reader + when it was
    /// last refreshed).
    pub database: GeoipState,
    /// The initially-configured blocked-country list.
    pub blocked_countries: Vec<String>,
    /// The initial database source (T-163) — DB-IP Lite, or `MaxMind` if the
    /// operator has stored credentials. `AppState::new` puts this behind its
    /// own `RwLock<Arc<_>>` so `run_geoip_updater` reads a fresh snapshot each
    /// cycle rather than holding the value it was spawned with.
    pub source: GeoipSource,
}

/// The two on-disk config files' paths, always resolved together from one
/// `app_data_dir()` call in `main.rs` — bundled as one field on
/// [`PersistTarget`] rather than two independent `Option<PathBuf>`s so
/// "config path present but overrides path absent" (or vice versa) is
/// unrepresentable, not just unreachable in practice (T-149, advisor-caught:
/// rust.md "Make Illegal States Unrepresentable").
#[derive(Debug, Clone)]
pub struct PersistPaths {
    /// `resolver_config.toml`'s path.
    pub config: PathBuf,
    /// `overrides.toml`'s path.
    pub overrides: PathBuf,
}

impl PersistPaths {
    /// The app-data directory the config files live in — `resolver_config.toml`'s
    /// parent. Used to derive the `keyring` entry for the `MaxMind` credentials
    /// (T-163, [`crate::key_store::maxmind_credentials_entry`]) and to locate a
    /// leftover pre-T-163 `geoip_maxmind.toml` for one-time migration. Derived
    /// rather than stored as a third field: all config artefacts live in the one
    /// `app_data_dir()` directory (the invariant this struct's own doc comment
    /// already relies on), so this avoids threading a new field through every
    /// `PersistPaths` construction site.
    #[must_use]
    pub fn app_data_dir(&self) -> PathBuf {
        // `config` is always `<app-data dir>/resolver_config.toml` — built that
        // way in `main.rs` and in every test `PersistPaths` — so `parent()` is
        // always `Some`. The fallback keeps the full path (not `"."`) so a
        // hypothetical parentless `config` still yields an install-unique
        // keyring entry rather than one shared across every install.
        self.config
            .parent()
            .map_or_else(|| self.config.clone(), std::path::Path::to_path_buf)
    }
}

/// Decode `wire_bytes`, run it through the pipeline, and encode whatever
/// comes back. `PipelineOutcome::ProxyToSingleUpstream` (T-25 — non-A/AAAA
/// types) is handled here, not left to the caller: this is the one place
/// that actually has an upstream `client` to proxy through.
///
/// Takes `&AppState<C>` rather than its seven fields as separate parameters
/// (T-147 added the seventh, `query_log`, tripping `clippy::too_many_arguments`)
/// — every one of those fields already lives in `state`, and this function
/// only ever runs against the shared per-service state `serve` already holds.
///
/// # Errors
///
/// Returns `Err` if `wire_bytes` doesn't decode as a DNS message, or if
/// (practically unreachable) the resolved response somehow fails to
/// re-encode.
pub(crate) async fn resolve_doh_request<C: DohClient + Sync>(
    wire_bytes: &[u8],
    state: &AppState<C>,
) -> Result<Vec<u8>, ProtoError> {
    let query = decode_wire_message(wire_bytes)?;
    // Counted only once the request is a real DNS query - a malformed
    // request never enters resolution, so it's never "in flight" in the
    // sense the tray tooltip/admin dashboard means (T-149). RAII, not a
    // manual inc/dec pair - this function (and handle_query below it) has
    // several return points, and a forgotten decrement on a future one
    // would leak the counter upward forever (the same class of bug T-147's
    // own notes already flag for this exact function).
    let _in_flight = InFlightGuard::new(&state.in_flight);
    let started = Instant::now();
    // Snapshot-read once, not re-read per field below - a `Copy` value, and
    // the lock is never held across the `.await` this call makes (T-52,
    // same "no `.await` under the lock" precedent `query_log.rs` already
    // established for its own `RwLock`).
    let settings = *state.runtime.read();
    // Same snapshot discipline as `settings` above, but `OverridesState`
    // isn't `Copy` (Vec-backed) - `Arc::clone` bumps a refcount under the
    // lock instead of either holding the lock across the `.await` below or
    // cloning the whole list on every query (T-149).
    let overrides_state = Arc::clone(&state.overrides.read());
    // Same snapshot discipline as `overrides_state` above (T-153) - a config
    // change swaps in a whole new `CacheState` (see its own doc comment for
    // why a live in-place update isn't possible), so this must be one
    // `Arc::clone` under the lock, not two separate field reads that could
    // straddle a swap and pair a stale `Cache` with a fresh `CacheConfig` or
    // vice versa.
    let cache_state = Arc::clone(&state.cache.read());
    // Same snapshot discipline as `cache_state` above (T-76) - two
    // independent `RwLock`s (`geoip`/`geoip_countries`, see their own doc
    // comments for why they're separate), each `Arc::clone`d once, never
    // held across the `.await` below.
    let geoip_state = Arc::clone(&state.geoip.read());
    let geoip_countries = Arc::clone(&state.geoip_countries.read());
    // Same snapshot discipline (T-72/T-73) — `Arc::clone` under the lock,
    // never held across the `.await`.
    let providers = Arc::clone(&state.providers.read());
    // T-154(b): one `Arc::clone` snapshot, same discipline as the others —
    // the reachability prober is the sole writer, this path only reads which
    // baseline URL is currently active.
    let baseline = Arc::clone(&state.baseline.read());
    let cache_context = CacheContext {
        cache: &cache_state.cache,
        config: &cache_state.config,
    };
    let geoip_filter = GeoipFilter {
        reader: geoip_state.reader.as_deref(),
        blocked_countries: &geoip_countries,
    };
    let upstream_context = UpstreamContext {
        timeout: &settings.timeout,
        baseline_url: baseline.current(),
        serve_baseline_fallback: settings.serve_baseline_when_filters_unreachable,
        reachability: state.reachability_snapshot(),
    };
    let response = match handle_query(
        &query,
        &state.client,
        &overrides_state.lists,
        &providers,
        &cache_context,
        &upstream_context,
        &geoip_filter,
    )
    .await
    {
        (PipelineOutcome::Response(message), meta) => {
            // T-147: the one place both the Response and proxy paths are
            // visible, and the natural point to bracket total latency - see
            // `pipeline::QueryLogMeta`'s own doc comment for why the push
            // isn't inside `handle_query` itself.
            if let Some(meta) = meta {
                let latency_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                state.query_log.push(LogEntry {
                    timestamp: SystemTime::now(),
                    domain: meta.domain,
                    qtype: meta.qtype,
                    decision: meta.decision,
                    decision_source: meta.decision_source,
                    voters: meta.voters,
                    geoip_country: meta.geoip_country,
                    resolved_ip_country: meta.resolved_ip_country,
                    latency_ms,
                });
            }
            message
        }
        // Non-A/AAAA proxy path: not logged this slice - handle_query never
        // sees the actual proxied response, and none of the four Ф1
        // decision_source values describe a proxy pass-through (T-147, named
        // gap, not silently dropped).
        (PipelineOutcome::ProxyToSingleUpstream, _) => {
            proxy_to_single_upstream(&state.client, &query, &settings.timeout, baseline.current())
                .await
        }
    };
    encode_wire_message(&response)
}

/// Everything one connection's worth of [`serve`] calls need — one instance
/// built at startup and shared (via `Arc`) across every accepted connection.
/// Generic over the same `C: DohClient` bound `pipeline::handle_query` uses,
/// so tests can substitute a mock client instead of a real
/// `upstream::ReqwestDohClient`.
pub struct AppState<C: DohClient + Sync> {
    client: C,
    overrides: RwLock<Arc<OverridesState>>,
    runtime: RwLock<RuntimeSettings>,
    /// The configured voter list (T-72/T-73) — swapped by `/admin/providers/*`
    /// and `apply_admin_reset`, read once per query as an `Arc::clone` under
    /// the lock (never held across `.await`), same shape as `cache`/`geoip`.
    providers: RwLock<Arc<Vec<ProviderEntry>>>,
    cache: RwLock<Arc<CacheState>>,
    /// T-75 — swapped by `geoip_updater::run_geoip_updater` after each
    /// successful database refresh, read by `pipeline::handle_query`'s
    /// `GeoIP` filtering step (T-76). `RwLock<Arc<_>>`, same
    /// snapshot-read-under-a-clone shape as `cache`/`overrides` — a query
    /// must never hold this lock across an `.await`. Deliberately doesn't
    /// carry the blocked-country list too — see [`GeoipInit`]'s own doc
    /// comment for why that's a separate field ([`AppState::geoip_countries`]).
    geoip: RwLock<Arc<GeoipState>>,
    /// T-76 — the `GeoIP` blocked-country list (SPEC.md §3.5), swapped by
    /// config load / `/admin/reset` / `POST /admin/geoip/add`/`remove`
    /// (T-77) — never by `geoip_updater`, which only ever touches `geoip`
    /// above. Same `RwLock<Arc<_>>` snapshot-read shape as every other
    /// per-query state here.
    geoip_countries: RwLock<Arc<Vec<String>>>,
    /// T-163 — which upstream `geoip_updater::run_geoip_updater` pulls from
    /// (DB-IP Lite or `MaxMind`). Swapped by `apply_admin_reset` and the
    /// `/admin/geoip/maxmind[/clear]` routes; the updater reads a fresh
    /// `Arc::clone` snapshot at the top of every cycle, so a credentials
    /// change takes effect with no `dnsqb-service` restart. Same
    /// `RwLock<Arc<_>>` shape as `geoip`; never held across `.await`.
    geoip_source: RwLock<Arc<GeoipSource>>,
    /// T-163 — wakes `run_geoip_updater` out of its inter-cycle sleep the
    /// moment `geoip_source` changes, so a new/cleared key triggers a fresh
    /// download within seconds instead of up to `GEOIP_CHECK_INTERVAL` later.
    /// `Notify::notify_one` before the updater parks on `notified()` is
    /// remembered (one permit), so a change *during* an in-flight refresh
    /// still wakes the next park; several rapid changes coalesce to one extra
    /// refresh.
    geoip_refresh_wake: Arc<Notify>,
    /// T-163 — whether the stored `MaxMind` credentials are still being
    /// accepted at the scheduled background refresh (the signal the save-time
    /// probe can't give). Written by `run_geoip_updater` after each refresh
    /// and reset by `update_geoip_source` when the source changes; surfaced on
    /// the `/admin/ui` `#geoip-maxmind` card via `MaxmindCredentialsView`.
    maxmind_health: RwLock<Arc<MaxmindHealth>>,
    /// T-154(b) — which baseline (non-filtering) resolver URL to use, plus
    /// its failover/recovery state. Read once per query as an `Arc::clone`
    /// snapshot (`pipeline::UpstreamContext::baseline_url`), never held
    /// across `.await`; the *writer* is the reachability prober task
    /// (`run_reachability_prober`), which health-checks the active URL each
    /// cycle and swaps this `Arc`. Same `RwLock<Arc<_>>` shape as every
    /// other per-query state here.
    baseline: RwLock<Arc<BaselineSelector>>,
    /// T-152 — whether the machine has any internet connectivity, published
    /// by `run_reachability_prober` and read once per query
    /// (`pipeline::handle_query`'s offline fast path). A plain
    /// `RwLock<NetworkReachability>` — the value is a `Copy` 1-byte enum, so
    /// the `Arc<_>` wrapper the bigger per-query state uses would be pure
    /// overhead. Never held across `.await`.
    reachability: RwLock<NetworkReachability>,
    query_log: QueryLog,
    persist: PersistTarget,
    /// How many requests are currently between "decoded" and "answered"
    /// (T-149) — a live counter surfaced in [`AdminStats::in_flight`],
    /// maintained by [`InFlightGuard`], never read/written directly outside
    /// [`resolve_doh_request`]/[`admin_status`]/[`apply_admin_config`]/
    /// [`apply_admin_reset`].
    in_flight: AtomicU64,
    /// The shutdown signal `POST /admin/shutdown` sends (T-149) — `false`
    /// until that route fires `send(true)`. `main.rs`'s accept loop holds
    /// the one long-lived [`watch::Receiver`] it `tokio::select!`s against
    /// ([`AppState::shutdown_handle`]); a plain `tokio::sync::Notify` was
    /// considered and rejected (see the T-149 plan) because its stored-
    /// permit/fresh-future semantics on every `select!` iteration are exactly
    /// the kind of claim this project verifies empirically before relying on
    /// — `watch` has no equivalent ambiguity, so no probe was needed.
    shutdown_tx: watch::Sender<bool>,
    /// Orders `POST /admin/config`'s, `POST /admin/cache-config/apply`'s
    /// (T-153), and `POST /admin/geoip/add`/`remove`'s (T-77) live-write +
    /// disk-persist sequences across concurrent requests (T-58) —
    /// `ResolverConfig::save` is a plain `fs::write`, not atomic, and happens
    /// *after* `runtime`'s (or `cache`'s, or `geoip_countries`'s) write lock
    /// is released (deliberately: holding any of them across a blocking disk
    /// write would stall every in-flight query's own read of that field
    /// too). **Shared by all three routes, not independent locks, because
    /// all three write into the *same* physical file**
    /// (`resolver_config.toml` carries `providers`/`timeout_mode`,
    /// `[cache]` (T-153), and `[geoip]` (T-77)) — separate locks guarding
    /// writes into one file would reproduce the exact disk-vs-live
    /// divergence this lock exists to prevent, just between three routes
    /// instead of two. Each handler's `save()` call snapshots **all three**
    /// fields (not just the one it's changing) while still holding this
    /// lock, so the file it writes always reflects the other fields'
    /// current live values too, never stale/default ones. Without this, two
    /// near-simultaneous admin POSTs (e.g. two quick clicks in the web UI)
    /// can persist to disk in the opposite order from the order their
    /// in-memory writes landed, leaving the on-disk file not matching the
    /// live settings. **Invariant: `persist_lock` is always acquired before
    /// `runtime`/`cache`/`geoip_countries`, never after.**
    /// **`apply_admin_reset` also takes this lock (T-153) across its whole
    /// load-then-commit sequence** — reset writes `runtime`, `cache`, *and*
    /// `geoip_countries` in memory after reading the same file this lock
    /// guards, so without it a concurrent admin POST could commit its own
    /// disk write between reset's read and reset's memory-write, leaving
    /// memory holding stale values while disk holds the new ones until
    /// restart (the same class of bug `overrides_persist_lock` below already
    /// exists to prevent for `overrides.toml`, now true here too because
    /// reset writes multiple in-memory fields sharing one on-disk file). No
    /// deadlock
    /// risk from `apply_admin_reset` holding both `persist_lock` and
    /// `overrides_persist_lock` at once: it is the only function that ever
    /// holds both, always acquired in the same order, and no other function
    /// holds either concurrently with the other.
    persist_lock: Mutex<()>,
    /// Same purpose as `persist_lock`, for `POST /admin/overrides/add`/
    /// `remove` (T-47) — a **separate** lock, not a shared one:
    /// `overrides.toml`/`resolver_config.toml` are independent resources
    /// with independent files, and sharing one lock would make an override
    /// edit block behind an unrelated config toggle (or vice versa) for no
    /// reason. Same invariant: always acquired before `overrides`'s own
    /// `RwLock`, never after. **Unlike `persist_lock`, `apply_admin_reset`
    /// *does* take this one** (advisor-caught before commit) — reset's new
    /// `OverrideLists` comes from disk, not from a read of `state.overrides`,
    /// but its write to that field still races a concurrent add/remove's own
    /// read-modify-write unless both go through the same lock; `persist_lock`
    /// has no equivalent concern because reset never writes
    /// `resolver_config.toml` back to disk, only `state.runtime` in memory.
    overrides_persist_lock: Mutex<()>,
    /// Orders the *read-decide-write* of `geoip_source` + `maxmind_health`
    /// across its three writers — `apply_admin_reset` and the two
    /// `/admin/geoip/maxmind[/clear]` routes (T-163). Each reads the stored
    /// credentials, decides the new `GeoipSource`, then calls
    /// `update_geoip_source`; without this lock two near-simultaneous edits
    /// (a `/reset` racing a `/maxmind` POST — "two quick clicks") can commit
    /// in the opposite order from their reads, leaving the credential store
    /// holding a key while the live source is DB-IP Lite until the next
    /// reset/restart — the same live-vs-stored divergence class
    /// `persist_lock` / `overrides_persist_lock` guard for their own files
    /// (T-57 / T-139 / T-149 / T-47 / T-77). A **separate** lock, not
    /// `persist_lock`: the credentials aren't in `resolver_config.toml`, and
    /// sharing would make a key edit block behind an unrelated config save.
    /// Acquired **outermost** — before `persist_lock` in `apply_admin_reset`
    /// (which is the only function that holds it alongside the other two);
    /// the maxmind routes hold only this one. Never held across an `.await`
    /// (the routes drop it before the credential probe).
    geoip_source_lock: Mutex<()>,
}

impl<C: DohClient + Sync> AppState<C> {
    /// Builds the shared per-service state `serve` reads from on every
    /// request. `runtime`'s two fields (T-52) are the admin channel's
    /// live-mutable settings — passed as plain values here and wrapped in
    /// the internal lock by this constructor, so existing call sites barely
    /// change shape even though the storage underneath now supports live
    /// updates. `overrides` is likewise wrapped (`RwLock<Arc<_>>`, T-149) so
    /// `/admin/reset` can swap the whole list atomically without forcing
    /// every per-query read to clone it — taken as one [`OverridesState`]
    /// (T-47), not two separate parameters, so that swap stays atomic across
    /// both fields (not just the parsed list) and this constructor stays
    /// under `clippy::too_many_arguments`. `cache` is taken as one
    /// [`CacheState`] (T-153) for the same reason — a cache-config change
    /// can only ever be applied by rebuilding the whole `Cache` instance
    /// alongside its config, never one field alone (see [`CacheState`]'s own
    /// doc comment).
    #[must_use]
    pub fn new(
        client: C,
        overrides: OverridesState,
        runtime: RuntimeInit,
        cache: CacheState,
        geoip: GeoipInit,
        query_log: QueryLog,
        persist: PersistTarget,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        // T-163: a MaxMind source starts `Pending` (no background refresh has
        // run yet); DB-IP Lite is `NotApplicable`.
        let initial_health = match &geoip.source {
            GeoipSource::Maxmind(_) => MaxmindHealth::Pending,
            GeoipSource::DbIpLite => MaxmindHealth::NotApplicable,
        };
        Self {
            client,
            overrides: RwLock::new(Arc::new(overrides)),
            runtime: RwLock::new(RuntimeSettings {
                timeout: runtime.timeout,
                serve_baseline_when_filters_unreachable: runtime
                    .serve_baseline_when_filters_unreachable,
            }),
            providers: RwLock::new(Arc::new(runtime.providers)),
            cache: RwLock::new(Arc::new(cache)),
            geoip: RwLock::new(Arc::new(geoip.database)),
            geoip_countries: RwLock::new(Arc::new(geoip.blocked_countries)),
            geoip_source: RwLock::new(Arc::new(geoip.source)),
            geoip_refresh_wake: Arc::new(Notify::new()),
            maxmind_health: RwLock::new(Arc::new(initial_health)),
            baseline: RwLock::new(Arc::new(BaselineSelector::new())),
            reachability: RwLock::new(NetworkReachability::default()),
            query_log,
            persist,
            in_flight: AtomicU64::new(0),
            shutdown_tx,
            persist_lock: Mutex::new(()),
            overrides_persist_lock: Mutex::new(()),
            geoip_source_lock: Mutex::new(()),
        }
    }

    /// Swaps in a newly-downloaded `GeoIP` database (T-75) — called only by
    /// `geoip_updater::run_geoip_updater` after the new database has
    /// already been validated and durably written to disk. Never called
    /// with `reader: None` to represent a failed refresh: a failed refresh
    /// simply doesn't call this at all, leaving the last-known-good
    /// database (if any) in place (see `geoip_updater`'s own module doc
    /// comment for the reasoning). Never touches `geoip_countries` — see
    /// that field's own doc comment.
    pub(crate) fn update_geoip(&self, new: GeoipState) {
        *self.geoip.write() = Arc::new(new);
    }

    /// Swaps in a new `GeoIP` blocked-country list — called by
    /// `apply_admin_reset` after a successful `resolver_config.toml` reload
    /// (T-76), and by `apply_geoip_change` after a live add/remove (T-77) —
    /// the single writer of `geoip_countries` both call sites share, rather
    /// than either writing the `RwLock` directly. Never touches `geoip`
    /// (the loaded database) — see that field's own doc comment.
    pub(crate) fn update_geoip_countries(&self, blocked_countries: Vec<String>) {
        *self.geoip_countries.write() = Arc::new(blocked_countries);
    }

    /// A snapshot of the current `GeoIP` database source (T-163) —
    /// `run_geoip_updater` calls this at the top of every cycle so a
    /// runtime credentials change is picked up without a restart.
    pub(crate) fn geoip_source_snapshot(&self) -> Arc<GeoipSource> {
        Arc::clone(&self.geoip_source.read())
    }

    /// Swaps in a new `GeoIP` database source (T-163) — the single writer
    /// `apply_admin_reset` and the `/admin/geoip/maxmind[/clear]` routes
    /// share. Callers pair this with [`Self::wake_geoip_refresh`] so the
    /// background updater acts on the change immediately. Also resets the
    /// `MaxMind` health signal: a fresh `Maxmind` source is `Pending` (the
    /// woken refresh's outcome resolves it), a `DbIpLite` source is
    /// `NotApplicable`.
    pub(crate) fn update_geoip_source(&self, source: GeoipSource) {
        let health = match &source {
            GeoipSource::Maxmind(_) => MaxmindHealth::Pending,
            GeoipSource::DbIpLite => MaxmindHealth::NotApplicable,
        };
        *self.geoip_source.write() = Arc::new(source);
        self.update_maxmind_health(health);
    }

    /// A snapshot of the current `MaxMind` credential-health signal (T-163) —
    /// read by `maxmind_view` for the `/admin/ui` card.
    pub(crate) fn maxmind_health_snapshot(&self) -> MaxmindHealth {
        **self.maxmind_health.read()
    }

    /// Sets the `MaxMind` health signal (T-163) — written by
    /// `run_geoip_updater` after each refresh and by [`Self::update_geoip_source`]
    /// on a source change.
    pub(crate) fn update_maxmind_health(&self, health: MaxmindHealth) {
        *self.maxmind_health.write() = Arc::new(health);
    }

    /// Publishes the latest network-reachability verdict (T-152) — the sole
    /// writer is `run_reachability_prober`.
    pub(crate) fn update_reachability(&self, reachability: NetworkReachability) {
        *self.reachability.write() = reachability;
    }

    /// The current network-reachability verdict (T-152) — read once per
    /// query by `resolve_doh_request`, never held across `.await`.
    pub(crate) fn reachability_snapshot(&self) -> NetworkReachability {
        *self.reachability.read()
    }

    /// One `Arc::clone` snapshot of the baseline selector (T-154) — the hot
    /// path reads `current()` off it; the reachability prober both reads and
    /// (via [`Self::update_baseline`]) writes it.
    pub(crate) fn baseline_snapshot(&self) -> Arc<BaselineSelector> {
        Arc::clone(&self.baseline.read())
    }

    /// Swaps in a baseline selector the reachability prober advanced after a
    /// failover / recovery (T-154). Sole writer.
    pub(crate) fn update_baseline(&self, selector: Arc<BaselineSelector>) {
        *self.baseline.write() = selector;
    }

    /// The live `DoH` client (T-154) — the reachability prober reuses it for
    /// its baseline health probe rather than encoding a `DoH` GET by hand.
    pub(crate) fn doh_client(&self) -> &C {
        &self.client
    }

    /// Wakes `run_geoip_updater` out of its inter-cycle sleep (T-163). Safe
    /// to call with no updater running (e.g. no app-data dir) — the permit is
    /// simply never consumed.
    pub(crate) fn wake_geoip_refresh(&self) {
        self.geoip_refresh_wake.notify_one();
    }

    /// The wake handle `run_geoip_updater` parks on (T-163) — taken once
    /// before its loop.
    pub(crate) fn geoip_refresh_wake_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.geoip_refresh_wake)
    }

    /// Swaps in a new configured voter list (T-72/T-73) — the single writer
    /// `apply_provider_change` (the `/admin/providers/*` routes) and
    /// `apply_admin_reset` both go through, rather than writing the `RwLock`
    /// directly.
    pub(crate) fn update_providers(&self, providers: Vec<ProviderEntry>) {
        *self.providers.write() = Arc::new(providers);
    }

    /// A snapshot of the configured voter list, for a handler that needs to
    /// read-modify-write it or re-serialize it to disk.
    pub(crate) fn providers_snapshot(&self) -> Vec<ProviderEntry> {
        self.providers.read().as_ref().clone()
    }

    /// Subscribes a new receiver for the shutdown signal (T-149) — each call
    /// returns an independent [`watch::Receiver`] starting from the current
    /// value, per `watch::Sender::subscribe`'s own semantics. `main.rs` calls
    /// this exactly once at startup and holds the result for the lifetime of
    /// the accept loop.
    #[must_use]
    pub fn shutdown_handle(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// The current query-log contents, age-bounded to `now` (T-146) — the
    /// snapshot `log_persist::run_query_log_persister` seals to
    /// `query-log.enc`. A thin pass-through to [`crate::query_log::QueryLog::snapshot`]
    /// so the field itself stays private to this module.
    #[must_use]
    pub fn query_log_snapshot(&self, now: SystemTime) -> Vec<LogEntry> {
        self.query_log.snapshot(now)
    }

    /// A point-in-time copy of the live quorum-verdict cache (T-97) — the
    /// snapshot `cache_persist::run_cache_persister` seals to `cache.enc`.
    /// `Arc::clone`s the current [`CacheState`] and drops the lock before
    /// returning; the scan itself is synchronous, no lock held across the
    /// caller's `.await`.
    #[must_use]
    pub fn cache_snapshot(&self) -> Vec<(CacheKey, CacheEntry)> {
        Arc::clone(&self.cache.read()).cache.snapshot()
    }

    /// Re-seeds the live cache from a persisted `cache.enc` snapshot (T-97),
    /// once at startup before the listener accepts traffic. `Arc::clone`s the
    /// current [`CacheState`] and releases the lock before the `.await`, the
    /// same discipline as every other `AppState` reader.
    pub async fn restore_cache(&self, entries: Vec<(CacheKey, CacheEntry)>) {
        let cache_state = Arc::clone(&self.cache.read());
        cache_state.cache.restore(entries).await;
    }
}

/// RAII in-flight counter guard (T-149) — increments on construction,
/// decrements on `Drop`. See [`resolve_doh_request`]'s own comment for why
/// this is RAII and not a manual increment/decrement pair.
struct InFlightGuard<'a> {
    counter: &'a AtomicU64,
}

impl<'a> InFlightGuard<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self { counter }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A fixed-`status`, empty-body response — used for every non-2xx outcome
/// below (`serve` never has a meaningful body to return alongside an error
/// status: RFC 8484 doesn't define one, and the request may not have parsed
/// far enough to have a query ID worth answering). Built via `Response::new`
/// and `status_mut`, not `Response::builder()...body(...)` — the builder
/// path returns a `Result` only because it also handles header/URI
/// validation this function never exercises, so unlike the
/// `resolved`-response builder below (a real `Content-Type` header, worth
/// double-checking), there is no failure mode here to handle at all.
pub(crate) fn status_response(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

/// `duration` rounded down to whole milliseconds, saturating at `u32::MAX`
/// rather than panicking or truncating silently — a per-query timeout will
/// never legitimately be anywhere near that large.
fn timeout_ms(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

/// Reads `watchdog-state.json` (written by `dnsqb-watcher`, SPEC.md §7.1 #7)
/// and projects it to the UI-relevant [`WatchdogStatusView`] for
/// [`AdminStatusResponse::watchdog`]. `None` when the file is absent,
/// unreadable, stale (`now - mtime > WATCHDOG_STATE_STALE_AFTER`), or in a
/// state the indicator doesn't surface. `now` is a parameter for testability —
/// the callers pass `SystemTime::now()`.
///
/// A synchronous sub-KB read on the ~2 s-polled status path. Deliberately not
/// cached: the read is cheap and a cache would add a staleness window of its
/// own (T-160 filing pattern — a small measured cost, recorded not optimised).
fn read_watchdog_view(paths: Option<&PersistPaths>, now: SystemTime) -> Option<WatchdogStatusView> {
    let dir = paths?.app_data_dir();
    let mtime = std::fs::metadata(dir.join(crate::STATE_FILE_NAME))
        .and_then(|meta| meta.modified())
        .ok()?;
    if crate::is_stale(now, mtime, WATCHDOG_STATE_STALE_AFTER) {
        return None;
    }
    match crate::read_watchdog_state(&dir).ok()?.state {
        WatchdogState::Restarting | WatchdogState::BackoffWait => {
            Some(WatchdogStatusView::Restarting)
        }
        WatchdogState::GaveUp => Some(WatchdogStatusView::GaveUp),
        WatchdogState::Healthy
        | WatchdogState::ChannelDegraded
        | WatchdogState::SuspectDead
        | WatchdogState::VerifyingPid => None,
    }
}

/// Builds the current [`AdminStatusResponse`] from `state` — shared by
/// `GET /admin/status` and the response [`apply_admin_config`] echoes back
/// after a `POST /admin/config`. `persisted` is the caller's to state
/// (always `true` for a plain status read, since nothing changed).
fn admin_status<C: DohClient + Sync>(state: &AppState<C>, persisted: bool) -> AdminStatusResponse {
    let settings = *state.runtime.read();
    let entries = state.query_log.snapshot(SystemTime::now());
    AdminStatusResponse {
        active_providers: ProviderStatusView::active_from(&state.providers.read()),
        timeout_mode: settings.timeout.mode,
        timeout_ms: timeout_ms(settings.timeout.duration),
        serve_baseline_when_filters_unreachable: settings.serve_baseline_when_filters_unreachable,
        network: NetworkStatusView::from(state.reachability_snapshot()),
        baseline_endpoint: BaselineEndpointView::from_active_index(
            state.baseline.read().active_index(),
        ),
        port: state.persist.port,
        stats: live_stats(state, &entries),
        watchdog: read_watchdog_view(state.persist.paths.as_ref(), SystemTime::now()),
        persisted,
        encrypted_persistence: EncryptedPersistenceView {
            query_log: state.persist.persist_query_log,
            cache: state.persist.persist_cache,
        },
    }
}

/// [`compute_stats`] plus the live in-flight counter [`compute_stats`]
/// itself has no access to (it only ever sees the log) — the one merge
/// point every [`AdminStatusResponse`] builder below shares (T-149).
fn live_stats<C: DohClient + Sync>(state: &AppState<C>, entries: &[LogEntry]) -> AdminStats {
    AdminStats {
        in_flight: state.in_flight.load(Ordering::Relaxed),
        ..compute_stats(entries)
    }
}

/// Applies `update` to `state`'s live runtime settings (one atomic write —
/// see [`RuntimeSettings`]'s own doc comment for why this is one lock, not
/// two), persists it to `state.persist.config_path` if one is configured,
/// and returns the resulting status. A persistence failure is
/// `tracing::warn!`'d and reflected as `persisted: false` — it never
/// discards the live change that already took effect (T-52 plan: an
/// in-memory update must not be reported as failed just because the disk
/// write was).
///
/// `state.persist_lock` (T-58, shared with the cache-config route since
/// T-153 — see the field's own doc comment) is held for the whole
/// write-then-persist sequence, acquired *before* `runtime`'s own lock — see
/// its own doc comment for why this is what keeps concurrent admin-channel
/// POSTs' disk-write order matching their in-memory-write order, without
/// holding `runtime` itself across the blocking `fs::write`. Also reads
/// `state.cache`'s current config and `state.geoip_countries`'s current list
/// (not just `runtime`) while still holding the lock, so the file this
/// writes reflects both other fields' live values too, not stale/default
/// ones — see `persist_lock`'s own doc comment for why this cross-field read
/// has to happen here (T-76 extended it to `geoip_countries`: without this,
/// an ordinary providers/timeout toggle would silently overwrite a
/// hand-edited `[geoip] blocked_countries` with an empty list on save).
fn apply_admin_config<C: DohClient + Sync>(
    state: &AppState<C>,
    update: AdminConfigUpdate,
) -> AdminStatusResponse {
    // Read the watchdog file *before* taking `persist_lock` — it is a blocking
    // `fs::metadata` + `fs::read` with nothing to do with the config write, and
    // `persist_lock` is the one lock that orders every concurrent admin write.
    let watchdog = read_watchdog_view(state.persist.paths.as_ref(), SystemTime::now());
    let _persist_guard = state.persist_lock.lock();
    // Captured inside the write guard's own scope, not re-read via a second
    // lock acquisition afterward — advisor-caught: re-reading opened a
    // window where a concurrent `POST` could persist *its* values under
    // *this* request's response, however unlikely with a single local UI
    // client. This way the values persisted/echoed are provably the exact
    // ones just written, not "whatever the lock currently holds."
    let settings = {
        let mut guard = state.runtime.write();
        guard.timeout.mode = update.timeout_mode;
        guard.serve_baseline_when_filters_unreachable =
            update.serve_baseline_when_filters_unreachable;
        *guard
    };
    let cache_config = state.cache.read().config;
    let blocked_countries = state.geoip_countries.read().as_ref().clone();
    // Cross-field read (T-72/T-73): the voter list is edited by
    // `/admin/providers/*`, not here, but this write re-serializes the whole
    // `resolver_config.toml`, so it must carry the list's live value too or
    // an unrelated timeout toggle would blank `[[providers]]` on save.
    let providers = state.providers_snapshot();
    let persisted = match state.persist.paths.as_ref() {
        Some(paths) => {
            let config = ResolverConfig {
                port: state.persist.port,
                timeout_mode: settings.timeout.mode,
                timeout_ms: timeout_ms(settings.timeout.duration),
                providers,
                cache: cache_config,
                geoip: GeoipConfig { blocked_countries },
                // T-155: `settings` already reflects `update`'s value (set
                // in the write guard above), so this persists the new toggle
                // alongside the timeout mode in one write.
                serve_baseline_when_filters_unreachable: settings
                    .serve_baseline_when_filters_unreachable,
                // T-146 cross-field read: not admin-mutable, but this write
                // rewrites the whole file so it must carry the live value.
                persist_query_log: state.persist.persist_query_log,
                persist_cache: state.persist.persist_cache,
            };
            match config.save(&paths.config) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!("failed to persist an admin config change to disk: {err}");
                    false
                }
            }
        }
        None => false,
    };
    AdminStatusResponse {
        active_providers: ProviderStatusView::active_from(&state.providers.read()),
        timeout_mode: settings.timeout.mode,
        timeout_ms: timeout_ms(settings.timeout.duration),
        serve_baseline_when_filters_unreachable: settings.serve_baseline_when_filters_unreachable,
        network: NetworkStatusView::from(state.reachability_snapshot()),
        baseline_endpoint: BaselineEndpointView::from_active_index(
            state.baseline.read().active_index(),
        ),
        port: state.persist.port,
        stats: live_stats(state, &state.query_log.snapshot(SystemTime::now())),
        watchdog,
        persisted,
        encrypted_persistence: EncryptedPersistenceView {
            query_log: state.persist.persist_query_log,
            cache: state.persist.persist_cache,
        },
    }
}

/// A `200 OK` JSON response, or `500` if `value` somehow fails to serialize
/// (not expected for these DTOs — no non-representable floats, no map keys
/// — but `serde_json::to_vec` returns a real `Result`, so this handles it
/// rather than unwrapping, same discipline as `config::ResolverConfig::save`).
fn json_response<T: Serialize>(value: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(bytes)))
            .unwrap_or_else(|_| status_response(StatusCode::INTERNAL_SERVER_ERROR)),
        Err(_) => status_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// `GET /admin/status` — method allowlisting for this path happens once,
/// centrally, in [`serve`]'s `ROUTES` check before this is ever called; this
/// function itself trusts that and doesn't re-check.
fn serve_admin_status<C: DohClient + Sync>(state: &AppState<C>) -> Response<Full<Bytes>> {
    json_response(&admin_status(state, true))
}

/// `GET /health` — watchdog channel 3 (T-86, SPEC.md §7.1 #4/#10). Method
/// allowlisting happens centrally in [`serve`]'s `ROUTES` check. Deeper than
/// "the process exists" but makes **no** upstream call: it runs the local
/// pipeline prefix (override lookup + cache lookup) for a sentinel domain —
/// proving that code path executes and no writer is holding a lock — then
/// reports the assembled pipeline state. The health signal is the 200 itself;
/// the body is informational (SPEC.md §3: `0` active providers is legal).
async fn serve_health<C: DohClient + Sync>(state: &AppState<C>) -> Response<Full<Bytes>> {
    let overrides_state = Arc::clone(&state.overrides.read());
    // Discarded — running it is the check, not the answer. Local, no network.
    let _ = overrides_state.lists.decision(HEALTH_SENTINEL_DOMAIN);

    if let Ok(key) = CacheKey::new(HEALTH_SENTINEL_DOMAIN, RecordType::A) {
        let cache_state = Arc::clone(&state.cache.read());
        // `moka::future::Cache::get` — a local map lookup, no network.
        let _ = cache_state.cache.get(&key).await;
    }

    let active_providers = state
        .providers
        .read()
        .iter()
        .filter(|entry| entry.enabled)
        .count();
    let geoip = if state.geoip.read().reader.is_some() {
        HealthGeoip::Loaded
    } else {
        HealthGeoip::Absent
    };
    json_response(&HealthResponse {
        active_providers,
        geoip,
    })
}

/// `POST /admin/config` — method allowlisting happens centrally in
/// [`serve`]'s `ROUTES` check, not re-checked here; a body that exceeds
/// [`MAX_ADMIN_BODY_SIZE`], fails to read, or doesn't decode as
/// [`AdminConfigUpdate`] is 400.
async fn serve_admin_config<C, B>(req: Request<B>, state: &AppState<C>) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // See `content_type_is_json`'s own doc comment - this is not a format
    // nicety, it's the whole CSRF defense for this route.
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    let Ok(collected) = limited.collect().await else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    let Ok(update) = serde_json::from_slice::<AdminConfigUpdate>(&collected.to_bytes()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    json_response(&apply_admin_config(state, update))
}

/// Errors reloading state from disk for `POST /admin/reset` (T-149).
#[derive(Debug, thiserror::Error)]
enum AdminResetError {
    /// No app-data directory was resolved at startup — nothing to reload
    /// from (same condition [`PersistTarget::paths`] being `None` already
    /// means for persisting an admin config change).
    #[error("no app-data directory available to reload from")]
    NoAppData,
    /// `resolver_config.toml` failed to reload.
    #[error("failed to reload resolver_config.toml: {0}")]
    Config(#[source] crate::config::ConfigError),
    /// `overrides.toml` failed to reload.
    #[error("failed to reload overrides.toml: {0}")]
    Overrides(#[source] OverrideError),
}

/// Soft-resets `state` (T-149): reloads both TOML files from disk into
/// local values first, and only swaps them into the live state once *both*
/// succeed (prepare-then-commit — same discipline as T-50's cert TOCTOU
/// fix) — a malformed file on disk must never leave `state` half-updated.
///
/// Overrides are swapped **before** the cache is cleared, not after — the
/// reverse order leaves a window where a query racing this reset could
/// repopulate the cache from the *old* overrides between the clear and the
/// swap; swap-then-clear can't produce that.
///
/// **`state.overrides_persist_lock` is held for the whole reload-then-commit
/// sequence (T-47, advisor-caught before commit)** — reset's new value comes
/// from disk, not from a read of `state.overrides`, but the lock still has
/// to cover this function's own write to that field: without it, a
/// concurrent `POST /admin/overrides/add` could read the *pre-reset*
/// `OverrideLists` as its `before`, then swap in `pre-reset-base +
/// new-entry` after reset already committed a freshly-loaded list — silently
/// discarding the reset the user just asked for (the same lost-update shape
/// [`apply_overrides_change`] itself guards against between two adds, just
/// between this route and that one).
///
/// **`state.persist_lock` is also held for this same sequence (T-153,
/// advisor-caught before commit — the mirror-image gap of the catch above,
/// one field over)** — reset now writes both `state.runtime` and
/// `state.cache` in memory from a `resolver_config.toml` read, and
/// `persist_lock` is what orders every other writer of that same file
/// (`apply_admin_config`, the new cache-config route). Without it: reset
/// reads the file, then (gap) a concurrent admin POST commits its own
/// memory-write and disk-write under `persist_lock`, then reset's own
/// memory-write lands *after* — leaving memory holding reset's stale values
/// while disk holds the concurrent POST's new ones, diverged until restart.
///
/// **`state.geoip_source_lock` is held outermost (T-163 closing review)** —
/// across the credential re-read → `update_geoip_source`, so a concurrent
/// `/admin/geoip/maxmind[/clear]` POST can't commit its own source change in
/// the gap. Acquisition order is always `geoip_source_lock` → `persist_lock`
/// → `overrides_persist_lock`; `apply_admin_reset` is the only holder of all
/// three, the maxmind routes hold only `geoip_source_lock`, and no other
/// function holds any of them concurrently with another — so no deadlock.
fn apply_admin_reset<C: DohClient + Sync>(
    state: &AppState<C>,
) -> Result<AdminStatusResponse, AdminResetError> {
    let paths = state
        .persist
        .paths
        .as_ref()
        .ok_or(AdminResetError::NoAppData)?;
    // T-163: `geoip_source_lock` is acquired **outermost** and held across
    // this whole function's read-of-credentials → `update_geoip_source`, so a
    // concurrent `/admin/geoip/maxmind[/clear]` POST can't commit its own
    // source change in the gap between reset's read and reset's write (which
    // would leave the store holding a key while the live source is DB-IP Lite
    // until the next reset/restart). The credential read itself is a
    // synchronous Credential Manager round-trip and stays **outside**
    // `persist_lock` — the source isn't part of the `resolver_config.toml`
    // cross-field-read invariant that lock protects.
    let _geoip_source_guard = state.geoip_source_lock.lock();
    let geoip_source = match geoip_credentials::load(&paths.app_data_dir()) {
        Ok(Some(creds)) => GeoipSource::Maxmind(creds),
        Ok(None) => GeoipSource::DbIpLite,
        Err(err) => {
            tracing::warn!(
                "MaxMind credentials reload failed on reset ({err}), keeping the current GeoIP source"
            );
            state.geoip_source_snapshot().as_ref().clone()
        }
    };
    let _persist_guard = state.persist_lock.lock();
    let _overrides_persist_guard = state.overrides_persist_lock.lock();
    let config = ResolverConfig::load(&paths.config).map_err(AdminResetError::Config)?;
    let (overrides, invalid) =
        OverrideLists::load(&paths.overrides).map_err(AdminResetError::Overrides)?;
    if !invalid.is_empty() {
        // Not dropped (T-47) - kept in `OverridesState.invalid` below so a
        // later `save()` (triggered by an unrelated admin-channel edit)
        // writes these raw lines back verbatim instead of silently losing
        // them. Still warned here - the operator should know a line in the
        // file they just asked to reload from didn't parse.
        tracing::warn!(
            "{} override-list entr{} rejected as invalid on reset, kept for the next save",
            invalid.len(),
            if invalid.len() == 1 { "y" } else { "ies" }
        );
    }
    if config.port != state.persist.port {
        // Live-apply only, never a rebind - the same "port isn't
        // admin-mutable" boundary `PersistTarget::port`'s own doc comment
        // already states, just reachable here from a different direction
        // (the file changed under the running service, not an admin POST).
        tracing::warn!(
            "resolver_config.toml's port ({}) differs from the running listener's port ({}) - \
             /admin/reset never rebinds, ignored",
            config.port,
            state.persist.port
        );
    }
    *state.runtime.write() = RuntimeSettings {
        timeout: TimeoutConfig {
            mode: config.timeout_mode,
            duration: Duration::from_millis(config.timeout_ms.into()),
        },
        serve_baseline_when_filters_unreachable: config.serve_baseline_when_filters_unreachable,
    };
    // T-72/T-73: reset reloads the `[[providers]]` list too — without this a
    // hand-edited provider list would only take effect at the next process
    // restart (the same completeness gap `overrides`/`cache`/`geoip_countries`
    // above already close).
    state.update_providers(config.providers);
    *state.overrides.write() = Arc::new(OverridesState {
        lists: overrides,
        invalid,
    });
    // A fresh `Cache::new(&config.cache)` swap (T-153), not the plain
    // `Cache::clear()` this used before — strictly safer, not just
    // equivalent: a query racing the old `clear()` could still insert into
    // the live cache in the gap between clearing and the racing query's own
    // insert; a query racing this swap either finishes against the `Arc`-
    // cloned old `CacheState` it already snapshotted (simply dropped once
    // unreferenced) or observes the new one, never a torn mix. Rebuilding
    // unconditionally (even when `config.cache` didn't actually change) is
    // simpler than branching on whether it did, for no real cost — reset is
    // already a full state reload, not a per-query hot path.
    *state.cache.write() = Arc::new(CacheState {
        cache: Cache::new(&config.cache),
        config: config.cache,
    });
    // T-76: reset reloads resolver_config.toml's whole [geoip] table too -
    // without this, a hand-edited blocked-country list would only take
    // effect at the next process restart, not on the very next reset (the
    // same completeness gap `overrides`/`cache` above already close).
    state.update_geoip_countries(config.geoip.blocked_countries);
    // T-163: apply the credentials re-read from the top of this function and
    // wake the background updater so a source change takes effect now, not at
    // the next 24h check or a restart.
    state.update_geoip_source(geoip_source);
    state.wake_geoip_refresh();
    state.query_log.clear();
    // `persisted: true` is correct here in its documented, admin-mutable-
    // subset sense (providers/timeout) even when `config.port` differed
    // above - `port` was never part of that promise (see
    // `apply_admin_config`'s own `persisted` handling, which never
    // considers port either).
    Ok(admin_status(state, true))
}

/// `POST /admin/reset` (T-149) — method allowlisting happens centrally in
/// [`serve`]'s `ROUTES` check, not re-checked here. Same CSRF gate and
/// body-size cap as `/admin/config`. A malformed/missing on-disk file is 500
/// (the caller didn't cause it); everything else about the request shape is
/// 400, same convention as every other route here.
async fn serve_admin_reset<C, B>(req: Request<B>, state: &AppState<C>) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    if limited.collect().await.is_err() {
        return status_response(StatusCode::BAD_REQUEST);
    }
    match apply_admin_reset(state) {
        Ok(response) => json_response(&response),
        Err(err) => {
            tracing::warn!("admin reset failed: {err}");
            status_response(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Builds the current [`OverrideListsResponse`] from `overrides` (T-47) —
/// shared by `GET /admin/overrides` and the response the two mutating routes
/// below echo back after applying a change, same "always return the fresh
/// live state" shape as [`admin_status`]. `persisted` is the caller's to
/// state, same convention as `admin_status`'s own parameter — always `true`
/// for a plain `GET` (nothing changed, so nothing could fail to persist).
fn overrides_view(overrides: &OverrideLists, persisted: bool) -> OverrideListsResponse {
    let view_of = |list: ListKind| {
        overrides
            .entries()
            .iter()
            .filter(|entry| entry.list == list)
            .map(|entry| OverrideDomainView {
                domain: entry.domain.clone(),
                is_wildcard: entry.is_wildcard,
            })
            .collect()
    };
    OverrideListsResponse {
        allowlist: view_of(ListKind::Allowlist),
        blocklist: view_of(ListKind::Blocklist),
        conflicts: overrides
            .conflicts()
            .into_iter()
            .map(str::to_string)
            .collect(),
        persisted,
    }
}

/// `GET /admin/overrides` (T-47) — method allowlisting happens centrally in
/// [`serve`]'s `ROUTES` check, not re-checked here. Read-only, no CSRF gate
/// needed (same as `GET /admin/status`).
fn serve_admin_overrides<C: DohClient + Sync>(state: &AppState<C>) -> Response<Full<Bytes>> {
    json_response(&overrides_view(&state.overrides.read().lists, true))
}

/// Applies `compute_new` to `state`'s live override lists (T-47) and returns
/// the fresh view — shared by `POST /admin/overrides/add` and `POST
/// /admin/overrides/remove`, which differ only in how the new list is
/// computed. `state.overrides_persist_lock` is held for the whole
/// swap-then-persist sequence, acquired *before* `overrides`'s own lock —
/// same reasoning as [`apply_admin_config`]'s `persist_lock`. [`apply_admin_reset`]
/// takes the same lock across its own swap of this field, so the two routes
/// can never interleave their reads and writes of `state.overrides` (see
/// that function's own doc comment).
///
/// Swap-then-invalidate, not the reverse — same reasoning
/// [`apply_admin_reset`]'s own doc comment already states: a query racing
/// this change must never repopulate the cache from the stale list in a gap
/// between clearing and swapping.
///
/// `after` is built locally and never re-read from `state.overrides`
/// (advisor-caught before commit) — a re-read after releasing the write
/// guard would only coincidentally match what this call just computed; under
/// the lock it's redundant, and without it (if a future writer ever touched
/// `state.overrides` without taking `overrides_persist_lock`) it would let
/// `invalidate_changed`/`save`/the returned view silently operate on a value
/// this request never produced — same class of bug T-52's own
/// `apply_admin_config` already fixed once for `runtime`.
fn apply_overrides_change<C: DohClient + Sync>(
    state: &AppState<C>,
    compute_new: impl FnOnce(&OverrideLists) -> Result<OverrideLists, InvalidReason>,
) -> Result<OverrideListsResponse, InvalidReason> {
    let _persist_guard = state.overrides_persist_lock.lock();
    let before = Arc::clone(&state.overrides.read());
    let new_lists = compute_new(&before.lists)?;
    let after = Arc::new(OverridesState {
        lists: new_lists,
        invalid: before.invalid.clone(),
    });
    *state.overrides.write() = Arc::clone(&after);
    invalidate_changed(&state.cache.read().cache, &before.lists, &after.lists);
    let persisted = match state.persist.paths.as_ref() {
        Some(paths) => match after.lists.save(&paths.overrides, &after.invalid) {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!("failed to persist an admin override-list change to disk: {err}");
                false
            }
        },
        None => false,
    };
    Ok(overrides_view(&after.lists, persisted))
}

/// `POST /admin/overrides/add` (T-47) — method allowlisting happens
/// centrally in [`serve`]'s `ROUTES` check, not re-checked here. Same CSRF
/// gate and body-size cap as `/admin/config`. An unparseable `pattern` is
/// `400`; the add itself is idempotent
/// (see [`OverrideLists::with_entry_added`]).
async fn serve_admin_overrides_add<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    let Ok(collected) = limited.collect().await else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    let Ok(request) = serde_json::from_slice::<OverrideAddRequest>(&collected.to_bytes()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    match apply_overrides_change(state, |current| {
        current.with_entry_added(&request.pattern, request.list)
    }) {
        Ok(response) => json_response(&response),
        Err(_) => status_response(StatusCode::BAD_REQUEST),
    }
}

/// `POST /admin/overrides/remove` (T-47) — method allowlisting happens
/// centrally in [`serve`]'s `ROUTES` check, not re-checked here. Same CSRF
/// gate and body-size cap as `/admin/config`. Removal is infallible
/// (see [`OverrideLists::with_entry_removed`]) — the `Err` arm below is
/// structurally unreachable for this call site, kept only because
/// [`apply_overrides_change`]'s signature is shared with the add route.
async fn serve_admin_overrides_remove<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    let Ok(collected) = limited.collect().await else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    let Ok(request) = serde_json::from_slice::<OverrideRemoveRequest>(&collected.to_bytes()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    match apply_overrides_change(state, |current| {
        Ok(current.with_entry_removed(&request.domain, request.is_wildcard, request.list))
    }) {
        Ok(response) => json_response(&response),
        Err(_) => status_response(StatusCode::BAD_REQUEST),
    }
}

/// `GET /admin/cache-config` (T-153) — method allowlisting happens centrally
/// in [`serve`]'s `ROUTES` check, not re-checked here. Read-only, no CSRF
/// gate needed (same as `GET /admin/status`/`/admin/overrides`).
fn serve_admin_cache_config<C: DohClient + Sync>(state: &AppState<C>) -> Response<Full<Bytes>> {
    json_response(&CacheConfigView::from_config(
        &state.cache.read().config,
        true,
    ))
}

/// Applies `update` to `state`'s live cache config (T-153): validates,
/// rebuilds the whole `Cache` (see [`CacheState`]'s own doc comment for why
/// a config change can't be applied to an existing `moka::Cache` in place),
/// swaps it in, persists to `state.persist.paths.config` if configured, and
/// returns the resulting view.
///
/// `state.persist_lock` is held for the whole validate-swap-persist
/// sequence, acquired *before* `cache`'s own lock — same shared-file
/// reasoning as [`apply_admin_config`], see `persist_lock`'s own doc
/// comment. Also reads `state.runtime`'s current settings and
/// `state.geoip_countries`'s current list (not just `cache`) while still
/// holding the lock, so the file this writes reflects all of their live
/// values too, not stale/default ones — same cross-field-read requirement
/// `apply_admin_config` has in the other direction (T-76 extended it here
/// too, same reasoning as that function's own doc comment).
fn apply_cache_config<C: DohClient + Sync>(
    state: &AppState<C>,
    update: CacheConfigUpdate,
) -> Result<CacheConfigView, CacheConfigError> {
    let _persist_guard = state.persist_lock.lock();
    let new_config = update.into_config()?;
    *state.cache.write() = Arc::new(CacheState {
        cache: Cache::new(&new_config),
        config: new_config,
    });
    let runtime = *state.runtime.read();
    let blocked_countries = state.geoip_countries.read().as_ref().clone();
    let providers = state.providers_snapshot();
    let persisted = match state.persist.paths.as_ref() {
        Some(paths) => {
            let config = ResolverConfig {
                port: state.persist.port,
                timeout_mode: runtime.timeout.mode,
                timeout_ms: timeout_ms(runtime.timeout.duration),
                serve_baseline_when_filters_unreachable: runtime
                    .serve_baseline_when_filters_unreachable,
                // T-146 cross-field read: not admin-mutable, but this write
                // rewrites the whole file so it must carry the live value.
                persist_query_log: state.persist.persist_query_log,
                persist_cache: state.persist.persist_cache,
                providers,
                cache: new_config,
                geoip: GeoipConfig { blocked_countries },
            };
            match config.save(&paths.config) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!("failed to persist an admin cache-config change to disk: {err}");
                    false
                }
            }
        }
        None => false,
    };
    Ok(CacheConfigView::from_config(&new_config, persisted))
}

/// `POST /admin/cache-config/apply` (T-153) — method allowlisting happens
/// centrally in [`serve`]'s `ROUTES` check, not re-checked here. Same CSRF
/// gate and body-size cap as `/admin/config`. A `clamp_min_secs >
/// clamp_max_secs` update is `400` (see [`CacheConfigUpdate::into_config`]).
async fn serve_admin_cache_config_apply<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    let Ok(collected) = limited.collect().await else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    let Ok(update) = serde_json::from_slice::<CacheConfigUpdate>(&collected.to_bytes()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    match apply_cache_config(state, update) {
        Ok(response) => json_response(&response),
        Err(_) => status_response(StatusCode::BAD_REQUEST),
    }
}

/// Shared view builder for `GET /admin/geoip` and the two mutating routes
/// below (T-77/T-78) — same "always return the fresh live state" shape as
/// [`overrides_view`]/[`CacheConfigView::from_config`]. `database` is read
/// fresh by each caller (never cached in this function) so
/// `database_loaded`/`database_built_at_ms` reflect the live
/// `GeoipState`, not a snapshot from whenever the list last changed — a
/// database refresh (`geoip_updater`) and a country-list edit are two
/// independent swaps (see `AppState::geoip`'s own doc comment) that can
/// interleave in either order.
fn geoip_view(
    blocked_countries: &[String],
    persisted: bool,
    database: &GeoipState,
) -> GeoipCountriesResponse {
    GeoipCountriesResponse {
        blocked_countries: blocked_countries.to_vec(),
        persisted,
        database_loaded: database.reader.is_some(),
        database_built_at_ms: database.updated_at.map(unix_millis),
        // Classified from the loaded reader's own metadata, never from the
        // configured `GeoipSource` (T-162) — those diverge exactly when
        // MaxMind credentials are set but rejected and the live file is still
        // DB-IP Lite.
        database_source: database
            .reader
            .as_deref()
            .map(|reader| DatabaseSource::classify(reader.database_type())),
    }
}

/// `GET /admin/geoip` (T-77) — method allowlisting happens centrally in
/// [`serve`]'s `ROUTES` check, not re-checked here. Read-only, no CSRF gate
/// needed (same as `GET /admin/status`/`/admin/overrides`/`/admin/cache-config`).
fn serve_admin_geoip<C: DohClient + Sync>(state: &AppState<C>) -> Response<Full<Bytes>> {
    json_response(&geoip_view(
        &state.geoip_countries.read(),
        true,
        &state.geoip.read(),
    ))
}

/// Applies `compute_new` to `state`'s live `GeoIP` blocked-country list
/// (T-77) and returns the fresh view — shared by `POST /admin/geoip/add`/
/// `remove`, which differ only in how the new list is computed.
///
/// `state.persist_lock` is held for the whole swap-then-persist sequence —
/// **shared with `POST /admin/config`/`POST /admin/cache-config/apply`, not
/// an independent lock**, because all three write into the same
/// `resolver_config.toml` (see `persist_lock`'s own doc comment). Also
/// reads `state.runtime`'s current settings and `state.cache`'s current
/// config (not just `geoip_countries`) while still holding the lock, so the
/// file this writes reflects all three fields' live values, not
/// stale/default ones — the same cross-field-read requirement
/// `apply_admin_config`/`apply_cache_config` already apply in the other two
/// directions. Also reads `state.geoip` (T-78) for the returned view's
/// `database_loaded`/`database_built_at_ms` — that field is never written
/// here (only `geoip_updater` swaps it after a database refresh), so this
/// read needs no lock ordering against `persist_lock`, just a fresh
/// snapshot for the response.
///
/// **No cache-invalidation call here, unlike [`apply_overrides_change`]** —
/// a `GeoIP` verdict is never cached (SPEC.md §3.5's own stated reason: it's
/// applied live on every read, cached or fresh, specifically so a
/// country-list change takes effect on the very next lookup with no
/// invalidation logic at all). Swaps via [`AppState::update_geoip_countries`],
/// the single writer this field shares with `apply_admin_reset`, rather
/// than writing the `RwLock` directly.
///
/// `after` is built locally by `compute_new` and never re-read from
/// `state.geoip_countries` — same "provably the exact value just written,
/// not whatever the lock currently holds" discipline
/// [`apply_overrides_change`]'s own doc comment already states.
fn apply_geoip_change<C: DohClient + Sync>(
    state: &AppState<C>,
    compute_new: impl FnOnce(&[String]) -> Result<Vec<String>, ConfigError>,
) -> Result<GeoipCountriesResponse, ConfigError> {
    let _persist_guard = state.persist_lock.lock();
    let before = state.geoip_countries.read().as_ref().clone();
    let after = compute_new(&before)?;
    state.update_geoip_countries(after.clone());
    let runtime = *state.runtime.read();
    let cache_config = state.cache.read().config;
    let providers = state.providers_snapshot();
    let persisted = match state.persist.paths.as_ref() {
        Some(paths) => {
            let config = ResolverConfig {
                port: state.persist.port,
                timeout_mode: runtime.timeout.mode,
                timeout_ms: timeout_ms(runtime.timeout.duration),
                serve_baseline_when_filters_unreachable: runtime
                    .serve_baseline_when_filters_unreachable,
                // T-146 cross-field read: not admin-mutable, but this write
                // rewrites the whole file so it must carry the live value.
                persist_query_log: state.persist.persist_query_log,
                persist_cache: state.persist.persist_cache,
                providers,
                cache: cache_config,
                geoip: GeoipConfig {
                    blocked_countries: after.clone(),
                },
            };
            match config.save(&paths.config) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!("failed to persist an admin geoip change to disk: {err}");
                    false
                }
            }
        }
        None => false,
    };
    Ok(geoip_view(&after, persisted, &state.geoip.read()))
}

/// `POST /admin/geoip/add` (T-77) — method allowlisting happens centrally
/// in [`serve`]'s `ROUTES` check, not re-checked here. Same CSRF gate and
/// body-size cap as `/admin/overrides/add`. An invalid country code is
/// `400` (see [`validate_country_code`]). Idempotent: adding an
/// already-present code is a no-op, not a duplicate entry (mirrors
/// [`crate::overrides::OverrideLists::with_entry_added`]'s own idempotency).
async fn serve_admin_geoip_add<C, B>(req: Request<B>, state: &AppState<C>) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    let Ok(collected) = limited.collect().await else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    let Ok(request) = serde_json::from_slice::<GeoipCountryRequest>(&collected.to_bytes()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    match apply_geoip_change(state, |current| {
        let code = validate_country_code(&request.country)?;
        let mut new_list = current.to_vec();
        if !new_list.iter().any(|c| c == &code) {
            new_list.push(code);
        }
        Ok(new_list)
    }) {
        Ok(response) => json_response(&response),
        Err(_) => status_response(StatusCode::BAD_REQUEST),
    }
}

/// `POST /admin/geoip/remove` (T-77) — same gates as add. **`country` is
/// validated and normalized the exact same way add's is, not compared
/// as-is** (advisor-caught during this task's own planning): the stored
/// list is always uppercase, so a lowercase or malformed request must be
/// rejected the same way add rejects one, not silently no-op against a
/// case-sensitive match — the same "correct only by an invariant enforced
/// elsewhere" trap `geoip::blocking_country`'s own `eq_ignore_ascii_case`
/// comparison already exists to guard against one layer down. Removal
/// itself is infallible once the code is valid (a not-present code is a
/// no-op, not an error) — mirrors
/// [`crate::overrides::OverrideLists::with_entry_removed`].
async fn serve_admin_geoip_remove<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    let Ok(collected) = limited.collect().await else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    let Ok(request) = serde_json::from_slice::<GeoipCountryRequest>(&collected.to_bytes()) else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    match apply_geoip_change(state, |current| {
        let code = validate_country_code(&request.country)?;
        Ok(current.iter().filter(|c| **c != code).cloned().collect())
    }) {
        Ok(response) => json_response(&response),
        Err(_) => status_response(StatusCode::BAD_REQUEST),
    }
}

/// Builds the current [`MaxmindCredentialsView`] from the stored credentials
/// (T-162) — shared by the GET route and the two mutating routes' echo-back.
/// A missing app-data dir or no stored credentials read as `configured:
/// false`. `check` is always [`MaxmindCredentialCheck::Skipped`] here — only
/// `POST` runs the probe. `refresh_health` reflects the live
/// `AppState::maxmind_health` (T-163).
fn maxmind_view<C: DohClient + Sync>(
    state: &AppState<C>,
    persisted: bool,
) -> MaxmindCredentialsView {
    let account_id = state
        .persist
        .paths
        .as_ref()
        .and_then(|paths| {
            geoip_credentials::load(&paths.app_data_dir())
                .ok()
                .flatten()
        })
        .map(|creds| creds.account_id);
    MaxmindCredentialsView {
        configured: account_id.is_some(),
        account_id,
        check: MaxmindCredentialCheck::Skipped,
        refresh_health: state.maxmind_health_snapshot().into(),
        persisted,
    }
}

/// Maps [`check_maxmind_credentials`]'s coarse `Result` onto the wire enum —
/// `401`/`403` is the one actionable case (`Rejected`), everything else the
/// operator can't fix by retyping the key (`Unverified`).
fn credential_check(result: &Result<(), GeoipUpdateError>) -> MaxmindCredentialCheck {
    match result {
        Ok(()) => MaxmindCredentialCheck::Verified,
        Err(GeoipUpdateError::MaxmindAuthRejected) => MaxmindCredentialCheck::Rejected,
        Err(_) => MaxmindCredentialCheck::Unverified,
    }
}

/// `/admin/geoip/maxmind` (T-162) — one handler for both methods (like
/// [`serve_dns_query`]), branching on `req.method()`; the `ROUTES` table
/// already rejected anything but `GET`/`POST` before this runs.
///
/// - `GET`: read-only, no CSRF gate — the current [`MaxmindCredentialsView`]
///   (never the license key).
/// - `POST`: same CSRF gate and body-size cap as `/admin/geoip/add`. Stores
///   the credentials in the OS credential store **first**, then runs one
///   authenticated probe against `MaxMind` and reports the outcome in
///   [`MaxmindCredentialsView::check`]. A blank field is `400`; a failed store
///   write is `persisted: false` in the body (the recurring "surface a
///   failed save" rule), never a `5xx`. On success the new credentials become
///   the live `GeoIP` source and the background updater is woken — no
///   `dnsqb-service` restart needed (T-163).
async fn serve_admin_geoip_maxmind<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.method() == Method::GET {
        return json_response(&maxmind_view(state, true));
    }

    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    let Ok(collected) = limited.collect().await else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    let Ok(request) = serde_json::from_slice::<MaxmindCredentialsRequest>(&collected.to_bytes())
    else {
        return status_response(StatusCode::BAD_REQUEST);
    };

    let Some(paths) = state.persist.paths.as_ref() else {
        // No app-data dir — nothing to persist to, and the credentials file
        // *is* the state (no live-apply half like `apply_geoip_change` has).
        return json_response(&MaxmindCredentialsView {
            configured: false,
            account_id: Some(request.account_id),
            check: MaxmindCredentialCheck::Skipped,
            refresh_health: state.maxmind_health_snapshot().into(),
            persisted: false,
        });
    };

    // T-163 closing review: hold `geoip_source_lock` across store →
    // read-back → `update_geoip_source` so a concurrent `/admin/reset` can't
    // interleave and clobber the source. Dropped before the credential
    // probe's `.await` (the `parking_lot` guard is `!Send`); the probe
    // doesn't touch the source.
    let save_outcome = {
        let _geoip_source_guard = state.geoip_source_lock.lock();
        let outcome = geoip_credentials::save(
            &paths.app_data_dir(),
            &request.account_id,
            &request.license_key,
        );
        if outcome.is_ok() {
            // The stored credentials are now the live GeoIP source. Read them
            // back (also a store round-trip check) and wake the updater so
            // the new key is used within seconds, no restart. A read-back
            // miss here is not fatal — it just leaves the previous source
            // until the next reset/restart.
            match geoip_credentials::load(&paths.app_data_dir()) {
                Ok(Some(creds)) => {
                    state.update_geoip_source(GeoipSource::Maxmind(creds));
                    state.wake_geoip_refresh();
                }
                other => tracing::warn!(
                    "MaxMind credentials saved but not readable back for runtime pickup: {other:?}"
                ),
            }
        }
        outcome
    };

    match save_outcome {
        Err(CredentialsError::Malformed) => status_response(StatusCode::BAD_REQUEST),
        Err(err) => {
            tracing::warn!("failed to persist MaxMind credentials to the store: {err}");
            json_response(&MaxmindCredentialsView {
                configured: false,
                account_id: Some(request.account_id),
                check: MaxmindCredentialCheck::Skipped,
                refresh_health: state.maxmind_health_snapshot().into(),
                persisted: false,
            })
        }
        Ok(()) => {
            // A one-off, operator-initiated outbound call — not the
            // status-poll hot path the "don't rebuild a TLS client 30x/min"
            // concern (T-149) was about. Talks to the public
            // `download.maxmind.com`, so no cert pinning.
            let check = match reqwest::Client::builder().build() {
                Ok(client) => credential_check(
                    &check_maxmind_credentials(&client, &request.account_id, &request.license_key)
                        .await,
                ),
                Err(_) => MaxmindCredentialCheck::Unverified,
            };
            json_response(&MaxmindCredentialsView {
                configured: true,
                account_id: Some(request.account_id),
                check,
                refresh_health: state.maxmind_health_snapshot().into(),
                persisted: true,
            })
        }
    }
}

/// `POST /admin/geoip/maxmind/clear` (T-162) — same gate; deletes the stored
/// credentials, reverting to the default DB-IP Lite source and waking the
/// background updater immediately (T-163). A missing entry is not an error.
async fn serve_admin_geoip_maxmind_clear<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    if limited.collect().await.is_err() {
        return status_response(StatusCode::BAD_REQUEST);
    }
    // T-163 closing review: `geoip_source_lock` across clear →
    // `update_geoip_source` for the same reason the POST route holds it —
    // ordering against a concurrent `/admin/reset`. All sync, no `.await`
    // inside.
    let persisted = {
        let _geoip_source_guard = state.geoip_source_lock.lock();
        let persisted = match state.persist.paths.as_ref() {
            Some(paths) => match geoip_credentials::clear(&paths.app_data_dir()) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!("failed to remove stored MaxMind credentials: {err}");
                    false
                }
            },
            None => false,
        };
        // Back to DB-IP Lite as the live source, effective now.
        state.update_geoip_source(GeoipSource::DbIpLite);
        state.wake_geoip_refresh();
        persisted
    };
    json_response(&MaxmindCredentialsView {
        configured: false,
        account_id: None,
        check: MaxmindCredentialCheck::Skipped,
        refresh_health: state.maxmind_health_snapshot().into(),
        persisted,
    })
}

/// Builds the current [`crate::admin::ProvidersResponse`] from `entries` (T-72/T-73) —
/// shared by `GET /admin/providers` and the three mutating routes' echo-back.
fn providers_view(entries: &[ProviderEntry], persisted: bool) -> crate::admin::ProvidersResponse {
    let enabled_count = entries.iter().filter(|entry| entry.enabled).count();
    crate::admin::ProvidersResponse {
        active: entries.iter().map(crate::admin::ProviderView::of).collect(),
        available_presets: all_builtin_presets()
            .iter()
            .map(|spec| crate::admin::ProviderView {
                id: spec.id.clone(),
                display_name: spec.display_name.clone(),
                doh_url: spec.doh_url.clone(),
                category: spec.category,
                block_signature: spec.block_signature,
                enabled: false,
                is_builtin: true,
            })
            .collect(),
        // enabled voters + 1 baseline resolver — the fan-out the user's
        // browsing history is exposed to (CLAUDE.md: keep this visible).
        third_party_count: enabled_count + 1,
        filtering_active: enabled_count > 0,
        persisted,
    }
}

/// Applies `compute` to the live voter list (T-72/T-73), swaps the result in,
/// re-serializes `resolver_config.toml` (reading the other live fields first,
/// same cross-field discipline as `apply_geoip_change`), and returns the
/// fresh view. Shares `state.persist_lock` with every other
/// `resolver_config.toml` writer. `Err(StatusCode)` is a rejected request
/// (`400`), surfaced payload-free.
fn apply_provider_change<C, F>(
    state: &AppState<C>,
    compute: F,
) -> Result<crate::admin::ProvidersResponse, StatusCode>
where
    C: DohClient + Sync,
    F: FnOnce(Vec<ProviderEntry>) -> Result<Vec<ProviderEntry>, StatusCode>,
{
    let _persist_guard = state.persist_lock.lock();
    let after = compute(state.providers_snapshot())?;
    state.update_providers(after.clone());
    let runtime = *state.runtime.read();
    let cache_config = state.cache.read().config;
    let blocked_countries = state.geoip_countries.read().as_ref().clone();
    let persisted = match state.persist.paths.as_ref() {
        Some(paths) => {
            let config = ResolverConfig {
                port: state.persist.port,
                timeout_mode: runtime.timeout.mode,
                timeout_ms: timeout_ms(runtime.timeout.duration),
                serve_baseline_when_filters_unreachable: runtime
                    .serve_baseline_when_filters_unreachable,
                // T-146 cross-field read: not admin-mutable, but this write
                // rewrites the whole file so it must carry the live value.
                persist_query_log: state.persist.persist_query_log,
                persist_cache: state.persist.persist_cache,
                providers: after.clone(),
                cache: cache_config,
                geoip: GeoipConfig { blocked_countries },
            };
            match config.save(&paths.config) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!("failed to persist an admin provider change to disk: {err}");
                    false
                }
            }
        }
        None => false,
    };
    Ok(providers_view(&after, persisted))
}

/// `GET /admin/providers` (T-72/T-73) — read-only, no CSRF gate (same as
/// `GET /admin/geoip`).
fn serve_admin_providers<C: DohClient + Sync>(state: &AppState<C>) -> Response<Full<Bytes>> {
    json_response(&providers_view(&state.providers_snapshot(), true))
}

/// Shared CSRF-gate + body-cap + JSON-decode preamble for the three
/// `/admin/providers/*` POST routes — returns the decoded body, or `Err` with
/// the HTTP status to send back instead.
async fn read_provider_body<B, T>(req: Request<B>) -> Result<T, StatusCode>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T: serde::de::DeserializeOwned,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    let Ok(collected) = limited.collect().await else {
        return Err(StatusCode::BAD_REQUEST);
    };
    serde_json::from_slice::<T>(&collected.to_bytes()).map_err(|_| StatusCode::BAD_REQUEST)
}

/// `POST /admin/providers/add` (T-72/T-73) — a built-in preset (`{id}` only)
/// or a custom `https` endpoint (`id` + `url` + `display_name` + `category`).
/// A malformed request, a duplicate id, an invalid id shape, or a
/// non-public/non-`https` URL is `400` (payload-free).
async fn serve_admin_providers_add<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let request: crate::admin::ProviderAddRequest = match read_provider_body(req).await {
        Ok(request) => request,
        Err(code) => return status_response(code),
    };
    let result = apply_provider_change(state, |mut entries| {
        if !crate::upstream::is_valid_provider_id(&request.id) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if entries.iter().any(|entry| entry.spec.id == request.id) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let spec = if let Some(preset) = builtin_preset(&request.id) {
            preset
        } else {
            let (Some(url), Some(display_name), Some(category)) = (
                request.url.as_deref(),
                request.display_name.as_deref(),
                request.category,
            ) else {
                return Err(StatusCode::BAD_REQUEST);
            };
            if crate::upstream::validate_provider_url(url).is_err() {
                return Err(StatusCode::BAD_REQUEST);
            }
            ProviderSpec {
                id: request.id.clone(),
                display_name: display_name.to_string(),
                doh_url: url.to_string(),
                category,
                block_signature: request
                    .block_signature
                    .unwrap_or(BlockSignature::NullIpOrNxdomain),
            }
        };
        entries.push(ProviderEntry {
            spec,
            enabled: true,
        });
        Ok(entries)
    });
    match result {
        Ok(response) => json_response(&response),
        Err(code) => status_response(code),
    }
}

/// `POST /admin/providers/remove` (T-72/T-73) — a **custom** entry only; a
/// built-in preset can only be disabled (`400` if `id` names one, or names
/// nothing configured).
async fn serve_admin_providers_remove<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let request: crate::admin::ProviderRemoveRequest = match read_provider_body(req).await {
        Ok(request) => request,
        Err(code) => return status_response(code),
    };
    let result = apply_provider_change(state, |mut entries| {
        if builtin_preset(&request.id).is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let before = entries.len();
        entries.retain(|entry| entry.spec.id != request.id);
        if entries.len() == before {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(entries)
    });
    match result {
        Ok(response) => json_response(&response),
        Err(code) => status_response(code),
    }
}

/// `POST /admin/providers/set-enabled` (T-72/T-73) — toggles one configured
/// entry (`400` if `id` isn't configured).
async fn serve_admin_providers_set_enabled<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let request: crate::admin::ProviderSetEnabledRequest = match read_provider_body(req).await {
        Ok(request) => request,
        Err(code) => return status_response(code),
    };
    let result = apply_provider_change(state, |mut entries| {
        let Some(entry) = entries.iter_mut().find(|entry| entry.spec.id == request.id) else {
            return Err(StatusCode::BAD_REQUEST);
        };
        entry.enabled = request.enabled;
        Ok(entries)
    });
    match result {
        Ok(response) => json_response(&response),
        Err(code) => status_response(code),
    }
}

/// `GET /admin/log`'s default result cap (T-54) — a value a user actually
/// reads in one screen, not [`DEFAULT_MAX_ENTRIES`] (1000): every other
/// input/output boundary in this crate is explicitly bounded, and a JSON
/// response whose size scales with live user traffic is no exception
/// (advisor-caught during planning). A client may ask for more via `?limit=`,
/// up to [`MAX_LOG_LIMIT`].
const DEFAULT_LOG_LIMIT: usize = 200;
/// The hard cap `?limit=` can't exceed — [`DEFAULT_MAX_ENTRIES`], the ring
/// buffer's own size bound. Asking for more than the buffer can ever hold is
/// meaningless, not a legitimate "give me everything" request.
const MAX_LOG_LIMIT: usize = DEFAULT_MAX_ENTRIES;

/// `GET /admin/log`'s parsed query-string facets (T-54) — mirrors
/// [`LogFilter`]'s three fields plus the result-count cap above. Derives
/// `Debug` for test-failure messages only — `domain_contains` carries
/// caller-supplied search text, so (same discipline as [`LogEntry`]) never
/// pass a `LogQuery` to `tracing`/a diagnostic-log context.
#[derive(Debug, Default)]
struct LogQuery {
    domain_contains: Option<String>,
    decision: Option<Decision>,
    /// Raw `?voter=` value, still unvalidated here (T-72/T-73 — the set of
    /// valid provider ids is runtime state `parse_log_query` has no access
    /// to). [`serve_admin_log`] checks it against the configured + built-in
    /// preset ids and returns `400` on a value matching neither, staying
    /// payload-free (the raw text is never echoed back).
    voter: Option<String>,
    limit: usize,
}

/// A malformed `GET /admin/log` query string — closed and coarse (no
/// arbitrary client-supplied text echoed back), same discipline as
/// [`DohRequestError`]/`overrides::InvalidReason`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum LogQueryError {
    /// A `domain_contains` value wasn't valid percent-encoded UTF-8.
    #[error("domain_contains is not valid percent-encoded UTF-8")]
    BadEncoding,
    /// `decision` was present but didn't match any [`Decision`] variant's
    /// wire name. Never silently treated as "no filter" (`None`, i.e. the
    /// facet's own `ALL`) - a typo'd `?decision=BLOCKD` must not silently
    /// widen a request for blocked-only entries into every entry
    /// (advisor-caught during planning, the same class of trap T-148's
    /// disabled-provider-defaults-to-`TimedOut` bug already named for this
    /// crate).
    #[error("decision does not match a known value")]
    UnknownDecision,
    /// Same reasoning as `UnknownDecision`, for `voter`.
    #[error("voter does not match a known provider identifier")]
    UnknownVoter,
    /// `limit` was present but didn't parse as a positive integer, or parsed
    /// as `0` — a request for zero results isn't a meaningful "give me
    /// fewer," it's almost certainly a client bug (an empty/`0`-valued form
    /// field), so it's rejected the same as a non-numeric value rather than
    /// silently returning an empty, indistinguishable-from-"no matches"
    /// success (advisor-caught on the closing review of this route).
    #[error("limit is not a valid positive integer")]
    BadLimit,
}

/// Parses `GET /admin/log`'s raw query string (RFC 3986 `application/
/// x-www-form-urlencoded`-style `key=value&key2=value2` pairs, percent-
/// decoded per key) into a [`LogQuery`]. `None`/an absent query string is
/// "no filters, default limit" - the same "missing means default, present-
/// but-wrong means 400" split [`LogQueryError`]'s own doc comments describe
/// per field.
fn parse_log_query(query_string: Option<&str>) -> Result<LogQuery, LogQueryError> {
    let mut parsed = LogQuery {
        limit: DEFAULT_LOG_LIMIT,
        ..LogQuery::default()
    };
    let Some(query_string) = query_string else {
        return Ok(parsed);
    };
    for pair in query_string.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_encoding::percent_decode_str(raw_value)
            .decode_utf8()
            .map_err(|_| LogQueryError::BadEncoding)?;
        match key {
            "domain_contains" => parsed.domain_contains = Some(value.into_owned()),
            "decision" => {
                parsed.decision = Some(match value.as_ref() {
                    "ALLOWED" => Decision::Allowed,
                    "BLOCKED" => Decision::Blocked,
                    "FAILED" => Decision::Failed,
                    _ => return Err(LogQueryError::UnknownDecision),
                });
            }
            "voter" => {
                if value.is_empty() {
                    return Err(LogQueryError::UnknownVoter);
                }
                parsed.voter = Some(value.into_owned());
            }
            "limit" => {
                let limit = value
                    .parse::<usize>()
                    .map_err(|_| LogQueryError::BadLimit)?;
                if limit == 0 {
                    return Err(LogQueryError::BadLimit);
                }
                parsed.limit = limit.min(MAX_LOG_LIMIT);
            }
            // An unrecognized key is ignored, not fatal - forward-compatible
            // with a future UI param this route doesn't know about yet,
            // unlike an unrecognized *value* for a key this route does
            // recognize (see LogQueryError's own doc comments for why those
            // two cases are handled differently).
            _ => {}
        }
    }
    Ok(parsed)
}

/// `GET /admin/log` (T-54) — method allowlisting happens centrally in
/// [`serve`]'s `ROUTES` check, not re-checked here. Read-only, no CSRF gate
/// needed (same as `GET /admin/status`/`GET /admin/overrides`). A malformed
/// query string is `400`, never silently widened to "no filter" (see
/// [`LogQueryError`]).
fn serve_admin_log<C: DohClient + Sync>(
    query_string: Option<&str>,
    state: &AppState<C>,
) -> Response<Full<Bytes>> {
    let Ok(parsed) = parse_log_query(query_string) else {
        return status_response(StatusCode::BAD_REQUEST);
    };
    // Validate `?voter=` against the ids a log entry could plausibly carry:
    // currently-configured voters plus every built-in preset — so a preset
    // that was toggled off (still in `all_builtin_presets`) stays filterable
    // against its historical rows. A *removed custom* id matches neither and
    // is rejected 400; its historical rows become unfilterable by voter (a
    // stated limitation, CLAUDE.md — not worth a full log scan for the id).
    // A value matching neither is otherwise a typo → 400, never silently
    // narrowed to an empty result.
    if let Some(voter) = parsed.voter.as_deref() {
        let known = state
            .providers
            .read()
            .iter()
            .any(|entry| entry.spec.id == voter)
            || all_builtin_presets()
                .iter()
                .any(|preset| preset.id == voter);
        if !known {
            return status_response(StatusCode::BAD_REQUEST);
        }
    }
    let filter = LogFilter {
        domain_contains: parsed.domain_contains.as_deref(),
        decision: parsed.decision,
        voter: parsed.voter.as_deref(),
    };
    let mut entries = state.query_log.search(SystemTime::now(), &filter);
    let truncated = entries.len() > parsed.limit;
    // Keeps the *newest* `limit` entries (search()/snapshot() return
    // oldest-first) - split_off's tail, not a `.take(limit)` off the front,
    // which would instead keep the oldest matches and silently hide
    // everything recent the moment a filter matches more than `limit`
    // entries.
    let keep_from = entries.len().saturating_sub(parsed.limit);
    entries = entries.split_off(keep_from);
    json_response(&LogQueryResponse {
        entries: entries.iter().map(LogEntryView::from_entry).collect(),
        truncated,
    })
}

/// `POST /admin/log/clear` (T-54) — same CSRF gate and body-size cap as
/// every other admin `POST`. No body fields to parse (same `{}`-body
/// convention `AdminClient::reset`/`shutdown` already use); the body is
/// still bounded and read, not ignored outright, so an oversized body is
/// rejected the same way every other admin `POST` rejects one, not silently
/// accepted because this route happens not to need it.
async fn serve_admin_log_clear<C, B>(req: Request<B>, state: &AppState<C>) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    if limited.collect().await.is_err() {
        return status_response(StatusCode::BAD_REQUEST);
    }
    state.query_log.clear();
    status_response(StatusCode::OK)
}

/// `POST /admin/uninstall-local-state` (T-70) — the in-app "Prepare for
/// removal" action `dnsqb-tray`'s "Повністю видалити" menu item and
/// `/admin/ui`'s danger-zone button both call. MSIX (T-156) has no
/// uninstall-time code hook, so this is the only place the trusted
/// certificate and the three Credential Manager secrets ever actually get
/// cleared — the caller still has to remove the app itself afterward. Same
/// CSRF gate and body-size cap as every other admin `POST`; no config file
/// touched, so no `persist_lock`.
async fn serve_admin_uninstall_local_state<C, B>(
    req: Request<B>,
    state: &AppState<C>,
) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    if limited.collect().await.is_err() {
        return status_response(StatusCode::BAD_REQUEST);
    }
    let app_data_dir = state.persist.paths.as_ref().map(PersistPaths::app_data_dir);
    let report = crate::local_state::remove_all(app_data_dir.as_deref());
    json_response(&UninstallLocalStateResponse::from(report))
}

/// `POST /admin/shutdown` (T-149) — the highest blast-radius endpoint on
/// this channel: its only consumer is `dnsqb-tray`'s "Зупинити фільтрацію"
/// menu item, which gates it behind a confirm dialog that names the
/// consequence before ever sending this request. Method allowlisting happens
/// centrally in [`serve`]'s `ROUTES` check, not re-checked here. Same CSRF
/// gate and body-size cap as `/admin/config`/`/admin/reset`.
///
/// Sends the shutdown signal and returns `200` immediately — the actual
/// process exit happens asynchronously in `main.rs`'s accept loop, driven by
/// [`AppState::shutdown_handle`]. This response is written by the same
/// per-connection task that keeps running regardless of when the accept loop
/// notices the signal, so "answer 200, then the process later exits" needs
/// no manual ordering here.
async fn serve_admin_shutdown<C, B>(req: Request<B>, state: &AppState<C>) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type_is_json(content_type) {
        return status_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let limited = Limited::new(req.into_body(), MAX_ADMIN_BODY_SIZE);
    if limited.collect().await.is_err() {
        return status_response(StatusCode::BAD_REQUEST);
    }
    // `Err` means every receiver has already been dropped - reachable if a
    // second `/admin/shutdown` arrives after the accept loop already exited
    // its `select!` and dropped its receiver, mid-drain. Not a failure from
    // this request's point of view: shutdown was already requested and is
    // already underway, so the same 200 is still correct.
    let _ = state.shutdown_tx.send(true);
    status_response(StatusCode::OK)
}

/// `/dns-query`'s `GET`/`POST` handling (SPEC.md §1 line 84) — everything
/// [`serve`] routed here after confirming the path. Decodes the request into
/// wire bytes and hands off to [`resolve_doh_request`]; every failure mode
/// maps to an HTTP status, never a panic.
async fn serve_dns_query<C, B>(req: Request<B>, state: &AppState<C>) -> Response<Full<Bytes>>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let wire_bytes = match *req.method() {
        Method::GET => wire_bytes_from_get(req.uri().query().unwrap_or_default()),
        Method::POST => {
            let content_type = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok());
            if content_type_is_dns_message(content_type) {
                let limited = Limited::new(req.into_body(), MAX_MESSAGE_SIZE);
                match limited.collect().await {
                    Ok(collected) => Ok(collected.to_bytes().to_vec()),
                    // `Limited<B>::Error` is `Box<dyn Error + Send + Sync>` and
                    // carries either a `LengthLimitError` or `B`'s own
                    // underlying error (e.g. the client disconnected
                    // mid-body) - only the former is genuinely "too large".
                    Err(err) if err.downcast_ref::<LengthLimitError>().is_some() => {
                        Err(DohRequestError::MessageTooLarge)
                    }
                    Err(_) => Err(DohRequestError::BodyReadError),
                }
            } else {
                Err(DohRequestError::UnsupportedContentType)
            }
        }
        // Unreachable via `serve()` - `ROUTES` only allows GET/POST for this
        // path, so this arm's response never actually goes out. Kept because
        // the two real arms above are branching on *behavior*, not just
        // permission, so this match can't be replaced by a `ROUTES` check
        // the way the four `serve_admin_*` handlers' checks were.
        _ => return status_response(StatusCode::METHOD_NOT_ALLOWED),
    };

    let wire_bytes = match wire_bytes {
        Ok(bytes) => bytes,
        Err(DohRequestError::MessageTooLarge) => {
            return status_response(StatusCode::PAYLOAD_TOO_LARGE)
        }
        Err(_) => return status_response(StatusCode::BAD_REQUEST),
    };

    let resolved = resolve_doh_request(&wire_bytes, state).await;

    match resolved {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
            .body(Full::new(Bytes::from(bytes)))
            .unwrap_or_else(|_| status_response(StatusCode::INTERNAL_SERVER_ERROR)),
        Err(_) => status_response(StatusCode::BAD_REQUEST),
    }
}

/// The `hyper` request handler `main.rs` hands every accepted, TLS-terminated
/// connection to. Routes `/dns-query` (SPEC.md §1 line 84) to
/// [`serve_dns_query`], `/admin/status`/`/admin/config` (T-52) to their own
/// handlers, and any other path to a 404 with no further processing.
///
/// Generic over the request body type `B` rather than hardcoded to
/// `hyper::body::Incoming` — `Incoming` can only be produced by a real
/// `hyper` connection, so a generic bound is what lets this function be unit
/// tested with a plain `http_body_util::Full` request instead of needing a
/// live socket. `main.rs` calls this with `Incoming`; the type is inferred
/// from context there, never spelled out.
///
/// # Errors
///
/// Never returns `Err` — every failure mode maps to an HTTP status instead,
/// which is what lets this be a `hyper` `Service` (`Infallible` is the
/// required error type for a connection that must never itself fail).
pub async fn serve<C, B>(
    req: Request<B>,
    state: Arc<AppState<C>>,
) -> Result<Response<Full<Bytes>>, Infallible>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let path = req.uri().path();
    let Some(&(_, allowed_methods)) = ROUTES.iter().find(|(route_path, _)| *route_path == path)
    else {
        return Ok(status_response(StatusCode::NOT_FOUND));
    };
    if !allowed_methods.contains(req.method()) {
        return Ok(status_response(StatusCode::METHOD_NOT_ALLOWED));
    }
    Ok(match path {
        DNS_QUERY_PATH => serve_dns_query(req, &state).await,
        HEALTH_PATH => serve_health(&state).await,
        ADMIN_STATUS_PATH => serve_admin_status(&state),
        ADMIN_CONFIG_PATH => serve_admin_config(req, &state).await,
        ADMIN_RESET_PATH => serve_admin_reset(req, &state).await,
        ADMIN_SHUTDOWN_PATH => serve_admin_shutdown(req, &state).await,
        ADMIN_OVERRIDES_PATH => serve_admin_overrides(&state),
        ADMIN_OVERRIDES_ADD_PATH => serve_admin_overrides_add(req, &state).await,
        ADMIN_OVERRIDES_REMOVE_PATH => serve_admin_overrides_remove(req, &state).await,
        ADMIN_CACHE_CONFIG_PATH => serve_admin_cache_config(&state),
        ADMIN_CACHE_CONFIG_APPLY_PATH => serve_admin_cache_config_apply(req, &state).await,
        ADMIN_GEOIP_PATH => serve_admin_geoip(&state),
        ADMIN_GEOIP_ADD_PATH => serve_admin_geoip_add(req, &state).await,
        ADMIN_GEOIP_REMOVE_PATH => serve_admin_geoip_remove(req, &state).await,
        ADMIN_GEOIP_MAXMIND_PATH => serve_admin_geoip_maxmind(req, &state).await,
        ADMIN_GEOIP_MAXMIND_CLEAR_PATH => serve_admin_geoip_maxmind_clear(req, &state).await,
        ADMIN_PROVIDERS_PATH => serve_admin_providers(&state),
        ADMIN_PROVIDERS_ADD_PATH => serve_admin_providers_add(req, &state).await,
        ADMIN_PROVIDERS_REMOVE_PATH => serve_admin_providers_remove(req, &state).await,
        ADMIN_PROVIDERS_SET_ENABLED_PATH => serve_admin_providers_set_enabled(req, &state).await,
        ADMIN_LOG_PATH => serve_admin_log(req.uri().query(), &state),
        ADMIN_LOG_CLEAR_PATH => serve_admin_log_clear(req, &state).await,
        ADMIN_UNINSTALL_LOCAL_STATE_PATH => serve_admin_uninstall_local_state(req, &state).await,
        ADMIN_UI_PATH => admin_ui::serve_html(req.method()),
        ADMIN_UI_JS_PATH => admin_ui::serve_js(req.method()),
        ADMIN_UI_CSS_PATH => admin_ui::serve_css(req.method()),
        // Unreachable: `path` already matched a `ROUTES` entry above, and
        // every `ROUTES` path has a corresponding arm here - kept as an
        // explicit, safe (404) fallback because the match itself has no way
        // to prove that correspondence to the compiler.
        _ => status_response(StatusCode::NOT_FOUND),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        admin_status, content_type_is_dns_message, parse_log_query, read_watchdog_view,
        resolve_doh_request, serve, wire_bytes_from_get, AppState, CacheState, DohRequestError,
        GeoipInit, GeoipSource, GeoipState, LogQueryError, OverridesState, PersistPaths,
        PersistTarget, RuntimeInit, WatchdogState, ADMIN_UNINSTALL_LOCAL_STATE_PATH,
        DEFAULT_LOG_LIMIT, DNS_QUERY_PATH, MAX_LOG_LIMIT, MAX_MESSAGE_SIZE, ROUTES,
    };
    use crate::admin::{
        AdminConfigUpdate, AdminStatusResponse, CacheConfigUpdate, CacheConfigView, DecisionView,
        GeoipCountriesResponse, GeoipCountryRequest, LogQueryResponse, MaxmindCredentialCheck,
        MaxmindCredentialsRequest, MaxmindCredentialsView, OverrideAddRequest,
        OverrideListsResponse, OverrideRemoveRequest, WatchdogStatusView,
    };
    use crate::cache::{Cache, CacheConfig, CacheEntry, CacheKey, Verdict};
    use crate::config::ResolverConfig;
    use crate::overrides::{ListKind, OverrideEntry, OverrideLists};
    use crate::query_log::{DecisionSource, LogEntry, QueryLog};
    use crate::quorum::{VoterRecord, VoterVerdict};
    use crate::upstream::{doh_get_url, DohClient, ProviderEntry, UpstreamError};
    use crate::watchdog::state::{WatchdogStateFile, WatchdogTarget, STATE_SCHEMA_VERSION};
    use crate::write_watchdog_state;
    use bytes::Bytes;
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use http::{header, Method, Request, StatusCode};
    use http_body_util::Full;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    fn query_bytes(domain: &str, qtype: RecordType) -> Vec<u8> {
        let Ok(name) = Name::from_str(domain) else {
            panic!("valid fixture domain");
        };
        let mut question = Query::new();
        question.set_name(name);
        question.set_query_type(qtype);
        let mut message = Message::query();
        message.add_query(question);
        let Ok(bytes) = crate::wire::encode_wire_message(&message) else {
            panic!("fixture message must encode");
        };
        bytes
    }

    // T-54: `GET /admin/log`/`POST /admin/log/clear` fixtures.

    fn sample_log_entry(domain: &str, decision: crate::query_log::Decision) -> LogEntry {
        LogEntry {
            timestamp: std::time::SystemTime::now(),
            domain: domain.to_string(),
            qtype: RecordType::A,
            decision,
            decision_source: crate::query_log::DecisionSource::Quorum,
            voters: vec![VoterRecord {
                provider_id: "quad9".to_string(),
                verdict: VoterVerdict::Allow,
                allow_ip_count: Some(1),
                error_message: None,
            }],
            geoip_country: None,
            resolved_ip_country: None,
            latency_ms: 5,
        }
    }

    fn admin_log_request(query: Option<&str>) -> Request<Full<Bytes>> {
        let uri = match query {
            Some(query) => format!("/admin/log?{query}"),
            None => "/admin/log".to_string(),
        };
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        req
    }

    fn admin_log_clear_request() -> Request<Full<Bytes>> {
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/log/clear")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        req
    }

    #[test]
    fn wire_bytes_from_get_round_trips_doh_get_urls_own_encoder() {
        let message_bytes = query_bytes("example.com.", RecordType::A);
        let url = doh_get_url("https://example.test/dns-query", &message_bytes);
        let Some(query_string) = url.split('?').nth(1) else {
            panic!("fixture URL must have a query string");
        };
        let decoded = match wire_bytes_from_get(query_string) {
            Ok(bytes) => bytes,
            Err(err) => panic!("a doh_get_url-encoded query string must decode: {err}"),
        };
        assert_eq!(decoded, message_bytes);
    }

    #[test]
    fn wire_bytes_from_get_rejects_a_missing_dns_param() {
        assert!(matches!(
            wire_bytes_from_get("other=1"),
            Err(DohRequestError::MissingDnsParam)
        ));
    }

    #[test]
    fn wire_bytes_from_get_rejects_invalid_base64() {
        assert!(matches!(
            wire_bytes_from_get("dns=not!valid!base64"),
            Err(DohRequestError::InvalidBase64)
        ));
    }

    #[test]
    fn wire_bytes_from_get_rejects_an_oversized_message() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let query_string = format!("dns={}", URL_SAFE_NO_PAD.encode(oversized));
        assert!(matches!(
            wire_bytes_from_get(&query_string),
            Err(DohRequestError::MessageTooLarge)
        ));
    }

    // T-58 fuzz pass: RFC 8484 §4.1.1's GET decode path is the first thing an
    // arbitrary, untrusted query string reaches - never a decoded DNS
    // message, since it's rejected or produces bytes before the `hickory-
    // proto` decoder ever sees them, but this function's own base64/length
    // handling must never panic regardless of input shape.
    proptest::proptest! {
        #[test]
        fn wire_bytes_from_get_never_panics_on_arbitrary_query_strings(query in "\\PC{0,256}") {
            // Ok/Err outcome is deliberately not asserted here - the exact
            // decode/reject behavior is already covered by the targeted
            // tests above; this property only proves the absence of a panic.
            let _ = wire_bytes_from_get(&query);
        }
    }

    // T-58 fuzz pass: exercises the whole `/admin/config` route (CSRF gate,
    // body-size limit, JSON decode, live-apply) against arbitrary bytes, not
    // just `AdminConfigUpdate`'s deserializer in isolation - proves the path
    // `serve()` actually routes requests through is panic-free end to end.
    // `proptest!` has no native async support, so each case builds its own
    // single-threaded runtime rather than reusing `#[tokio::test]`.
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]
        #[test]
        fn serve_admin_config_never_panics_on_arbitrary_bodies(
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)
        ) {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                panic!("must be able to build a current-thread runtime");
            };
            rt.block_on(async {
                let Ok(req) = Request::builder()
                    .method(Method::POST)
                    .uri("/admin/config")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(body)))
                else {
                    panic!("fixture request must build");
                };
                // Response status is deliberately not asserted here - the
                // real status-code behavior is already covered by the
                // targeted tests above; this property only proves the
                // absence of a panic anywhere in the routing/decode path.
                let _ = serve(req, state_with(no_op_client())).await;
            });
        }
    }

    // T-58 fuzz bar, redefined as data (TASKS.md's Ф1 closure plan,
    // 2026-08-29): the property above proves `/admin/config` alone is
    // panic-free, but a hardcoded list of individually-fuzzed routes can't
    // prove anything about a route *added later* - the same shape T-59's own
    // `ROUTES`-table fix already had to solve for route *dispatch* (see
    // `ROUTES`'s own doc comment). This property generates its (path,
    // method) pair from `ROUTES` itself via `route_method_at`/
    // `route_method_count` below, so a new route *or* a new method on an
    // existing route is automatically exercised the moment it's added to
    // `ROUTES`, with no second test to remember to write - `/dns-query`'s
    // POST specifically is only reachable this way, since `route_method_at`
    // flattens every method per path rather than picking just the first.
    // Uses a benign `Instant`-answering client, not `no_op_client()`'s
    // `Panic` responses - `/dns-query` is one of the routes this property
    // can select, and while an arbitrary byte buffer decoding into a valid,
    // allowlist/blocklist/cache-missing query is astronomically unlikely,
    // "unlikely" isn't the same as "provably never" the way it is for the
    // admin-only property above, which never reaches `handle_query` at all.

    /// Routes this property deliberately never selects. T-70's real handler
    /// (once past the content-type gate, which this property always
    /// satisfies for a non-GET route - see below) spawns a real
    /// `certutil.exe` subprocess and mutates whatever this project's fixed
    /// `CommonName` has installed in the machine's actual `CurrentUser\Root`
    /// store, the same real-external-resource side effect `trust_store`'s
    /// and `cert_rotation`'s own tests already refuse to trigger (see
    /// `local_state.rs`'s `remove_all` doc comment). Unlike every other
    /// route this property fuzzes, the handler never even inspects the
    /// body once the gate passes, so fuzzing it here buys nothing while
    /// still paying a real subprocess-spawn cost per case, repeated across
    /// however many of `Config::with_cases`' 64 cases happen to land on it.
    /// Routing/method-gating for this path is proven instead by
    /// `serve_matches_the_documented_admin_route_allowlist` +
    /// `serve_enforces_the_route_table_it_matched_above` (whose fixture
    /// request carries no `Content-Type` at all, so it never reaches the
    /// real handler either), plus this route's own two gate tests below.
    const FUZZ_EXCLUDED_ROUTES: &[&str] = &[ADMIN_UNINSTALL_LOCAL_STATE_PATH];

    fn fuzzable_routes() -> impl Iterator<Item = &'static (&'static str, &'static [Method])> {
        ROUTES
            .iter()
            .filter(|(path, _)| !FUZZ_EXCLUDED_ROUTES.contains(path))
    }

    /// Total `(path, method)` pairs across every fuzzable [`ROUTES`] entry -
    /// a plain module-level fn, not a captured closure, since `proptest!`'s
    /// generated `#[test] fn` can only reference items, not locals from an
    /// enclosing block.
    fn route_method_count() -> usize {
        fuzzable_routes().map(|(_, methods)| methods.len()).sum()
    }

    /// The `index`-th `(path, method)` pair, flattening the fuzzable subset
    /// of `ROUTES` in declaration order. Panics on an out-of-range `index` -
    /// callers only ever pass `0..route_method_count()`, so this is a real
    /// invariant violation, not untrusted input.
    fn route_method_at(index: usize) -> (&'static str, Method) {
        let mut remaining = index;
        for (path, methods) in fuzzable_routes() {
            if remaining < methods.len() {
                return (path, methods[remaining].clone());
            }
            remaining -= methods.len();
        }
        panic!("route_method_at index out of range - route_method_count() and this must stay consistent");
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]
        #[test]
        fn serve_never_panics_on_arbitrary_input_for_any_documented_route(
            pair_index in 0..route_method_count(),
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096),
            // A real key name from *some* GET route's own param set, not an
            // arbitrary one - see the `query_key`/`query_value` comment
            // below for why an arbitrary key would defeat the point of this
            // property (advisor-caught before commit, first draft used a
            // single arbitrary blob and never actually reached either
            // param-parsing function it claimed to fuzz).
            query_key in proptest::prop_oneof![
                proptest::prelude::Just("dns"),
                proptest::prelude::Just("domain_contains"),
                proptest::prelude::Just("decision"),
                proptest::prelude::Just("voter"),
                proptest::prelude::Just("limit"),
            ],
            query_value in "\\PC{0,128}",
        ) {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                panic!("must be able to build a current-thread runtime");
            };
            rt.block_on(async {
                let (path, method) = route_method_at(pair_index);
                // GET routes get a fuzzed `key=value` query pair appended
                // (this is the one path a GET request can carry untrusted
                // input on - /dns-query's own `?dns=`, /admin/log's
                // filters); non-GET routes get the fuzzed bytes as the body
                // instead, matching how each method actually carries input
                // in this API.
                //
                // **Advisor-caught, empirically confirmed (not assumed) —
                // two real gaps in the first draft, neither a production
                // bug, both "the property never reaches the code it claims
                // to":**
                // (1) percent-encoding the *whole* arbitrary query string
                // with `NON_ALPHANUMERIC` also encodes `=`/`&`, so no GET
                // case ever produced a real `key=value` pair -
                // `wire_bytes_from_get`/`parse_log_query` always took their
                // "no recognized param" early-return. Fixed by building the
                // pair explicitly (`query_key` from the real per-route
                // param-name set, only `query_value` percent-encoded) so
                // the key is always recognizable while the value stays
                // arbitrary.
                // (2) POST requests all carried `Content-Type: application/
                // json`, so `/dns-query`'s POST case always 415'd before
                // `content_type_is_dns_message`'s body-decode branch ever
                // ran. Fixed by making the content-type route-dependent.
                // Confirmed by temporarily inserting `panic!()` at the top
                // of `parse_log_query`'s `for pair in ...` loop body and at
                // the top of `serve_dns_query`'s `if content_type_is_dns_
                // message(...)` block: both fixes applied -> red (proving
                // this property does reach them); both temporary panics
                // reverted -> green again (295 total, this test included).
                let is_dns_query = path == DNS_QUERY_PATH;
                let (uri, body_bytes, content_type) = if method == Method::GET {
                    let encoded_value = percent_encoding::utf8_percent_encode(
                        &query_value,
                        percent_encoding::NON_ALPHANUMERIC,
                    );
                    (
                        format!("{path}?{query_key}={encoded_value}"),
                        Bytes::new(),
                        "application/json",
                    )
                } else {
                    (
                        path.to_string(),
                        Bytes::from(body),
                        if is_dns_query { "application/dns-message" } else { "application/json" },
                    )
                };
                let Ok(req) = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Full::new(body_bytes))
                else {
                    panic!("fixture request must build");
                };
                let client = MockClient {
                    baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(9, 9, 9, 9))),
                    quorum: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(9, 9, 9, 9))),
                    calls: AtomicU32::new(0),
                };
                // Status/body content deliberately not asserted - every
                // route's real behavior is already covered by its own
                // targeted tests; this property only proves the absence of
                // a panic, for every path `serve()` documents, not just the
                // ones someone remembered to fuzz individually.
                let _ = serve(req, state_with(client)).await;
            });
        }
    }

    #[test]
    fn content_type_accepts_the_exact_media_type() {
        assert!(content_type_is_dns_message(Some("application/dns-message")));
    }

    #[test]
    fn content_type_accepts_different_case() {
        assert!(content_type_is_dns_message(Some("Application/DNS-Message")));
    }

    #[test]
    fn content_type_accepts_a_charset_parameter() {
        assert!(content_type_is_dns_message(Some(
            "application/dns-message; charset=utf-8"
        )));
    }

    #[test]
    fn content_type_rejects_the_wrong_type() {
        assert!(!content_type_is_dns_message(Some("application/json")));
    }

    #[test]
    fn content_type_rejects_a_missing_header() {
        assert!(!content_type_is_dns_message(None));
    }

    #[derive(Clone)]
    enum MockResponse {
        Instant(Message),
        Panic,
        /// Never resolves (T-56) — same idea as `quorum.rs`'s own
        /// `MockResponse::Pending`, added here so `MockClient` can force a
        /// real `VoterVerdict::Timeout` under `#[tokio::test(start_paused =
        /// true)]`. Needs `query` to have a genuine `.await` inside, hence
        /// the `async fn` below instead of the previous plain `fn` +
        /// `std::future::ready(...)` (which had no `.await` at all) —
        /// `quorum.rs`'s `MockDohClient::query` already establishes this
        /// exact `async fn` shape against the same trait.
        Pending,
    }

    struct MockClient {
        baseline: MockResponse,
        quorum: MockResponse,
        calls: AtomicU32,
    }

    impl DohClient for MockClient {
        async fn query(&self, url: &str, _query: &Message) -> Result<Message, UpstreamError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let response = if url == crate::upstream::BASELINE_DOH_URL {
                &self.baseline
            } else {
                &self.quorum
            };
            match response {
                MockResponse::Instant(message) => Ok(message.clone()),
                MockResponse::Panic => panic!("unexpected upstream call to {url}"),
                MockResponse::Pending => std::future::pending().await,
            }
        }
    }

    fn allow_message_with_ip(ip: Ipv4Addr) -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NoError;
        message
            .answers
            .push(Record::from_rdata(Name::root(), 300, RData::A(A(ip))));
        message
    }

    #[tokio::test]
    async fn resolve_doh_request_answers_an_a_query_via_quorum() {
        // An A/AAAA Allow verdict queries baseline too, not just the two
        // filtering voters (quorum::resolve's own representative-answer
        // logic) - same three-way fixture pipeline.rs's own
        // cache_miss_allow_with_records_is_cached_and_reused test uses.
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let state = state_with(client);

        let response_bytes = match resolve_doh_request(&wire_bytes, &state).await {
            Ok(bytes) => bytes,
            Err(err) => panic!("must resolve: {err}"),
        };
        let Ok(decoded) = crate::wire::decode_wire_message(&response_bytes) else {
            panic!("response must decode");
        };
        assert_eq!(decoded.metadata.response_code, ResponseCode::NoError);
    }

    // T-149: catches a broken/missing decrement (e.g. a `fetch_add` paired
    // with the wrong field, or a guard that never actually drops) - doesn't
    // prove the *increment* happened mid-flight, which needs a
    // never-resolving mock future to observe (not worth the complexity
    // here; the RAII shape itself, not this test, is what makes the
    // increment/decrement pairing provable).
    #[tokio::test]
    async fn resolve_doh_request_leaves_in_flight_at_zero_after_completing() {
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let state = state_with(client);

        if let Err(err) = resolve_doh_request(&wire_bytes, &state).await {
            panic!("must resolve: {err}");
        }

        assert_eq!(state.in_flight.load(Ordering::SeqCst), 0);
    }

    // T-147: resolve_doh_request is the one place that pushes a LogEntry -
    // a test at pipeline.rs's level can prove the metadata is computed
    // correctly, but only this layer can prove it actually reaches the log.
    #[tokio::test]
    async fn resolve_doh_request_pushes_a_log_entry_for_a_resolved_a_query() {
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let state = state_with(client);

        if let Err(err) = resolve_doh_request(&wire_bytes, &state).await {
            panic!("must resolve: {err}");
        }

        let entries = state.query_log.snapshot(std::time::SystemTime::now());
        assert_eq!(entries.len(), 1, "exactly one query must have been logged");
        assert_eq!(entries[0].domain, "example.com");
        assert_eq!(entries[0].decision, crate::query_log::Decision::Allowed);
        assert_eq!(
            entries[0].decision_source,
            crate::query_log::DecisionSource::Quorum
        );
    }

    // T-56: proves a real Timeout voter reaches both the log and
    // AdminStats's degraded_* counters through the actual production
    // wiring (resolve_doh_request -> pipeline::handle_query -> quorum::
    // resolve -> query_with_timeout -> LogEntry.voters -> compute_stats),
    // not just admin::degraded_counts in isolation - same bar T-153's own
    // closing note already sets for this crate.
    #[tokio::test(start_paused = true)]
    async fn resolve_doh_request_records_a_real_timeout_voter_and_marks_admin_stats_degraded() {
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(9, 9, 9, 9))),
            quorum: MockResponse::Pending,
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let state = state_with(client);

        if let Err(err) = resolve_doh_request(&wire_bytes, &state).await {
            panic!("must resolve: {err}");
        }

        let entries = state.query_log.snapshot(std::time::SystemTime::now());
        assert_eq!(entries.len(), 1, "exactly one query must have been logged");
        // T-155: *both* filtering voters time out here, so this is the
        // `BASELINE_FALLBACK` row (served via baseline under the default
        // `fail_open` toggle-off behaviour) — `degraded_counts` counts it
        // like a `QUORUM` row since it carries the same voter timeout data.
        assert_eq!(entries[0].decision_source, DecisionSource::BaselineFallback);
        // Assert the actual recorded mechanism first, not just the derived
        // stat below (advisor review: a `degraded_events > 0`-only
        // assertion could pass for the wrong reason - this crate's own
        // gotchas already record this exact "test doesn't prove its own
        // named property" shape three times before this one; a fourth,
        // empirically checked here: with both filtering voters Pending and
        // no Block signal ever produced, nothing triggers T-30's early-
        // return/cancellation path, so both voters genuinely run out
        // query_with_timeout's own timeout rather than getting dropped as
        // Canceled - confirmed by temporarily asserting `Canceled` instead
        // and watching it fail with `[Timeout, Timeout]`, then reverting).
        assert!(
            entries[0]
                .voters
                .iter()
                .any(|v| v.verdict == VoterVerdict::Timeout),
            "expected a real Timeout voter, got {:?}",
            entries[0]
                .voters
                .iter()
                .map(|v| v.verdict)
                .collect::<Vec<_>>()
        );

        // Exact equality, not `>= 1` - exactly one query was logged above,
        // so the counts are fully known, not just bounded.
        let status = admin_status(&state, true);
        assert_eq!(status.stats.degraded_window, 1);
        assert_eq!(status.stats.degraded_events, 1);
    }

    // T-147: the proxy path is a named, still-open gap - not logged yet.
    #[tokio::test]
    async fn resolve_doh_request_does_not_log_a_proxied_non_a_aaaa_query() {
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(9, 9, 9, 9))),
            quorum: MockResponse::Panic,
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::TXT);
        let state = state_with(client);

        if let Err(err) = resolve_doh_request(&wire_bytes, &state).await {
            panic!("must resolve: {err}");
        }

        assert!(state
            .query_log
            .snapshot(std::time::SystemTime::now())
            .is_empty());
    }

    #[tokio::test]
    async fn resolve_doh_request_proxies_a_non_a_aaaa_query_to_a_single_upstream() {
        // T-25: TXT never consults quorum - proving the baseline mock was
        // called (not the quorum branch, which panics on any call) is what
        // distinguishes "proxied" from "coincidentally also NOERROR".
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(9, 9, 9, 9))),
            quorum: MockResponse::Panic,
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::TXT);
        let state = state_with(client);

        if let Err(err) = resolve_doh_request(&wire_bytes, &state).await {
            panic!("must resolve: {err}");
        }
        assert_eq!(state.client.calls.load(Ordering::SeqCst), 1);
    }

    fn state_with(client: MockClient) -> Arc<AppState<MockClient>> {
        state_with_persist(
            client,
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: None,
            },
        )
    }

    // NB: a test that drives `POST /admin/reset` against a state built here
    // with `paths: Some(..)` must also take `crate::key_store::STORE_TEST_GUARD`
    // — `apply_admin_reset` reads the OS credential store (T-163), and that
    // backend races under concurrent access from one process.
    fn state_with_persist(client: MockClient, persist: PersistTarget) -> Arc<AppState<MockClient>> {
        state_with_overrides_and_persist(client, OverrideLists::empty(), persist)
    }

    /// Like [`state_with_persist`], but with pre-populated override lists
    /// (T-47) — tests exercising `/admin/overrides` need an existing entry
    /// to remove/observe conflicts against, not just an empty starting list.
    fn state_with_overrides_and_persist(
        client: MockClient,
        overrides: OverrideLists,
        persist: PersistTarget,
    ) -> Arc<AppState<MockClient>> {
        Arc::new(AppState::new(
            client,
            OverridesState {
                lists: overrides,
                invalid: Vec::new(),
            },
            RuntimeInit::default(),
            CacheState {
                cache: Cache::new(&CacheConfig::default()),
                config: CacheConfig::default(),
            },
            GeoipInit {
                database: GeoipState::default(),
                blocked_countries: Vec::new(),
                source: GeoipSource::DbIpLite,
            },
            QueryLog::default(),
            persist,
        ))
    }

    /// Like [`state_with`], but with a caller-supplied `GeoipState` (T-78) —
    /// `state_with`'s own `GeoipState::default()` (`reader: None`) can only
    /// ever exercise the "no database loaded" branch of
    /// `GeoipCountriesResponse::database_loaded`/`database_built_at_ms`.
    fn state_with_geoip_database(
        client: MockClient,
        database: GeoipState,
    ) -> Arc<AppState<MockClient>> {
        Arc::new(AppState::new(
            client,
            OverridesState {
                lists: OverrideLists::empty(),
                invalid: Vec::new(),
            },
            RuntimeInit::default(),
            CacheState {
                cache: Cache::new(&CacheConfig::default()),
                config: CacheConfig::default(),
            },
            GeoipInit {
                database,
                blocked_countries: Vec::new(),
                source: GeoipSource::DbIpLite,
            },
            QueryLog::default(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: None,
            },
        ))
    }

    fn no_op_client() -> MockClient {
        MockClient {
            baseline: MockResponse::Panic,
            quorum: MockResponse::Panic,
            calls: AtomicU32::new(0),
        }
    }

    #[tokio::test]
    async fn serve_returns_404_for_a_path_other_than_dns_query() {
        let req = match Request::builder()
            .method(Method::GET)
            .uri("/other")
            .body(Full::new(Bytes::new()))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // T-86: `/health` runs the local pipeline prefix and reports assembled
    // state; the default provider set (quad9 + adguard) is 2 enabled voters,
    // and the test state has no GeoIP database.
    #[tokio::test]
    async fn serve_health_returns_200_with_pipeline_status() {
        let req = match Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Full::new(Bytes::new()))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = body_bytes(response).await;
        let health: crate::admin::HealthResponse = match serde_json::from_slice(&bytes) {
            Ok(health) => health,
            Err(err) => panic!("/health body must decode: {err}"),
        };
        assert_eq!(health.active_providers, 2);
        assert_eq!(health.geoip, crate::admin::HealthGeoip::Absent);
    }

    #[tokio::test]
    async fn serve_returns_405_for_an_unsupported_method_on_dns_query() {
        let req = match Request::builder()
            .method(Method::DELETE)
            .uri("/dns-query")
            .body(Full::new(Bytes::new()))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn serve_returns_400_for_a_malformed_get_query_string() {
        let req = match Request::builder()
            .method(Method::GET)
            .uri("/dns-query?other=1")
            .body(Full::new(Bytes::new()))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serve_returns_400_for_a_post_with_the_wrong_content_type() {
        let req = match Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"irrelevant")))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serve_returns_413_for_an_oversized_post_body() {
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let req = match Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header(header::CONTENT_TYPE, "application/dns-message")
            .body(Full::new(Bytes::from(oversized)))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn serve_answers_a_valid_get_request_with_200_and_the_encoded_response() {
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let url = doh_get_url("/dns-query", &wire_bytes);
        let req = match Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Full::new(Bytes::new()))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let response = match serve(req, state_with(client)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/dns-message"))
        );
    }

    #[tokio::test]
    async fn serve_answers_a_valid_post_request_with_200() {
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let req = match Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header(header::CONTENT_TYPE, "application/dns-message")
            .body(Full::new(Bytes::from(wire_bytes)))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let response = match serve(req, state_with(client)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn body_bytes(response: http::Response<Full<Bytes>>) -> Bytes {
        use http_body_util::BodyExt;
        match response.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => match err {},
        }
    }

    fn admin_config_request(body: AdminConfigUpdate) -> Request<Full<Bytes>> {
        let Ok(json) = serde_json::to_vec(&body) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/config")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        req
    }

    #[tokio::test]
    async fn serve_admin_status_returns_the_default_live_settings() {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/status")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(status) = serde_json::from_slice::<AdminStatusResponse>(&bytes) else {
            panic!("response body must decode as AdminStatusResponse");
        };
        let active_ids: Vec<&str> = status
            .active_providers
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(active_ids, vec!["quad9", "adguard"]);
        assert!(status.persisted);
        assert!(
            !status.encrypted_persistence.query_log,
            "T-96: the default fixture has persist_query_log off"
        );
        assert!(
            !status.encrypted_persistence.cache,
            "T-97: the default fixture has persist_cache off"
        );
        assert_eq!(status.stats.total, 0);
        // `state_with` uses `paths: None`, so there is nowhere to read a
        // watchdog state file from (T-95).
        assert_eq!(status.watchdog, None);
    }

    // T-96 / T-97: `GET /admin/status` echoes both persistence flags from the
    // live `PersistTarget`, so each passive `/admin/ui` warning reflects the
    // actual state.
    #[tokio::test]
    async fn serve_admin_status_reports_the_persistence_flags_when_they_are_set() {
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: true,
                persist_cache: true,
                paths: None,
            },
        );
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/status")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        let bytes = body_bytes(response).await;
        let Ok(status) = serde_json::from_slice::<AdminStatusResponse>(&bytes) else {
            panic!("response body must decode as AdminStatusResponse");
        };
        assert!(status.encrypted_persistence.query_log);
        assert!(status.encrypted_persistence.cache);
    }

    fn watchdog_test_paths(dir: &std::path::Path) -> PersistPaths {
        PersistPaths {
            config: dir.join("resolver_config.toml"),
            overrides: dir.join("overrides.toml"),
        }
    }

    fn write_watchdog_fixture(dir: &std::path::Path, state: WatchdogState) {
        let file = WatchdogStateFile {
            schema_version: STATE_SCHEMA_VERSION,
            state,
            target: WatchdogTarget::Service,
            restart_attempts_in_window: 0,
            window_started_at: None,
            last_transition_at: SystemTime::UNIX_EPOCH,
            last_error: None,
        };
        if let Err(err) = write_watchdog_state(dir, &file) {
            panic!("write_watchdog_state must succeed: {err}");
        }
    }

    // Happy + boundary: the two UI-surfaced states, and BackoffWait folding into
    // Restarting (T-95).
    #[test]
    fn read_watchdog_view_projects_the_ui_relevant_states() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir must be creatable");
        };
        let paths = watchdog_test_paths(dir.path());

        for state in [WatchdogState::Restarting, WatchdogState::BackoffWait] {
            write_watchdog_fixture(dir.path(), state);
            assert_eq!(
                read_watchdog_view(Some(&paths), SystemTime::now()),
                Some(WatchdogStatusView::Restarting),
                "{state:?} -> RESTARTING"
            );
        }

        write_watchdog_fixture(dir.path(), WatchdogState::GaveUp);
        assert_eq!(
            read_watchdog_view(Some(&paths), SystemTime::now()),
            Some(WatchdogStatusView::GaveUp)
        );
    }

    // The four internal automaton steps are not shown — they map to `None`, not
    // a fabricated "healthy" reading.
    #[test]
    fn read_watchdog_view_hides_the_internal_states() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir must be creatable");
        };
        let paths = watchdog_test_paths(dir.path());
        for state in [
            WatchdogState::Healthy,
            WatchdogState::ChannelDegraded,
            WatchdogState::SuspectDead,
            WatchdogState::VerifyingPid,
        ] {
            write_watchdog_fixture(dir.path(), state);
            assert_eq!(
                read_watchdog_view(Some(&paths), SystemTime::now()),
                None,
                "{state:?} is an internal step"
            );
        }
    }

    // Misuse: a state file the watcher has stopped rewriting (its `mtime` is
    // old) reads as `None` — "watchdog not running" — never the recorded state.
    #[test]
    fn read_watchdog_view_is_none_for_a_stale_file() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir must be creatable");
        };
        let paths = watchdog_test_paths(dir.path());
        write_watchdog_fixture(dir.path(), WatchdogState::Restarting);
        let long_after = SystemTime::now() + Duration::from_secs(3600);
        assert_eq!(read_watchdog_view(Some(&paths), long_after), None);
    }

    // Error: no persist paths, no file, and a corrupt file all yield `None`,
    // never a panic or a 500.
    #[test]
    fn read_watchdog_view_is_none_for_absent_missing_or_corrupt() {
        assert_eq!(read_watchdog_view(None, SystemTime::now()), None);

        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir must be creatable");
        };
        let paths = watchdog_test_paths(dir.path());
        assert_eq!(
            read_watchdog_view(Some(&paths), SystemTime::now()),
            None,
            "no state file yet"
        );

        if let Err(err) = std::fs::write(dir.path().join(crate::STATE_FILE_NAME), b"{ not json") {
            panic!("fixture write must succeed: {err}");
        }
        assert_eq!(
            read_watchdog_view(Some(&paths), SystemTime::now()),
            None,
            "a corrupt file must not panic or 500"
        );
    }

    #[tokio::test]
    async fn serve_admin_status_rejects_non_get_methods() {
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/status")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn serve_admin_config_rejects_non_post_methods() {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/config")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn serve_admin_config_rejects_a_malformed_body() {
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/config")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"not json")))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // T-52, advisor-caught before commit: without this gate, a `text/plain`
    // (or missing) Content-Type is a CORS *simple* request - no preflight -
    // so any page the browser is rendering could silently flip filtering off
    // for the whole machine the moment cert.pem is trust-store-installed
    // (T-49). This test is the CSRF defense's own regression test, not a
    // format nicety - see `content_type_is_json`'s doc comment.
    #[tokio::test]
    async fn serve_admin_config_rejects_a_missing_content_type_even_with_a_valid_json_body() {
        let update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::FailOpen,
            serve_baseline_when_filters_unreachable: false,
        };
        let Ok(json) = serde_json::to_vec(&update) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/config")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn serve_admin_config_rejects_a_non_json_content_type_even_with_a_valid_json_body() {
        let update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::FailOpen,
            serve_baseline_when_filters_unreachable: false,
        };
        let Ok(json) = serde_json::to_vec(&update) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/config")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // T-52/T-72: both providers disabled (now via `/admin/providers/set-enabled`)
    // is a live-reachable state - the exact regression shape T-148 proved at
    // the quorum::resolve level
    // (quad9_disabled_under_fail_closed_is_still_allow_not_falsely_blocked),
    // re-proven here at the HTTP admin-channel level: under fail_closed it
    // must still resolve via pass-through, never fail-closed-block, and must
    // never call the quorum-branch mock at all.
    #[tokio::test]
    async fn disabling_every_provider_is_pass_through_not_fail_closed() {
        let ip = Ipv4Addr::new(9, 9, 9, 9);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Panic,
            calls: AtomicU32::new(0),
        };
        let state = state_with(client);

        let update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::FailClosed,
            serve_baseline_when_filters_unreachable: false,
        };
        let config_response = match serve(admin_config_request(update), Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(config_response.status(), StatusCode::OK);
        for id in ["quad9", "adguard"] {
            let response = match serve(
                admin_post_json(
                    "/admin/providers/set-enabled",
                    &serde_json::json!({"id": id, "enabled": false}),
                ),
                Arc::clone(&state),
            )
            .await
            {
                Ok(response) => response,
                Err(err) => match err {},
            };
            assert_eq!(response.status(), StatusCode::OK);
        }

        let providers = providers_json(Arc::clone(&state)).await;
        assert!(
            !providers.filtering_active,
            "no voter enabled — the UI must be told filtering is off"
        );
        assert_eq!(providers.third_party_count, 1, "baseline only");

        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let query_req = match Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header(header::CONTENT_TYPE, "application/dns-message")
            .body(Full::new(Bytes::from(wire_bytes)))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(query_req, state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "pass-through must still resolve, not fail-closed-block"
        );
    }

    #[tokio::test]
    async fn serve_admin_config_persists_a_change_to_disk_when_a_config_path_is_set() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );

        let update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::FailClosed,
            serve_baseline_when_filters_unreachable: false,
        };
        let response = match serve(admin_config_request(update), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(status) = serde_json::from_slice::<AdminStatusResponse>(&bytes) else {
            panic!("response body must decode as AdminStatusResponse");
        };
        assert!(status.persisted);

        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the saved file must load back: {err}"),
        };
        assert_eq!(loaded.timeout_mode, update.timeout_mode);
        // T-72/T-73 cross-field read: a timeout-only change must still write
        // the live provider list, not blank `[[providers]]`.
        assert_eq!(loaded.providers, ProviderEntry::default_active_set());
    }

    // T-155: the new toggle round-trips through POST /admin/config -> the
    // echoed status, the live runtime, and resolver_config.toml, and a
    // change to it doesn't blank the timeout mode or provider list.
    #[tokio::test]
    async fn serve_admin_config_round_trips_the_baseline_fallback_toggle() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );

        let update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::Degraded,
            serve_baseline_when_filters_unreachable: true,
        };
        let response = match serve(admin_config_request(update), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(status) = serde_json::from_slice::<AdminStatusResponse>(&bytes) else {
            panic!("response body must decode as AdminStatusResponse");
        };
        assert!(status.serve_baseline_when_filters_unreachable);
        assert_eq!(status.timeout_mode, crate::timeout::TimeoutMode::Degraded);
        assert!(status.persisted);

        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the saved file must load back: {err}"),
        };
        assert!(loaded.serve_baseline_when_filters_unreachable);
        assert_eq!(loaded.timeout_mode, crate::timeout::TimeoutMode::Degraded);
        assert_eq!(loaded.providers, ProviderEntry::default_active_set());
    }

    // T-146 / T-97 cross-field read: neither `persist_query_log` nor
    // `persist_cache` has an admin route, but an unrelated POST /admin/config
    // still re-serializes the whole file - so both live values (from
    // PersistTarget) must survive the write, not reset to `false`.
    #[tokio::test]
    async fn serve_admin_config_preserves_persist_flags_on_an_unrelated_write() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: true,
                persist_cache: true,
                paths: Some(PersistPaths {
                    config: path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );

        let update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::FailClosed,
            serve_baseline_when_filters_unreachable: false,
        };
        match serve(admin_config_request(update), state).await {
            Ok(response) => assert_eq!(response.status(), StatusCode::OK),
            Err(err) => match err {},
        }

        match ResolverConfig::load(&path) {
            Ok(loaded) => {
                assert!(
                    loaded.persist_query_log,
                    "an unrelated config write must not blank persist_query_log"
                );
                assert!(
                    loaded.persist_cache,
                    "an unrelated config write must not blank persist_cache"
                );
            }
            Err(err) => panic!("the saved file must load back: {err}"),
        }
    }

    // T-76, advisor-caught before commit: an unrelated `POST /admin/config`
    // (providers/timeout-mode only) must not silently wipe a hand-edited
    // `[geoip] blocked_countries` on save - the same "backend snapshots the
    // *other* field's live value too" discipline `persist_lock`'s own doc
    // comment already documents for `providers`/`timeout_mode`/`cache`,
    // extended here to `geoip_countries`. Without the cross-field read this
    // test would fail (the saved file's `[geoip]` table would come back
    // empty).
    #[tokio::test]
    async fn serve_admin_config_does_not_wipe_a_preexisting_geoip_blocked_country_list() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );
        state.update_geoip_countries(vec!["SE".to_string()]);

        let update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::FailClosed,
            serve_baseline_when_filters_unreachable: false,
        };
        let response = match serve(admin_config_request(update), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the saved file must load back: {err}"),
        };
        assert_eq!(
            loaded.geoip.blocked_countries,
            vec!["SE".to_string()],
            "an unrelated providers/timeout-mode change must not wipe the geoip country list"
        );
    }

    // T-58, SPEC.md §8.1's "rapid toggle race" misuse example. Several
    // `POST /admin/config` calls run concurrently (real OS-thread
    // parallelism, `flavor = "multi_thread"` - a current-thread runtime
    // could never interleave these at all, since `apply_admin_config` itself
    // has no `.await` point to yield at) and every one must complete
    // successfully. This is a genuine, empirically-confirmed regression test,
    // not a vacuous one (same discipline T-59's `ROUTES` fix established -
    // verified by watching it fail, not assumed from reading the code): with
    // `state.persist_lock` reverted, this test failed 16/20 runs on this dev
    // machine (`cargo test -- --test-threads=1`, looped); with the lock in
    // place, 20/20 passed. The race window around one small `fs::write` is
    // real and reliably hits under actual thread contention, not just a
    // theoretical concern. What this test proves: no deadlock under real
    // contention, and after every call finishes, the live in-memory settings
    // and the on-disk file agree with each other on *some* one of the applied
    // updates - never a value that matches neither (which a broken
    // read-modify-write, not just a persist-ordering race, could produce).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_admin_config_posts_leave_disk_matching_live_settings() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let config_path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: config_path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );

        let updates = [
            AdminConfigUpdate {
                timeout_mode: crate::timeout::TimeoutMode::FailOpen,
                serve_baseline_when_filters_unreachable: false,
            },
            AdminConfigUpdate {
                timeout_mode: crate::timeout::TimeoutMode::FailClosed,
                serve_baseline_when_filters_unreachable: false,
            },
            AdminConfigUpdate {
                timeout_mode: crate::timeout::TimeoutMode::Degraded,
                serve_baseline_when_filters_unreachable: false,
            },
        ];

        let mut handles = Vec::new();
        for update in updates {
            let state = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                match serve(admin_config_request(update), state).await {
                    Ok(response) => response.status(),
                    Err(err) => match err {},
                }
            }));
        }
        for handle in handles {
            match handle.await {
                Ok(status) => assert_eq!(status, StatusCode::OK),
                Err(err) => panic!("admin config task must not panic: {err}"),
            }
        }

        let live = *state.runtime.read();
        let loaded = match ResolverConfig::load(&config_path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the persisted file must still load: {err}"),
        };
        assert_eq!(
            loaded.timeout_mode, live.timeout.mode,
            "disk must match the live settings after concurrent admin config writes"
        );
        assert!(
            updates.iter().any(|u| u.timeout_mode == live.timeout.mode),
            "final live settings must match one of the applied updates exactly, not a mix"
        );
    }

    #[tokio::test]
    async fn serve_admin_config_reports_not_persisted_when_no_config_path_is_set() {
        let state = state_with(no_op_client());
        let update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::FailOpen,
            serve_baseline_when_filters_unreachable: false,
        };
        let response = match serve(admin_config_request(update), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(status) = serde_json::from_slice::<AdminStatusResponse>(&bytes) else {
            panic!("response body must decode as AdminStatusResponse");
        };
        assert!(!status.persisted);
    }

    #[tokio::test]
    async fn serve_admin_reset_rejects_non_post_methods() {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/reset")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    // T-149, mirrors serve_admin_config_rejects_a_missing_content_type_even_with_a_valid_json_body
    // - same CSRF gate, same regression risk: a nominally-no-body mutating
    // route is exactly the one a naive implementation forgets to gate
    // (advisor-caught in the plan review, not a test written first).
    #[tokio::test]
    async fn serve_admin_reset_rejects_a_missing_content_type() {
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/reset")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    fn admin_reset_request() -> Request<Full<Bytes>> {
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/reset")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        req
    }

    #[tokio::test]
    async fn serve_admin_reset_returns_500_with_no_app_data_configured() {
        let response = match serve(admin_reset_request(), state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // T-58, SPEC.md §8.1's "malformed override file" misuse example:
    // apply_admin_reset's prepare-then-commit discipline (its own doc
    // comment) means a malformed overrides.toml must leave live state
    // untouched, not half-updated - proven here via Arc pointer identity
    // (the exact same Arc, not just an equal-looking one) rather than value
    // equality, the strongest available proof that no swap happened at all.
    #[tokio::test]
    async fn serve_admin_reset_returns_500_for_a_malformed_overrides_file_and_leaves_state_untouched(
    ) {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let config_path = dir.path().join("resolver_config.toml");
        let overrides_path = dir.path().join("overrides.toml");
        if let Err(err) = std::fs::write(
            &config_path,
            "port = 8443\ntimeout_mode = \"fail_open\"\ntimeout_ms = 2000\n",
        ) {
            panic!("must be able to write the fixture config: {err}");
        }
        if let Err(err) = std::fs::write(&overrides_path, "not valid toml ===") {
            panic!("must be able to write the fixture overrides file: {err}");
        }

        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: config_path,
                    overrides: overrides_path,
                }),
            },
        );
        let before_overrides = std::sync::Arc::as_ptr(&state.overrides.read());
        let before_runtime = *state.runtime.read();
        let before_providers = std::sync::Arc::as_ptr(&state.providers.read());

        let response = match serve(admin_reset_request(), Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            std::sync::Arc::as_ptr(&state.overrides.read()),
            before_overrides,
            "a malformed overrides file must never swap in a new (even empty) OverrideLists"
        );
        assert_eq!(
            std::sync::Arc::as_ptr(&state.providers.read()),
            before_providers,
            "a failed reset must not swap in a new provider list"
        );
        let after_runtime = *state.runtime.read();
        assert_eq!(after_runtime.timeout.mode, before_runtime.timeout.mode);
        assert_eq!(
            after_runtime.timeout.duration,
            before_runtime.timeout.duration
        );
    }

    // T-58, SPEC.md §8.1's "huge override file" misuse example, at the
    // config-file sibling instead: config::MAX_CONFIG_FILE_SIZE's own
    // rejection (unit-tested directly in config.rs) must actually surface as
    // a real 500 through the admin-reset route, not get lost in translation.
    #[tokio::test]
    async fn serve_admin_reset_returns_500_for_an_oversized_resolver_config_file() {
        // `apply_admin_reset` reads the OS credential store (T-163); serialize
        // like every other credential-store test in this crate.
        let _store_guard = store_test_guard();
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let config_path = dir.path().join("resolver_config.toml");
        let oversized = "#".repeat(70 * 1024);
        if let Err(err) = std::fs::write(&config_path, oversized) {
            panic!("must be able to write the fixture config: {err}");
        }
        let overrides_path = dir.path().join("overrides.toml");

        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: config_path,
                    overrides: overrides_path,
                }),
            },
        );

        let response = match serve(admin_reset_request(), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn serve_admin_reset_reloads_settings_and_clears_state() {
        let _store_guard = store_test_guard();
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let config_path = dir.path().join("resolver_config.toml");
        let overrides_path = dir.path().join("overrides.toml");
        if let Err(err) = std::fs::write(
            &config_path,
            concat!(
                "port = 8443\ntimeout_mode = \"fail_closed\"\ntimeout_ms = 3000\n\n",
                "[[providers]]\nid = \"quad9\"\nenabled = false\n\n",
                "[[providers]]\nid = \"adguard\"\nenabled = true\n"
            ),
        ) {
            panic!("must be able to write the fixture config: {err}");
        }
        // A real entry, not an empty file - an empty→empty overrides swap
        // would pass even if the load path/swap itself were broken
        // (advisor-caught: same shape as `IsCa::NoCa`'s own "passes because
        // the extension is absent, not because the bytes say so" gotcha).
        // The post-reset query below proves this landed end to end, not
        // just that `state.overrides` holds *some* value.
        if let Err(err) = std::fs::write(&overrides_path, "blocklist = [\"reset-fixture.test\"]\n")
        {
            panic!("must be able to write the fixture overrides file: {err}");
        }

        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let state = state_with_persist(
            client,
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: config_path,
                    overrides: overrides_path,
                }),
            },
        );

        // Prime the query log with one entry so the test can prove reset
        // actually clears it, not just that it returns 200.
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        if let Err(err) = resolve_doh_request(&wire_bytes, &state).await {
            panic!("priming query must resolve: {err}");
        }
        assert_eq!(
            state.query_log.snapshot(std::time::SystemTime::now()).len(),
            1,
            "priming query must have been logged"
        );

        let response = match serve(admin_reset_request(), Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(status) = serde_json::from_slice::<AdminStatusResponse>(&bytes) else {
            panic!("response body must decode as AdminStatusResponse");
        };
        let active_ids: Vec<&str> = status
            .active_providers
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(
            active_ids,
            vec!["adguard"],
            "reset must reload providers from the fixture file (quad9 disabled)"
        );
        assert_eq!(
            status.timeout_mode,
            crate::timeout::TimeoutMode::FailClosed,
            "reset must reload timeout_mode from the fixture file"
        );
        assert_eq!(status.stats.total, 0, "reset must clear the query log");
        assert!(status.persisted);

        assert!(
            state
                .query_log
                .snapshot(std::time::SystemTime::now())
                .is_empty(),
            "the live query log must actually be empty, not just reported as 0"
        );

        // Proves the overrides swap itself actually took effect (not just
        // that *some* `OverrideLists` value is present) - a fresh query for
        // the fixture's blocklisted domain must be blocked without ever
        // reaching the quorum mock (which would panic if called, since
        // `resolve-fixture.test` was never part of the Instant-response
        // fixtures above).
        let blocklisted_wire_bytes = query_bytes("reset-fixture.test.", RecordType::A);
        if let Err(err) = resolve_doh_request(&blocklisted_wire_bytes, &state).await {
            panic!("post-reset blocklisted query must still resolve: {err}");
        }
        let entries = state.query_log.snapshot(std::time::SystemTime::now());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "reset-fixture.test");
        assert_eq!(entries[0].decision, crate::query_log::Decision::Blocked);
        assert_eq!(
            entries[0].decision_source,
            crate::query_log::DecisionSource::Blocklist
        );
    }

    // T-153, advisor-caught gap: `serve_admin_reset_reloads_settings_and_clears_state`
    // above proves `providers`/`timeout_mode` reload, but reset's own new
    // behaviour this slice added - rebuilding `state.cache` from the
    // fixture's `[cache]` table, not just clearing it - had no test at all.
    // `serve_admin_reset_reloads_settings_and_clears_state`'s own log-clear
    // assertion would pass identically whether or not `[cache]` was ever
    // read, since a plain `Cache::clear()` looks the same from outside as a
    // config-driven rebuild unless the *config* values themselves are
    // checked. Values chosen to differ from every field of
    // `CacheConfig::default()` (30s/24h/24h/24h/10_000), so a silently
    // unread `[cache]` table would fail every assertion below, not just one.
    #[tokio::test]
    async fn serve_admin_reset_reloads_cache_config_from_the_fixture_file() {
        let _store_guard = store_test_guard();
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let config_path = dir.path().join("resolver_config.toml");
        let overrides_path = dir.path().join("overrides.toml");
        if let Err(err) = std::fs::write(
            &config_path,
            "port = 8443\ntimeout_mode = \"fail_open\"\ntimeout_ms = 2000\n\n\
             [cache]\nclamp_min_secs = 45\nclamp_max_secs = 1800\n\
             block_verdict_ttl_secs = 1800\nstale_grace_secs = 43200\n\
             max_capacity = 2500\n",
        ) {
            panic!("must be able to write the fixture config: {err}");
        }
        if let Err(err) = std::fs::write(&overrides_path, "") {
            panic!("must be able to write the fixture overrides file: {err}");
        }

        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: config_path,
                    overrides: overrides_path,
                }),
            },
        );

        let response = match serve(admin_reset_request(), Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let cache_config = state.cache.read().config;
        let Ok(expected) = CacheConfig::from_secs(45, 1800, 1800, 43_200, 2_500) else {
            panic!("fixture values must be a valid CacheConfig");
        };
        assert_eq!(
            cache_config, expected,
            "reset must reload [cache] from the fixture file, not just clear the cache"
        );
    }

    // T-76, advisor-caught gap: /admin/reset must reload [geoip]
    // blocked_countries too, same completeness requirement as
    // `serve_admin_reset_reloads_cache_config_from_the_fixture_file` above -
    // a hand-edited country list must take effect on the next reset, not
    // wait for a process restart. Built with a real, loaded GeoipReader
    // (the vendored fixture geoip.rs's own tests use), not
    // `GeoipState::default()` - a `reader: None` state would make this
    // test's whole subject (`blocks_any`) short-circuit to false regardless
    // of whether the reload actually happened, proving nothing.
    #[tokio::test]
    async fn serve_admin_reset_reloads_the_geoip_blocked_country_list_from_the_fixture_file() {
        let _store_guard = store_test_guard();
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let config_path = dir.path().join("resolver_config.toml");
        let overrides_path = dir.path().join("overrides.toml");
        if let Err(err) = std::fs::write(
            &config_path,
            "port = 8443\ntimeout_mode = \"fail_open\"\ntimeout_ms = 2000\n\n\
             [geoip]\nblocked_countries = [\"se\"]\n",
        ) {
            panic!("must be able to write the fixture config: {err}");
        }
        if let Err(err) = std::fs::write(&overrides_path, "") {
            panic!("must be able to write the fixture overrides file: {err}");
        }
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/geoip/GeoIP2-Country-Test.mmdb");
        let Ok(reader) = crate::geoip::GeoipReader::open(&fixture_path) else {
            panic!("geoip fixture must load");
        };

        let state = Arc::new(AppState::new(
            no_op_client(),
            OverridesState {
                lists: OverrideLists::empty(),
                invalid: Vec::new(),
            },
            RuntimeInit::default(),
            CacheState {
                cache: Cache::new(&CacheConfig::default()),
                config: CacheConfig::default(),
            },
            GeoipInit {
                database: GeoipState {
                    reader: Some(Arc::new(reader)),
                    updated_at: None,
                },
                // Starts empty - the reset below is what must populate it
                // from the fixture file's own [geoip] table.
                blocked_countries: Vec::new(),
                source: GeoipSource::DbIpLite,
            },
            QueryLog::default(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: config_path,
                    overrides: overrides_path,
                }),
            },
        ));

        let response = match serve(admin_reset_request(), Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        // ResolverConfig::load normalizes to uppercase - the swapped-in live
        // value must reflect that, not the raw lowercase file text.
        assert_eq!(
            **state.geoip_countries.read(),
            vec!["SE".to_string()],
            "reset must reload [geoip] blocked_countries from the fixture file"
        );
        // And the reload is real, not just a stored string - the actual
        // filter this crate ships (geoip::blocking_country) must now block
        // the fixture's own known-good SE address.
        let se_ip: std::net::IpAddr = match "89.160.20.112".parse() {
            Ok(ip) => ip,
            Err(err) => panic!("valid IPv4 literal: {err}"),
        };
        let geoip_snapshot = Arc::clone(&state.geoip.read());
        let countries_snapshot = Arc::clone(&state.geoip_countries.read());
        assert_eq!(
            crate::geoip::blocking_country(
                geoip_snapshot.reader.as_deref(),
                &countries_snapshot,
                &[se_ip]
            ),
            Some("SE".to_string()),
            "the reloaded country list must actually block the fixture's known SE address"
        );
    }

    fn admin_overrides_add_request(pattern: &str, list: ListKind) -> Request<Full<Bytes>> {
        let Ok(json) = serde_json::to_vec(&OverrideAddRequest {
            pattern: pattern.to_string(),
            list,
        }) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/overrides/add")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        req
    }

    fn admin_overrides_remove_request(
        domain: &str,
        is_wildcard: bool,
        list: ListKind,
    ) -> Request<Full<Bytes>> {
        let Ok(json) = serde_json::to_vec(&OverrideRemoveRequest {
            domain: domain.to_string(),
            is_wildcard,
            list,
        }) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/overrides/remove")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        req
    }

    #[tokio::test]
    async fn serve_admin_overrides_returns_the_current_lists_and_conflicts() {
        let overrides = OverrideLists::from_entries_for_test(vec![
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
        let state = state_with_overrides_and_persist(
            no_op_client(),
            overrides,
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: None,
            },
        );
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/overrides")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<OverrideListsResponse>(&bytes) else {
            panic!("response body must decode as OverrideListsResponse");
        };
        assert_eq!(body.allowlist.len(), 1);
        assert_eq!(body.blocklist.len(), 1);
        assert_eq!(body.conflicts, vec!["example.com".to_string()]);
    }

    #[tokio::test]
    async fn serve_admin_overrides_add_appends_a_new_entry_and_it_is_visible_on_the_next_get() {
        let state = state_with(no_op_client());
        let response = match serve(
            admin_overrides_add_request("example.com", ListKind::Blocklist),
            Arc::clone(&state),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<OverrideListsResponse>(&bytes) else {
            panic!("response body must decode as OverrideListsResponse");
        };
        assert_eq!(body.blocklist.len(), 1);
        assert_eq!(body.blocklist[0].domain, "example.com");
        assert!(!body.blocklist[0].is_wildcard);
        // T-47, advisor-caught: `state_with` sets `paths: None`, so this
        // change live-applies but can't persist - the response must say so,
        // the same "in-memory change succeeded, disk write didn't" honesty
        // `AdminConfigUpdate`'s own `persisted` field already established.
        assert!(!body.persisted);
    }

    #[tokio::test]
    async fn serve_admin_overrides_add_rejects_an_invalid_pattern() {
        let state = state_with(no_op_client());
        let response = match serve(
            admin_overrides_add_request("*.*.broken.example", ListKind::Blocklist),
            state,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // Same CSRF concern as `/admin/config` (T-52) - see
    // `content_type_is_json`'s own doc comment. A missing/`text/plain`
    // `Content-Type` is a CORS *simple* request with no preflight, so this
    // gate is the whole defense, not a format nicety.
    #[tokio::test]
    async fn serve_admin_overrides_add_rejects_a_missing_content_type() {
        let Ok(json) = serde_json::to_vec(&OverrideAddRequest {
            pattern: "example.com".to_string(),
            list: ListKind::Blocklist,
        }) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/overrides/add")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn serve_admin_overrides_remove_removes_the_matching_entry() {
        let overrides = OverrideLists::from_entries_for_test(vec![OverrideEntry {
            domain: "example.com".to_string(),
            is_wildcard: false,
            list: ListKind::Blocklist,
        }]);
        let state = state_with_overrides_and_persist(
            no_op_client(),
            overrides,
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: None,
            },
        );
        let response = match serve(
            admin_overrides_remove_request("example.com", false, ListKind::Blocklist),
            state,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<OverrideListsResponse>(&bytes) else {
            panic!("response body must decode as OverrideListsResponse");
        };
        assert!(body.blocklist.is_empty());
    }

    // T-47, advisor-caught before implementing: `OverrideLists` only ever
    // holds successfully-*parsed* entries - a save() triggered by an
    // unrelated add must not silently delete a pre-existing line that failed
    // to parse. Proves the raw line survives a save()+reload round trip
    // through the actual admin route, not just through `OverrideLists::save`
    // directly (already covered in `overrides.rs`'s own unit test).
    #[tokio::test]
    async fn serve_admin_overrides_add_persists_and_preserves_a_pre_existing_invalid_line() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let overrides_path = dir.path().join("overrides.toml");
        if let Err(err) = std::fs::write(
            &overrides_path,
            "blocklist = [\"already-here.test\", \"*.*.broken.example\"]\n",
        ) {
            panic!("must be able to write the fixture overrides file: {err}");
        }
        let (overrides, invalid) = match OverrideLists::load(&overrides_path) {
            Ok(result) => result,
            Err(err) => panic!("fixture file must load: {err}"),
        };
        assert_eq!(invalid.len(), 1, "fixture must contain one invalid line");
        let state = Arc::new(AppState::new(
            no_op_client(),
            OverridesState {
                lists: overrides,
                invalid,
            },
            RuntimeInit::default(),
            CacheState {
                cache: Cache::new(&CacheConfig::default()),
                config: CacheConfig::default(),
            },
            GeoipInit {
                database: GeoipState::default(),
                blocked_countries: Vec::new(),
                source: GeoipSource::DbIpLite,
            },
            QueryLog::default(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: dir.path().join("resolver_config.toml"),
                    overrides: overrides_path.clone(),
                }),
            },
        ));

        let response = match serve(
            admin_overrides_add_request("new.example.com", ListKind::Allowlist),
            state,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<OverrideListsResponse>(&bytes) else {
            panic!("response body must decode as OverrideListsResponse");
        };
        assert!(body.persisted, "a real path is set, so this must persist");

        let (reloaded, reloaded_invalid) = match OverrideLists::load(&overrides_path) {
            Ok(result) => result,
            Err(err) => panic!("the saved file must load back: {err}"),
        };
        let block_decision = match reloaded.decision("already-here.test") {
            Ok(decision) => decision,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(
            block_decision,
            Some(ListKind::Blocklist),
            "the pre-existing valid entry must survive"
        );
        let allow_decision = match reloaded.decision("new.example.com") {
            Ok(decision) => decision,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(allow_decision, Some(ListKind::Allowlist));
        assert_eq!(
            reloaded_invalid.len(),
            1,
            "the pre-existing invalid line must survive the save, not be silently dropped"
        );
        assert_eq!(reloaded_invalid[0].raw, "*.*.broken.example");
    }

    #[tokio::test]
    async fn serve_admin_overrides_add_invalidates_a_cached_verdict_for_the_newly_blocked_domain() {
        let state = state_with(no_op_client());
        let Ok(key) = CacheKey::new("cache-inval.test", RecordType::A) else {
            panic!("valid fixture domain");
        };
        let cache_state = Arc::clone(&state.cache.read());
        cache_state
            .cache
            .insert(
                key.clone(),
                CacheEntry::new(
                    Verdict::Allow(vec![Ipv4Addr::new(1, 2, 3, 4).into()]),
                    std::time::Duration::from_secs(300),
                ),
            )
            .await;
        assert!(cache_state.cache.get(&key).await.is_some());

        let response = match serve(
            admin_overrides_add_request("cache-inval.test", ListKind::Blocklist),
            Arc::clone(&state),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            cache_state.cache.get(&key).await.is_none(),
            "adding a blocklist entry must invalidate the domain's cached verdict"
        );
    }

    // Same discipline as `concurrent_admin_config_posts_leave_disk_matching_
    // live_settings` (T-58), applied to `overrides_persist_lock` - but the
    // property this asserts is the *stronger* one an advisor review flagged
    // as the actual risk here: without the lock, two concurrent adds both
    // read the same base list, each computes base+own-entry, and the second
    // swap silently discards the first add - a genuine lost update, not just
    // a disk/memory mismatch (both would still consistently show the losing
    // state, so a weaker "disk matches live" assertion wouldn't catch it).
    // Empirically confirmed, not assumed: with `overrides_persist_lock`
    // temporarily reverted to a no-op, this test failed most runs under
    // real OS-thread contention; with the lock in place, it passes
    // consistently.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_admin_overrides_add_posts_lose_no_updates() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let overrides_path = dir.path().join("overrides.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: dir.path().join("resolver_config.toml"),
                    overrides: overrides_path.clone(),
                }),
            },
        );

        let domains = ["a.example.com", "b.example.com", "c.example.com"];
        let mut handles = Vec::new();
        for domain in domains {
            let state = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                match serve(
                    admin_overrides_add_request(domain, ListKind::Blocklist),
                    state,
                )
                .await
                {
                    Ok(response) => response.status(),
                    Err(err) => match err {},
                }
            }));
        }
        for handle in handles {
            match handle.await {
                Ok(status) => assert_eq!(status, StatusCode::OK),
                Err(err) => panic!("admin overrides add task must not panic: {err}"),
            }
        }

        let live = Arc::clone(&state.overrides.read());
        let (reloaded, _) = match OverrideLists::load(&overrides_path) {
            Ok(result) => result,
            Err(err) => panic!("the persisted file must still load: {err}"),
        };
        for domain in domains {
            let live_decision = match live.lists.decision(domain) {
                Ok(decision) => decision,
                Err(err) => panic!("expected Ok: {err}"),
            };
            assert_eq!(
                live_decision,
                Some(ListKind::Blocklist),
                "{domain} must be present in the live list - a lost update if missing"
            );
            let disk_decision = match reloaded.decision(domain) {
                Ok(decision) => decision,
                Err(err) => panic!("expected Ok: {err}"),
            };
            assert_eq!(
                disk_decision,
                Some(ListKind::Blocklist),
                "{domain} must be present in the persisted file"
            );
        }
    }

    #[tokio::test]
    async fn serve_routes_admin_ui_to_the_embedded_html_document() {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/ui")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/html; charset=utf-8"
            ))
        );
    }

    fn admin_cache_config_apply_request(update: CacheConfigUpdate) -> Request<Full<Bytes>> {
        let Ok(json) = serde_json::to_vec(&update) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/cache-config/apply")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        req
    }

    fn non_default_cache_config_update() -> CacheConfigUpdate {
        CacheConfigUpdate {
            clamp_min_secs: 45,
            clamp_max_secs: 1800,
            block_verdict_ttl_secs: 1800,
            stale_grace_secs: 43_200,
            max_capacity: 2_500,
        }
    }

    #[tokio::test]
    async fn serve_admin_cache_config_returns_the_default_live_settings() {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/cache-config")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(view) = serde_json::from_slice::<CacheConfigView>(&bytes) else {
            panic!("response body must decode as CacheConfigView");
        };
        let defaults = CacheConfig::default().to_secs();
        assert_eq!(view.clamp_min_secs, defaults.clamp_min_secs);
        assert_eq!(view.clamp_max_secs, defaults.clamp_max_secs);
        assert_eq!(view.max_capacity, defaults.max_capacity);
        assert!(view.persisted);
    }

    #[tokio::test]
    async fn serve_admin_cache_config_apply_updates_the_live_settings() {
        let state = state_with(no_op_client());
        let update = non_default_cache_config_update();
        let response = match serve(admin_cache_config_apply_request(update), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(view) = serde_json::from_slice::<CacheConfigView>(&bytes) else {
            panic!("response body must decode as CacheConfigView");
        };
        assert_eq!(view.clamp_min_secs, update.clamp_min_secs);
        assert_eq!(view.clamp_max_secs, update.clamp_max_secs);
        assert_eq!(view.block_verdict_ttl_secs, update.block_verdict_ttl_secs);
        assert_eq!(view.stale_grace_secs, update.stale_grace_secs);
        assert_eq!(view.max_capacity, update.max_capacity);
    }

    #[tokio::test]
    async fn serve_admin_cache_config_apply_rejects_an_inverted_clamp_range() {
        let state = state_with(no_op_client());
        let update = CacheConfigUpdate {
            clamp_min_secs: 100,
            clamp_max_secs: 10,
            ..non_default_cache_config_update()
        };
        let response = match serve(admin_cache_config_apply_request(update), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // Same CSRF concern as `/admin/config`/`/admin/overrides/add` (T-52/T-47)
    // - see `content_type_is_json`'s own doc comment.
    #[tokio::test]
    async fn serve_admin_cache_config_apply_rejects_a_missing_content_type() {
        let Ok(json) = serde_json::to_vec(&non_default_cache_config_update()) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/cache-config/apply")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn serve_admin_cache_config_apply_persists_a_change_to_disk_when_a_config_path_is_set() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );
        let update = non_default_cache_config_update();
        let response = match serve(admin_cache_config_apply_request(update), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(view) = serde_json::from_slice::<CacheConfigView>(&bytes) else {
            panic!("response body must decode as CacheConfigView");
        };
        assert!(view.persisted);

        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the saved file must load back: {err}"),
        };
        let loaded_secs = loaded.cache.to_secs();
        assert_eq!(loaded_secs.clamp_min_secs, update.clamp_min_secs);
        assert_eq!(loaded_secs.max_capacity, update.max_capacity);
    }

    // T-76, same cross-field-read requirement as `serve_admin_config_does_
    // not_wipe_a_preexisting_geoip_blocked_country_list` above, mirrored for
    // this route (`apply_cache_config` reads `state.geoip_countries` too).
    #[tokio::test]
    async fn serve_admin_cache_config_apply_does_not_wipe_a_preexisting_geoip_blocked_country_list()
    {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );
        state.update_geoip_countries(vec!["DE".to_string()]);

        let update = non_default_cache_config_update();
        let response = match serve(admin_cache_config_apply_request(update), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the saved file must load back: {err}"),
        };
        assert_eq!(
            loaded.geoip.blocked_countries,
            vec!["DE".to_string()],
            "an unrelated cache-config change must not wipe the geoip country list"
        );
    }

    #[tokio::test]
    async fn serve_admin_cache_config_apply_reports_not_persisted_when_no_config_path_is_set() {
        let state = state_with(no_op_client());
        let response = match serve(
            admin_cache_config_apply_request(non_default_cache_config_update()),
            state,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(view) = serde_json::from_slice::<CacheConfigView>(&bytes) else {
            panic!("response body must decode as CacheConfigView");
        };
        assert!(!view.persisted);
    }

    // The real flush property (T-153, advisor-caught before implementing: a
    // naive "insert then apply then assert cache.get is None" test would
    // pass trivially against any brand-new empty Cache and prove only that
    // the swap happened, nothing about whether a query actually stops being
    // served from cache). Runs the same query twice via the real
    // resolve_doh_request/handle_query path against a MockClient whose
    // `calls` counter (already used elsewhere in this file to prove
    // cancellation/pass-through) increments once per upstream query: the
    // second identical query must re-query upstream (quad9+adguard+baseline,
    // 3 calls) after a cache-config apply, not silently hit a cache entry
    // that survived the swap.
    #[tokio::test]
    async fn serve_admin_cache_config_apply_forces_a_fresh_upstream_query_not_a_stale_cache_hit() {
        let ip = Ipv4Addr::new(5, 6, 7, 8);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let state = state_with(client);
        let wire_bytes = query_bytes("cache-flush.test", RecordType::A);

        let first = match resolve_doh_request(&wire_bytes, &state).await {
            Ok(bytes) => bytes,
            Err(err) => panic!("must resolve: {err}"),
        };
        let _ = first;
        let calls_after_first = state.client.calls.load(Ordering::SeqCst);
        assert!(calls_after_first > 0, "the first query must hit upstream");

        // Same domain again, still no config change - must be a cache hit,
        // no new upstream calls.
        let second = match resolve_doh_request(&wire_bytes, &state).await {
            Ok(bytes) => bytes,
            Err(err) => panic!("must resolve: {err}"),
        };
        let _ = second;
        assert_eq!(
            state.client.calls.load(Ordering::SeqCst),
            calls_after_first,
            "an unchanged cache-config must still serve the second identical query from cache"
        );

        let apply_response = match serve(
            admin_cache_config_apply_request(non_default_cache_config_update()),
            Arc::clone(&state),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(apply_response.status(), StatusCode::OK);

        let third = match resolve_doh_request(&wire_bytes, &state).await {
            Ok(bytes) => bytes,
            Err(err) => panic!("must resolve: {err}"),
        };
        let _ = third;
        assert!(
            state.client.calls.load(Ordering::SeqCst) > calls_after_first,
            "a cache-config apply must flush the cache - the same query afterward must \
             re-query upstream, not silently hit an entry that survived the swap"
        );
    }

    // Same discipline as `concurrent_admin_config_posts_leave_disk_matching_
    // live_settings` (T-58) and `concurrent_admin_overrides_add_posts_lose_
    // no_updates` (T-47), applied one level up: `/admin/config` and
    // `/admin/cache-config/apply` now write into the *same* file
    // (`resolver_config.toml`) via the *same* shared `persist_lock` (T-153).
    // Empirically confirmed the same way those two were, not assumed from
    // the lock alone: with the cache-config route's `_persist_guard` acquire
    // temporarily removed, this test failed 1/20 runs on this dev machine
    // (looped, `cargo test -- --exact` per run) - a narrower window than
    // T-58's 16/20 (this handler does far less work between the two
    // independent lock acquisitions it would otherwise race on, so the
    // interleaving is rarer, not absent); with the shared lock restored,
    // 20/20 passed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_admin_config_and_cache_config_posts_leave_disk_matching_both_live_fields() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let config_path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: config_path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );

        let config_update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::FailClosed,
            serve_baseline_when_filters_unreachable: false,
        };
        let cache_update = non_default_cache_config_update();

        let config_state = Arc::clone(&state);
        let config_handle = tokio::spawn(async move {
            match serve(admin_config_request(config_update), config_state).await {
                Ok(response) => response.status(),
                Err(err) => match err {},
            }
        });
        let cache_state = Arc::clone(&state);
        let cache_handle = tokio::spawn(async move {
            match serve(admin_cache_config_apply_request(cache_update), cache_state).await {
                Ok(response) => response.status(),
                Err(err) => match err {},
            }
        });
        match config_handle.await {
            Ok(status) => assert_eq!(status, StatusCode::OK),
            Err(err) => panic!("admin config task must not panic: {err}"),
        }
        match cache_handle.await {
            Ok(status) => assert_eq!(status, StatusCode::OK),
            Err(err) => panic!("cache config task must not panic: {err}"),
        }

        let loaded = match ResolverConfig::load(&config_path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the persisted file must still load: {err}"),
        };
        assert_eq!(
            loaded.timeout_mode, config_update.timeout_mode,
            "the timeout-mode change must survive a concurrent cache-config write"
        );
        assert_eq!(
            loaded.providers,
            ProviderEntry::default_active_set(),
            "the provider list must survive a concurrent cache-config write"
        );
        let loaded_cache_secs = loaded.cache.to_secs();
        assert_eq!(
            loaded_cache_secs.clamp_min_secs, cache_update.clamp_min_secs,
            "the cache-config change must survive a concurrent admin-config write"
        );
        assert_eq!(
            loaded_cache_secs.max_capacity, cache_update.max_capacity,
            "the cache-config change must survive a concurrent admin-config write"
        );
    }

    // T-153, advisor-caught gap: `apply_admin_reset` also now writes
    // `state.cache` (rebuilt from `resolver_config.toml`'s own `[cache]`
    // table) and shares `persist_lock` with the cache-config route for
    // exactly this reason (see `apply_admin_reset`'s own doc comment) - but
    // that guard had never been verified empirically to actually matter,
    // the same "confirmed, not assumed" bar
    // `concurrent_admin_config_and_cache_config_posts_leave_disk_matching_
    // both_live_fields` above was held to. Property asserted is symmetric
    // (live matches disk), not "reset wins" or "cache-config wins" - either
    // outcome of the race is legitimate, a *divergence* between the two is
    // not. With `apply_admin_reset`'s `_persist_guard` acquire temporarily
    // removed, this test failed 20/20 runs on this dev machine (looped,
    // `cargo test -- --exact` per run - a wider window than the sibling
    // admin-config/cache-config test's 1/20, since reset does real disk I/O
    // for two files between reading and committing, not just a few in-memory
    // field reads); with the shared lock restored, 20/20 passed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_admin_reset_and_cache_config_apply_leave_disk_matching_live_cache_config() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let config_path = dir.path().join("resolver_config.toml");
        let overrides_path = dir.path().join("overrides.toml");
        if let Err(err) = std::fs::write(
            &config_path,
            "port = 8443\ntimeout_mode = \"fail_open\"\ntimeout_ms = 2000\n",
        ) {
            panic!("must be able to write the fixture config: {err}");
        }
        if let Err(err) = std::fs::write(&overrides_path, "") {
            panic!("must be able to write the fixture overrides file: {err}");
        }
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: config_path.clone(),
                    overrides: overrides_path,
                }),
            },
        );
        let cache_update = non_default_cache_config_update();

        let reset_state = Arc::clone(&state);
        let reset_handle = tokio::spawn(async move {
            match serve(admin_reset_request(), reset_state).await {
                Ok(response) => response.status(),
                Err(err) => match err {},
            }
        });
        let cache_state = Arc::clone(&state);
        let cache_handle = tokio::spawn(async move {
            match serve(admin_cache_config_apply_request(cache_update), cache_state).await {
                Ok(response) => response.status(),
                Err(err) => match err {},
            }
        });
        match reset_handle.await {
            Ok(status) => assert_eq!(status, StatusCode::OK),
            Err(err) => panic!("admin reset task must not panic: {err}"),
        }
        match cache_handle.await {
            Ok(status) => assert_eq!(status, StatusCode::OK),
            Err(err) => panic!("cache config task must not panic: {err}"),
        }

        let loaded = match ResolverConfig::load(&config_path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the persisted file must still load: {err}"),
        };
        let live = state.cache.read().config;
        assert_eq!(
            live, loaded.cache,
            "live cache config must match what's actually on disk after a concurrent \
             reset and cache-config apply - a divergence here is the exact \
             disk-vs-live split apply_admin_reset's persist_lock exists to prevent"
        );
    }

    // T-77: `GET /admin/geoip`/`POST /admin/geoip/add`/`remove`.

    fn admin_geoip_add_request(country: &str) -> Request<Full<Bytes>> {
        let Ok(json) = serde_json::to_vec(&GeoipCountryRequest {
            country: country.to_string(),
        }) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/geoip/add")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        req
    }

    fn admin_geoip_remove_request(country: &str) -> Request<Full<Bytes>> {
        let Ok(json) = serde_json::to_vec(&GeoipCountryRequest {
            country: country.to_string(),
        }) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/geoip/remove")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        req
    }

    fn admin_geoip_get_request() -> Request<Full<Bytes>> {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/geoip")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        req
    }

    /// The vendored fixture `geoip.rs`/`pipeline.rs`'s own tests already
    /// use (T-74) — a real, structurally valid `MaxMind` database, not a
    /// hand-built one.
    fn open_geoip_fixture() -> crate::geoip::GeoipReader {
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/geoip/GeoIP2-Country-Test.mmdb");
        let Ok(reader) = crate::geoip::GeoipReader::open(&fixture_path) else {
            panic!("geoip fixture must load");
        };
        reader
    }

    // T-78: `database_loaded`/`database_built_at_ms` have three reachable
    // combinations (`AppState::geoip`'s own doc comment) - this test and
    // the two below each cover one, advisor-caught during this task's own
    // planning as needing to stay distinguishable rather than collapsing
    // into a single `Option<u64>` ("date unknown" must not read the same
    // as "GeoIP filtering isn't happening at all").
    #[tokio::test]
    async fn serve_admin_geoip_reports_no_database_loaded_when_none_is_configured() {
        let state = state_with(no_op_client());
        let response = match serve(admin_geoip_get_request(), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert!(!body.database_loaded);
        assert_eq!(body.database_built_at_ms, None);
        assert_eq!(
            body.database_source, None,
            "no reader loaded → no source to classify (T-162)"
        );
    }

    #[tokio::test]
    async fn serve_admin_geoip_reports_the_loaded_databases_build_time() {
        let built_at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let state = state_with_geoip_database(
            no_op_client(),
            GeoipState {
                reader: Some(Arc::new(open_geoip_fixture())),
                updated_at: Some(built_at),
            },
        );
        let response = match serve(admin_geoip_get_request(), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert!(body.database_loaded);
        assert_eq!(body.database_built_at_ms, Some(1_700_000_000_000));
    }

    #[tokio::test]
    async fn serve_admin_geoip_reports_a_loaded_database_with_no_known_build_time() {
        let state = state_with_geoip_database(
            no_op_client(),
            GeoipState {
                reader: Some(Arc::new(open_geoip_fixture())),
                updated_at: None,
            },
        );
        let response = match serve(admin_geoip_get_request(), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert!(
            body.database_loaded,
            "a loaded reader must report database_loaded even without a known build time"
        );
        assert_eq!(body.database_built_at_ms, None);
        assert!(
            body.database_source.is_some(),
            "a loaded reader must classify to some DatabaseSource (T-162); the exact \
             DB-IP/GeoLite2/Other mapping is unit-tested in admin.rs"
        );
    }

    /// Holds [`crate::key_store::STORE_TEST_GUARD`] behind an opaque type so
    /// an `async` test can keep it alive across `.await` without tripping
    /// `clippy::await_holding_lock` (which only tracks bare `MutexGuard`
    /// locals) — the same mechanism `MaxmindTestDir`'s `_guard` field relies
    /// on. For credential-store tests that don't build a `MaxmindTestDir`.
    struct StoreTestGuard(#[allow(dead_code)] parking_lot::MutexGuard<'static, ()>);

    fn store_test_guard() -> StoreTestGuard {
        StoreTestGuard(crate::key_store::STORE_TEST_GUARD.lock())
    }

    /// A scratch app-data dir plus a `Drop` that deletes the `MaxMind`
    /// credentials keyring entry derived from it — so these tests, which now
    /// hit the real OS credential store (T-163), never leak an entry into the
    /// dev machine's or CI runner's Credential Manager. Also holds
    /// [`crate::key_store::STORE_TEST_GUARD`] so credential-store tests across
    /// the whole crate run serially (the Windows backend races under
    /// concurrent access even on distinct entries).
    struct MaxmindTestDir {
        dir: tempfile::TempDir,
        _guard: parking_lot::MutexGuard<'static, ()>,
    }

    impl MaxmindTestDir {
        fn path(&self) -> &std::path::Path {
            self.dir.path()
        }
    }

    impl Drop for MaxmindTestDir {
        fn drop(&mut self) {
            let entry = crate::key_store::maxmind_credentials_entry(self.dir.path());
            let _ = crate::key_store::delete_secret(&entry);
        }
    }

    fn maxmind_state_with_tempdir() -> (MaxmindTestDir, Arc<AppState<MockClient>>) {
        let guard = crate::key_store::STORE_TEST_GUARD.lock();
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: dir.path().join("resolver_config.toml"),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );
        (MaxmindTestDir { dir, _guard: guard }, state)
    }

    fn admin_maxmind_get_request() -> Request<Full<Bytes>> {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/geoip/maxmind")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        req
    }

    fn admin_maxmind_post_request(account_id: &str, license_key: &str) -> Request<Full<Bytes>> {
        let Ok(json) = serde_json::to_vec(&MaxmindCredentialsRequest {
            account_id: account_id.to_string(),
            license_key: license_key.to_string(),
        }) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/geoip/maxmind")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        req
    }

    async fn maxmind_view_via_get(state: Arc<AppState<MockClient>>) -> MaxmindCredentialsView {
        let response = match serve(admin_maxmind_get_request(), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(view) = serde_json::from_slice::<MaxmindCredentialsView>(&bytes) else {
            panic!("response must decode as MaxmindCredentialsView");
        };
        view
    }

    #[tokio::test]
    async fn maxmind_get_reports_not_configured_on_a_fresh_state() {
        let (_dir, state) = maxmind_state_with_tempdir();
        let view = maxmind_view_via_get(state).await;
        assert!(!view.configured);
        assert_eq!(view.account_id, None);
        assert_eq!(view.check, MaxmindCredentialCheck::Skipped);
    }

    // The save-time probe reaches the real `download.maxmind.com`, so the
    // *write* path is exercised without going through the POST handler
    // (`geoip_credentials::save` directly, then a plain GET) — same "network
    // behind `#[ignore]`" discipline the rest of this crate keeps. The
    // `check` result plumbing is covered by `geoip_updater`'s own
    // `#[ignore]`d live test.
    #[tokio::test]
    async fn maxmind_get_echoes_the_account_id_after_a_save_and_never_the_key() {
        let (dir, state) = maxmind_state_with_tempdir();
        if let Err(err) =
            crate::geoip_credentials::save(dir.path(), "acct-987", "a-very-secret-license-key")
        {
            panic!("save fixture must succeed: {err}");
        }
        let view = maxmind_view_via_get(Arc::clone(&state)).await;
        assert!(view.configured);
        assert_eq!(view.account_id.as_deref(), Some("acct-987"));

        let response = match serve(admin_maxmind_get_request(), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        let raw = String::from_utf8_lossy(&body_bytes(response).await).into_owned();
        assert!(
            !raw.contains("a-very-secret-license-key") && !raw.contains("license"),
            "the GET response must never carry the license key in any form: {raw}"
        );
    }

    #[tokio::test]
    async fn maxmind_post_with_a_blank_field_is_400_before_any_probe() {
        let (_dir, state) = maxmind_state_with_tempdir();
        // A blank `license_key` — `geoip_credentials::save` rejects it as
        // `Malformed` before the handler ever builds a client, so this stays
        // network-free.
        let response = match serve(admin_maxmind_post_request("acct", "   "), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn maxmind_clear_removes_the_credentials_and_reports_not_configured() {
        let (dir, state) = maxmind_state_with_tempdir();
        if let Err(err) = crate::geoip_credentials::save(dir.path(), "acct", "key") {
            panic!("save fixture must succeed: {err}");
        }
        let Ok(clear_req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/geoip/maxmind/clear")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(clear_req, Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(view) = serde_json::from_slice::<MaxmindCredentialsView>(&bytes) else {
            panic!("clear response must decode as MaxmindCredentialsView");
        };
        assert!(!view.configured);
        assert!(
            view.persisted,
            "removing existing credentials must report persisted"
        );
        match crate::geoip_credentials::load(dir.path()) {
            Ok(None) => {}
            Ok(Some(_)) => {
                panic!("the stored credentials must be gone after /clear, got Ok(Some(_))")
            }
            Err(err) => panic!("the stored credentials must be gone after /clear, got Err({err})"),
        }
        assert!(!maxmind_view_via_get(state).await.configured);
    }

    #[test]
    fn update_geoip_source_is_visible_on_the_next_snapshot() {
        let state = state_with(no_op_client());
        assert!(matches!(
            *state.geoip_source_snapshot(),
            GeoipSource::DbIpLite
        ));
        state.update_geoip_source(GeoipSource::Maxmind(
            crate::geoip_credentials::MaxmindCredentials {
                account_id: "acct".to_string(),
                license_key: crate::geoip_credentials::LicenseKey::new("k".to_string()),
            },
        ));
        assert!(matches!(
            *state.geoip_source_snapshot(),
            GeoipSource::Maxmind(_)
        ));
    }

    // The wake channel's "no lost wake" property is tested against the real
    // `geoip_updater::park_until_due`, not re-implemented here. This test only
    // covers that `AppState::wake_geoip_refresh` reaches the same `Notify` the
    // updater parks on.
    #[tokio::test(start_paused = true)]
    async fn wake_geoip_refresh_leaves_a_permit_on_the_handle_the_updater_parks_on() {
        let state = state_with(no_op_client());
        let wake = state.geoip_refresh_wake_handle();
        state.wake_geoip_refresh();
        let start = tokio::time::Instant::now();
        wake.notified().await;
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "wake_geoip_refresh must leave a permit on geoip_refresh_wake_handle()"
        );
    }

    #[test]
    fn maxmind_health_starts_not_applicable_and_tracks_source_changes() {
        let state = state_with(no_op_client());
        // A DB-IP Lite start (the test helper's default) is NotApplicable.
        assert_eq!(
            state.maxmind_health_snapshot(),
            crate::geoip_updater::MaxmindHealth::NotApplicable
        );
        // Switching to MaxMind resets to Pending (a woken refresh resolves it).
        state.update_geoip_source(GeoipSource::Maxmind(
            crate::geoip_credentials::MaxmindCredentials {
                account_id: "acct".to_string(),
                license_key: crate::geoip_credentials::LicenseKey::new("k".to_string()),
            },
        ));
        assert_eq!(
            state.maxmind_health_snapshot(),
            crate::geoip_updater::MaxmindHealth::Pending
        );
        // A later refresh outcome lands...
        state.update_maxmind_health(crate::geoip_updater::MaxmindHealth::AuthRejected);
        assert_eq!(
            state.maxmind_health_snapshot(),
            crate::geoip_updater::MaxmindHealth::AuthRejected
        );
        // ...and switching back to DB-IP Lite clears it.
        state.update_geoip_source(GeoipSource::DbIpLite);
        assert_eq!(
            state.maxmind_health_snapshot(),
            crate::geoip_updater::MaxmindHealth::NotApplicable
        );
    }

    #[test]
    fn geoip_source_snapshot_debug_never_contains_the_license_key() {
        let state = state_with(no_op_client());
        state.update_geoip_source(GeoipSource::Maxmind(
            crate::geoip_credentials::MaxmindCredentials {
                account_id: "acct".to_string(),
                license_key: crate::geoip_credentials::LicenseKey::new(
                    "super-secret-license-key-value".to_string(),
                ),
            },
        ));
        let debug = format!("{:?}", state.geoip_source_snapshot());
        assert!(!debug.contains("super-secret-license-key-value"));
        assert!(!debug.contains("license-key-value"));
        assert!(
            debug.contains("acct"),
            "the non-secret field is fine to show"
        );
    }

    #[tokio::test]
    async fn admin_reset_picks_up_a_credentials_change_and_wakes_the_updater() {
        let (dir, state) = maxmind_state_with_tempdir();
        // Seed a valid config so `/admin/reset` has something to reload.
        if let Err(err) = std::fs::write(
            dir.path().join("resolver_config.toml"),
            concat!(
                "port = 8443\ntimeout_mode = \"fail_open\"\ntimeout_ms = 3000\n\n",
                "[[providers]]\nid = \"quad9\"\nenabled = true\n"
            ),
        ) {
            panic!("must be able to write the config fixture: {err}");
        }
        if let Err(err) = std::fs::write(dir.path().join("overrides.toml"), "") {
            panic!("must be able to write the overrides fixture: {err}");
        }
        if let Err(err) = crate::geoip_credentials::save(dir.path(), "acct-42", "the-key") {
            panic!("seeding credentials must succeed: {err}");
        }
        assert!(matches!(
            *state.geoip_source_snapshot(),
            GeoipSource::DbIpLite
        ));

        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/reset")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            matches!(*state.geoip_source_snapshot(), GeoipSource::Maxmind(_)),
            "reset must re-read the stored MaxMind credentials into the live source"
        );
    }

    #[tokio::test]
    async fn serve_admin_geoip_returns_the_current_list() {
        let state = state_with(no_op_client());
        state.update_geoip_countries(vec!["SE".to_string(), "DE".to_string()]);
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/geoip")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert_eq!(
            body.blocked_countries,
            vec!["SE".to_string(), "DE".to_string()]
        );
        assert!(body.persisted);
    }

    #[tokio::test]
    async fn serve_admin_geoip_add_appends_a_new_country_and_it_is_visible_on_the_next_get() {
        let state = state_with(no_op_client());
        let response = match serve(admin_geoip_add_request("SE"), Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert_eq!(body.blocked_countries, vec!["SE".to_string()]);
        // `state_with` sets `paths: None`, so this change live-applies but
        // can't persist - same "in-memory change succeeded, disk write
        // didn't" honesty T-47's own equivalent test already established.
        assert!(!body.persisted);
    }

    #[tokio::test]
    async fn serve_admin_geoip_add_normalizes_a_lowercase_code_to_uppercase() {
        let state = state_with(no_op_client());
        let response = match serve(admin_geoip_add_request("se"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert_eq!(
            body.blocked_countries,
            vec!["SE".to_string()],
            "a lowercase request must be stored uppercase, same as a config-file entry"
        );
    }

    #[tokio::test]
    async fn serve_admin_geoip_add_is_idempotent_for_an_already_present_country() {
        let state = state_with(no_op_client());
        state.update_geoip_countries(vec!["SE".to_string()]);
        let response = match serve(admin_geoip_add_request("SE"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert_eq!(
            body.blocked_countries,
            vec!["SE".to_string()],
            "re-adding an already-present code must not duplicate it"
        );
    }

    #[tokio::test]
    async fn serve_admin_geoip_add_rejects_an_invalid_code() {
        let state = state_with(no_op_client());
        let response = match serve(admin_geoip_add_request("RUS"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // Same CSRF concern as `/admin/overrides/add` (T-47) - see
    // `content_type_is_json`'s own doc comment.
    #[tokio::test]
    async fn serve_admin_geoip_add_rejects_a_missing_content_type() {
        let Ok(json) = serde_json::to_vec(&GeoipCountryRequest {
            country: "SE".to_string(),
        }) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/geoip/add")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn serve_admin_geoip_remove_removes_the_matching_country() {
        let state = state_with(no_op_client());
        state.update_geoip_countries(vec!["SE".to_string(), "DE".to_string()]);
        let response = match serve(admin_geoip_remove_request("SE"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert_eq!(body.blocked_countries, vec!["DE".to_string()]);
    }

    // Advisor-caught during this task's own planning: the stored list is
    // always uppercase, so a lowercase remove request must still match the
    // stored entry, not silently no-op (which would look like a broken
    // "Видалити" button in the UI - nothing tells the caller the country is
    // still there).
    #[tokio::test]
    async fn serve_admin_geoip_remove_accepts_a_lowercase_code_matching_the_stored_uppercase_entry()
    {
        let state = state_with(no_op_client());
        state.update_geoip_countries(vec!["SE".to_string()]);
        let response = match serve(admin_geoip_remove_request("se"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert!(
            body.blocked_countries.is_empty(),
            "a lowercase remove request must match the stored uppercase entry"
        );
    }

    // Mirrors `serve_admin_geoip_add_rejects_an_invalid_code` - a malformed
    // code on remove must be a loud 400, not a silent no-op against a list
    // it can never match (same advisor catch as the lowercase-match test
    // above, the other half of the same "normalize/validate on both
    // routes, not just add" gap).
    #[tokio::test]
    async fn serve_admin_geoip_remove_rejects_an_invalid_code() {
        let state = state_with(no_op_client());
        state.update_geoip_countries(vec!["SE".to_string()]);
        let response = match serve(admin_geoip_remove_request("Sweden"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serve_admin_geoip_add_persists_a_change_to_disk_when_a_config_path_is_set() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );
        let response = match serve(admin_geoip_add_request("SE"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<GeoipCountriesResponse>(&bytes) else {
            panic!("response body must decode as GeoipCountriesResponse");
        };
        assert!(body.persisted);

        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the saved file must load back: {err}"),
        };
        assert_eq!(loaded.geoip.blocked_countries, vec!["SE".to_string()]);
    }

    // T-77, mirrors `serve_admin_config_does_not_wipe_a_preexisting_geoip_
    // blocked_country_list`/`serve_admin_cache_config_apply_does_not_wipe_a_
    // preexisting_geoip_blocked_country_list` in the other direction: an
    // unrelated `/admin/geoip/add` must not silently wipe already-persisted
    // `providers`/`timeout_mode`/`[cache]` back to their defaults on save -
    // same cross-field-read discipline `persist_lock`'s own doc comment
    // documents for all three fields.
    #[tokio::test]
    async fn serve_admin_geoip_add_does_not_wipe_preexisting_providers_and_cache_config() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("resolver_config.toml");
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );
        let providers_update = AdminConfigUpdate {
            timeout_mode: crate::timeout::TimeoutMode::FailClosed,
            serve_baseline_when_filters_unreachable: false,
        };
        let response = match serve(admin_config_request(providers_update), Arc::clone(&state)).await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let cache_update = non_default_cache_config_update();
        let response = match serve(
            admin_cache_config_apply_request(cache_update),
            Arc::clone(&state),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let response = match serve(admin_geoip_add_request("SE"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("the saved file must load back: {err}"),
        };
        assert_eq!(
            loaded.providers,
            ProviderEntry::default_active_set(),
            "an unrelated geoip add must not wipe the provider list"
        );
        assert_eq!(
            loaded.timeout_mode, providers_update.timeout_mode,
            "an unrelated geoip add must not wipe the timeout mode"
        );
        let Ok(expected_cache) = cache_update.into_config() else {
            panic!("fixture cache update must be valid");
        };
        assert_eq!(
            loaded.cache, expected_cache,
            "an unrelated geoip add must not wipe the cache config"
        );
    }

    // T-54: `GET /admin/log`/`POST /admin/log/clear`.

    #[tokio::test]
    async fn serve_admin_log_returns_an_empty_array_for_an_empty_log() {
        let state = state_with(no_op_client());
        let response = match serve(admin_log_request(None), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<LogQueryResponse>(&bytes) else {
            panic!("body must decode as LogQueryResponse");
        };
        assert!(body.entries.is_empty());
        assert!(!body.truncated);
    }

    // T-79: proves the whole `GeoIP` block's `geoip_country` survives the
    // full HTTP round-trip (LogEntry -> LogEntryView::from_entry ->
    // serde_json), not just the direct-call unit test already covering
    // `LogEntryView::from_entry` in `admin.rs`.
    #[tokio::test]
    async fn serve_admin_log_reports_the_real_geoip_country_for_a_geoip_sourced_entry() {
        let state = state_with(no_op_client());
        let mut entry = sample_log_entry("blocked.example", crate::query_log::Decision::Blocked);
        entry.decision_source = crate::query_log::DecisionSource::Geoip;
        entry.voters = Vec::new();
        entry.geoip_country = Some("SE".to_string());
        state.query_log.push(entry);

        let response = match serve(admin_log_request(None), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<LogQueryResponse>(&bytes) else {
            panic!("body must decode as LogQueryResponse");
        };
        assert_eq!(body.entries.len(), 1);
        assert_eq!(body.entries[0].geoip_country, Some("SE".to_string()));
    }

    #[tokio::test]
    async fn serve_admin_log_filters_by_domain_contains() {
        let state = state_with(no_op_client());
        state.query_log.push(sample_log_entry(
            "match.example",
            crate::query_log::Decision::Allowed,
        ));
        state.query_log.push(sample_log_entry(
            "other.example",
            crate::query_log::Decision::Allowed,
        ));

        let response = match serve(admin_log_request(Some("domain_contains=match")), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<LogQueryResponse>(&bytes) else {
            panic!("body must decode as LogQueryResponse");
        };
        assert_eq!(body.entries.len(), 1);
        assert_eq!(body.entries[0].domain, "match.example");
    }

    #[tokio::test]
    async fn serve_admin_log_filters_by_decision() {
        let state = state_with(no_op_client());
        state.query_log.push(sample_log_entry(
            "blocked.example",
            crate::query_log::Decision::Blocked,
        ));
        state.query_log.push(sample_log_entry(
            "allowed.example",
            crate::query_log::Decision::Allowed,
        ));

        let response = match serve(admin_log_request(Some("decision=BLOCKED")), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<LogQueryResponse>(&bytes) else {
            panic!("body must decode as LogQueryResponse");
        };
        assert_eq!(body.entries.len(), 1);
        assert_eq!(body.entries[0].domain, "blocked.example");
    }

    #[tokio::test]
    async fn serve_admin_log_filters_by_voter() {
        let state = state_with(no_op_client());
        let mut adguard_entry =
            sample_log_entry("adguard-voted.example", crate::query_log::Decision::Allowed);
        adguard_entry.voters = vec![VoterRecord {
            provider_id: "adguard".to_string(),
            verdict: VoterVerdict::Allow,
            allow_ip_count: Some(1),
            error_message: None,
        }];
        state.query_log.push(adguard_entry);
        state.query_log.push(sample_log_entry(
            "quad9-voted.example",
            crate::query_log::Decision::Allowed,
        ));

        let response = match serve(admin_log_request(Some("voter=adguard")), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<LogQueryResponse>(&bytes) else {
            panic!("body must decode as LogQueryResponse");
        };
        assert_eq!(body.entries.len(), 1);
        assert_eq!(body.entries[0].domain, "adguard-voted.example");
    }

    // Advisor-caught during planning: an unrecognized `decision`/`voter`
    // value must never silently fall back to "no filter" (the facet's own
    // `ALL`) - these three prove the actual HTTP behavior is 400, not just
    // that `parse_log_query` returns an `Err` in isolation.

    #[tokio::test]
    async fn serve_admin_log_rejects_an_unrecognized_decision_value() {
        let response = match serve(
            admin_log_request(Some("decision=BLOCKD")),
            state_with(no_op_client()),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serve_admin_log_rejects_an_unrecognized_voter_value() {
        let response = match serve(
            admin_log_request(Some("voter=bogus")),
            state_with(no_op_client()),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serve_admin_log_rejects_a_non_numeric_limit() {
        let response = match serve(
            admin_log_request(Some("limit=abc")),
            state_with(no_op_client()),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serve_admin_log_caps_the_response_at_the_requested_limit_and_reports_truncated() {
        let state = state_with(no_op_client());
        for i in 0..5 {
            state.query_log.push(sample_log_entry(
                &format!("domain{i}.example"),
                crate::query_log::Decision::Allowed,
            ));
        }

        let response = match serve(admin_log_request(Some("limit=2")), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<LogQueryResponse>(&bytes) else {
            panic!("body must decode as LogQueryResponse");
        };
        assert_eq!(body.entries.len(), 2);
        assert!(body.truncated);
        // The *newest* two, not the oldest two - domain3/domain4 were pushed
        // last.
        assert_eq!(body.entries[0].domain, "domain3.example");
        assert_eq!(body.entries[1].domain, "domain4.example");
    }

    #[tokio::test]
    async fn serve_admin_log_clear_rejects_a_missing_content_type() {
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/log/clear")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn serve_admin_log_clear_actually_empties_the_log() {
        let state = state_with(no_op_client());
        state.query_log.push(sample_log_entry(
            "to-be-cleared.example",
            crate::query_log::Decision::Allowed,
        ));
        assert_eq!(
            state.query_log.snapshot(std::time::SystemTime::now()).len(),
            1
        );

        let response = match serve(admin_log_clear_request(), Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state
            .query_log
            .snapshot(std::time::SystemTime::now())
            .is_empty());
    }

    #[test]
    fn parse_log_query_defaults_to_no_filters_and_the_default_limit() {
        let Ok(parsed) = parse_log_query(None) else {
            panic!("None must parse");
        };
        assert!(parsed.domain_contains.is_none());
        assert!(parsed.decision.is_none());
        assert!(parsed.voter.is_none());
        assert_eq!(parsed.limit, DEFAULT_LOG_LIMIT);
    }

    #[test]
    fn parse_log_query_percent_decodes_domain_contains() {
        let Ok(parsed) = parse_log_query(Some("domain_contains=a%20b")) else {
            panic!("must parse")
        };
        assert_eq!(parsed.domain_contains.as_deref(), Some("a b"));
    }

    #[test]
    fn parse_log_query_clamps_a_limit_above_the_hard_cap() {
        let Ok(parsed) = parse_log_query(Some("limit=999999")) else {
            panic!("must parse")
        };
        assert_eq!(parsed.limit, MAX_LOG_LIMIT);
    }

    // Advisor-caught on the closing review: `?limit=0` against a non-empty
    // log would silently return an empty-but-successful result,
    // indistinguishable from "nothing matched the filter" - rejected
    // outright instead, the same "don't silently answer a probably-buggy
    // request" reasoning as the unrecognized-decision/voter checks above.
    #[test]
    fn parse_log_query_rejects_a_zero_limit() {
        match parse_log_query(Some("limit=0")) {
            Err(LogQueryError::BadLimit) => {}
            other => panic!("expected BadLimit, got {other:?}"),
        }
    }

    #[test]
    fn parse_log_query_rejects_invalid_percent_encoding() {
        match parse_log_query(Some("domain_contains=%ff%fe")) {
            Err(LogQueryError::BadEncoding) => {}
            other => panic!("expected BadEncoding, got {other:?}"),
        }
    }

    // Advisor-caught on the closing review: `parse_log_query`'s `"ALLOWED"/
    // "BLOCKED"/"FAILED"` literals are a second, independent copy of the
    // wire strings `DecisionView`'s serde `rename_all` produces - nothing
    // ties them together, so a future casing change to one side could
    // silently desync from the other (the response would emit a value the
    // filter can no longer accept). This test pins both sides against each
    // other, not just against a hardcoded expectation.
    #[test]
    fn parse_log_query_decision_literals_match_decision_views_actual_wire_strings() {
        use crate::query_log::Decision;
        for decision in [Decision::Allowed, Decision::Blocked, Decision::Failed] {
            let Ok(wire) = serde_json::to_string(&DecisionView::from(decision)) else {
                panic!("must serialize")
            };
            let wire = wire.trim_matches('"');
            let Ok(parsed) = parse_log_query(Some(&format!("decision={wire}"))) else {
                panic!("must parse the value DecisionView itself just produced")
            };
            assert_eq!(parsed.decision, Some(decision));
        }
    }

    #[test]
    fn parse_log_query_ignores_an_unrecognized_key() {
        let Ok(parsed) = parse_log_query(Some("nonsense=1&domain_contains=x")) else {
            panic!("must parse")
        };
        assert_eq!(parsed.domain_contains.as_deref(), Some("x"));
    }

    proptest::proptest! {
        // T-54, same discipline as `wire_bytes_from_get_never_panics_on_arbitrary_query_strings`
        // (T-58): the query-string parsing boundary for a second admin GET
        // route must never panic on arbitrary client input, whatever it
        // decides to return.
        #[test]
        fn parse_log_query_never_panics_on_arbitrary_query_strings(query in "\\PC{0,256}") {
            let _ = parse_log_query(Some(&query));
        }
    }

    #[tokio::test]
    async fn serve_admin_shutdown_rejects_non_post_methods() {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/shutdown")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    // T-149, same CSRF regression class as serve_admin_reset_rejects_a_missing_content_type
    // - the highest blast-radius route on this channel is exactly the one
    // that must never be reachable via a CORS-simple cross-origin request.
    #[tokio::test]
    async fn serve_admin_shutdown_rejects_a_missing_content_type() {
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/shutdown")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn serve_admin_shutdown_returns_200_and_signals_the_watch_channel() {
        let state = state_with(no_op_client());
        let mut rx = state.shutdown_handle();
        assert!(!*rx.borrow(), "must start unsignaled");

        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/shutdown")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);

        match tokio::time::timeout(std::time::Duration::from_secs(1), rx.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("sender must not have been dropped: {err}"),
            Err(elapsed) => panic!("shutdown signal must arrive promptly: {elapsed}"),
        }
        assert!(*rx.borrow(), "signaled value must be true");
    }

    // A second `/admin/shutdown` after every receiver has already been
    // dropped (main.rs's accept loop, mid-drain) must still answer 200, not
    // fail - see serve_admin_shutdown's own doc comment for why.
    #[tokio::test]
    async fn serve_admin_shutdown_still_returns_200_once_every_receiver_is_dropped() {
        let state = state_with(no_op_client());
        drop(state.shutdown_handle());

        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/shutdown")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
    }

    // T-70: only the two gates that reject *before* `local_state::
    // remove_all` is ever called are tested through `serve()` here — the
    // real success path spawns a real `certutil.exe` and mutates the
    // machine's actual trust store (see `serve_never_panics_on_arbitrary_
    // input_for_any_documented_route`'s `FUZZ_EXCLUDED_ROUTES` comment for
    // the full reasoning); `local_state::remove_secret` is unit-tested
    // directly instead, in `local_state.rs`.

    #[tokio::test]
    async fn serve_admin_uninstall_local_state_rejects_non_post_methods() {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/uninstall-local-state")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn serve_admin_uninstall_local_state_rejects_a_missing_content_type() {
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri("/admin/uninstall-local-state")
            .body(Full::new(Bytes::from_static(b"{}")))
        else {
            panic!("fixture request must build");
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    /// T-53/T-59: `serve()`'s `ROUTES` table (declared near this module's
    /// `_PATH` consts) is the actual dispatch source — a request is checked
    /// against it *before* the handler-selection `match` in `serve()` ever
    /// runs (see `ROUTES`'s own doc comment). This compares that live table
    /// against an independent, hand-written copy: adding, removing, or
    /// widening a route in `ROUTES` changes what's reachable, so it must
    /// also change here, or this assertion fails — unlike a test that only
    /// ever probes a hardcoded list of paths (which a genuinely new route
    /// would silently sail past), this one fails on that exact case because
    /// it reads the same table `serve()` uses, not a copy of `serve()`'s
    /// `match` arms.
    const EXPECTED_ADMIN_ROUTES: &[(&str, &[Method])] = &[
        ("/dns-query", &[Method::GET, Method::POST]),
        ("/health", &[Method::GET]),
        ("/admin/status", &[Method::GET]),
        ("/admin/config", &[Method::POST]),
        ("/admin/reset", &[Method::POST]),
        ("/admin/shutdown", &[Method::POST]),
        ("/admin/overrides", &[Method::GET]),
        ("/admin/overrides/add", &[Method::POST]),
        ("/admin/overrides/remove", &[Method::POST]),
        ("/admin/cache-config", &[Method::GET]),
        ("/admin/cache-config/apply", &[Method::POST]),
        ("/admin/geoip", &[Method::GET]),
        ("/admin/geoip/add", &[Method::POST]),
        ("/admin/geoip/remove", &[Method::POST]),
        ("/admin/geoip/maxmind", &[Method::GET, Method::POST]),
        ("/admin/geoip/maxmind/clear", &[Method::POST]),
        ("/admin/providers", &[Method::GET]),
        ("/admin/providers/add", &[Method::POST]),
        ("/admin/providers/remove", &[Method::POST]),
        ("/admin/providers/set-enabled", &[Method::POST]),
        ("/admin/log", &[Method::GET]),
        ("/admin/log/clear", &[Method::POST]),
        ("/admin/uninstall-local-state", &[Method::POST]),
        ("/admin/ui", &[Method::GET]),
        ("/admin/ui/main.js", &[Method::GET]),
        ("/admin/ui/style.css", &[Method::GET]),
    ];

    #[test]
    fn serve_matches_the_documented_admin_route_allowlist() {
        assert_eq!(super::ROUTES, EXPECTED_ADMIN_ROUTES);
    }

    /// `HEAD` is deliberately left out of this sweep: RFC 7231 §4.3.2
    /// recommends supporting it wherever GET is supported, which this
    /// project hasn't decided either way for any route yet (SPEC.md's own
    /// "RFC over intuition" rule) — pinning "HEAD is 405 everywhere" as
    /// tested behavior here would silently make that decision by omission.
    const ALL_HTTP_METHODS: &[Method] = &[
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::OPTIONS,
        Method::TRACE,
    ];

    /// Complements `serve_matches_the_documented_admin_route_allowlist`:
    /// that test proves `ROUTES` matches this same expected list; this one
    /// proves `ROUTES` is actually *enforced*, not just declared — every
    /// listed (path, method) pair reaches a handler instead of being
    /// rejected, and every method not listed for a given path gets 405.
    #[tokio::test]
    async fn serve_enforces_the_route_table_it_matched_above() {
        for &(path, allowed) in EXPECTED_ADMIN_ROUTES {
            for method in ALL_HTTP_METHODS {
                let Ok(req) = Request::builder()
                    .method(method.clone())
                    .uri(path)
                    .body(Full::new(Bytes::new()))
                else {
                    panic!("fixture request must build");
                };
                let response = match serve(req, state_with(no_op_client())).await {
                    Ok(response) => response,
                    Err(err) => match err {},
                };
                if allowed.contains(method) {
                    assert!(
                        response.status() != StatusCode::NOT_FOUND
                            && response.status() != StatusCode::METHOD_NOT_ALLOWED,
                        "{method} {path} is in the allowlist but got {}",
                        response.status()
                    );
                } else {
                    assert_eq!(
                        response.status(),
                        StatusCode::METHOD_NOT_ALLOWED,
                        "{method} {path} is not in the allowlist but wasn't rejected as 405"
                    );
                }
            }
        }
    }

    // T-72/T-73: the `/admin/providers/*` route group.

    fn providers_state() -> (tempfile::TempDir, Arc<AppState<MockClient>>) {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let state = state_with_persist(
            no_op_client(),
            PersistTarget {
                port: 8443,
                persist_query_log: false,
                persist_cache: false,
                paths: Some(PersistPaths {
                    config: dir.path().join("resolver_config.toml"),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );
        (dir, state)
    }

    fn admin_get(uri: &str) -> Request<Full<Bytes>> {
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        req
    }

    fn admin_post_json(uri: &str, body: &serde_json::Value) -> Request<Full<Bytes>> {
        let Ok(json) = serde_json::to_vec(body) else {
            panic!("fixture body must serialize");
        };
        let Ok(req) = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
        else {
            panic!("fixture request must build");
        };
        req
    }

    async fn providers_json(state: Arc<AppState<MockClient>>) -> crate::admin::ProvidersResponse {
        let response = match serve(admin_get("/admin/providers"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body_bytes(response).await;
        let Ok(body) = serde_json::from_slice::<crate::admin::ProvidersResponse>(&bytes) else {
            panic!("body must decode as ProvidersResponse");
        };
        body
    }

    #[tokio::test]
    async fn serve_admin_providers_lists_the_default_two_and_every_preset() {
        let (_dir, state) = providers_state();
        let body = providers_json(state).await;
        let active_ids: Vec<&str> = body.active.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(active_ids, vec!["quad9", "adguard"]);
        assert!(body.active.iter().all(|p| p.is_builtin && p.enabled));
        assert!(body.available_presets.len() >= 10);
        assert_eq!(body.third_party_count, 3, "2 voters + baseline");
    }

    #[tokio::test]
    async fn serve_admin_providers_add_a_preset_then_it_is_active_and_persisted() {
        let (dir, state) = providers_state();
        let response = match serve(
            admin_post_json(
                "/admin/providers/add",
                &serde_json::json!({"id": "cloudflare-family"}),
            ),
            Arc::clone(&state),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body = providers_json(state).await;
        assert!(body
            .active
            .iter()
            .any(|p| p.id == "cloudflare-family" && p.enabled));
        assert_eq!(body.third_party_count, 4);
        let Ok(loaded) = ResolverConfig::load(&dir.path().join("resolver_config.toml")) else {
            panic!("saved config must load");
        };
        assert!(loaded
            .providers
            .iter()
            .any(|e| e.spec.id == "cloudflare-family"));
    }

    #[tokio::test]
    async fn serve_admin_providers_add_a_custom_https_endpoint() {
        let (_dir, state) = providers_state();
        let response = match serve(
            admin_post_json(
                "/admin/providers/add",
                &serde_json::json!({
                    "id": "my-nextdns",
                    "url": "https://abc123.dns.nextdns.io/dns-query",
                    "display_name": "NextDNS",
                    "category": "SECURITY"
                }),
            ),
            Arc::clone(&state),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body = providers_json(state).await;
        let Some(custom) = body.active.iter().find(|p| p.id == "my-nextdns") else {
            panic!("the custom entry must be in the active list");
        };
        assert!(!custom.is_builtin);
        assert_eq!(custom.doh_url, "https://abc123.dns.nextdns.io/dns-query");
    }

    #[tokio::test]
    async fn serve_admin_providers_add_rejects_ssrf_and_duplicate_and_bad_id() {
        let (_dir, state) = providers_state();
        for bad in [
            serde_json::json!({"id": "evil", "url": "https://127.0.0.1/dns-query", "display_name": "x", "category": "SECURITY"}),
            serde_json::json!({"id": "quad9"}), // already active
            serde_json::json!({"id": "Bad Id"}),
            serde_json::json!({"id": "mystery"}), // non-preset, no url/name/category
        ] {
            let response = match serve(
                admin_post_json("/admin/providers/add", &bad),
                Arc::clone(&state),
            )
            .await
            {
                Ok(response) => response,
                Err(err) => match err {},
            };
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{bad} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn serve_admin_providers_remove_a_custom_entry_but_not_a_builtin() {
        let (_dir, state) = providers_state();
        let _ = serve(
            admin_post_json(
                "/admin/providers/add",
                &serde_json::json!({"id": "my-controld", "url": "https://dns.controld.com/x", "display_name": "ControlD", "category": "ADS_TRACKERS"}),
            ),
            Arc::clone(&state),
        )
        .await;
        // A builtin can't be removed.
        let response = match serve(
            admin_post_json(
                "/admin/providers/remove",
                &serde_json::json!({"id": "quad9"}),
            ),
            Arc::clone(&state),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // The custom one can.
        let response = match serve(
            admin_post_json(
                "/admin/providers/remove",
                &serde_json::json!({"id": "my-controld"}),
            ),
            Arc::clone(&state),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body = providers_json(state).await;
        assert!(!body.active.iter().any(|p| p.id == "my-controld"));
    }

    #[tokio::test]
    async fn serve_admin_providers_set_enabled_toggles_and_status_reflects_it() {
        let (_dir, state) = providers_state();
        let response = match serve(
            admin_post_json(
                "/admin/providers/set-enabled",
                &serde_json::json!({"id": "quad9", "enabled": false}),
            ),
            Arc::clone(&state),
        )
        .await
        {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body = providers_json(Arc::clone(&state)).await;
        assert!(body.active.iter().any(|p| p.id == "quad9" && !p.enabled));
        assert_eq!(body.third_party_count, 2, "only adguard + baseline now");

        let status_response = match serve(admin_get("/admin/status"), state).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        let bytes = body_bytes(status_response).await;
        let Ok(status) = serde_json::from_slice::<AdminStatusResponse>(&bytes) else {
            panic!("status must decode");
        };
        let active: Vec<&str> = status
            .active_providers
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(active, vec!["adguard"]);
    }

    #[tokio::test]
    async fn serve_returns_404_for_every_path_outside_the_documented_allowlist() {
        const UNLISTED_PATHS: &[&str] = &[
            "/",
            "/admin",
            "/admin/",
            "/admin/config/",
            "/dns-query/",
            "/ADMIN/STATUS",
            "/admin/secret",
            "/health/",
        ];
        for path in UNLISTED_PATHS {
            let Ok(req) = Request::builder()
                .method(Method::GET)
                .uri(*path)
                .body(Full::new(Bytes::new()))
            else {
                panic!("fixture request must build");
            };
            let response = match serve(req, state_with(no_op_client())).await {
                Ok(response) => response,
                Err(err) => match err {},
            };
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} unexpectedly matched a route"
            );
        }
    }
}
