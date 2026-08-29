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
//! one, the same "extend the existing port" pattern already named for the
//! future `/health` (T-86). `/health` itself is still free to add later
//! without colliding.

use crate::admin::{
    compute_stats, AdminConfigUpdate, AdminStats, AdminStatusResponse, CacheConfigUpdate,
    CacheConfigView, LogEntryView, LogQueryResponse, OverrideAddRequest, OverrideDomainView,
    OverrideListsResponse, OverrideRemoveRequest,
};
use crate::admin_ui;
use crate::cache::{Cache, CacheConfig, CacheConfigError};
use crate::config::ResolverConfig;
use crate::overrides::{InvalidEntry, InvalidReason, ListKind, OverrideError, OverrideLists};
use crate::pipeline::{
    handle_query, invalidate_changed, proxy_to_single_upstream, PipelineOutcome,
};
use crate::query_log::{Decision, LogEntry, LogFilter, QueryLog, DEFAULT_MAX_ENTRIES};
use crate::quorum::EnabledProviders;
use crate::timeout::TimeoutConfig;
use crate::upstream::{DohClient, Provider};
use crate::wire::{decode_wire_message, encode_wire_message};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
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
use tokio::sync::watch;

/// The largest a DNS wire message is allowed to be, GET or POST alike — the
/// classic DNS-over-TCP 2-byte length prefix this project doesn't use still
/// names the right upper bound (a real DNS message can't legally exceed it),
/// and rejecting anything larger here is what actually bounds allocation
/// (SPEC.md §8.1: "ліміт розміру, не необмежена алокація").
pub(crate) const MAX_MESSAGE_SIZE: usize = 65_535;

const DNS_QUERY_PATH: &str = "/dns-query";
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

const ADMIN_STATUS_PATH: &str = "/admin/status";
const ADMIN_CONFIG_PATH: &str = "/admin/config";
const ADMIN_RESET_PATH: &str = "/admin/reset";
const ADMIN_SHUTDOWN_PATH: &str = "/admin/shutdown";
const ADMIN_OVERRIDES_PATH: &str = "/admin/overrides";
const ADMIN_OVERRIDES_ADD_PATH: &str = "/admin/overrides/add";
const ADMIN_OVERRIDES_REMOVE_PATH: &str = "/admin/overrides/remove";
const ADMIN_CACHE_CONFIG_PATH: &str = "/admin/cache-config";
const ADMIN_CACHE_CONFIG_APPLY_PATH: &str = "/admin/cache-config/apply";
const ADMIN_LOG_PATH: &str = "/admin/log";
const ADMIN_LOG_CLEAR_PATH: &str = "/admin/log/clear";
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
    (ADMIN_STATUS_PATH, &[Method::GET]),
    (ADMIN_CONFIG_PATH, &[Method::POST]),
    (ADMIN_RESET_PATH, &[Method::POST]),
    (ADMIN_SHUTDOWN_PATH, &[Method::POST]),
    (ADMIN_OVERRIDES_PATH, &[Method::GET]),
    (ADMIN_OVERRIDES_ADD_PATH, &[Method::POST]),
    (ADMIN_OVERRIDES_REMOVE_PATH, &[Method::POST]),
    (ADMIN_CACHE_CONFIG_PATH, &[Method::GET]),
    (ADMIN_CACHE_CONFIG_APPLY_PATH, &[Method::POST]),
    (ADMIN_LOG_PATH, &[Method::GET]),
    (ADMIN_LOG_CLEAR_PATH, &[Method::POST]),
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

/// The admin-mutable subset of resolver config (T-52) — bundled into one
/// [`AppState::runtime`] lock rather than two separate locks, so a read/
/// write is atomic across both fields: a query must never be able to
/// observe a newly-changed `providers` paired with a stale `timeout`, which
/// two independent locks could momentarily allow between an admin write to
/// one and the other.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeSettings {
    /// Which providers are currently queried.
    pub providers: EnabledProviders,
    /// Current timeout mode/duration.
    pub timeout: TimeoutConfig,
}

/// Where (if anywhere) admin-channel config changes should be persisted,
/// plus the immutable `port` value needed to reconstruct a full
/// [`ResolverConfig`] for that write. `port` itself is never admin-mutable —
/// changing it needs a listener re-bind, out of scope for a live-apply call.
#[derive(Debug, Clone)]
pub struct PersistTarget {
    /// The local `DoH` listener's port (unchanging at runtime).
    pub port: u16,
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
    let response = match handle_query(
        &query,
        &state.client,
        &overrides_state.lists,
        settings.providers,
        &cache_state.cache,
        &cache_state.config,
        &settings.timeout,
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
            proxy_to_single_upstream(&state.client, &query, &settings.timeout).await
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
    cache: RwLock<Arc<CacheState>>,
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
    /// Orders `POST /admin/config`'s and `POST /admin/cache-config/apply`'s
    /// (T-153) live-write + disk-persist sequences across concurrent
    /// requests (T-58) — `ResolverConfig::save` is a plain `fs::write`, not
    /// atomic, and happens *after* `runtime`'s (or `cache`'s) write lock is
    /// released (deliberately: holding either across a blocking disk write
    /// would stall every in-flight query's own read of that field too).
    /// **Shared by both routes, not two independent locks, because both
    /// write into the *same* physical file** (`resolver_config.toml` now
    /// carries `providers`/`timeout_mode` *and* `[cache]`, T-153) — two
    /// separate locks guarding writes into one file would reproduce the
    /// exact disk-vs-live divergence this lock exists to prevent, just
    /// between two different routes instead of two calls to the same one.
    /// Each handler's `save()` call snapshots **both** `runtime` and `cache`
    /// (not just the field it's changing) while still holding this lock, so
    /// the file it writes always reflects the other field's current live
    /// value too, never a stale/default one. Without this, two
    /// near-simultaneous admin POSTs (e.g. two quick clicks in the web UI)
    /// can persist to disk in the opposite order from the order their
    /// in-memory writes landed, leaving the on-disk file not matching the
    /// live settings. **Invariant: `persist_lock` is always acquired before
    /// `runtime`/`cache`, never after.** **`apply_admin_reset` also takes
    /// this lock (T-153) across its whole load-then-commit sequence** —
    /// unlike the state before T-153, reset now writes both `runtime` *and*
    /// `cache` in memory after reading the same file this lock guards, so
    /// without it a concurrent admin POST could commit its own disk write
    /// between reset's read and reset's memory-write, leaving memory holding
    /// stale values while disk holds the new ones until restart (the same
    /// class of bug `overrides_persist_lock` below already exists to
    /// prevent for `overrides.toml`, now true here too because reset gained
    /// a second in-memory field with a shared on-disk file). No deadlock
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
        runtime: RuntimeSettings,
        cache: CacheState,
        query_log: QueryLog,
        persist: PersistTarget,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            client,
            overrides: RwLock::new(Arc::new(overrides)),
            runtime: RwLock::new(runtime),
            cache: RwLock::new(Arc::new(cache)),
            query_log,
            persist,
            in_flight: AtomicU64::new(0),
            shutdown_tx,
            persist_lock: Mutex::new(()),
            overrides_persist_lock: Mutex::new(()),
        }
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

/// Builds the current [`AdminStatusResponse`] from `state` — shared by
/// `GET /admin/status` and the response [`apply_admin_config`] echoes back
/// after a `POST /admin/config`. `persisted` is the caller's to state
/// (always `true` for a plain status read, since nothing changed).
fn admin_status<C: DohClient + Sync>(state: &AppState<C>, persisted: bool) -> AdminStatusResponse {
    let settings = *state.runtime.read();
    let entries = state.query_log.snapshot(SystemTime::now());
    AdminStatusResponse {
        providers: settings.providers,
        timeout_mode: settings.timeout.mode,
        timeout_ms: timeout_ms(settings.timeout.duration),
        port: state.persist.port,
        stats: live_stats(state, &entries),
        persisted,
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
/// `state.cache`'s current config (not just `runtime`) while still holding
/// the lock, so the file this writes reflects the cache config's live value
/// too, not a stale/default one — see `persist_lock`'s own doc comment for
/// why this cross-field read has to happen here.
fn apply_admin_config<C: DohClient + Sync>(
    state: &AppState<C>,
    update: AdminConfigUpdate,
) -> AdminStatusResponse {
    let _persist_guard = state.persist_lock.lock();
    // Captured inside the write guard's own scope, not re-read via a second
    // lock acquisition afterward — advisor-caught: re-reading opened a
    // window where a concurrent `POST` could persist *its* values under
    // *this* request's response, however unlikely with a single local UI
    // client. This way the values persisted/echoed are provably the exact
    // ones just written, not "whatever the lock currently holds."
    let settings = {
        let mut guard = state.runtime.write();
        guard.providers = update.providers;
        guard.timeout.mode = update.timeout_mode;
        *guard
    };
    let cache_config = state.cache.read().config;
    let persisted = match state.persist.paths.as_ref() {
        Some(paths) => {
            let config = ResolverConfig {
                port: state.persist.port,
                timeout_mode: settings.timeout.mode,
                timeout_ms: timeout_ms(settings.timeout.duration),
                providers: settings.providers,
                cache: cache_config,
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
        providers: settings.providers,
        timeout_mode: settings.timeout.mode,
        timeout_ms: timeout_ms(settings.timeout.duration),
        port: state.persist.port,
        stats: live_stats(state, &state.query_log.snapshot(SystemTime::now())),
        persisted,
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
/// No deadlock risk holding both locks here: this is the only function that
/// ever holds both, always in this order, and no other function holds
/// either concurrently with the other.
fn apply_admin_reset<C: DohClient + Sync>(
    state: &AppState<C>,
) -> Result<AdminStatusResponse, AdminResetError> {
    let paths = state
        .persist
        .paths
        .as_ref()
        .ok_or(AdminResetError::NoAppData)?;
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
        providers: config.providers,
        timeout: TimeoutConfig {
            mode: config.timeout_mode,
            duration: Duration::from_millis(config.timeout_ms.into()),
        },
    };
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
/// comment. Also reads `state.runtime`'s current settings (not just
/// `cache`) while still holding the lock, so the file this writes reflects
/// `providers`/`timeout_mode`'s live values too, not stale/default ones —
/// same cross-field-read requirement `apply_admin_config` has in the other
/// direction.
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
    let persisted = match state.persist.paths.as_ref() {
        Some(paths) => {
            let config = ResolverConfig {
                port: state.persist.port,
                timeout_mode: runtime.timeout.mode,
                timeout_ms: timeout_ms(runtime.timeout.duration),
                providers: runtime.providers,
                cache: new_config,
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
    voter: Option<Provider>,
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
                parsed.voter = Some(
                    value
                        .parse::<Provider>()
                        .map_err(|_| LogQueryError::UnknownVoter)?,
                );
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
    let filter = LogFilter {
        domain_contains: parsed.domain_contains.as_deref(),
        decision: parsed.decision,
        voter: parsed.voter,
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
        ADMIN_STATUS_PATH => serve_admin_status(&state),
        ADMIN_CONFIG_PATH => serve_admin_config(req, &state).await,
        ADMIN_RESET_PATH => serve_admin_reset(req, &state).await,
        ADMIN_SHUTDOWN_PATH => serve_admin_shutdown(req, &state).await,
        ADMIN_OVERRIDES_PATH => serve_admin_overrides(&state),
        ADMIN_OVERRIDES_ADD_PATH => serve_admin_overrides_add(req, &state).await,
        ADMIN_OVERRIDES_REMOVE_PATH => serve_admin_overrides_remove(req, &state).await,
        ADMIN_CACHE_CONFIG_PATH => serve_admin_cache_config(&state),
        ADMIN_CACHE_CONFIG_APPLY_PATH => serve_admin_cache_config_apply(req, &state).await,
        ADMIN_LOG_PATH => serve_admin_log(req.uri().query(), &state),
        ADMIN_LOG_CLEAR_PATH => serve_admin_log_clear(req, &state).await,
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
        admin_status, content_type_is_dns_message, parse_log_query, resolve_doh_request, serve,
        wire_bytes_from_get, AppState, CacheState, DohRequestError, LogQueryError, OverridesState,
        PersistPaths, PersistTarget, RuntimeSettings, DEFAULT_LOG_LIMIT, DNS_QUERY_PATH,
        MAX_LOG_LIMIT, MAX_MESSAGE_SIZE, ROUTES,
    };
    use crate::admin::{
        AdminConfigUpdate, AdminStatusResponse, CacheConfigUpdate, CacheConfigView, DecisionView,
        LogQueryResponse, OverrideAddRequest, OverrideListsResponse, OverrideRemoveRequest,
    };
    use crate::cache::{Cache, CacheConfig, CacheEntry, CacheKey, Verdict};
    use crate::config::ResolverConfig;
    use crate::overrides::{ListKind, OverrideEntry, OverrideLists};
    use crate::query_log::{DecisionSource, LogEntry, QueryLog};
    use crate::quorum::{EnabledProviders, VoterRecord, VoterVerdict};
    use crate::timeout::TimeoutConfig;
    use crate::upstream::{doh_get_url, DohClient, Provider, UpstreamError};
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
                provider: Provider::Quad9,
                verdict: VoterVerdict::Allow,
                allow_ip_count: Some(1),
                error_message: None,
            }],
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

    /// Total `(path, method)` pairs across every [`ROUTES`] entry - a plain
    /// module-level fn, not a captured closure, since `proptest!`'s
    /// generated `#[test] fn` can only reference items, not locals from an
    /// enclosing block.
    fn route_method_count() -> usize {
        ROUTES.iter().map(|(_, methods)| methods.len()).sum()
    }

    /// The `index`-th `(path, method)` pair, flattening `ROUTES` in
    /// declaration order. Panics on an out-of-range `index` - callers only
    /// ever pass `0..route_method_count()`, so this is a real invariant
    /// violation, not untrusted input.
    fn route_method_at(index: usize) -> (&'static str, Method) {
        let mut remaining = index;
        for (path, methods) in ROUTES {
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
        assert_eq!(entries[0].decision_source, DecisionSource::Quorum);
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
                paths: None,
            },
        )
    }

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
            RuntimeSettings {
                providers: EnabledProviders::default(),
                timeout: TimeoutConfig::default(),
            },
            CacheState {
                cache: Cache::new(&CacheConfig::default()),
                config: CacheConfig::default(),
            },
            QueryLog::default(),
            persist,
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
        assert_eq!(status.providers, EnabledProviders::default());
        assert!(status.persisted);
        assert_eq!(status.stats.total, 0);
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
            providers: EnabledProviders::default(),
            timeout_mode: crate::timeout::TimeoutMode::FailOpen,
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
            providers: EnabledProviders::default(),
            timeout_mode: crate::timeout::TimeoutMode::FailOpen,
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

    // T-52: both providers disabled is newly reachable through a UI (the
    // admin channel) for the first time - the exact regression shape T-148
    // already proved at the quorum::resolve level
    // (quad9_disabled_under_fail_closed_is_still_allow_not_falsely_blocked),
    // re-proven here at the HTTP admin-channel level: a live-applied
    // both-disabled update under fail_closed must still resolve via
    // pass-through, never fail-closed-block, and must never call the
    // quorum-branch mock at all.
    #[tokio::test]
    async fn serve_admin_config_disabling_both_providers_is_pass_through_not_fail_closed() {
        let ip = Ipv4Addr::new(9, 9, 9, 9);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Panic,
            calls: AtomicU32::new(0),
        };
        let state = state_with(client);

        let update = AdminConfigUpdate {
            providers: EnabledProviders {
                quad9: false,
                adguard: false,
            },
            timeout_mode: crate::timeout::TimeoutMode::FailClosed,
        };
        let config_response = match serve(admin_config_request(update), Arc::clone(&state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(config_response.status(), StatusCode::OK);

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
                paths: Some(PersistPaths {
                    config: path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );

        let update = AdminConfigUpdate {
            providers: EnabledProviders {
                quad9: false,
                adguard: true,
            },
            timeout_mode: crate::timeout::TimeoutMode::FailClosed,
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
        assert_eq!(loaded.providers, update.providers);
        assert_eq!(loaded.timeout_mode, update.timeout_mode);
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
                paths: Some(PersistPaths {
                    config: config_path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );

        let updates = [
            AdminConfigUpdate {
                providers: EnabledProviders {
                    quad9: true,
                    adguard: false,
                },
                timeout_mode: crate::timeout::TimeoutMode::FailOpen,
            },
            AdminConfigUpdate {
                providers: EnabledProviders {
                    quad9: false,
                    adguard: true,
                },
                timeout_mode: crate::timeout::TimeoutMode::FailClosed,
            },
            AdminConfigUpdate {
                providers: EnabledProviders {
                    quad9: true,
                    adguard: true,
                },
                timeout_mode: crate::timeout::TimeoutMode::Degraded,
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
            loaded.providers, live.providers,
            "disk must match the live settings after concurrent admin config writes"
        );
        assert_eq!(
            loaded.timeout_mode, live.timeout.mode,
            "disk must match the live settings after concurrent admin config writes"
        );
        assert!(
            updates
                .iter()
                .any(|u| u.providers == live.providers && u.timeout_mode == live.timeout.mode),
            "final live settings must match one of the applied updates exactly, not a mix"
        );
    }

    #[tokio::test]
    async fn serve_admin_config_reports_not_persisted_when_no_config_path_is_set() {
        let state = state_with(no_op_client());
        let update = AdminConfigUpdate {
            providers: EnabledProviders::default(),
            timeout_mode: crate::timeout::TimeoutMode::FailOpen,
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
                paths: Some(PersistPaths {
                    config: config_path,
                    overrides: overrides_path,
                }),
            },
        );
        let before_overrides = std::sync::Arc::as_ptr(&state.overrides.read());
        let before_runtime = *state.runtime.read();

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
        let after_runtime = *state.runtime.read();
        assert_eq!(after_runtime.providers, before_runtime.providers);
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
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let config_path = dir.path().join("resolver_config.toml");
        let overrides_path = dir.path().join("overrides.toml");
        if let Err(err) = std::fs::write(
            &config_path,
            "port = 8443\ntimeout_mode = \"fail_closed\"\ntimeout_ms = 3000\n\n\
             [providers]\nquad9 = false\nadguard = true\n",
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
        assert_eq!(
            status.providers,
            EnabledProviders {
                quad9: false,
                adguard: true,
            },
            "reset must reload providers from the fixture file"
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
            RuntimeSettings {
                providers: EnabledProviders::default(),
                timeout: TimeoutConfig::default(),
            },
            CacheState {
                cache: Cache::new(&CacheConfig::default()),
                config: CacheConfig::default(),
            },
            QueryLog::default(),
            PersistTarget {
                port: 8443,
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
                paths: Some(PersistPaths {
                    config: config_path.clone(),
                    overrides: dir.path().join("overrides.toml"),
                }),
            },
        );

        let config_update = AdminConfigUpdate {
            providers: EnabledProviders {
                quad9: false,
                adguard: true,
            },
            timeout_mode: crate::timeout::TimeoutMode::FailClosed,
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
            loaded.providers, config_update.providers,
            "the providers change must survive a concurrent cache-config write"
        );
        assert_eq!(
            loaded.timeout_mode, config_update.timeout_mode,
            "the timeout-mode change must survive a concurrent cache-config write"
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
            provider: Provider::AdGuard,
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
        ("/admin/status", &[Method::GET]),
        ("/admin/config", &[Method::POST]),
        ("/admin/reset", &[Method::POST]),
        ("/admin/shutdown", &[Method::POST]),
        ("/admin/overrides", &[Method::GET]),
        ("/admin/overrides/add", &[Method::POST]),
        ("/admin/overrides/remove", &[Method::POST]),
        ("/admin/cache-config", &[Method::GET]),
        ("/admin/cache-config/apply", &[Method::POST]),
        ("/admin/log", &[Method::GET]),
        ("/admin/log/clear", &[Method::POST]),
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
            "/health",
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
