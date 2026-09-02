#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `dnsqb-service` binary entry point (T-143) — TCP accept loop + TLS
//! termination only; `DoH` GET/POST request/response logic lives in
//! `dnsqb_service::dispatch` (a lib module, unit-tested there without a live
//! socket). This file is deliberately not unit-tested itself, same
//! "hardcoded real resource, untested by design" precedent as
//! `paths::app_data_dir`/`cert::write_cert_and_key_to_app_data` — see the
//! manual smoke-test step recorded for T-143 in `TASKS-DONE.md` instead.
//!
//! Батч 3.3 adds the service side of the watchdog (SPEC.md §7): the channel-1
//! heartbeat pipe server, the `service.hb` touch loop (channel 2), and the
//! `service -> watcher` decision loop, all detached `tokio` tasks
//! ([`spawn_watchdog_tasks`]). Two interpretations of §7.1 worth naming: (a)
//! the service sends no channel-1 ping frame of its own — a regularly-arriving
//! ping from the watcher *is* its channel-1 liveness evidence (§7.1 #1's "both
//! directions multiplexed"); (b) the `service -> watcher` direction is never
//! written to `watchdog-state.json` — `dnsqb-watcher` is its sole writer
//! (§7.1 #7) — so this side acts and logs loudly but does not persist. The
//! decision logic itself is the pure `watchdog::loop_driver`, unit-tested
//! there; these task shells stay untested by the precedent above.

use dnsqb_service::{
    acquire_instance_guard, app_data_dir, bind_listener, load_maxmind_credentials,
    load_or_generate_server_config, migrate_legacy_credentials_file, run_geoip_updater,
    run_reachability_prober, serve, write_pid_file, AppState, BindError, Cache, CacheState,
    GeoipInit, GeoipReader, GeoipSource, GeoipState, GuardError, InstanceGuard, InstanceRole,
    InvalidEntry, OverrideLists, OverridesState, PersistPaths, PersistTarget, QueryLog,
    ReqwestDohClient, ResolverConfig, RuntimeInit, TimeoutConfig,
};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;

// Batch 3.3 — the watchdog wiring (SPEC.md §7). Windows-only for now, the same
// `#[cfg(windows)]` seam `watchdog::pipe` already sits behind; the Фаза 6 port
// lifts both together.
#[cfg(windows)]
use dnsqb_service::{
    is_stale, read_heartbeat_file, read_pid_file, spawn_sibling, touch_heartbeat_file,
    verify_pid_alive, ChannelObs, Direction, Effect, HeartbeatPipeServer, LoopDriver,
    WatchdogState,
};
#[cfg(windows)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(windows)]
use std::time::SystemTime;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Resolved once (a pure env read), used for the guard, resolver config and
    // override lists below (T-144) - a missing app-data directory
    // (`%LOCALAPPDATA%` unset) isn't fatal for any of them: they fall back to
    // defaults/empty with a warning.
    let app_data = app_data_dir().ok();

    // T-92: take the single-instance lock *before* `load_or_generate_server_config`
    // (SPEC.md §7.1 #2) - on a first run two concurrently-started services would
    // otherwise both reach `GeneratedFirstRun`, each writing `cert.pem` and each
    // `store_secret`-ing its key into the same app-data-derived entry, leaving a
    // `cert.pem` on disk that doesn't match the key the surviving process serves
    // (the mismatch class T-67's discard ordering exists to avoid). Held for the
    // whole process lifetime; the OS frees the handle on exit.
    let _instance_guard = acquire_service_guard(app_data.as_deref());

    let server_config = match load_or_generate_server_config() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!("failed to obtain a TLS certificate: {err}");
            std::process::exit(1);
        }
    };
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let resolver_config = load_resolver_config(app_data.as_deref());

    let listener = match bind_listener(resolver_config.port).await {
        Ok(listener) => listener,
        Err(BindError::AddrInUse(port)) => {
            // SPEC.md §1: an already-used port is an explicit error, never a
            // silent fallback to a different port.
            tracing::error!(
                "port {port} is already in use - not falling back to a different port \
                 (SPEC.md §1); stop the conflicting process, or edit resolver_config.toml"
            );
            std::process::exit(1);
        }
        Err(err) => {
            tracing::error!("failed to bind the DoH listener: {err}");
            std::process::exit(1);
        }
    };

    let client = match ReqwestDohClient::new() {
        Ok(client) => client,
        Err(err) => {
            tracing::error!("failed to build the upstream DoH client: {err}");
            std::process::exit(1);
        }
    };

    let (overrides, invalid_overrides) = load_overrides(app_data.as_deref());

    let runtime = RuntimeInit {
        providers: resolver_config.providers.clone(),
        timeout: TimeoutConfig {
            mode: resolver_config.timeout_mode,
            duration: Duration::from_millis(resolver_config.timeout_ms.into()),
        },
        serve_baseline_when_filters_unreachable: resolver_config
            .serve_baseline_when_filters_unreachable,
    };
    // T-52/T-149: the admin channel persists a config change back to
    // whichever path it was loaded from, and /admin/reset (T-149) reloads
    // from the same two paths - `None` (no app-data dir) means a live
    // change still applies in-memory, it just can't survive a restart (and
    // /admin/reset has nothing to reload from, 500), same tolerance
    // `load_resolver_config`/`load_overrides` already apply to a missing
    // app-data directory. Both paths are always resolved together from the
    // same `app_data_dir()` call - never independently `Some`/`None`.
    let persist = PersistTarget {
        port: resolver_config.port,
        paths: app_data.as_deref().map(|dir| PersistPaths {
            config: dir.join("resolver_config.toml"),
            overrides: dir.join("overrides.toml"),
        }),
    };

    // T-75: a database a previous run already downloaded is loaded
    // synchronously here so a restart doesn't lose GeoIP filtering until the
    // background updater's next periodic check completes - `geoip_path` is
    // `None` under the same "no app-data directory" tolerance every other
    // persisted file in this function already applies.
    let geoip_path = app_data.as_deref().map(|dir| dir.join("geoip.mmdb"));
    let geoip_database = load_geoip_state(geoip_path.as_deref());
    // T-76: the blocked-country list starts from whatever resolver_config.
    // toml's own [geoip] table resolved to (empty by default, SPEC.md
    // §3.5) - bundled with `geoip_database` into one `GeoipInit` (see that
    // type's own doc comment for why `AppState::new` splits it into two
    // independently-swapped fields rather than taking it as a single value).
    // T-163: the GeoIP source (DB-IP Lite / MaxMind) now lives on `AppState`
    // so it can be swapped at runtime — resolved here, once, and handed to the
    // constructor via `GeoipInit`. `run_geoip_updater` re-reads it from the
    // shared state each cycle rather than taking it as a spawn argument.
    let geoip = GeoipInit {
        database: geoip_database,
        blocked_countries: resolver_config.geoip.blocked_countries.clone(),
        source: load_geoip_source(app_data.as_deref()),
    };

    // Cache TTL/capacity config is now live-editable (T-153) - built from
    // whatever `resolver_config.toml`'s own `[cache]` table resolved to
    // (defaults if absent), not a hardcoded `CacheConfig::default()`.
    // Query-log sizing itself stays config-free - T-146 (SPEC.md §6's own
    // stated defaults: 1000 entries or 24 hours).
    let state = Arc::new(AppState::new(
        client,
        OverridesState {
            lists: overrides,
            invalid: invalid_overrides,
        },
        runtime,
        CacheState {
            cache: Cache::new(&resolver_config.cache),
            config: resolver_config.cache,
        },
        geoip,
        QueryLog::default(),
        persist,
    ));

    // T-75: the GeoIP database updater talks to a public third party
    // (db-ip.com, or download.maxmind.com in T-80's advanced mode), never
    // this service's own pinned-cert admin channel - a separate,
    // plainly-configured `reqwest::Client` with normal public-CA validation,
    // the same construction `ReqwestDohClient` itself uses for its own public
    // upstream queries (Quad9/AdGuard/Cloudflare).
    if let Some(path) = geoip_path {
        match reqwest::Client::builder().build() {
            Ok(geoip_client) => {
                tokio::spawn(run_geoip_updater(geoip_client, path, Arc::clone(&state)));
            }
            Err(err) => {
                tracing::error!("failed to build the GeoIP update HTTP client: {err}");
            }
        }
    } else {
        tracing::warn!("no app-data directory available, GeoIP database updates are disabled");
    }

    // T-152: the network-reachability prober. Its own plain `reqwest::Client`
    // (public-CA validation, no connection pool shared with the DoH client) —
    // hitting a few third-party `generate_204`-class markers has nothing to
    // do with upstream resolution. Deliberately not tied to `/health` or any
    // watchdog channel (a network outage must not look like a dead service).
    match reqwest::Client::builder().build() {
        Ok(probe_client) => {
            tokio::spawn(run_reachability_prober(probe_client, Arc::clone(&state)));
        }
        Err(err) => {
            tracing::error!("failed to build the reachability probe HTTP client: {err}");
        }
    }

    let port = resolver_config.port;
    tracing::info!("dns-quorum-filter listening on https://127.0.0.1:{port}/dns-query");

    // Batch 3.3: the heartbeat producers (pipe server + `service.hb` touch) and
    // the `service -> watcher` decision loop. Detached — they run alongside the
    // accept loop and are dropped on shutdown (the watchdog is a UX mechanism,
    // not graceful-shutdown-critical). The `watcher -> service` direction lives
    // in `dnsqb-watcher`; this process is not a writer of `watchdog-state.json`
    // (SPEC.md §7.1 #7), so the service-side direction acts and logs but never
    // persists.
    spawn_watchdog_tasks(app_data.as_deref());

    serve_until_shutdown(listener, acceptor, state).await;
}

/// The shared heartbeat tick for both watchdog directions (SPEC.md §7.1 #8).
#[cfg(windows)]
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);

/// A peer channel counts as silent for one tick once its last signal is older
/// than two intervals — one missed beat is jitter, two is a real miss. The
/// `loop_driver`'s own three-consecutive-miss threshold then decides the vote.
#[cfg(windows)]
const WATCHDOG_CHANNEL_FRESH: Duration = Duration::from_secs(10);

/// Milliseconds since the Unix epoch, saturating at `u64::MAX` — only ever
/// compared as a freshness delta, never converted back for display.
#[cfg(windows)]
fn watchdog_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

/// Starts the three background watchdog tasks (SPEC.md §7): the channel-1
/// heartbeat pipe server, this process's own `service.hb` touch loop (channel
/// 2), and the `service -> watcher` decision loop. A missing app-data directory
/// disables all three — the same tolerance every other persisted artefact in
/// this file applies.
fn spawn_watchdog_tasks(app_data: Option<&Path>) {
    #[cfg(windows)]
    {
        let Some(dir) = app_data.map(Path::to_path_buf) else {
            tracing::warn!("no app-data directory - watchdog heartbeat disabled");
            return;
        };
        let last_ping_at = Arc::new(AtomicU64::new(watchdog_now_millis()));
        tokio::spawn(run_heartbeat_pipe_server(
            dir.clone(),
            Arc::clone(&last_ping_at),
        ));
        tokio::spawn(run_service_heartbeat_touch(dir.clone()));
        tokio::spawn(run_service_to_watcher_watchdog(dir, last_ping_at));
    }
    #[cfg(not(windows))]
    {
        let _ = app_data;
    }
}

/// Channel 1 server (SPEC.md §7.1 #1): answers the watcher's ping/pong on the
/// one duplex pipe and records the arrival time of every ping. The service
/// sends no ping frame of its own — a regularly-arriving ping *is* the
/// service's channel-1 evidence that the watcher is alive ("both directions
/// multiplexed on the one pipe"). After a client disconnects, the next pipe
/// instance is opened and the loop waits again.
#[cfg(windows)]
async fn run_heartbeat_pipe_server(dir: std::path::PathBuf, last_ping_at: Arc<AtomicU64>) {
    let mut server = match HeartbeatPipeServer::bind(&dir) {
        Ok(server) => server,
        Err(err) => {
            tracing::error!("watchdog: heartbeat pipe server bind failed: {err}");
            return;
        }
    };
    loop {
        match server.accept().await {
            Ok(()) => {
                while server.respond_once(watchdog_now_millis()).await.is_ok() {
                    last_ping_at.store(watchdog_now_millis(), Ordering::Relaxed);
                }
                tracing::debug!("watchdog: heartbeat pipe client disconnected");
            }
            Err(err) => {
                tracing::warn!("watchdog: heartbeat pipe accept failed: {err}");
                tokio::time::sleep(WATCHDOG_INTERVAL).await;
            }
        }
        if let Err(err) = server.recreate() {
            tracing::error!("watchdog: heartbeat pipe recreate failed: {err}");
            return;
        }
    }
}

/// Channel 2 producer (SPEC.md §7.1 #4): re-touch `service.hb` every interval so
/// the watcher's file channel stays fresh.
#[cfg(windows)]
async fn run_service_heartbeat_touch(dir: std::path::PathBuf) {
    loop {
        if let Err(err) = touch_heartbeat_file(&dir, InstanceRole::Service) {
            tracing::warn!("watchdog: service.hb touch failed: {err}");
        }
        tokio::time::sleep(WATCHDOG_INTERVAL).await;
    }
}

/// The `service -> watcher` decision loop (SPEC.md §7): a unanimous vote over
/// channel 1 (age of the last ping received) and channel 2 (`watcher.hb` age);
/// on a confirmed-dead watcher, respawn it by absolute sibling path
/// ([`spawn_sibling`], never `PATH`). In-memory only — this direction is never
/// persisted (§7.1 #7).
#[cfg(windows)]
async fn run_service_to_watcher_watchdog(dir: std::path::PathBuf, last_ping_at: Arc<AtomicU64>) {
    let mut driver = LoopDriver::new(Direction::ServiceToWatcher);
    let watcher_hb = dir.join(format!("{}.hb", InstanceRole::Watcher.as_str()));
    loop {
        tokio::time::sleep(WATCHDOG_INTERVAL).await;
        let now = SystemTime::now();

        let last_ping = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(last_ping_at.load(Ordering::Relaxed)))
            .unwrap_or(now);
        let ipc_signal = !is_stale(now, last_ping, WATCHDOG_CHANNEL_FRESH);

        let file_signal = match read_heartbeat_file(&watcher_hb) {
            Ok(hb) => hb.marker_ok && !is_stale(now, hb.mtime, WATCHDOG_CHANNEL_FRESH),
            Err(_) => false,
        };

        let pid = if driver.state() == WatchdogState::VerifyingPid {
            read_pid_file(&dir, InstanceRole::Watcher)
                .ok()
                .map(|record| verify_pid_alive(record.pid, &record.exe_path))
        } else {
            None
        };

        let obs = ChannelObs {
            ipc_signal,
            file_signal,
            health_signal: None,
            pid,
        };
        for effect in driver.tick(now, &obs).effects {
            match effect {
                Effect::Spawn => match spawn_sibling(InstanceRole::Watcher) {
                    Ok(_child) => tracing::warn!("watchdog: respawned dnsqb-watcher"),
                    Err(err) => {
                        tracing::error!("watchdog: failed to respawn dnsqb-watcher: {err}");
                    }
                },
                Effect::LogGaveUp => tracing::error!(
                    "watchdog: gave up restarting dnsqb-watcher after the retry budget - \
                     manual recovery needed"
                ),
                // VerifyPid: the pid file is re-read next tick, driven by
                // `driver.state()`. WriteState: never emitted for the
                // service -> watcher direction (§7.1 #7).
                Effect::VerifyPid | Effect::WriteState(_) => {}
            }
        }
    }
}

/// T-92: take the `dnsqb-service` single-instance lock (SPEC.md §7.1 #2) and
/// write the pid file. A same-role process already holding the lock, or any
/// other lock-open failure, exits the process rather than racing the first over
/// the listener port and the config files. A missing app-data directory
/// (nowhere to place the lockfile) logs a warning and returns `None`, the same
/// tolerance `load_resolver_config`/`load_overrides` already apply.
fn acquire_service_guard(app_data: Option<&Path>) -> Option<InstanceGuard> {
    let Some(dir) = app_data else {
        tracing::warn!("%LOCALAPPDATA% is unset - starting without a single-instance guard");
        return None;
    };
    match acquire_instance_guard(dir, InstanceRole::Service) {
        Ok(guard) => {
            if let Err(err) = write_pid_file(dir, InstanceRole::Service) {
                tracing::warn!("could not write the pid file: {err}");
            }
            Some(guard)
        }
        Err(GuardError::AlreadyRunning(role)) => {
            tracing::error!(
                "another {role} instance is already running on this app-data directory - \
                 not starting a second one (SPEC.md §7.1 #2)"
            );
            std::process::exit(1);
        }
        Err(GuardError::Io(err)) => {
            tracing::error!("could not acquire the single-instance lock: {err}");
            std::process::exit(1);
        }
        // Unreachable on the only build target (deny.toml `targets` =
        // windows-msvc); named for exhaustiveness, never `unreachable!()`
        // (rust.md "Panic-Free Production Code").
        Err(GuardError::UnsupportedPlatform) => {
            tracing::error!("single-instance guard is unavailable on this platform");
            std::process::exit(1);
        }
    }
}

/// Loads a `GeoIP` database a previous run already persisted, if any (T-75).
/// A missing file is the ordinary first-run state, not an error - the
/// background updater's first successful check fills it in. A present but
/// unreadable/corrupt file is also non-fatal (same tolerance
/// `load_overrides`/`load_resolver_config` apply to their own files) -
/// worst case, filtering starts with no `GeoIP` database until the next
/// periodic refresh replaces the bad file.
fn load_geoip_state(path: Option<&Path>) -> GeoipState {
    let Some(path) = path else {
        return GeoipState::default();
    };
    match GeoipReader::open(path) {
        Ok(reader) => {
            tracing::info!("loaded existing GeoIP database from {}", path.display());
            // The database's own embedded build time, not this file's disk
            // mtime - see `GeoipReader::build_time`'s own doc comment for
            // why that distinction matters for T-78's future "how stale is
            // this" indicator.
            let updated_at = reader.build_time();
            GeoipState {
                reader: Some(Arc::new(reader)),
                updated_at,
            }
        }
        Err(_) => GeoipState::default(),
    }
}

/// Decides which upstream the `GeoIP` database updater pulls from (T-80/T-163).
/// DB-IP Lite (SPEC.md §3.5's registration-free default) unless the operator
/// stored `MaxMind` credentials (via `POST /admin/geoip/maxmind`, held in the
/// OS credential store since T-163). A missing app-data dir, no stored
/// credentials, or a *malformed* stored blob all fall back to DB-IP Lite — a
/// broken entry is logged (payload-free) and non-fatal, same posture as
/// [`load_overrides`]/[`load_geoip_state`]. The log line never contains the
/// credentials.
///
/// Runs the one-time pre-T-163 `geoip_maxmind.toml` → credential-store
/// migration first; a migration failure is logged and non-fatal (the load
/// below then simply finds no stored credentials).
fn load_geoip_source(app_data: Option<&Path>) -> GeoipSource {
    let Some(dir) = app_data else {
        return GeoipSource::DbIpLite;
    };
    if let Err(err) = migrate_legacy_credentials_file(dir) {
        tracing::warn!("MaxMind credentials migration failed ({err}), using stored/none");
    }
    match load_maxmind_credentials(dir) {
        Ok(Some(creds)) => {
            tracing::info!(
                "GeoIP source: MaxMind GeoLite2 (credentials from the OS credential store)"
            );
            GeoipSource::Maxmind(creds)
        }
        Ok(None) => {
            tracing::info!("GeoIP source: DB-IP Lite (default; no MaxMind credentials stored)");
            GeoipSource::DbIpLite
        }
        Err(err) => {
            tracing::warn!("ignoring stored MaxMind credentials ({err}), using DB-IP Lite");
            GeoipSource::DbIpLite
        }
    }
}

/// Accepts connections until `/admin/shutdown` signals (T-149), then drains
/// whatever's already in flight before returning. Split out of `main` to
/// stay under `clippy::too_many_lines` — same "extract a helper, not
/// `#[allow(...)]`" precedent T-147/T-148 already established for
/// `handle_query`/`resolve`.
///
/// `/admin/shutdown`'s only effect is sending `true` on `state`'s shutdown
/// channel - one long-lived receiver here, `tokio::select!`ed against
/// `listener.accept()` on every loop iteration. `graceful` gets one
/// `Watcher` per accepted connection (`graceful.watcher()`, not the
/// `GracefulShutdown` itself - it's deliberately not `Clone`, see its own doc
/// comment) so a connection accepted just before shutdown still gets watched
/// and drained rather than dropped mid-response.
async fn serve_until_shutdown(
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<AppState<ReqwestDohClient>>,
) {
    let mut shutdown_rx = state.shutdown_handle();
    let graceful = GracefulShutdown::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::warn!("failed to accept a connection: {err}");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let state = Arc::clone(&state);
                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(err) => {
                            tracing::warn!("TLS handshake failed: {err}");
                            return;
                        }
                    };
                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(move |req| serve(req, Arc::clone(&state)));
                    let builder = auto::Builder::new(TokioExecutor::new());
                    let conn = builder.serve_connection(io, service);
                    if let Err(err) = watcher.watch(conn).await {
                        tracing::warn!("connection error: {err}");
                    }
                });
            }
            // `Receiver::changed()` only resolves on an actual `true` send
            // from `/admin/shutdown` - `watch`'s initial value (`false`)
            // never triggers this branch on its own.
            _ = shutdown_rx.changed() => {
                tracing::info!(
                    "shutdown requested via /admin/shutdown - draining active connections"
                );
                break;
            }
        }
    }

    // Stop accepting new connections immediately - `graceful.shutdown()`
    // below only drains what's already been accepted.
    drop(listener);

    // Never `std::process::exit()` here - that would kill the still-running
    // `/admin/shutdown` handler's own connection before its 200 response
    // finishes writing. A 5s cap bounds a connection that never closes on
    // its own (e.g. a browser tab left open on `/admin/ui`) - draining is
    // best-effort past that point, not a promise every connection finished
    // cleanly.
    tokio::select! {
        () = graceful.shutdown() => {
            tracing::info!("graceful shutdown complete");
        }
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            tracing::warn!("graceful shutdown timed out after 5s - exiting anyway");
        }
    }
}

/// Loads `overrides.toml` from `app_data` (SPEC.md §5: a plain,
/// manually-edited TOML file, T-145; T-47 added a live UI writer on top).
/// `OverrideLists::load` already treats a missing file as "no overrides
/// yet," so a first run with no file present starts empty rather than
/// failing. A missing `app_data` (the app-data directory couldn't be
/// resolved) is not fatal either — SPEC.md's user-safety principle:
/// starting with no overrides is strictly better than refusing to start at
/// all.
///
/// Returns the invalid (unparseable) lines alongside the parsed lists
/// (T-47) — `AppState` keeps both so a later admin-channel edit's `save()`
/// writes them back verbatim instead of silently deleting them.
fn load_overrides(app_data: Option<&Path>) -> (OverrideLists, Vec<InvalidEntry>) {
    let Some(dir) = app_data else {
        tracing::warn!("no app-data directory available, starting with empty override lists");
        return (OverrideLists::empty(), Vec::new());
    };
    let toml_path = dir.join("overrides.toml");
    warn_if_legacy_json_sibling_exists(&toml_path, &dir.join("overrides.json"));
    match OverrideLists::load(&toml_path) {
        Ok((overrides, invalid)) => {
            if !invalid.is_empty() {
                tracing::warn!(
                    "{} override-list entr{} rejected as invalid, kept for the next save",
                    invalid.len(),
                    if invalid.len() == 1 { "y" } else { "ies" }
                );
            }
            (overrides, invalid)
        }
        Err(err) => {
            tracing::warn!("failed to load override lists ({err}), starting with none");
            (OverrideLists::empty(), Vec::new())
        }
    }
}

/// Loads `resolver_config.toml` from `app_data` (T-144, format switched to
/// TOML by T-145). A missing `app_data` falls back to
/// [`ResolverConfig::default`] with a warning, same tolerance as
/// [`load_overrides`]. Unlike override lists, a present-but-malformed config
/// file is **fatal** — SPEC.md §1's explicit "never a silent fallback on
/// port" rule means silently substituting the default port for a corrupted
/// `resolver_config.toml` could restart the service on a different port than
/// the one the user's browser is actually pointed at, invisibly.
/// `ResolverConfig::load` already validates `port`/`timeout_ms` aren't `0`
/// internally, so any `Err` here is a config the user needs to actually fix,
/// not a routine startup condition.
fn load_resolver_config(app_data: Option<&Path>) -> ResolverConfig {
    let Some(dir) = app_data else {
        tracing::warn!("no app-data directory available, using default resolver config");
        return ResolverConfig::default();
    };
    let toml_path = dir.join("resolver_config.toml");
    warn_if_legacy_json_sibling_exists(&toml_path, &dir.join("resolver_config.json"));
    match ResolverConfig::load(&toml_path) {
        Ok(config) => config,
        Err(err) => {
            tracing::error!("failed to load resolver_config.toml: {err}");
            std::process::exit(1);
        }
    }
}

/// T-145: the config file format switched from JSON to TOML with a hard
/// cutover, no dual-format loading — but a hard cutover on its own would make
/// an existing populated `overrides.json` silently invisible (`load()` sees
/// no `overrides.toml`, returns empty, and the caller only warns on `Err`,
/// never on a merely-missing file). A user with a real blocklist would go
/// silently unfiltered — worse off than before, with no indication why
/// (Три Б, user safety). This only logs the two file *paths*, never file
/// contents, so it carries no domain-name exposure risk.
fn warn_if_legacy_json_sibling_exists(toml_path: &Path, json_path: &Path) {
    if !toml_path.exists() && json_path.exists() {
        tracing::warn!(
            "found {} but not {} - the config file format changed to TOML (T-145); \
             rename/recreate it in the new format, the old file is being ignored",
            json_path.display(),
            toml_path.display()
        );
    }
}
