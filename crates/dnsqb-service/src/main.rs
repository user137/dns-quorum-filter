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

use dnsqb_service::{
    app_data_dir, bind_listener, load_or_generate_server_config, serve, AppState, BindError, Cache,
    CacheConfig, OverrideLists, PersistPaths, PersistTarget, QueryLog, ReqwestDohClient,
    ResolverConfig, RuntimeSettings, TimeoutConfig,
};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let server_config = match load_or_generate_server_config() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!("failed to obtain a TLS certificate: {err}");
            std::process::exit(1);
        }
    };
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Resolved once, used for both the resolver config and override lists
    // below (T-144) - a missing app-data directory (`%LOCALAPPDATA%` unset)
    // isn't fatal for either, same tolerance `load_overrides` already had
    // before this slice: both fall back to defaults/empty with a warning.
    let app_data = app_data_dir().ok();

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

    let overrides = load_overrides(app_data.as_deref());

    let runtime = RuntimeSettings {
        providers: resolver_config.providers,
        timeout: TimeoutConfig {
            mode: resolver_config.timeout_mode,
            duration: Duration::from_millis(resolver_config.timeout_ms.into()),
        },
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

    // No config-driven sizing yet - T-146 (SPEC.md §6's own stated defaults:
    // 1000 entries or 24 hours).
    let state = Arc::new(AppState::new(
        client,
        overrides,
        runtime,
        Cache::new(&CacheConfig::default()),
        CacheConfig::default(),
        QueryLog::default(),
        persist,
    ));

    let port = resolver_config.port;
    tracing::info!("dns-quorum-filter listening on https://127.0.0.1:{port}/dns-query");

    serve_until_shutdown(listener, acceptor, state).await;
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
/// manually-edited TOML file, T-145 — T-46/T-47's UI writer is later work).
/// `OverrideLists::load` already treats a missing file as "no overrides
/// yet," so a first run with no file present starts empty rather than
/// failing. A missing `app_data` (the app-data directory couldn't be
/// resolved) is not fatal either — SPEC.md's user-safety principle:
/// starting with no overrides is strictly better than refusing to start at
/// all.
fn load_overrides(app_data: Option<&Path>) -> OverrideLists {
    let Some(dir) = app_data else {
        tracing::warn!("no app-data directory available, starting with empty override lists");
        return OverrideLists::empty();
    };
    let toml_path = dir.join("overrides.toml");
    warn_if_legacy_json_sibling_exists(&toml_path, &dir.join("overrides.json"));
    match OverrideLists::load(&toml_path) {
        Ok((overrides, invalid)) => {
            if !invalid.is_empty() {
                tracing::warn!(
                    "{} override-list entr{} rejected as invalid, ignored",
                    invalid.len(),
                    if invalid.len() == 1 { "y" } else { "ies" }
                );
            }
            overrides
        }
        Err(err) => {
            tracing::warn!("failed to load override lists ({err}), starting with none");
            OverrideLists::empty()
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
