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
    CacheConfig, OverrideLists, ReqwestDohClient, TimeoutConfig, Voters,
};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// MVP hardcoded default (no config UI yet — T-52). SPEC.md §1 requires the
/// port be fixed-by-default and configurable, but doesn't itself name a
/// number — provisional, documented tech debt, same pattern as T-48's cert
/// validity window; T-52's Tauri settings screen is where this becomes a
/// real setting.
const DOH_PORT: u16 = 8443;

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

    let listener = match bind_listener(DOH_PORT).await {
        Ok(listener) => listener,
        Err(BindError::AddrInUse(port)) => {
            // SPEC.md §1: an already-used port is an explicit error, never a
            // silent fallback to a different port.
            tracing::error!(
                "port {port} is already in use - not falling back to a different port \
                 (SPEC.md §1); stop the conflicting process, or wait for a configurable-port \
                 setting (T-52)"
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

    let overrides = load_overrides();

    let state = Arc::new(AppState::new(
        client,
        overrides,
        Voters::Enabled, // MVP default, no toggle UI yet (T-52)
        Cache::new(&CacheConfig::default()),
        CacheConfig::default(),
        TimeoutConfig::default(),
    ));

    tracing::info!("dns-quorum-filter listening on https://127.0.0.1:{DOH_PORT}/dns-query");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!("failed to accept a connection: {err}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);
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
            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                tracing::warn!("connection error: {err}");
            }
        });
    }
}

/// Loads `overrides.json` from the app-data directory (SPEC.md §5: a plain,
/// manually-edited JSON file — T-46/T-47's UI writer is later work).
/// `OverrideLists::load` already treats a missing file as "no overrides
/// yet," so a first run with no file present starts empty rather than
/// failing. An app-data directory that can't be resolved at all is not
/// fatal either — SPEC.md's user-safety principle: starting with no
/// overrides is strictly better than refusing to start at all.
fn load_overrides() -> OverrideLists {
    let dir = match app_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            tracing::warn!(
                "could not resolve the app-data directory ({err}), starting with empty \
                 override lists"
            );
            return OverrideLists::empty();
        }
    };
    match OverrideLists::load(&dir.join("overrides.json")) {
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
