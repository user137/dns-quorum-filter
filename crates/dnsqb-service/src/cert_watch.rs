//! T-211 — publish the trust state of the local `cert.pem` onto [`AppState`]
//! on a slow background poll, so `GET /admin/cert-status` (and
//! `admin::compute_hero_state`, T-204) read a cached value instead of
//! spawning two `certutil` processes on every call — `/admin/status` sits on
//! the `/admin/ui` 2 s poll.
//!
//! Same shape as [`crate::pause_watch::run_pause_watcher`] /
//! [`crate::reachability::run_reachability_prober`]: a detached loop that
//! publishes a `Copy` value read elsewhere with no lock held across `.await`.
//! Unlike the pause watcher, [`crate::trust_store::is_trusted`] is a blocking
//! `certutil` subprocess, so each poll goes through
//! [`tokio::task::spawn_blocking`] and the cadence is correspondingly slow:
//! cert trust only changes on a deliberate install / uninstall / rotate, and
//! the two in-process routes ([`crate::dispatch`]'s `/admin/install-cert` and
//! `/admin/uninstall-local-state`) poke [`AppState::update_cert_trust`]
//! synchronously — this loop is the backstop for an out-of-process change
//! (the tray's own cert menu items) and for the first reading after startup.
//!
//! `certutil` here runs via `trust_store::certutil_command` with
//! `CREATE_NO_WINDOW` (T-194) and never touches a domain name.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::admin::CertTrustView;
use crate::dispatch::AppState;
use crate::upstream::DohClient;

/// Poll cadence. Slow on purpose — see the module doc: the value changes only
/// on an explicit user action, and both in-process paths poke the cache
/// directly.
pub const CERT_TRUST_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Background task: read `cert.pem`'s trust state, publish it via
/// [`AppState::update_cert_trust`], sleep, repeat. Runs one reading
/// immediately on entry so the `None` ("never checked") window is sub-second.
/// Detached and never joined — the process exit reclaims it. Generic over the
/// client (never used here), like [`crate::pause_watch::run_pause_watcher`].
pub async fn run_cert_trust_watch<C: DohClient + Sync>(
    cert_path: PathBuf,
    state: Arc<AppState<C>>,
) {
    loop {
        let probe_path = cert_path.clone();
        let reading = tokio::task::spawn_blocking(move || {
            match crate::trust_store::is_trusted(&probe_path) {
                Ok(true) => CertTrustView::Trusted,
                Ok(false) => CertTrustView::NotTrusted,
                Err(_) => CertTrustView::Unknown,
            }
        })
        .await;
        // A `JoinError` here means the blocking pool cancelled the probe — skip
        // this cycle rather than publish a fabricated reading; the next tick
        // retries.
        if let Ok(trust) = reading {
            state.update_cert_trust(trust);
        }
        tokio::time::sleep(CERT_TRUST_POLL_INTERVAL).await;
    }
}
