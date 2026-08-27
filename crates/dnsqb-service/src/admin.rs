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

use crate::query_log::{Decision, LogEntry};
use crate::quorum::EnabledProviders;
use crate::timeout::TimeoutMode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Live resolver state plus a snapshot of log-derived stats — the body of
/// `GET /admin/status`, and echoed back by `POST /admin/config` after
/// applying an update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminStatusResponse {
    /// Which providers are currently queried.
    pub providers: EnabledProviders,
    /// Current timeout-interpretation mode.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminConfigUpdate {
    /// The desired provider toggles.
    pub providers: EnabledProviders,
    /// The desired timeout mode.
    pub timeout_mode: TimeoutMode,
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
}
