#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `dnsqb-ui` (T-52) — a minimal, on-demand Tauri window for the three
//! Ф1 UI controls SPEC.md §8 names: upstream (provider) toggles, timeout
//! mode, and a blocked-query stat. Unlike `dnsqb-service`/`dnsqb-watcher`
//! (SERVICES.md: "обидва — окремі, довготривалі процеси"), this is not a
//! long-running daemon — it's opened when the user wants to check status or
//! change settings, and talks to whichever `dnsqb-service` instance is
//! already running via the admin channel (`dnsqb_service::admin`, T-52) on
//! the same machine.
//!
//! No local optimistic state: every command re-fetches or re-derives the
//! live status from the service and returns it, so the frontend always
//! renders what the resolver actually just did, not what the UI assumed it
//! did.
//!
//! Not yet the formal, audited Tauri-command allowlist SPEC.md §8 requires
//! (T-53) — these three commands are a reasonable minimal surface, but T-53
//! is the task that reviews and locks the surface down for real.

use dnsqb_service::{
    app_data_dir, AdminClient, AdminClientError, AdminConfigUpdate, AdminStatusResponse,
    EnabledProviders, ResolverConfig, TimeoutMode,
};
use serde::Serialize;

/// Errors surfaced to the webview across the Tauri IPC boundary. `Serialize`d
/// as an internally-tagged enum (not a bare `String`) so the frontend can
/// distinguish "the service isn't running right now" (an expected, user-
/// facing state — SPEC.md §8's indicator requirement) from any other
/// failure, without string-matching an error message.
#[derive(Debug, thiserror::Error, Serialize)]
#[serde(tag = "kind", content = "message", rename_all = "SCREAMING_SNAKE_CASE")]
enum UiError {
    /// No app-data directory could be resolved (`%LOCALAPPDATA%` unset) —
    /// nothing to do with whether the service is running.
    #[error("no app-data directory available: {0}")]
    AppData(String),
    /// `resolver_config.toml` exists but doesn't parse — same fatal-for-the-
    /// service condition `dnsqb-service` itself would refuse to start on.
    #[error("failed to read resolver config: {0}")]
    Config(String),
    /// The admin client couldn't be built — most likely `cert.pem` doesn't
    /// exist yet, meaning `dnsqb-service` has never been run on this
    /// machine at all.
    #[error("admin client unavailable: {0}")]
    ClientBuild(String),
    /// The admin request itself failed — most likely the service isn't
    /// running right now (connection refused). The frontend renders this as
    /// "сервіс не запущено", never as a fake `0`/`0` stat (Три Б).
    #[error("dnsqb-service is not reachable: {0}")]
    ServiceUnreachable(String),
}

impl From<AdminClientError> for UiError {
    fn from(err: AdminClientError) -> Self {
        match err {
            AdminClientError::CertRead(_) | AdminClientError::ClientBuild(_) => {
                Self::ClientBuild(err.to_string())
            }
            AdminClientError::Request(_) => Self::ServiceUnreachable(err.to_string()),
        }
    }
}

/// Builds an [`AdminClient`] targeting whichever port the local
/// `resolver_config.toml` currently names (falling back to
/// [`ResolverConfig::default`]'s port if the file doesn't exist yet — same
/// tolerance `dnsqb-service`'s own `main.rs` already applies to a missing
/// config file).
fn admin_client() -> Result<AdminClient, UiError> {
    let dir = app_data_dir().map_err(|err| UiError::AppData(err.to_string()))?;
    let config = ResolverConfig::load(&dir.join("resolver_config.toml"))
        .map_err(|err| UiError::Config(err.to_string()))?;
    AdminClient::new(&dir, config.port).map_err(UiError::from)
}

#[tauri::command]
async fn get_status() -> Result<AdminStatusResponse, UiError> {
    admin_client()?.status().await.map_err(UiError::from)
}

/// Sets both provider toggles together (the dashboard always has both on
/// hand — see [`AdminConfigUpdate`]'s own doc comment for why the wire
/// format is a full replace, not a per-field patch). Fetches the current
/// timeout mode first so this command doesn't have to guess it.
#[tauri::command]
async fn set_providers(quad9: bool, adguard: bool) -> Result<AdminStatusResponse, UiError> {
    let client = admin_client()?;
    let current = client.status().await?;
    client
        .apply(AdminConfigUpdate {
            providers: EnabledProviders { quad9, adguard },
            timeout_mode: current.timeout_mode,
        })
        .await
        .map_err(UiError::from)
}

#[tauri::command]
async fn set_timeout_mode(mode: TimeoutMode) -> Result<AdminStatusResponse, UiError> {
    let client = admin_client()?;
    let current = client.status().await?;
    client
        .apply(AdminConfigUpdate {
            providers: current.providers,
            timeout_mode: mode,
        })
        .await
        .map_err(UiError::from)
}

fn main() {
    let result = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_status,
            set_providers,
            set_timeout_mode
        ])
        .run(tauri::generate_context!());
    if let Err(err) = result {
        eprintln!("failed to run dnsqb-ui: {err}");
        std::process::exit(1);
    }
}
