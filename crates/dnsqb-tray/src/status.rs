//! Background polling for the tray tooltip's live status (T-149) — a
//! dedicated OS thread with its own single-threaded `tokio` runtime, since
//! `tao`'s event loop owns the main thread and never yields it to `async`
//! code (confirmed against `tao`'s own docs during the T-149 Крок 0 probe).
//! The main thread never awaits anything here — it just reads
//! [`StatusHandle::current`], a cheap lock-guarded read of whatever this
//! background thread last wrote.

use dnsqb_service::{
    AdminClient, AdminStatusResponse, NetworkStatusView, WatchdogState, WATCHDOG_STATE_STALE_AFTER,
};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Honestly distinguished states (T-149's own "Три Б" precedent — same
/// discipline as `dnsqb-ui`'s former `bothOff` banner and T-66's cold/warm
/// relabel): never collapse "the service is unreachable" and "the service is
/// reachable but unfiltered" into the same tooltip text, and never show a fake
/// `0` count when the real answer is "unknown."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayStatus {
    /// `dnsqb-service` isn't running, isn't reachable on the expected port,
    /// or has never generated `cert.pem` yet (first run before it's ever
    /// been started) — these are deliberately not distinguished for the
    /// user, both mean "nothing to show right now."
    Unreachable,
    /// The watchdog is restarting `dnsqb-service` (T-95). Read straight from
    /// `watchdog-state.json` — the service is unreachable on the admin channel
    /// while this is true, so this is the only place the status is visible.
    /// Ranked above `NoActiveProvider` (user's priority decision 2026-09-02).
    ServiceRestarting,
    /// The watchdog's restart budget is spent — `dnsqb-service` is stopped,
    /// awaiting manual recovery (T-95, `GaveUp`).
    ServiceGaveUp,
    /// The machine has no internet connectivity (T-152). Ranked directly
    /// below the watchdog states and above `NoActiveProvider` — an
    /// environment failure the user can't fix by toggling providers
    /// (DECISIONS.md 2026-09-03). `dnsqb-service` is still reachable on the
    /// admin channel; it's the upstream network that's gone.
    Offline,
    /// Reachable, but both providers are disabled — unfiltered pass-through,
    /// the same warning state `dnsqb-service`'s embedded web UI already
    /// banners.
    NoActiveProvider {
        /// Live in-flight count, even while unfiltered.
        in_flight: u64,
    },
    /// Reachable and actively filtering.
    Filtering {
        /// Live in-flight count.
        in_flight: u64,
        /// Blocked count in the current log window (not "today" — see
        /// `AdminStats`'s own doc comment).
        blocked: u64,
        /// Total count in the current log window.
        total: u64,
        /// How many of the last `degraded_window` quorum-decided log
        /// entries had at least one voter timeout/error (T-56,
        /// `AdminStats::degraded_events`'s own doc comment) — a *recent
        /// recorded* signal, not a live upstream-health check.
        degraded_events: u64,
        /// How many quorum-decided entries `degraded_events` was actually
        /// computed over (T-56, `AdminStats::degraded_window`) — `0` means
        /// no signal yet, not "healthy".
        degraded_window: u64,
    },
}

impl TrayStatus {
    fn from_response(response: &AdminStatusResponse) -> Self {
        // T-152: no internet at all outranks the config-choice state below
        // (DECISIONS.md 2026-09-03) — showing "you disabled all providers"
        // when the real problem is a dead network would be misleading, and
        // the user can't fix it by re-enabling a provider. The watchdog
        // states still outrank this; they're checked before the admin call
        // in `spawn`'s poll loop.
        if response.network == NetworkStatusView::Offline {
            return Self::Offline;
        }
        // T-72/T-73: `active_providers` is the enabled voter list; empty =
        // SPEC.md §3/§8.1 pass-through (`NoActiveProvider`).
        if response.active_providers.is_empty() {
            Self::NoActiveProvider {
                in_flight: response.stats.in_flight,
            }
        } else {
            Self::Filtering {
                in_flight: response.stats.in_flight,
                blocked: response.stats.blocked,
                total: response.stats.total,
                degraded_events: response.stats.degraded_events,
                degraded_window: response.stats.degraded_window,
            }
        }
    }

    /// The text shown as the tray icon's hover tooltip.
    #[must_use]
    pub fn tooltip(&self) -> String {
        match self {
            Self::Unreachable => "dns-quorum-filter: сервіс недоступний".to_string(),
            Self::ServiceRestarting => {
                "dns-quorum-filter: сервіс перезапускається".to_string()
            }
            Self::ServiceGaveUp => {
                "dns-quorum-filter: сервіс зупинено \u{2014} перевищено ліміт спроб перезапуску"
                    .to_string()
            }
            Self::Offline => {
                "dns-quorum-filter: немає підключення до інтернету \u{2014} резолвінг призупинено"
                    .to_string()
            }
            Self::NoActiveProvider { in_flight } => format!(
                "dns-quorum-filter: фільтрація вимкнена (обидва провайдери вимкнено) \u{2014} {in_flight} запит(ів) зараз"
            ),
            Self::Filtering {
                in_flight,
                blocked,
                total,
                degraded_events,
                degraded_window,
            } => {
                let base = format!(
                    "dns-quorum-filter: {blocked}/{total} заблоковано \u{2014} {in_flight} запит(ів) зараз"
                );
                // Raw counts, not a collapsed bool/percentage (admin.rs's
                // own degraded_counts doc comment) — any nonzero count is
                // shown as-is, letting the reader judge severity instead of
                // an always-on warning masking it (T-56, advisor-caught
                // during planning: a bare threshold-free boolean would go
                // permanently true under routine fail-open timeouts).
                if *degraded_events > 0 {
                    format!(
                        "{base} \u{2014} {degraded_events}/{degraded_window} останніх апстрім-запитів мали тайм-аут/помилку"
                    )
                } else {
                    base
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{watchdog_override, TrayStatus};
    use dnsqb_service::{
        write_watchdog_state, AdminStats, AdminStatusResponse, ProviderStatusView, TimeoutMode,
        WatchdogState, WatchdogStateFile, WatchdogTarget, STATE_FILE_NAME, STATE_SCHEMA_VERSION,
    };
    use std::time::SystemTime;

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

    // T-95: a fresh state file in a restart-related state overrides everything
    // the admin channel could say (the service is unreachable there anyway).
    #[test]
    fn watchdog_override_wins_for_restarting_and_gave_up() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir must be creatable");
        };
        for state in [WatchdogState::Restarting, WatchdogState::BackoffWait] {
            write_watchdog_fixture(dir.path(), state);
            assert_eq!(
                watchdog_override(dir.path()),
                Some(TrayStatus::ServiceRestarting),
                "{state:?}"
            );
        }
        write_watchdog_fixture(dir.path(), WatchdogState::GaveUp);
        assert_eq!(
            watchdog_override(dir.path()),
            Some(TrayStatus::ServiceGaveUp)
        );
    }

    // Healthy / internal states / a missing file all fall through (`None`) so
    // the normal admin-channel logic runs.
    #[test]
    fn watchdog_override_is_none_for_healthy_internal_or_absent() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir must be creatable");
        };
        assert_eq!(watchdog_override(dir.path()), None, "no file");
        for state in [
            WatchdogState::Healthy,
            WatchdogState::ChannelDegraded,
            WatchdogState::SuspectDead,
            WatchdogState::VerifyingPid,
        ] {
            write_watchdog_fixture(dir.path(), state);
            assert_eq!(watchdog_override(dir.path()), None, "{state:?}");
        }
    }

    // A corrupt file must not panic — fall through.
    #[test]
    fn watchdog_override_is_none_for_a_corrupt_file() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir must be creatable");
        };
        if let Err(err) = std::fs::write(dir.path().join(STATE_FILE_NAME), b"{ not json") {
            panic!("fixture write must succeed: {err}");
        }
        assert_eq!(watchdog_override(dir.path()), None);
    }

    fn response(
        active_providers: Vec<ProviderStatusView>,
        stats: AdminStats,
    ) -> AdminStatusResponse {
        AdminStatusResponse {
            active_providers,
            timeout_mode: TimeoutMode::FailOpen,
            timeout_ms: 2000,
            serve_baseline_when_filters_unreachable: false,
            network: dnsqb_service::NetworkStatusView::Online,
            baseline_endpoint: dnsqb_service::BaselineEndpointView::Primary,
            port: 8443,
            stats,
            watchdog: None,
            persisted: true,
            query_log_persisted: false,
        }
    }

    fn stats(degraded_window: u64, degraded_events: u64) -> AdminStats {
        AdminStats {
            total: 10,
            blocked: 1,
            degraded_window,
            degraded_events,
            in_flight: 0,
        }
    }

    #[test]
    fn from_response_carries_degraded_counts_through_when_filtering() {
        let resp = response(
            vec![ProviderStatusView {
                id: "quad9".to_string(),
                display_name: "Quad9 Filtered".to_string(),
                category: dnsqb_service::Category::Security,
            }],
            stats(20, 3),
        );
        let status = TrayStatus::from_response(&resp);
        assert_eq!(
            status,
            TrayStatus::Filtering {
                in_flight: 0,
                blocked: 1,
                total: 10,
                degraded_events: 3,
                degraded_window: 20,
            }
        );
    }

    #[test]
    fn offline_network_outranks_no_active_provider() {
        // Empty provider list *and* offline — offline wins (DECISIONS.md
        // 2026-09-03: an environment failure above a config choice).
        let mut resp = response(vec![], stats(0, 0));
        resp.network = dnsqb_service::NetworkStatusView::Offline;
        assert_eq!(TrayStatus::from_response(&resp), TrayStatus::Offline);
    }

    #[test]
    fn online_network_with_no_providers_is_still_no_active_provider() {
        let resp = response(vec![], stats(0, 0));
        assert_eq!(
            TrayStatus::from_response(&resp),
            TrayStatus::NoActiveProvider { in_flight: 0 }
        );
    }

    #[test]
    fn offline_network_outranks_filtering() {
        let mut resp = response(
            vec![ProviderStatusView {
                id: "quad9".to_string(),
                display_name: "Quad9 Filtered".to_string(),
                category: dnsqb_service::Category::Security,
            }],
            stats(20, 0),
        );
        resp.network = dnsqb_service::NetworkStatusView::Offline;
        assert_eq!(TrayStatus::from_response(&resp), TrayStatus::Offline);
    }

    #[test]
    fn tooltip_omits_the_degraded_suffix_when_no_events_are_recorded() {
        let resp = response(
            vec![ProviderStatusView {
                id: "quad9".to_string(),
                display_name: "Quad9 Filtered".to_string(),
                category: dnsqb_service::Category::Security,
            }],
            stats(20, 0),
        );
        let tooltip = TrayStatus::from_response(&resp).tooltip();
        assert!(
            !tooltip.contains("тайм-аут"),
            "must not warn with zero recorded degraded events: {tooltip}"
        );
    }

    #[test]
    fn tooltip_includes_the_raw_degraded_counts_when_events_are_recorded() {
        let resp = response(
            vec![ProviderStatusView {
                id: "quad9".to_string(),
                display_name: "Quad9 Filtered".to_string(),
                category: dnsqb_service::Category::Security,
            }],
            stats(20, 3),
        );
        let tooltip = TrayStatus::from_response(&resp).tooltip();
        assert!(
            tooltip.contains("3/20"),
            "expected the raw counts in the tooltip, got: {tooltip}"
        );
    }

    #[test]
    fn no_active_provider_state_never_carries_a_degraded_signal() {
        // Even if the log still holds Timeout entries from before providers
        // were disabled (AdminStats::degraded_events's own doc comment) -
        // NoActiveProvider is a distinct pass-through state, no voters run
        // there at all.
        let resp = response(Vec::new(), stats(20, 5));
        assert_eq!(
            TrayStatus::from_response(&resp),
            TrayStatus::NoActiveProvider { in_flight: 0 }
        );
    }
}

/// A cheap, clonable read handle onto the background thread's latest result
/// (T-149) — `main.rs`'s event loop tick reads [`Self::current`] on every
/// pass; it never blocks and never itself talks to `dnsqb-service`.
#[derive(Clone)]
pub struct StatusHandle {
    current: Arc<RwLock<TrayStatus>>,
}

impl StatusHandle {
    /// The most recently observed status. Starts as [`TrayStatus::Unreachable`]
    /// until the background thread's first poll completes.
    #[must_use]
    pub fn current(&self) -> TrayStatus {
        *self.current.read()
    }
}

/// The watchdog's own view, read straight from `watchdog-state.json`
/// (`dnsqb-watcher` is its sole writer, SPEC.md §7.1 #7). `None` — fall through
/// to the admin channel — when the file is absent, unreadable, **stale** (the
/// watcher stopped rewriting it), or in an internal automaton step the
/// indicator doesn't show. Mirrors `dispatch::read_watchdog_view`, kept as its
/// own small copy rather than a shared cross-crate helper (different return
/// type, ~8 lines).
fn watchdog_override(app_data_dir: &Path) -> Option<TrayStatus> {
    let mtime = std::fs::metadata(app_data_dir.join(dnsqb_service::STATE_FILE_NAME))
        .and_then(|meta| meta.modified())
        .ok()?;
    if dnsqb_service::is_stale(SystemTime::now(), mtime, WATCHDOG_STATE_STALE_AFTER) {
        return None;
    }
    match dnsqb_service::read_watchdog_state(app_data_dir).ok()?.state {
        WatchdogState::Restarting | WatchdogState::BackoffWait => {
            Some(TrayStatus::ServiceRestarting)
        }
        WatchdogState::GaveUp => Some(TrayStatus::ServiceGaveUp),
        WatchdogState::Healthy
        | WatchdogState::ChannelDegraded
        | WatchdogState::SuspectDead
        | WatchdogState::VerifyingPid => None,
    }
}

/// Spawns the background polling thread and returns a handle to read its
/// latest result. `app_data_dir`/`port` are resolved once by the caller
/// (`main.rs`, at startup) — this never re-resolves either.
#[must_use]
pub fn spawn(app_data_dir: PathBuf, port: u16) -> StatusHandle {
    let current = Arc::new(RwLock::new(TrayStatus::Unreachable));
    let handle = StatusHandle {
        current: Arc::clone(&current),
    };

    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            tracing::error!("tray status thread failed to start its own tokio runtime");
            return;
        };
        runtime.block_on(async move {
            // Built once, on the first successful attempt, then reused for
            // every later poll — not rebuilt every tick (T-149,
            // advisor-caught: reading `cert.pem` and building a fresh TLS
            // client ~30x/minute is exactly the "helper promoted from an
            // edge case to the whole-traffic path without a re-audit" class
            // of gotcha CLAUDE.md already names for T-39\u{2192}T-41; the
            // old `dnsqb-ui` only ever built one per user-initiated command,
            // a much rarer cadence). `None` covers both "cert.pem doesn't
            // exist yet" (dnsqb-service has never run on this machine) and
            // any other build failure — both retried on the next tick
            // rather than cached as permanent.
            let mut client: Option<AdminClient> = None;
            loop {
                // T-95: the watchdog's own state file wins over anything the
                // admin channel could say — a restarting or given-up service is
                // unreachable on that channel by definition, so the still-alive
                // watcher's `watchdog-state.json` is the only place the status
                // is visible. Ranked above `NoActiveProvider` (user's priority
                // decision 2026-09-02: watchdog above 0-voters).
                if let Some(watchdog_status) = watchdog_override(&app_data_dir) {
                    *current.write() = watchdog_status;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                if client.is_none() {
                    client = AdminClient::new(&app_data_dir, port).ok();
                }
                let status = if let Some(c) = &client {
                    if let Ok(response) = c.status().await {
                        TrayStatus::from_response(&response)
                    } else {
                        // Advisor-caught: a request failure is NOT always
                        // just "the service is temporarily down" - it's also
                        // what a stale pinned certificate looks like, e.g.
                        // `tls::load_or_generate_server_config` regenerating
                        // `cert.pem` after a load failure (T-142), or a
                        // future T-69 rotation. Keeping the same client in
                        // that case would pin this thread to a dead cert
                        // forever - every later poll fails, the tooltip
                        // reads "Unreachable" permanently, while
                        // `spawn_admin_action`'s own per-click fresh clients
                        // in `main.rs` keep working fine. Dropping the
                        // client here means the next tick re-reads
                        // `cert.pem` and rebuilds - a real cost only while
                        // genuinely unreachable, which is exactly the state
                        // where nothing else is competing for the poll
                        // thread anyway.
                        client = None;
                        TrayStatus::Unreachable
                    }
                } else {
                    TrayStatus::Unreachable
                };
                *current.write() = status;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    });

    handle
}
