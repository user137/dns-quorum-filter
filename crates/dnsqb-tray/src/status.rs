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
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Filtering is paused on purpose (T-185) — the user clicked "Призупинити
    /// фільтрацію". Since T-193 `dnsqb-service` **stays up** and serves every
    /// query through the unfiltered baseline; the watchdog keeps supervising it
    /// normally. The presence of `stop.flag` is still the whole signal, read
    /// straight off disk here. Ranked **above** every watchdog and admin state
    /// — a pause is a deliberate choice the user needs named as such, not as a
    /// failure. (The pipeline and the `/admin/ui` hero rank `Offline` above
    /// `Paused`; the tray ranks `Paused` first. Both are correct — the tray's
    /// is the actionable reading. Intentional, not to be "reconciled".)
    Paused,
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
        /// T-128: the rating-filter «bubble» (SPEC.md §5.3) is enabled
        /// **and** gating queries (`RatingFilterStatusView::active`). Adds a
        /// tooltip suffix only — never the icon colour (the bubble is a
        /// deliberate scope choice, not a health signal, same "pass-through
        /// ≠ failure" reasoning as `NoActiveProvider`). `enabled` but not yet
        /// `active` (Fork B) shows no suffix — that transient state is the
        /// web UI's Fork-B notice to explain, not the tray's.
        rating_filter_active: bool,
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
                // `active` is already `enabled && zone non-empty` server-side
                // (the single `rating_filter_is_active` authority).
                rating_filter_active: response.rating_filter.active,
            }
        }
    }

    /// The text shown as the tray icon's hover tooltip. T-176 reworded these
    /// for a non-technical reader (no "резолвінг", no "апстрім", no stale
    /// "обидва провайдери") while keeping the raw counts intact.
    #[must_use]
    pub fn tooltip(&self) -> String {
        match self {
            Self::Unreachable => "DNS Quorum Filter: служба недоступна".to_string(),
            Self::ServiceRestarting => {
                "DNS Quorum Filter: служба перезапускається\u{2026}".to_string()
            }
            Self::ServiceGaveUp => {
                "DNS Quorum Filter: служба зупинилася \u{2014} відкрийте вікно, щоб перезапустити"
                    .to_string()
            }
            Self::Paused => {
                "DNS Quorum Filter: фільтрацію призупинено \u{2014} увімкніть через меню".to_string()
            }
            Self::Offline => {
                "DNS Quorum Filter: немає інтернету \u{2014} перевірки призупинено".to_string()
            }
            Self::NoActiveProvider { in_flight } => format!(
                "DNS Quorum Filter: фільтрація вимкнена \u{2014} жоден провайдер не активний ({in_flight} запит(ів) зараз)"
            ),
            Self::Filtering {
                in_flight,
                blocked,
                total,
                degraded_events,
                degraded_window,
                rating_filter_active,
            } => {
                let base = format!(
                    "DNS Quorum Filter: захищає \u{2014} {blocked}/{total} заблоковано ({in_flight} запит(ів) зараз)"
                );
                // Raw counts, not a collapsed bool/percentage (admin.rs's
                // own degraded_counts doc comment) — any nonzero count is
                // shown as-is, letting the reader judge severity instead of
                // an always-on warning masking it (T-56, advisor-caught
                // during planning: a bare threshold-free boolean would go
                // permanently true under routine fail-open timeouts).
                let mut text = if *degraded_events > 0 {
                    format!(
                        "{base} \u{2014} деякі перевірки не відповідають ({degraded_events}/{degraded_window} останніх запитів мали тайм-аут)"
                    )
                } else {
                    base
                };
                // T-128: an informational suffix, ranked after the degraded
                // note (a real problem outranks a scope choice).
                if *rating_filter_active {
                    text.push_str(" \u{2014} рейтинг-фільтр «бульбашка» активний");
                }
                text
            }
        }
    }
}

/// Which of the four generated tray-icon blobs to display (T-191). A
/// *rendering* of the existing [`TrayStatus`] ladder plus `cert_trusted` as a
/// second, orthogonal input — it adds no new status condition and does not
/// reorder the priority the poll loop already applies (DECISIONS.md
/// 2026-09-02 / 2026-09-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconColour {
    Green,
    Amber,
    Grey,
    Red,
}

/// Pure and total. The `match` is exhaustive with no wildcard arm on purpose:
/// a future 8th [`TrayStatus`] variant must fail to compile here rather than
/// silently render green ("захищає"). DECISIONS.md 2026-09-08 records why the
/// cert-not-trusted → red override touches only [`TrayStatus::Filtering`].
///
/// T-196: `Filtering` goes amber only when **every** recent quorum query was
/// degraded (`degraded_events == degraded_window`) — i.e. filtering is
/// effectively not happening. A single recovered upstream timeout is a
/// trailing-window blip, not an alarm: the icon stays green and
/// [`TrayStatus::tooltip`]'s own "N/M останніх" suffix carries the nuance.
#[must_use]
pub fn icon_colour(status: TrayStatus, cert_trusted: bool) -> IconColour {
    match status {
        TrayStatus::Unreachable | TrayStatus::ServiceGaveUp => IconColour::Red,
        TrayStatus::ServiceRestarting | TrayStatus::Offline => IconColour::Amber,
        // "Filtering off on purpose" — SPEC.md §3/§8.1 requires this be shown
        // as a distinct, non-failure state, so an untrusted cert does not
        // repaint it red; [`cert_warning`] still names the cert issue in the
        // tooltip.
        TrayStatus::Paused | TrayStatus::NoActiveProvider { .. } => IconColour::Grey,
        TrayStatus::Filtering {
            degraded_events,
            degraded_window,
            ..
        } => {
            if !cert_trusted {
                IconColour::Red
            } else if degraded_window > 0 && degraded_events == degraded_window {
                // Every recent quorum query degraded → filtering effectively
                // isn't happening (T-196). `degraded_window == 0` is a fresh
                // start with no quorum entries yet, not a failure.
                IconColour::Amber
            } else {
                IconColour::Green
            }
        }
    }
}

/// Tooltip suffix naming the untrusted-certificate problem. `Some` exactly
/// when the certificate the `DoH` listener serves isn't trusted **and** the
/// service is otherwise reachable ([`TrayStatus::Filtering`] /
/// [`TrayStatus::NoActiveProvider`]) — the states where the browser's own
/// `DoH` to us then fails silently. Mirrors the `degraded_events` suffix
/// already in [`TrayStatus::tooltip`]; appended by [`compose_tooltip`], never
/// alone, so a red icon can't sit beside a green-sounding tooltip.
#[must_use]
pub fn cert_warning(status: TrayStatus, cert_trusted: bool) -> Option<&'static str> {
    if cert_trusted {
        return None;
    }
    match status {
        TrayStatus::Filtering { .. } | TrayStatus::NoActiveProvider { .. } => Some(
            " \u{2014} сертифікат не встановлено: у меню іконки \u{2192} «Встановити сертифікат»",
        ),
        _ => None,
    }
}

/// The tray tooltip for `status`, plus the [`cert_warning`] suffix when it
/// applies. `main.rs` calls this instead of [`TrayStatus::tooltip`] directly.
#[must_use]
pub fn compose_tooltip(status: TrayStatus, cert_trusted: bool) -> String {
    let mut text = status.tooltip();
    if let Some(suffix) = cert_warning(status, cert_trusted) {
        text.push_str(suffix);
    }
    text
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
            paused: false,
            baseline_endpoint: dnsqb_service::BaselineEndpointView::Primary,
            port: 8443,
            stats,
            watchdog: None,
            persisted: true,
            encrypted_persistence: dnsqb_service::EncryptedPersistenceView {
                query_log: false,
                cache: false,
            },
            rating_filter: dnsqb_service::RatingFilterStatusView {
                enabled: false,
                active: false,
                lists: Vec::new(),
                available_lists: Vec::new(),
                loaded: Vec::new(),
            },
        }
    }

    fn stats(degraded_window: u64, degraded_events: u64) -> AdminStats {
        AdminStats {
            total: 10,
            blocked: 1,
            degraded_window,
            degraded_events,
            in_flight: 0,
            rejected_connections: 0,
            active_connections: 0,
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
                rating_filter_active: false,
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

    fn quad9_filtering_response(stats: AdminStats) -> AdminStatusResponse {
        response(
            vec![ProviderStatusView {
                id: "quad9".to_string(),
                display_name: "Quad9 Filtered".to_string(),
                category: dnsqb_service::Category::Security,
            }],
            stats,
        )
    }

    #[test]
    fn tooltip_names_the_rating_filter_bubble_only_when_it_is_actually_gating() {
        // T-128: `enabled && active` → a suffix; `enabled` but Fork B
        // (no list loaded) → nothing (the web UI's own notice covers that
        // transient state); disabled → nothing.
        let mut resp = quad9_filtering_response(stats(20, 0));

        resp.rating_filter.enabled = true;
        resp.rating_filter.active = true;
        assert!(
            TrayStatus::from_response(&resp)
                .tooltip()
                .contains("рейтинг-фільтр «бульбашка» активний"),
            "an active bubble must add its suffix"
        );

        resp.rating_filter.active = false;
        assert!(
            !TrayStatus::from_response(&resp)
                .tooltip()
                .contains("рейтинг-фільтр"),
            "Fork B (enabled, no list) gets no tray suffix"
        );

        resp.rating_filter.enabled = false;
        assert!(
            !TrayStatus::from_response(&resp)
                .tooltip()
                .contains("рейтинг-фільтр"),
            "a disabled bubble gets no suffix"
        );
    }

    #[test]
    fn an_active_rating_filter_never_changes_the_icon_colour() {
        // The bubble is a scope choice, not a health signal (same
        // "pass-through ≠ failure" rule as NoActiveProvider).
        let active = TrayStatus::Filtering {
            in_flight: 0,
            blocked: 1,
            total: 9,
            degraded_events: 0,
            degraded_window: 20,
            rating_filter_active: true,
        };
        assert_eq!(icon_colour(active, true), IconColour::Green);
        assert_eq!(icon_colour(active, false), IconColour::Red); // cert still wins
    }

    #[test]
    fn paused_tooltip_names_the_state_plainly_and_not_as_a_failure() {
        // T-185: a deliberate pause must not read as "служба недоступна" /
        // "зупинилася" — those are failure states, this one the user chose.
        let tooltip = TrayStatus::Paused.tooltip();
        assert!(tooltip.contains("призупинено"), "got: {tooltip}");
        assert!(!tooltip.contains("недоступна"), "got: {tooltip}");
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

    // ---- T-191: coloured tray icon ----

    use super::{cert_warning, compose_tooltip, icon_colour, IconColour};

    fn filtering(degraded_events: u64) -> TrayStatus {
        filtering_wd(degraded_events, 20)
    }

    fn filtering_wd(degraded_events: u64, degraded_window: u64) -> TrayStatus {
        TrayStatus::Filtering {
            in_flight: 0,
            blocked: 1,
            total: 9,
            degraded_events,
            degraded_window,
            rating_filter_active: false,
        }
    }

    #[test]
    fn every_tray_status_maps_to_a_colour_when_the_cert_is_trusted() {
        let cases = [
            (TrayStatus::Unreachable, IconColour::Red),
            (TrayStatus::ServiceGaveUp, IconColour::Red),
            (TrayStatus::ServiceRestarting, IconColour::Amber),
            (TrayStatus::Offline, IconColour::Amber),
            (TrayStatus::Paused, IconColour::Grey),
            (
                TrayStatus::NoActiveProvider { in_flight: 0 },
                IconColour::Grey,
            ),
            (filtering(0), IconColour::Green),
            // T-196: a partial degraded count is a recovered blip, not amber.
            (filtering(2), IconColour::Green),
            (filtering_wd(20, 20), IconColour::Amber),
        ];
        for (status, want) in cases {
            assert_eq!(icon_colour(status, true), want, "{status:?}");
        }
    }

    #[test]
    fn filtering_icon_is_amber_only_when_every_recent_query_degraded() {
        // T-196 — the taskbar icon must not cry wolf over a single recovered
        // upstream timeout; it goes amber only when filtering is effectively
        // not happening at all.
        assert_eq!(icon_colour(filtering_wd(1, 20), true), IconColour::Green);
        assert_eq!(icon_colour(filtering_wd(19, 20), true), IconColour::Green);
        assert_eq!(icon_colour(filtering_wd(20, 20), true), IconColour::Amber);
        // A fresh start (no quorum entries yet) is green, not amber.
        assert_eq!(icon_colour(filtering_wd(0, 0), true), IconColour::Green);
    }

    #[test]
    fn untrusted_cert_reddens_only_filtering() {
        // The one state where a silently-failing browser DoH is the problem
        // the user must act on (DECISIONS.md 2026-09-08).
        assert_eq!(icon_colour(filtering(0), false), IconColour::Red);
        assert_eq!(icon_colour(filtering(3), false), IconColour::Red);
    }

    #[test]
    fn untrusted_cert_does_not_redden_paused_offline_no_provider_or_watchdog_states() {
        // Regression lock on the precedence decision: a deliberate "off"
        // state or an infra failure must not be repainted red by cert trust.
        assert_eq!(icon_colour(TrayStatus::Paused, false), IconColour::Grey);
        assert_eq!(
            icon_colour(TrayStatus::NoActiveProvider { in_flight: 0 }, false),
            IconColour::Grey
        );
        assert_eq!(icon_colour(TrayStatus::Offline, false), IconColour::Amber);
        assert_eq!(
            icon_colour(TrayStatus::ServiceRestarting, false),
            IconColour::Amber
        );
        assert_eq!(icon_colour(TrayStatus::Unreachable, false), IconColour::Red);
        assert_eq!(
            icon_colour(TrayStatus::ServiceGaveUp, false),
            IconColour::Red
        );
    }

    #[test]
    fn cert_warning_fires_for_reachable_states_only_and_never_when_trusted() {
        assert!(cert_warning(filtering(0), false).is_some());
        assert!(cert_warning(TrayStatus::NoActiveProvider { in_flight: 0 }, false).is_some());
        // Trusted → never a warning.
        assert!(cert_warning(filtering(0), true).is_none());
        // Unreachable / paused → the cert isn't the point; no suffix.
        assert!(cert_warning(TrayStatus::Unreachable, false).is_none());
        assert!(cert_warning(TrayStatus::Paused, false).is_none());
    }

    #[test]
    fn compose_tooltip_appends_the_cert_warning_when_it_applies() {
        let status = filtering(0);
        let with = compose_tooltip(status, false);
        assert!(with.contains("захищає"), "{with}");
        assert!(with.contains("сертифікат не встановлено"), "{with}");
        // Trusted → identical to the plain tooltip.
        assert_eq!(compose_tooltip(status, true), status.tooltip());
    }

    #[test]
    fn trust_poll_cadence_stays_fast_until_a_confirmed_trusted_cert() {
        use super::next_delay;
        use std::time::Duration;

        // Closing-advisor regression: an `Err` first poll (cert.pem not
        // written yet) is `confirmed_trusted == false` and must take the fast
        // ladder, not the 300 s slow branch — otherwise a fresh install shows
        // a green icon for 5 minutes while the cert is untrusted.
        assert_eq!(next_delay(false, 0), Duration::from_secs(2));
        assert_eq!(next_delay(false, 1), Duration::from_secs(5));
        assert_eq!(next_delay(false, 2), Duration::from_secs(15));
        assert_eq!(next_delay(false, 4), Duration::from_secs(300));
        // Index clamps — never panics no matter how long the streak.
        assert_eq!(next_delay(false, 999), Duration::from_secs(300));
        // Only a proven-trusted cert earns the slow interval.
        assert_eq!(next_delay(true, 0), Duration::from_secs(300));
        assert_eq!(next_delay(true, 3), Duration::from_secs(300));
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
                // T-185 (Батч 3.12) / T-193: filtering paused from the tray
                // menu. `stop.flag`'s presence is the whole signal and outranks
                // everything below — a deliberate pause must read as such, not
                // as a failure. Since T-193 the service stays up (it serves the
                // unfiltered baseline while the flag exists), so `/admin/status`
                // would report a healthy, filtering-looking service — this
                // check is what still surfaces the pause. Checked on this 2s
                // poll cadence, not on the main thread's 100ms event-loop tick.
                if dnsqb_service::stop_flag_is_set(&app_data_dir) {
                    *current.write() = TrayStatus::Paused;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
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

/// Poll cadence for [`spawn_trust_watch`]. Only a **confirmed** `Ok(true)`
/// from [`dnsqb_service::is_trusted`] earns the slow interval; a still-untrusted
/// cert (`Ok(false)`) **and** an error (`cert.pem` not written yet — the
/// fresh-install case, since the tray is spawned before the service, T-187)
/// both take the back-off ladder, so the icon turns red within seconds of the
/// service coming up rather than after a 5-minute nap (closing-advisor,
/// Батч 3.14 — keying this on the `trusted` cache instead let an `Err` on the
/// first poll leave the seed `true` and pick the 300 s branch).
fn next_delay(confirmed_trusted: bool, miss_streak: usize) -> Duration {
    const BACKOFF: [Duration; 5] = [
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(15),
        Duration::from_secs(60),
        Duration::from_secs(300),
    ];
    const SLOW: Duration = Duration::from_secs(300);
    if confirmed_trusted {
        SLOW
    } else {
        // Index clamped to the last element — provably in bounds from the line.
        BACKOFF[miss_streak.min(BACKOFF.len() - 1)]
    }
}

/// Latest known `CurrentUser\Root` trust state of the local `cert.pem`,
/// maintained by [`spawn_trust_watch`]'s own OS thread (T-191). Seeded `true`
/// — no red override — so a first run before `cert.pem` exists, or a
/// transient `certutil` failure, never flips the icon red on "unknown"; red
/// is shown only once `certutil` has actually *proven* the cert untrusted.
/// (The seed governs the *displayed* state only — the poll *cadence* keys on a
/// confirmed `Ok(true)`, see [`next_delay`].)
#[derive(Clone)]
pub struct TrustState {
    trusted: Arc<AtomicBool>,
    recheck: Arc<AtomicBool>,
    /// `true` once the thread has had at least one conclusive `certutil`
    /// answer (either polarity). Until then [`Self::is_trusted`] is the
    /// optimistic seed, not a reading — the T-188 first-run wizard keys on
    /// this so it never fires on "unknown" (on a fresh MSIX install the
    /// service hasn't written `cert.pem` yet when the tray starts, T-187).
    confirmed: Arc<AtomicBool>,
}

impl TrustState {
    /// The last polled trust state. Cheap, non-blocking — `main.rs` reads it
    /// on every event-loop tick.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        self.trusted.load(Ordering::Relaxed)
    }

    /// Whether [`Self::is_trusted`] reflects a real `certutil` answer yet
    /// rather than the seeded default. See [`Self::confirmed`].
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        self.confirmed.load(Ordering::Relaxed)
    }

    /// A cert menu action just ran — re-poll `certutil` promptly instead of
    /// waiting out the current back-off sleep.
    pub fn request_recheck(&self) {
        self.recheck.store(true, Ordering::Relaxed);
    }
}

/// Spawns the dedicated trust-watch thread and returns a handle to read its
/// result. Kept off [`spawn`]'s poll loop on purpose: [`dnsqb_service::is_trusted`]
/// is two blocking `certutil` subprocesses (~100–300 ms each), and threading a
/// slow, self-scheduling check through a 2 s loop that already
/// early-`continue`s on `stop.flag` / `watchdog_override` is tangled and risks
/// skipping the seed when the app starts paused. This matches what the crate
/// already does twice for synchronous work (`spawn_trust_store_action`,
/// `spawn_admin_action`). The thread is never joined — like [`spawn`], process
/// exit (the `tao` loop never returns) reclaims it.
#[must_use]
pub fn spawn_trust_watch(cert_path: PathBuf) -> TrustState {
    let trusted = Arc::new(AtomicBool::new(true));
    let recheck = Arc::new(AtomicBool::new(false));
    let confirmed = Arc::new(AtomicBool::new(false));
    let state = TrustState {
        trusted: Arc::clone(&trusted),
        recheck: Arc::clone(&recheck),
        confirmed: Arc::clone(&confirmed),
    };

    std::thread::spawn(move || {
        let mut miss_streak: usize = 0;
        let mut logged_err = false;
        loop {
            let result = dnsqb_service::is_trusted(&cert_path);
            // Cadence keys on a *confirmed* `Ok(true)`, not on the `trusted`
            // cache: an `Err` on the first poll (cert.pem not written yet)
            // must not leave the thread on the 300 s branch — see [`next_delay`].
            let confirmed_trusted = matches!(result, Ok(true));
            match result {
                Ok(now_trusted) => {
                    trusted.store(now_trusted, Ordering::Relaxed);
                    // Any `Ok` — trusted or not — means `certutil` gave a real
                    // answer, so the displayed flag is now a reading, not the
                    // seed (T-188).
                    confirmed.store(true, Ordering::Relaxed);
                    logged_err = false;
                }
                Err(err) => {
                    // First run (cert.pem absent) is the common case, not an
                    // anomaly — log once on entry to the error state, then
                    // stay quiet (no console in release; a warn per tick is
                    // spam). The previous displayed value is kept: "unknown"
                    // is not "untrusted".
                    if !logged_err {
                        tracing::warn!(
                            "cert trust check unavailable, keeping previous state: {err}"
                        );
                        logged_err = true;
                    }
                }
            }

            let delay = next_delay(confirmed_trusted, miss_streak);
            miss_streak = if confirmed_trusted {
                0
            } else {
                miss_streak.saturating_add(1)
            };

            // A cert menu action (`request_recheck`) short-circuits the sleep.
            let step = Duration::from_millis(500);
            let mut waited = Duration::ZERO;
            while waited < delay && !recheck.swap(false, Ordering::Relaxed) {
                std::thread::sleep(step);
                waited += step;
            }
        }
    });

    state
}
