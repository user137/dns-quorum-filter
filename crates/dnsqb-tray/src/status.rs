//! Background polling for the tray tooltip's live status (T-149) — a
//! dedicated OS thread with its own single-threaded `tokio` runtime, since
//! `tao`'s event loop owns the main thread and never yields it to `async`
//! code (confirmed against `tao`'s own docs during the T-149 Крок 0 probe).
//! The main thread never awaits anything here — it just reads
//! [`StatusHandle::current`], a cheap lock-guarded read of whatever this
//! background thread last wrote.

use crate::i18n;
use dnsqb_service::{
    AdminClient, AdminStatusResponse, NetworkStatusView, StartupFailure, WatchdogState,
    WATCHDOG_STATE_STALE_AFTER,
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
    /// awaiting the user's retry (T-95, `GaveUp`; «Спробувати ще раз» since
    /// хвиля 13b).
    ServiceGaveUp,
    /// Хвиля 13b: `GaveUp` because the service recorded a deterministic
    /// startup failure (`startup-error.json`) — the reason is named in the
    /// tooltip, with its one action. Ranked, like `ServiceGaveUp`, **above**
    /// `Paused`: since T-193 a pause keeps the service up, so a dead service
    /// during a pause is a real failure the grey icon must not hide.
    ServiceStartupFailed(StartupFailure),
    /// Filtering is paused on purpose (T-185) — the user clicked "Призупинити
    /// фільтрацію". Since T-193 `dnsqb-service` **stays up** and serves every
    /// query through the unfiltered baseline; the watchdog keeps supervising it
    /// normally. The presence of `stop.flag` is still the whole signal, read
    /// straight off disk here. Ranked **above** `ServiceRestarting` and every
    /// admin state — a pause is a deliberate choice the user needs named as
    /// such, not as a failure — but **below** `ServiceGaveUp` /
    /// `ServiceStartupFailed` since хвиля 13b (a dead service is a real failure
    /// even during a pause; see [`local_status`]). (The pipeline and the `/admin/ui` hero rank `Offline` above
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
        /// ARCH-04: how long ago the browser last asked — the one hint that
        /// the browser still goes through the service. Tooltip only, never
        /// the icon colour: a closed browser is not a fault (SPEC.md §8.1).
        last_query: LastQuery,
    },
}

/// First `/admin/*` schema whose `AdminStats` carries `last_query_unix_ms`;
/// an older service decodes the absent field as `None` (serde default).
const LAST_QUERY_SINCE_SCHEMA: u32 = 7;

/// The age of the newest query-log entry, bucketed to what the tooltip
/// shows — so [`TrayStatus`] changes only when that text does, not on every
/// 2 s poll. No day bucket: the log keeps at most 24 h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastQuery {
    /// The service is older than the field — show nothing.
    Unknown,
    /// No entry in the current log window.
    Empty,
    JustNow,
    Minutes(u64),
    Hours(u64),
}

impl LastQuery {
    fn from_stats(schema_version: u32, last_query_unix_ms: Option<u64>, now_unix_ms: u64) -> Self {
        if schema_version < LAST_QUERY_SINCE_SCHEMA {
            return Self::Unknown;
        }
        let Some(at) = last_query_unix_ms else {
            return Self::Empty;
        };
        // A clock step back makes the entry look newer than now: just now.
        let minutes = now_unix_ms.saturating_sub(at) / 60_000;
        match minutes {
            0 => Self::JustNow,
            1..=59 => Self::Minutes(minutes),
            _ => Self::Hours(minutes / 60),
        }
    }

    fn segment(self, locale: &str) -> Option<String> {
        match self {
            Self::Unknown => None,
            Self::Empty => Some(i18n::t(locale, "tooltip.lastQueryEmpty")),
            Self::JustNow => Some(i18n::t(locale, "tooltip.lastQueryJustNow")),
            Self::Minutes(minutes) => Some(i18n::t_args(
                locale,
                "tooltip.lastQueryMinutesTemplate",
                &[("minutes", &minutes.to_string())],
            )),
            Self::Hours(hours) => Some(i18n::t_args(
                locale,
                "tooltip.lastQueryHoursTemplate",
                &[("hours", &hours.to_string())],
            )),
        }
    }
}

impl TrayStatus {
    fn from_response(response: &AdminStatusResponse, now_unix_ms: u64) -> Self {
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
                last_query: LastQuery::from_stats(
                    response.schema_version,
                    response.stats.last_query_unix_ms,
                    now_unix_ms,
                ),
            }
        }
    }

    /// The hover tooltip's headline plus its optional segments, most
    /// important first — [`fit_tooltip`] drops from the least important
    /// when space runs out (T-253), so the counts go last: a real problem
    /// outranks a scope choice, and both outrank a number. T-176 reworded
    /// these for a non-technical reader (no "резолвінг", no "апстрім", no
    /// stale "обидва провайдери") while keeping the raw counts intact.
    /// **T-151 Батч 5.5:** `locale` is an explicit parameter, never read from
    /// ambient global state - see `i18n.rs`'s own module doc comment for why.
    fn tooltip_parts(&self, locale: &str) -> (String, Vec<String>) {
        match self {
            Self::Unreachable => (i18n::t(locale, "tooltip.unreachable"), Vec::new()),
            Self::ServiceRestarting => (i18n::t(locale, "tooltip.restarting"), Vec::new()),
            Self::ServiceGaveUp => (i18n::t(locale, "tooltip.gaveUp"), Vec::new()),
            Self::ServiceStartupFailed(reason) => {
                (startup_failure_tooltip(*reason, locale), Vec::new())
            }
            Self::Paused => (i18n::t(locale, "tooltip.paused"), Vec::new()),
            Self::Offline => (i18n::t(locale, "tooltip.offline"), Vec::new()),
            Self::NoActiveProvider { in_flight } => (
                i18n::t(locale, "tooltip.noActiveProvider"),
                vec![i18n::t_args(
                    locale,
                    "tooltip.noActiveProviderCountsTemplate",
                    &[("inFlight", &in_flight.to_string())],
                )],
            ),
            Self::Filtering {
                in_flight,
                blocked,
                total,
                degraded_events,
                degraded_window,
                rating_filter_active,
                last_query,
            } => {
                let mut segments = Vec::new();
                // Raw counts, not a collapsed bool/percentage (admin.rs's
                // own degraded_counts doc comment) — any nonzero count is
                // shown as-is, letting the reader judge severity instead of
                // an always-on warning masking it (T-56, advisor-caught
                // during planning: a bare threshold-free boolean would go
                // permanently true under routine fail-open timeouts).
                if *degraded_events > 0 {
                    segments.push(i18n::t_args(
                        locale,
                        "tooltip.degradedSegmentTemplate",
                        &[
                            ("degradedEvents", &degraded_events.to_string()),
                            ("degradedWindow", &degraded_window.to_string()),
                        ],
                    ));
                }
                if let Some(segment) = last_query.segment(locale) {
                    segments.push(segment);
                }
                if *rating_filter_active {
                    segments.push(i18n::t(locale, "tooltip.ratingFilterSuffix"));
                }
                segments.push(i18n::t_args(
                    locale,
                    "tooltip.filteringCountsTemplate",
                    &[
                        ("blocked", &blocked.to_string()),
                        ("total", &total.to_string()),
                        ("inFlight", &in_flight.to_string()),
                    ],
                ));
                (i18n::t(locale, "tooltip.filteringHead"), segments)
            }
        }
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
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
/// trailing-window blip, not an alarm: the icon stays green and the
/// tooltip's own "N/M" degraded segment ([`compose_tooltip`]) carries the
/// nuance.
#[must_use]
pub fn icon_colour(status: TrayStatus, cert_trusted: bool) -> IconColour {
    match status {
        TrayStatus::Unreachable
        | TrayStatus::ServiceGaveUp
        | TrayStatus::ServiceStartupFailed(_) => IconColour::Red,
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

/// The i18n key naming `reason` (and its one action) in the tooltip. Every
/// rendered text must fit the 63 UTF-16 units `tray-icon` 0.21 leaves visible
/// (T-253) — tested per locale.
fn startup_failure_tooltip_key(reason: StartupFailure) -> &'static str {
    match reason {
        StartupFailure::PortInUse { .. } => "tooltip.startupFailed.portInUseTemplate",
        StartupFailure::BindFailed => "tooltip.startupFailed.bindFailed",
        StartupFailure::ConfigInvalid => "tooltip.startupFailed.configInvalid",
        StartupFailure::ConfigUnreadable => "tooltip.startupFailed.configUnreadable",
        StartupFailure::CertificateUnavailable => "tooltip.startupFailed.certificateUnavailable",
        StartupFailure::UpstreamClientFailed => "tooltip.startupFailed.upstreamClientFailed",
        StartupFailure::InstanceLockFailed => "tooltip.startupFailed.instanceLockFailed",
    }
}

fn startup_failure_tooltip(reason: StartupFailure, locale: &str) -> String {
    match reason {
        StartupFailure::PortInUse { port } => i18n::t_args(
            locale,
            startup_failure_tooltip_key(reason),
            &[("port", &port.to_string())],
        ),
        _ => i18n::t(locale, startup_failure_tooltip_key(reason)),
    }
}

/// Which recovery menu items are enabled for `status`: («Спробувати ще раз»,
/// «Скинути налаштування»). Хвиля 13b — retry is live whenever the service is
/// not answering (`Unreachable` included: a dead watcher leaves the state file
/// stale, and the retry click also relaunches the watcher); the reset only
/// answers an invalid config.
#[must_use]
pub fn recovery_actions(status: TrayStatus) -> (bool, bool) {
    match status {
        TrayStatus::ServiceGaveUp | TrayStatus::Unreachable => (true, false),
        TrayStatus::ServiceStartupFailed(reason) => (true, reason == StartupFailure::ConfigInvalid),
        TrayStatus::ServiceRestarting
        | TrayStatus::Paused
        | TrayStatus::Offline
        | TrayStatus::NoActiveProvider { .. }
        | TrayStatus::Filtering { .. } => (false, false),
    }
}

/// The locally-read part of the status ladder, ranked: a given-up service
/// (with or without a recorded reason) outranks a pause; a pause outranks
/// a restarting service; `None` falls through to the admin channel.
fn local_status(paused: bool, watchdog: Option<TrayStatus>) -> Option<TrayStatus> {
    match watchdog {
        Some(down @ (TrayStatus::ServiceGaveUp | TrayStatus::ServiceStartupFailed(_))) => {
            Some(down)
        }
        _ if paused => Some(TrayStatus::Paused),
        other => other,
    }
}

/// Tooltip suffix naming the untrusted-certificate problem. `Some` exactly
/// when the certificate the `DoH` listener serves isn't trusted **and** the
/// service is otherwise reachable ([`TrayStatus::Filtering`] /
/// [`TrayStatus::NoActiveProvider`]) — the states where the browser's own
/// `DoH` to us then fails silently. [`compose_tooltip`] puts it first among
/// the segments, never alone, so a red icon can't sit beside a
/// green-sounding tooltip.
#[must_use]
pub fn cert_warning(status: TrayStatus, cert_trusted: bool, locale: &str) -> Option<String> {
    if cert_trusted {
        return None;
    }
    match status {
        TrayStatus::Filtering { .. } | TrayStatus::NoActiveProvider { .. } => {
            Some(i18n::t(locale, "tooltip.certWarningSuffix"))
        }
        _ => None,
    }
}

/// The tray tooltip for `status`, plus the [`cert_warning`] suffix when it
/// applies — the one entry point for tray tooltip text.
/// The warning goes first among the segments, so it is the last thing
/// [`fit_tooltip`] would drop.
#[must_use]
pub fn compose_tooltip(status: TrayStatus, cert_trusted: bool, locale: &str) -> String {
    let (head, mut segments) = status.tooltip_parts(locale);
    if let Some(suffix) = cert_warning(status, cert_trusted, locale) {
        segments.insert(0, suffix);
    }
    fit_tooltip(&head, &segments)
}

/// Longest tooltip the shell can show: `NOTIFYICONDATAW.szTip` holds 128
/// UTF-16 units including the NUL, and `tray-icon` copies up to 128 units
/// without adding one, so one unit stays free for it (T-253).
pub(crate) const TOOLTIP_MAX_UTF16: usize = 127;

/// `head` plus the longest prefix of `segments` (each carries its own leading
/// separator) that fits in [`TOOLTIP_MAX_UTF16`]. The first segment that
/// doesn't fit ends the tooltip, so a less important segment never shows
/// while a more important one is missing, and none is cut mid-sentence. A
/// `head` that alone is too long is cut at a char boundary and ends in `…`.
pub(crate) fn fit_tooltip(head: &str, segments: &[String]) -> String {
    let mut used = head.encode_utf16().count();
    if used > TOOLTIP_MAX_UTF16 {
        let budget = TOOLTIP_MAX_UTF16 - '…'.len_utf16();
        let mut text = String::new();
        let mut kept = 0;
        for c in head.chars() {
            kept += c.len_utf16();
            if kept > budget {
                break;
            }
            text.push(c);
        }
        text.push('…');
        return text;
    }
    let mut text = head.to_string();
    for segment in segments {
        used += segment.encode_utf16().count();
        if used > TOOLTIP_MAX_UTF16 {
            break;
        }
        text.push_str(segment);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{
        local_status, recovery_actions, startup_failure_tooltip, startup_failure_tooltip_key,
        watchdog_override, LastQuery, TrayStatus,
    };
    use crate::i18n::I18N_DICTS;
    use dnsqb_service::{StartupFailure, STARTUP_ERROR_FILE_NAME};

    const EVERY_FAILURE: [StartupFailure; 7] = [
        StartupFailure::PortInUse { port: 65535 },
        StartupFailure::BindFailed,
        StartupFailure::ConfigInvalid,
        StartupFailure::ConfigUnreadable,
        StartupFailure::CertificateUnavailable,
        StartupFailure::UpstreamClientFailed,
        StartupFailure::InstanceLockFailed,
    ];

    // Хвиля 13b: GaveUp + a recorded reason names the reason; without one it
    // stays the plain GaveUp.
    #[test]
    fn watchdog_override_names_a_recorded_startup_failure() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir must be creatable");
        };
        write_watchdog_fixture(dir.path(), WatchdogState::GaveUp);
        assert_eq!(
            watchdog_override(dir.path()),
            Some(TrayStatus::ServiceGaveUp)
        );
        // The on-disk contract dnsqb-service writes (startup_failure.rs).
        let record = br#"{"schema_version":1,"reason":{"kind":"port_in_use","port":4443}}"#;
        if let Err(err) = std::fs::write(dir.path().join(STARTUP_ERROR_FILE_NAME), record) {
            panic!("fixture write must succeed: {err}");
        }
        assert_eq!(
            watchdog_override(dir.path()),
            Some(TrayStatus::ServiceStartupFailed(
                StartupFailure::PortInUse { port: 4443 }
            ))
        );
    }

    // Хвиля 13b: a dead service outranks a pause (T-193 keeps the service up
    // while paused); a restarting one does not.
    #[test]
    fn local_status_ranks_gave_up_above_paused_above_restarting() {
        let failed = TrayStatus::ServiceStartupFailed(StartupFailure::ConfigInvalid);
        for paused in [true, false] {
            assert_eq!(
                local_status(paused, Some(TrayStatus::ServiceGaveUp)),
                Some(TrayStatus::ServiceGaveUp)
            );
            assert_eq!(local_status(paused, Some(failed)), Some(failed));
        }
        assert_eq!(
            local_status(true, Some(TrayStatus::ServiceRestarting)),
            Some(TrayStatus::Paused)
        );
        assert_eq!(local_status(true, None), Some(TrayStatus::Paused));
        assert_eq!(
            local_status(false, Some(TrayStatus::ServiceRestarting)),
            Some(TrayStatus::ServiceRestarting)
        );
        assert_eq!(local_status(false, None), None);
    }

    #[test]
    fn recovery_actions_offer_retry_when_down_and_reset_only_for_a_bad_config() {
        assert_eq!(recovery_actions(TrayStatus::ServiceGaveUp), (true, false));
        assert_eq!(recovery_actions(TrayStatus::Unreachable), (true, false));
        for reason in EVERY_FAILURE {
            let want_reset = reason == StartupFailure::ConfigInvalid;
            assert_eq!(
                recovery_actions(TrayStatus::ServiceStartupFailed(reason)),
                (true, want_reset),
                "{reason:?}"
            );
        }
        for other in [
            TrayStatus::ServiceRestarting,
            TrayStatus::Paused,
            TrayStatus::Offline,
            TrayStatus::NoActiveProvider { in_flight: 0 },
        ] {
            assert_eq!(recovery_actions(other), (false, false), "{other:?}");
        }
    }

    // T-253: a failure tooltip is never cut by `fit_tooltip` — the raw text
    // (worst-case port) fits whole in every locale, and each reason has its
    // own text.
    #[test]
    fn every_failure_tooltip_fits_the_visible_limit_in_every_locale() {
        let mut keys: Vec<&str> = EVERY_FAILURE
            .iter()
            .map(|r| startup_failure_tooltip_key(*r))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), EVERY_FAILURE.len(), "one key per reason");
        for &(code, _) in I18N_DICTS {
            let mut texts: Vec<String> = EVERY_FAILURE
                .iter()
                .map(|r| startup_failure_tooltip(*r, code))
                .collect();
            texts.push(crate::i18n::t(code, "tooltip.gaveUp"));
            for text in texts {
                let units = text.encode_utf16().count();
                assert!(
                    units <= super::TOOLTIP_MAX_UTF16,
                    "{code}: {units} units: {text}"
                );
                assert!(!text.contains('{'), "{code}: unfilled placeholder: {text}");
            }
        }
    }
    use dnsqb_service::{
        write_watchdog_state, AdminStats, AdminStatusResponse, ProviderStatusView, StartupTaskView,
        TimeoutMode, WatchdogState, WatchdogStateFile, WatchdogTarget, STATE_FILE_NAME,
        STATE_SCHEMA_VERSION,
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
            schema_version: dnsqb_service::ADMIN_DTO_SCHEMA_VERSION,
            // T-204: the tray does not consume `hero_state` (it keeps its own
            // `from_response` ranking — DECISIONS.md 2026-09-07/08); a fixture
            // value is enough.
            hero_state: dnsqb_service::HeroStateView::Protected,
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
                personal_zone_enabled: false,
                suggested_list: None,
            },
            // T-218 Батч 7.4 частина 2: the tray doesn't render this field
            // (that's `/admin/ui`, part 3) — a default fixture is enough.
            blocklist_bundles: dnsqb_service::BlocklistBundlesStatusView::default(),
            // Фаза 5, T-115/T-118: same reasoning — the tray doesn't render
            // this field either.
            cctld_block: dnsqb_service::CctldBlockStatusView::default(),
            // T-241 follow-up: `/admin/ui`-only display field, same reasoning
            // as `blocklist_bundles`/`cctld_block` above.
            app_version: String::new(),
            startup_task: StartupTaskView::Unknown,
        }
    }

    const NOW_MS: u64 = 1_800_000_000_000;

    // ARCH-04: the bucket, not the raw age, lives in `TrayStatus`, so the
    // status (and the tooltip) changes only when the shown text does.
    #[test]
    fn last_query_buckets_follow_the_age_of_the_newest_entry() {
        let at = |age_ms: u64| LastQuery::from_stats(7, Some(NOW_MS - age_ms), NOW_MS);
        assert_eq!(at(0), LastQuery::JustNow);
        assert_eq!(at(59_999), LastQuery::JustNow);
        assert_eq!(at(60_000), LastQuery::Minutes(1));
        assert_eq!(at(3_599_999), LastQuery::Minutes(59));
        assert_eq!(at(3_600_000), LastQuery::Hours(1));
        assert_eq!(at(23 * 3_600_000 + 3_599_999), LastQuery::Hours(23));
        // A clock step back: the entry is "in the future", read as just now.
        assert_eq!(
            LastQuery::from_stats(7, Some(NOW_MS + 5_000), NOW_MS),
            LastQuery::JustNow
        );
        assert_eq!(LastQuery::from_stats(7, None, NOW_MS), LastQuery::Empty);
    }

    // A service older than the field decodes it as `None` (serde default) —
    // that is "unknown", never "no queries".
    #[test]
    fn last_query_is_unknown_from_a_service_older_than_the_field() {
        assert_eq!(LastQuery::from_stats(6, None, NOW_MS), LastQuery::Unknown);
        assert_eq!(
            LastQuery::from_stats(0, Some(NOW_MS), NOW_MS),
            LastQuery::Unknown
        );
        let mut resp = response(
            vec![ProviderStatusView {
                id: "quad9".to_string(),
                display_name: "Quad9 Filtered".to_string(),
                category: dnsqb_service::Category::Security,
            }],
            stats(0, 0),
        );
        resp.schema_version = 6;
        let tooltip = compose_tooltip(TrayStatus::from_response(&resp, NOW_MS), true, "uk");
        assert!(!tooltip.contains("останній запит"), "{tooltip}");
        assert!(!tooltip.contains("у журналі"), "{tooltip}");
    }

    fn filtering_with(last_query: LastQuery) -> TrayStatus {
        TrayStatus::Filtering {
            in_flight: 0,
            blocked: 1,
            total: 9,
            degraded_events: 0,
            degraded_window: 20,
            rating_filter_active: false,
            last_query,
        }
    }

    #[test]
    fn the_last_query_segment_names_the_age_or_an_empty_log() {
        let with = |last_query| compose_tooltip(filtering_with(last_query), true, "uk");
        assert!(with(LastQuery::Minutes(5)).contains("останній запит: 5 хв тому"));
        assert!(with(LastQuery::Hours(3)).contains("останній запит: 3 год тому"));
        assert!(with(LastQuery::JustNow).contains("останній запит: щойно"));
        assert!(with(LastQuery::Empty).contains("у журналі немає запитів"));
        let unknown = with(LastQuery::Unknown);
        assert!(!unknown.contains("останній запит") && !unknown.contains("у журналі"));
    }

    // ARCH-04 (SPEC.md §8.1): a closed browser is not a fault — an old or
    // empty last query never repaints the icon.
    #[test]
    fn last_query_age_never_changes_the_icon_colour() {
        for last_query in [LastQuery::Empty, LastQuery::Hours(23), LastQuery::Unknown] {
            assert_eq!(
                icon_colour(filtering_with(last_query), true),
                IconColour::Green
            );
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
            last_query_unix_ms: None,
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
        let status = TrayStatus::from_response(&resp, NOW_MS);
        assert_eq!(
            status,
            TrayStatus::Filtering {
                in_flight: 0,
                blocked: 1,
                total: 10,
                degraded_events: 3,
                degraded_window: 20,
                rating_filter_active: false,
                last_query: LastQuery::Empty,
            }
        );
    }

    #[test]
    fn offline_network_outranks_no_active_provider() {
        // Empty provider list *and* offline — offline wins (DECISIONS.md
        // 2026-09-03: an environment failure above a config choice).
        let mut resp = response(vec![], stats(0, 0));
        resp.network = dnsqb_service::NetworkStatusView::Offline;
        assert_eq!(
            TrayStatus::from_response(&resp, NOW_MS),
            TrayStatus::Offline
        );
    }

    #[test]
    fn online_network_with_no_providers_is_still_no_active_provider() {
        let resp = response(vec![], stats(0, 0));
        assert_eq!(
            TrayStatus::from_response(&resp, NOW_MS),
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
        assert_eq!(
            TrayStatus::from_response(&resp, NOW_MS),
            TrayStatus::Offline
        );
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
        let tooltip = compose_tooltip(TrayStatus::from_response(&resp, NOW_MS), true, "uk");
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
        let tooltip = compose_tooltip(TrayStatus::from_response(&resp, NOW_MS), true, "uk");
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
            compose_tooltip(TrayStatus::from_response(&resp, NOW_MS), true, "uk")
                .contains("рейтинг-фільтр «бульбашка» активний"),
            "an active bubble must add its suffix"
        );

        resp.rating_filter.active = false;
        assert!(
            !compose_tooltip(TrayStatus::from_response(&resp, NOW_MS), true, "uk")
                .contains("рейтинг-фільтр"),
            "Fork B (enabled, no list) gets no tray suffix"
        );

        resp.rating_filter.enabled = false;
        assert!(
            !compose_tooltip(TrayStatus::from_response(&resp, NOW_MS), true, "uk")
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
            last_query: LastQuery::Unknown,
        };
        assert_eq!(icon_colour(active, true), IconColour::Green);
        assert_eq!(icon_colour(active, false), IconColour::Red); // cert still wins
    }

    #[test]
    fn paused_tooltip_names_the_state_plainly_and_not_as_a_failure() {
        // T-185: a deliberate pause must not read as "служба недоступна" /
        // "зупинилася" — those are failure states, this one the user chose.
        let tooltip = compose_tooltip(TrayStatus::Paused, true, "uk");
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
            TrayStatus::from_response(&resp, NOW_MS),
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
            last_query: LastQuery::Unknown,
        }
    }

    #[test]
    fn every_tray_status_maps_to_a_colour_when_the_cert_is_trusted() {
        let cases = [
            (TrayStatus::Unreachable, IconColour::Red),
            (TrayStatus::ServiceGaveUp, IconColour::Red),
            (
                TrayStatus::ServiceStartupFailed(dnsqb_service::StartupFailure::BindFailed),
                IconColour::Red,
            ),
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
        assert!(cert_warning(filtering(0), false, "uk").is_some());
        assert!(cert_warning(TrayStatus::NoActiveProvider { in_flight: 0 }, false, "uk").is_some());
        // Trusted → never a warning.
        assert!(cert_warning(filtering(0), true, "uk").is_none());
        // Unreachable / paused → the cert isn't the point; no suffix.
        assert!(cert_warning(TrayStatus::Unreachable, false, "uk").is_none());
        assert!(cert_warning(TrayStatus::Paused, false, "uk").is_none());
    }

    // ---- T-253: the tooltip fits the shell's buffer, problems first ----

    use super::{fit_tooltip, TOOLTIP_MAX_UTF16};

    fn units(text: &str) -> usize {
        text.encode_utf16().count()
    }

    #[test]
    fn fit_tooltip_stops_at_the_first_segment_that_does_not_fit() {
        // A shorter, less important segment never jumps over a dropped one.
        let head = "h".repeat(100);
        let too_long = " ".to_string() + &"x".repeat(30);
        let short = " y".to_string();
        let text = fit_tooltip(&head, &[too_long, short]);
        assert_eq!(text, head);
    }

    #[test]
    fn fit_tooltip_keeps_every_segment_when_all_fit() {
        let text = fit_tooltip("a", &[" b".to_string(), " c".to_string()]);
        assert_eq!(text, "a b c");
    }

    #[test]
    fn fit_tooltip_cuts_an_overlong_head_with_an_ellipsis_inside_the_budget() {
        // 4-byte chars: a cut must never split a surrogate pair.
        let head = "\u{1F600}".repeat(100);
        let text = fit_tooltip(&head, &[" tail".to_string()]);
        assert!(units(&text) <= TOOLTIP_MAX_UTF16, "{}", units(&text));
        assert!(text.ends_with('…'), "{text}");
        assert!(!text.contains("tail"), "{text}");
        assert!(text.chars().all(|c| c == '\u{1F600}' || c == '…'));
    }

    fn worst_filtering() -> TrayStatus {
        TrayStatus::Filtering {
            in_flight: u64::MAX,
            blocked: u64::MAX,
            total: u64::MAX,
            degraded_events: u64::MAX,
            degraded_window: u64::MAX,
            rating_filter_active: true,
            last_query: LastQuery::Hours(u64::MAX),
        }
    }

    #[test]
    fn every_tooltip_fits_and_keeps_the_cert_warning_whole_in_every_locale() {
        let mut statuses = vec![
            worst_filtering(),
            TrayStatus::NoActiveProvider {
                in_flight: u64::MAX,
            },
            TrayStatus::Unreachable,
            TrayStatus::ServiceRestarting,
            TrayStatus::ServiceGaveUp,
            TrayStatus::Paused,
            TrayStatus::Offline,
        ];
        statuses.extend(
            EVERY_FAILURE
                .iter()
                .map(|r| TrayStatus::ServiceStartupFailed(*r)),
        );
        for &(code, _) in I18N_DICTS {
            for &status in &statuses {
                for trusted in [true, false] {
                    let text = compose_tooltip(status, trusted, code);
                    assert!(units(&text) <= TOOLTIP_MAX_UTF16, "{code}: {text}");
                    let (head, _) = status.tooltip_parts(code);
                    assert!(text.starts_with(&head), "{code}: headline cut: {text}");
                    assert!(!text.contains('{'), "{code}: unfilled placeholder: {text}");
                    if let Some(warning) = cert_warning(status, trusted, code) {
                        assert!(text.contains(&warning), "{code}: lost cert warning: {text}");
                    }
                }
            }
        }
    }

    // The degraded window is `DEGRADED_LOOKBACK` = 20 queries (admin.rs): the
    // degraded warning must survive whole, cert warning or not.
    #[test]
    fn the_degraded_warning_fits_whole_in_every_locale() {
        let status = TrayStatus::Filtering {
            in_flight: 99,
            blocked: 99_999,
            total: 999_999,
            degraded_events: 20,
            degraded_window: 20,
            rating_filter_active: true,
            last_query: LastQuery::Hours(23),
        };
        for &(code, _) in I18N_DICTS {
            let segment = crate::i18n::t_args(
                code,
                "tooltip.degradedSegmentTemplate",
                &[("degradedEvents", "20"), ("degradedWindow", "20")],
            );
            for trusted in [true, false] {
                let text = compose_tooltip(status, trusted, code);
                assert!(
                    text.contains(&segment),
                    "{code}: lost degraded warning: {text}"
                );
            }
        }
    }

    // ARCH-04: with a trusted cert the last-query line fits whole next to a
    // full degraded warning. With an untrusted one it may drop (Greek is
    // already near the limit) — the cert warning, kept first, already says
    // why no query reaches the service.
    #[test]
    fn the_last_query_segment_fits_whole_beside_the_degraded_warning() {
        for last_query in [
            LastQuery::Minutes(59),
            LastQuery::Hours(23),
            LastQuery::JustNow,
            LastQuery::Empty,
        ] {
            let status = TrayStatus::Filtering {
                in_flight: 99,
                blocked: 99_999,
                total: 999_999,
                degraded_events: 20,
                degraded_window: 20,
                rating_filter_active: true,
                last_query,
            };
            for &(code, _) in I18N_DICTS {
                let Some(segment) = last_query.segment(code) else {
                    panic!("{code}: {last_query:?} must have a segment");
                };
                let text = compose_tooltip(status, true, code);
                assert!(text.contains(&segment), "{code}: lost last query: {text}");
            }
        }
    }

    #[test]
    fn problems_come_before_the_counts() {
        let text = compose_tooltip(
            TrayStatus::Filtering {
                in_flight: 0,
                blocked: 1,
                total: 9,
                degraded_events: 3,
                degraded_window: 20,
                rating_filter_active: false,
                last_query: LastQuery::Unknown,
            },
            false,
            "uk",
        );
        assert!(
            text.starts_with("DNS Quorum Filter: захищає — сертифікат не встановлено — деякі"),
            "{text}"
        );
        assert!(text.contains("3/20"), "{text}");
    }

    #[test]
    fn compose_tooltip_appends_the_cert_warning_when_it_applies() {
        let status = filtering(0);
        let with = compose_tooltip(status, false, "uk");
        assert!(with.contains("захищає"), "{with}");
        assert!(with.contains("сертифікат не встановлено"), "{with}");
        // Trusted → identical to the plain tooltip.
        let without = compose_tooltip(status, true, "uk");
        assert!(!without.contains("сертифікат"), "{without}");
    }

    // T-255: a cert change the service saw first (the `/admin/ui` install
    // button, an outside `certutil`) re-polls the tray's own trust watch.
    #[test]
    fn service_cert_change_is_a_hero_transition_into_or_out_of_a_cert_state() {
        use super::service_cert_changed;
        use dnsqb_service::HeroStateView as H;

        assert!(service_cert_changed(Some(H::CertNotTrusted), H::Protected));
        assert!(service_cert_changed(Some(H::Protected), H::CertNotTrusted));
        assert!(service_cert_changed(
            Some(H::CertUnknown),
            H::FiltersDegraded
        ));
        assert!(service_cert_changed(
            Some(H::CertNotTrusted),
            H::CertUnknown
        ));
        // Not cert-related, unchanged, or no earlier reading: no re-poll.
        assert!(!service_cert_changed(Some(H::Offline), H::Protected));
        assert!(!service_cert_changed(
            Some(H::CertNotTrusted),
            H::CertNotTrusted
        ));
        assert!(!service_cert_changed(None, H::CertNotTrusted));
    }

    // ARCH-19 b: the event loop is woken only when what it shows changes.
    #[test]
    fn publish_reports_only_a_real_change() {
        use super::publish;
        use parking_lot::RwLock;

        let current = RwLock::new(TrayStatus::Unreachable);
        assert!(!publish(&current, TrayStatus::Unreachable));
        assert!(publish(&current, TrayStatus::Paused));
        assert_eq!(*current.read(), TrayStatus::Paused);
        assert!(!publish(&current, TrayStatus::Paused));
    }

    // ARCH-19 b: a trust flip and the first conclusive answer both wake the
    // loop — onboarding keys on `confirmed`, the icon on `trusted`.
    #[test]
    fn record_trust_reports_a_flip_and_the_first_confirmation() {
        use super::record_trust;
        use std::sync::atomic::{AtomicBool, Ordering};

        let trusted = AtomicBool::new(true);
        let confirmed = AtomicBool::new(false);
        assert!(record_trust(&trusted, &confirmed, true));
        assert!(confirmed.load(Ordering::Relaxed));
        assert!(!record_trust(&trusted, &confirmed, true));
        assert!(record_trust(&trusted, &confirmed, false));
        assert!(!trusted.load(Ordering::Relaxed));
        assert!(!record_trust(&trusted, &confirmed, false));
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
        WatchdogState::GaveUp => Some(match dnsqb_service::read_startup_failure(app_data_dir) {
            Ok(reason) => TrayStatus::ServiceStartupFailed(reason),
            Err(_) => TrayStatus::ServiceGaveUp,
        }),
        WatchdogState::Healthy
        | WatchdogState::ChannelDegraded
        | WatchdogState::SuspectDead
        | WatchdogState::VerifyingPid => None,
    }
}

/// Stores `status` and reports whether it differs from what was there — the
/// poll thread wakes the event loop only on a real change (ARCH-19 b).
fn publish(current: &RwLock<TrayStatus>, status: TrayStatus) -> bool {
    let mut slot = current.write();
    let changed = *slot != status;
    *slot = status;
    changed
}

/// T-255: whether the service's `hero_state` moved into or out of a cert
/// state since the previous answer — the service learns of a cert change
/// first (`POST /admin/install-cert` pokes its cache at once), while the
/// tray's own trust watch may be sleeping up to 300 s. Only a re-poll
/// trigger: the tray's status ranking stays its own (see
/// `HeroStateView`'s authority note), and `None` (no earlier answer) never
/// fires — the trust watch makes its own first check at startup.
fn service_cert_changed(
    previous: Option<dnsqb_service::HeroStateView>,
    current: dnsqb_service::HeroStateView,
) -> bool {
    use dnsqb_service::HeroStateView as H;
    let is_cert = |h| matches!(h, H::CertNotTrusted | H::CertUnknown);
    previous.is_some_and(|p| p != current && (is_cert(p) || is_cert(current)))
}

/// Spawns the background polling thread and returns a handle to read its
/// latest result. `app_data_dir`/`port` are resolved once by the caller
/// (`main.rs`, at startup) — this never re-resolves either.
#[must_use]
pub fn spawn(app_data_dir: PathBuf, port: u16, trust: TrustState) -> StatusHandle {
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
            let mut last_hero = None;
            loop {
                // T-185 (Батч 3.12) / T-193: filtering paused from the tray
                // menu. `stop.flag`'s presence is the whole signal and outranks
                // everything below — a deliberate pause must read as such, not
                // as a failure. Since T-193 the service stays up (it serves the
                // unfiltered baseline while the flag exists), so `/admin/status`
                // would report a healthy, filtering-looking service — this
                // check is what still surfaces the pause. Checked on this 2s
                // poll cadence, not on the main thread's event loop.
                //
                // T-95: the watchdog's own state file wins over anything the
                // admin channel could say — a restarting or given-up service is
                // unreachable on that channel by definition, so the still-alive
                // watcher's `watchdog-state.json` is the only place the status
                // is visible. Ranked above `NoActiveProvider` (user's priority
                // decision 2026-09-02: watchdog above 0-voters). Хвиля 13b: a
                // given-up service now outranks the pause ([`local_status`]).
                let paused = dnsqb_service::stop_flag_is_set(&app_data_dir);
                if let Some(local) = local_status(paused, watchdog_override(&app_data_dir)) {
                    if publish(&current, local) {
                        crate::wake_event_loop();
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                if client.is_none() {
                    client = AdminClient::new(&app_data_dir, port).ok();
                }
                let status = if let Some(c) = &client {
                    if let Ok(response) = c.status().await {
                        if service_cert_changed(last_hero, response.hero_state) {
                            trust.request_recheck();
                        }
                        last_hero = Some(response.hero_state);
                        TrayStatus::from_response(&response, unix_ms_now())
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
                if publish(&current, status) {
                    crate::wake_event_loop();
                }
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

/// Stores one conclusive `certutil` answer and reports whether the event loop
/// has anything new to show: a trust flip (icon colour) or the first
/// confirmation (the onboarding offer keys on it) — ARCH-19 b.
fn record_trust(trusted: &AtomicBool, confirmed: &AtomicBool, now_trusted: bool) -> bool {
    let flipped = trusted.swap(now_trusted, Ordering::Relaxed) != now_trusted;
    let first_confirmation = !confirmed.swap(true, Ordering::Relaxed);
    flipped || first_confirmation
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
                    // Any `Ok` — trusted or not — means `certutil` gave a real
                    // answer, so the displayed flag is now a reading, not the
                    // seed (T-188).
                    if record_trust(&trusted, &confirmed, now_trusted) {
                        crate::wake_event_loop();
                    }
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
