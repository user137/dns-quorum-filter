//! T-152: is there any internet connectivity at all — a state distinct from
//! "an upstream is slow or degraded but the network is up". A light periodic
//! probe of several independent, always-on markers; when they all fail the
//! service can skip the full per-query fan-out and fail fast (SPEC.md §3.7)
//! instead of making the browser wait out a `2s × N` timeout on every
//! lookup.
//!
//! **Privacy (SPEC.md "Наскрізні вимоги"):** the markers are third-party
//! beacons hit on a timer from a privacy-focused product. Each request is a
//! bare `HEAD` with no query string and no browsing data — it reveals only
//! "this IP's box is online", which is exactly what a `generate_204`-class
//! endpoint exists to receive. Three *independent* infrastructures (Google,
//! Cloudflare, Apple), rotated over, so the marker traffic gives no single
//! one a continuous heartbeat and one operator's outage can't fake an
//! "offline" verdict. Separately, the baseline health probe below **does**
//! send one fixed `example.com A` query to the *active* baseline resolver
//! every `Online` cycle — a continuous heartbeat to that one operator
//! (usually Cloudflare, already this service's resolver for real traffic).
//! It carries no browsing data and its cadence is bounded by
//! [`IDLE_INTERVAL`]; the SPEC ВП №2 question about a public resolver's
//! terms of service for an automated client applies to it, not the markers.
//!
//! Deliberately **not** wired into `GET /health` or any watchdog channel
//! (TASKS.md — `/health` is upstream-free on purpose so a network outage
//! can't trigger a restart, the exact false positive SPEC.md §7's
//! multi-channel voting defends against).
//!
//! The same task also drives `baseline_selector`'s failover (T-154, §3.7):
//! while `Online` it health-checks the active baseline URL with one real
//! `DoH` query through the production client and folds the result into the
//! selector, switching to an alternate after repeated failure and probing
//! the primary back once it recovers. Failover is therefore between-query,
//! at this task's cadence — the hot path only ever reads `current()`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

use crate::baseline_selector::{BaselineEvent, BaselineHealth, BASELINE_CHAIN};
use crate::dispatch::AppState;
use crate::upstream::{DohClient, ReqwestDohClient};

/// Independent always-on connectivity markers (SPEC.md §3.7). Only one has to
/// answer for the verdict to be `Online`.
pub const MARKERS: [&str; 3] = [
    "https://www.google.com/generate_204",
    "https://cloudflare.com/cdn-cgi/trace",
    "https://captive.apple.com/hotspot-detect.html",
];

/// Per-marker request deadline — short, so a full offline probe cycle
/// resolves quickly rather than dragging out the recheck interval.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Gap between probe cycles while the network is steadily `Online`.
pub const IDLE_INTERVAL: Duration = Duration::from_secs(30);

/// Gap between probe cycles while `Offline`, or right after the verdict
/// changed — short, so a transition (either direction) is caught fast.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(3);

/// Consecutive all-markers-failed cycles required before the prober publishes
/// `Offline`. Publishing `Offline` fails *every* query fast — the high-stakes
/// direction — so a single saturated moment, a Wi-Fi roam or a VPN reconnect
/// (all three markers exceeding [`PROBE_TIMEOUT`] in one cycle) must not
/// trigger it; a real outage lasts well past a few [`RECHECK_INTERVAL`]s.
/// Recovery is deliberately **not** debounced — one successful cycle
/// republishes `Online` at once (fast un-break). Mirrors
/// `baseline_selector::SWITCH_THRESHOLD`, which guards the far lower-stakes
/// "swap a baseline URL" decision with the same shape.
pub const OFFLINE_CONFIRM_CYCLES: u32 = 3;

/// Entry-only debounce for the `Offline` verdict (see [`OFFLINE_CONFIRM_CYCLES`]).
/// Folds each cycle's raw verdict in and returns the verdict to *publish*.
#[derive(Debug, Default)]
struct OfflineDebounce {
    consecutive_fail: u32,
}

impl OfflineDebounce {
    /// A raw `Online` resets the streak and publishes `Online` immediately.
    /// A raw `Offline` publishes `Offline` only once the streak has reached
    /// [`OFFLINE_CONFIRM_CYCLES`]; until then the published verdict stays
    /// `Online`.
    fn observe(&mut self, raw: NetworkReachability) -> NetworkReachability {
        match raw {
            NetworkReachability::Online => {
                self.consecutive_fail = 0;
                NetworkReachability::Online
            }
            NetworkReachability::Offline => {
                self.consecutive_fail = self.consecutive_fail.saturating_add(1);
                if self.consecutive_fail >= OFFLINE_CONFIRM_CYCLES {
                    NetworkReachability::Offline
                } else {
                    NetworkReachability::Online
                }
            }
        }
    }
}

/// Whether the machine currently has any internet connectivity (T-152).
/// Starts `Online`: before the first probe completes there is no evidence
/// of an outage, and a false `Offline` would fail every query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkReachability {
    /// At least one marker answered on the last cycle.
    #[default]
    Online,
    /// Every marker failed on the last cycle.
    Offline,
}

/// `Offline` only when **every** marker failed this cycle — a single CDN
/// blip must not flip the state; `Online` as soon as any one answered.
#[must_use]
pub fn verdict_from_probe_results(results: [bool; MARKERS.len()]) -> NetworkReachability {
    if results.iter().any(|&ok| ok) {
        NetworkReachability::Online
    } else {
        NetworkReachability::Offline
    }
}

/// How long to wait before the next probe cycle. Only a steady `Online`
/// (`previous` published `Online` **and** this cycle's `raw` verdict `Online`)
/// earns the full [`IDLE_INTERVAL`]; anything else — a just-recovered link, or
/// a failing cycle whether or not the debounce has published `Offline` yet —
/// takes the short [`RECHECK_INTERVAL`], so a genuine outage is confirmed in a
/// few seconds rather than a few [`IDLE_INTERVAL`]s.
#[must_use]
pub fn next_probe_delay(previous: NetworkReachability, raw: NetworkReachability) -> Duration {
    if previous == NetworkReachability::Online && raw == NetworkReachability::Online {
        IDLE_INTERVAL
    } else {
        RECHECK_INTERVAL
    }
}

/// Background task (T-152): probe the markers, publish the verdict on
/// [`AppState`], sleep, repeat. `client` is a plain `reqwest::Client` kept
/// separate from the `DoH` client — a connectivity probe has nothing to do
/// with upstream resolution and must not share its connection pool or
/// per-request tuning.
pub async fn run_reachability_prober(
    client: reqwest::Client,
    state: Arc<AppState<ReqwestDohClient>>,
) {
    let sentinel = sentinel_query();
    let mut previous = NetworkReachability::Online;
    let mut debounce = OfflineDebounce::default();
    loop {
        let raw = verdict_from_probe_results(probe_all_markers(&client).await);
        let current = debounce.observe(raw);
        if current != previous {
            match current {
                NetworkReachability::Offline => {
                    tracing::warn!("network appears offline — every reachability marker failed");
                }
                NetworkReachability::Online => {
                    tracing::info!("network reachability restored");
                }
            }
        }
        state.update_reachability(current);
        // T-154: gate on the *raw* verdict, not the published one — while the
        // offline debounce is still counting (`raw == Offline`, `current`
        // still `Online`) the network really is down, so a baseline probe
        // would just report every chain entry dead and churn the selector.
        if raw == NetworkReachability::Online {
            probe_baseline_health(&state, &sentinel).await;
        }
        let delay = next_probe_delay(previous, raw);
        previous = current;
        tokio::time::sleep(delay).await;
    }
}

/// One fixed `example.com A` query, built once and reused for every baseline
/// health probe. `recursion_desired` set explicitly — a strict resolver can
/// `SERVFAIL` an `RD=0` query for anything not edge-cached (CLAUDE.md gotcha).
fn sentinel_query() -> Message {
    let mut message = Message::query();
    // The literal always parses; the no-`else` `if let` is only to avoid an
    // `unwrap`/`expect` (crate-wide deny). A question-less sentinel could
    // never happen with this constant, and would at worst make every baseline
    // probe read as failed — never a false `Responded`.
    if let Ok(name) = Name::from_ascii("example.com.") {
        message.add_query(Query::query(name, RecordType::A));
    }
    message.metadata.recursion_desired = true;
    message
}

/// T-154: check the active baseline URL (and, when due, the primary) with a
/// real `DoH` query through the production client, and fold the result into
/// `baseline_selector::BaselineSelector`. Between-query, probe-granularity
/// failover — the hot path only ever reads `current()`.
async fn probe_baseline_health(state: &AppState<ReqwestDohClient>, sentinel: &Message) {
    let selector = state.baseline_snapshot();
    let now = SystemTime::now();
    let url = if selector.should_retry_primary(now) {
        BASELINE_CHAIN[0]
    } else {
        selector.current()
    };
    let health = match state.doh_client().query(url, sentinel).await {
        Ok(response) if is_usable_response(&response) => BaselineHealth::Responded,
        _ => BaselineHealth::Failed,
    };
    let mut next = (*selector).clone();
    match next.record(now, url, health) {
        Some(BaselineEvent::SwitchedTo { index }) => {
            tracing::warn!(
                index,
                "baseline resolver failed over to an alternate endpoint"
            );
        }
        Some(BaselineEvent::RecoveredToPrimary) => {
            tracing::info!("baseline resolver recovered — back on the primary endpoint");
        }
        None => {}
    }
    if next != *selector {
        state.update_baseline(Arc::new(next));
    }
}

fn is_usable_response(message: &Message) -> bool {
    matches!(
        message.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    )
}

async fn probe_all_markers(client: &reqwest::Client) -> [bool; MARKERS.len()] {
    let (a, b, c) = tokio::join!(
        probe_one(client, MARKERS[0]),
        probe_one(client, MARKERS[1]),
        probe_one(client, MARKERS[2]),
    );
    [a, b, c]
}

/// One marker probe: a bare `HEAD` under [`PROBE_TIMEOUT`]. *Any* HTTP
/// response — whatever the status — counts as reachable; only a
/// connect/DNS/TLS failure or the timeout counts as unreachable.
async fn probe_one(client: &reqwest::Client, url: &str) -> bool {
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, client.head(url).send()).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::{
        next_probe_delay, verdict_from_probe_results, NetworkReachability, OfflineDebounce,
        IDLE_INTERVAL, OFFLINE_CONFIRM_CYCLES, RECHECK_INTERVAL,
    };

    #[test]
    fn any_single_marker_answering_means_online() {
        assert_eq!(
            verdict_from_probe_results([true, false, false]),
            NetworkReachability::Online
        );
        assert_eq!(
            verdict_from_probe_results([false, false, true]),
            NetworkReachability::Online
        );
        assert_eq!(
            verdict_from_probe_results([true, true, true]),
            NetworkReachability::Online
        );
    }

    #[test]
    fn every_marker_failing_means_offline() {
        assert_eq!(
            verdict_from_probe_results([false, false, false]),
            NetworkReachability::Offline
        );
    }

    #[test]
    fn one_marker_permanently_down_does_not_flip_the_verdict() {
        // Marker 0 (say Google) blocked on this network — the other two
        // keep the verdict `Online`.
        for other in [[true, false], [false, true], [true, true]] {
            assert_eq!(
                verdict_from_probe_results([false, other[0], other[1]]),
                NetworkReachability::Online
            );
        }
    }

    #[test]
    fn default_is_online() {
        assert_eq!(NetworkReachability::default(), NetworkReachability::Online);
    }

    #[test]
    fn sentinel_query_is_a_recursion_desired_a_lookup() {
        let q = super::sentinel_query();
        assert!(
            q.metadata.recursion_desired,
            "RD must be set (CLAUDE.md gotcha)"
        );
        let Some(question) = q.queries.first() else {
            panic!("sentinel must carry a question");
        };
        assert_eq!(question.query_type(), super::RecordType::A);
    }

    #[test]
    fn steady_online_uses_the_idle_interval_everything_else_the_recheck_interval() {
        use NetworkReachability::{Offline, Online};
        // Second arg is this cycle's *raw* verdict.
        assert_eq!(next_probe_delay(Online, Online), IDLE_INTERVAL);
        // A failing cycle takes the fast cadence even before the debounce
        // has published `Offline` — otherwise a real outage would take
        // `OFFLINE_CONFIRM_CYCLES * IDLE_INTERVAL` to confirm.
        assert_eq!(next_probe_delay(Online, Offline), RECHECK_INTERVAL);
        assert_eq!(next_probe_delay(Offline, Online), RECHECK_INTERVAL);
        assert_eq!(next_probe_delay(Offline, Offline), RECHECK_INTERVAL);
    }

    #[test]
    fn one_failing_cycle_does_not_publish_offline() {
        let mut d = OfflineDebounce::default();
        assert_eq!(
            d.observe(NetworkReachability::Offline),
            NetworkReachability::Online,
            "a single all-markers-failed cycle is not yet an outage"
        );
    }

    #[test]
    fn offline_is_published_only_after_the_confirm_threshold() {
        let mut d = OfflineDebounce::default();
        for _ in 0..OFFLINE_CONFIRM_CYCLES - 1 {
            assert_eq!(
                d.observe(NetworkReachability::Offline),
                NetworkReachability::Online
            );
        }
        assert_eq!(
            d.observe(NetworkReachability::Offline),
            NetworkReachability::Offline,
            "the Nth consecutive failing cycle publishes Offline"
        );
    }

    #[test]
    fn one_success_resets_the_streak() {
        let mut d = OfflineDebounce::default();
        d.observe(NetworkReachability::Offline);
        d.observe(NetworkReachability::Offline);
        assert_eq!(
            d.observe(NetworkReachability::Online),
            NetworkReachability::Online
        );
        // Streak restarts from zero — two more fails still isn't an outage.
        assert_eq!(
            d.observe(NetworkReachability::Offline),
            NetworkReachability::Online
        );
        assert_eq!(
            d.observe(NetworkReachability::Offline),
            NetworkReachability::Online
        );
    }

    #[test]
    fn recovery_from_confirmed_offline_is_immediate() {
        let mut d = OfflineDebounce::default();
        for _ in 0..OFFLINE_CONFIRM_CYCLES {
            d.observe(NetworkReachability::Offline);
        }
        assert_eq!(
            d.observe(NetworkReachability::Online),
            NetworkReachability::Online,
            "recovery is not debounced"
        );
    }

    #[test]
    fn a_long_outage_stays_offline_without_overflowing() {
        let mut d = OfflineDebounce::default();
        let mut last = NetworkReachability::Online;
        for _ in 0..10_000 {
            last = d.observe(NetworkReachability::Offline);
        }
        assert_eq!(last, NetworkReachability::Offline);
    }
}
