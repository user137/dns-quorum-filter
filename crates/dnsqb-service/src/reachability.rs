//! T-152: is there any internet connectivity at all — a state distinct from
//! "an upstream is slow or degraded but the network is up". A light periodic
//! probe of several independent, always-on markers; when they all fail the
//! service can skip the full per-query fan-out and fail fast (SPEC.md §3.7)
//! instead of making the browser wait out a `2s × N` timeout on every
//! lookup.
//!
//! **Privacy (SPEC.md "Наскрізні вимоги"):** these markers are third-party
//! beacons hit on a timer from a privacy-focused product. Each request is a
//! bare `HEAD` with no query string and no browsing data — it reveals only
//! "this IP's box is online", which is exactly what a `generate_204`-class
//! endpoint exists to receive. Three *independent* infrastructures (Google,
//! Cloudflare, Apple) so no single operator sees a continuous heartbeat and
//! one operator's outage can't fake an "offline" verdict. Cloudflare is
//! already a data recipient here (the baseline resolver), so it adds no new
//! third party.
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

/// How long to wait before the next probe cycle. Steady `Online` → the full
/// [`IDLE_INTERVAL`]; anything else (currently `Offline`, or the verdict
/// just changed) → the short [`RECHECK_INTERVAL`].
#[must_use]
pub fn next_probe_delay(previous: NetworkReachability, current: NetworkReachability) -> Duration {
    if previous == NetworkReachability::Online && current == NetworkReachability::Online {
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
    loop {
        let current = verdict_from_probe_results(probe_all_markers(&client).await);
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
        // T-154: only meaningful while the network is up — an `Offline`
        // cycle would just report every chain entry dead and churn the
        // selector for nothing.
        if current == NetworkReachability::Online {
            probe_baseline_health(&state, &sentinel).await;
        }
        let delay = next_probe_delay(previous, current);
        previous = current;
        tokio::time::sleep(delay).await;
    }
}

/// One fixed `example.com A` query, built once and reused for every baseline
/// health probe. `recursion_desired` set explicitly — a strict resolver can
/// `SERVFAIL` an `RD=0` query for anything not edge-cached (CLAUDE.md gotcha).
fn sentinel_query() -> Message {
    let mut message = Message::query();
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
        next_probe_delay, verdict_from_probe_results, NetworkReachability, IDLE_INTERVAL,
        RECHECK_INTERVAL,
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
        assert_eq!(next_probe_delay(Online, Online), IDLE_INTERVAL);
        assert_eq!(next_probe_delay(Online, Offline), RECHECK_INTERVAL);
        assert_eq!(next_probe_delay(Offline, Online), RECHECK_INTERVAL);
        assert_eq!(next_probe_delay(Offline, Offline), RECHECK_INTERVAL);
    }
}
