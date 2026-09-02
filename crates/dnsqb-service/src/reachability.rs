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

use std::sync::Arc;
use std::time::Duration;

use crate::dispatch::AppState;
use crate::upstream::ReqwestDohClient;

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
        let delay = next_probe_delay(previous, current);
        previous = current;
        tokio::time::sleep(delay).await;
    }
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
    fn steady_online_uses_the_idle_interval_everything_else_the_recheck_interval() {
        use NetworkReachability::{Offline, Online};
        assert_eq!(next_probe_delay(Online, Online), IDLE_INTERVAL);
        assert_eq!(next_probe_delay(Online, Offline), RECHECK_INTERVAL);
        assert_eq!(next_probe_delay(Offline, Online), RECHECK_INTERVAL);
        assert_eq!(next_probe_delay(Offline, Offline), RECHECK_INTERVAL);
    }
}
