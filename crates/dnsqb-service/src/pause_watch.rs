//! T-193 — publish the tray's pause state (`lifecycle::stop.flag`) onto
//! [`AppState`] so `pipeline::handle_query` serves every query through the
//! unfiltered baseline while it is set, **without `dnsqb-service` going down**.
//!
//! Same shape as [`crate::reachability::run_reachability_prober`]: a detached
//! background loop that publishes a `Copy` value to `AppState`, read once per
//! query on the hot path. `stop.flag` is just a `Path::exists`, so this needs
//! no HTTP client and no `#[cfg(windows)]`. A bare `stat` once a second on a
//! detached task needs no `spawn_blocking` — the watchdog/heartbeat paths
//! already do blocking fs from async, and the cost is a single directory
//! lookup.
//!
//! Before T-193 the tray's "Призупинити фільтрацію" wrote `stop.flag` *and*
//! sent `POST /admin/shutdown`, and the watcher froze supervision — so a pause
//! left the browser with no DNS at all. Now the flag is a behaviour signal the
//! service itself observes; the tray only writes it, the watcher keeps
//! supervising normally (a crash mid-pause is respawned and comes back in
//! bypass mode). See `DECISIONS.md` (2026-09-08, revising the 2026-09-07 T-185
//! entry).
//!
//! **Stale flag on a bare launch.** `stop.flag` is cleared by the *watcher* on
//! every startup (`lifecycle.rs`'s "entry-point clears on startup" rule), and
//! in the real (MSIX) flow the watcher always starts the service, so the
//! service never inherits a stale flag there. A **standalone `dnsqb-service`**
//! launched without the watcher (a bare `cargo run -p dnsqb-service`) *can*
//! inherit a `stop.flag` a prior session left behind — e.g. after a
//! `QUIT_APP_ID` quit, which writes `stop.flag` + `quit.flag` and only the
//! latter is cleared. The first poll below logs `filtering paused …` in that
//! case, so it is visible in the log file rather than silent; clearing the
//! flag is the watcher's job, not this task's (it must not clear a flag the
//! user may have set on purpose).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::dispatch::AppState;
use crate::upstream::DohClient;

/// Poll cadence — ~1 s, so a tray pause/resume takes effect well inside the
/// "DNS keeps working" promise the confirm dialog now makes.
pub const PAUSE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Background task: publish `stop.flag`'s presence onto
/// [`AppState::update_filtering_paused`], sleep, repeat. Detached and never
/// joined, exactly like the reachability prober — the process exit reclaims
/// it. Logs once per transition (the watcher's own pause log is removed in
/// T-193, and with no console — T-181 — the log file is the only diagnostic).
///
/// Generic over the client because this task never touches it — unlike the
/// reachability prober, which pins `ReqwestDohClient` for its baseline probe.
pub async fn run_pause_watcher<C: DohClient + Sync>(app_data: PathBuf, state: Arc<AppState<C>>) {
    let mut previous = state.filtering_paused_snapshot();
    loop {
        let now = crate::lifecycle::stop_flag_is_set(&app_data);
        state.update_filtering_paused(now);
        if now != previous {
            if now {
                tracing::info!(
                    "filtering paused by the user (stop.flag present) — serving unfiltered baseline"
                );
            } else {
                tracing::info!("filtering resumed (stop.flag cleared) — quorum filtering active");
            }
            previous = now;
        }
        tokio::time::sleep(PAUSE_POLL_INTERVAL).await;
    }
}
