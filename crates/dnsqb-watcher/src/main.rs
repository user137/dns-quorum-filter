// Release/MSIX: no console window (T-181). The watcher is the MSIX entry
// point, so without this the Start-menu tile opened a terminal and closing
// it killed the whole process group. Debug keeps the console for `cargo run`.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `dnsqb-watcher` — the watchdog process (SPEC.md §7). Two responsibilities:
//!
//! 1. **Idempotent autostart launcher (T-150).** On start it checks each sibling
//!    (`dnsqb-service`, `dnsqb-tray`) through the single-instance guard / PID
//!    primitives and spawns whichever is missing. A re-run of the autostart
//!    shortcut takes the same path and duplicates nothing — the state check
//!    happens before every spawn. Registering the Run-key / shortcut is T-156;
//!    this file is only the behaviour.
//! 2. **`watcher -> service` heartbeat loop.** Every 5 s it exchanges an IPC
//!    ping/pong (channel 1), re-touches `watcher.hb` and reads `service.hb`
//!    (channel 2), and polls `GET /health` through the cert-pinned
//!    [`AdminClient`] (channel 3). A 2-of-3 silent vote drives the pure
//!    `watchdog::loop_driver` automaton; on a confirmed-dead service it respawns
//!    it by absolute sibling path. This process is the **sole writer** of
//!    `watchdog-state.json` (§7.1 #7) — it rewrites it every tick so the file's
//!    `mtime` stays fresh and a reader treats a stale file as "watchdog not
//!    running", never as the recorded state.
//!
//! `#[tokio::main(flavor = "current_thread")]` keeps the runtime single-threaded
//! (§7.1 #9) — the feature set alone can't, since the `dnsqb-service` lib
//! dependency unifies `rt-multi-thread` in. `main` is not unit-tested (the
//! "hardcoded real resource, untested by design" precedent `dnsqb-service`'s own
//! `main.rs` records); the decision logic it drives is `watchdog::loop_driver`,
//! tested there.

use std::path::Path;
use std::time::Duration;

use dnsqb_service::{
    acquire_instance_guard, app_data_dir, clear_quit_flag, clear_stop_flag, ensure_sibling_running,
    init_logging, read_pid_file, spawn_sibling, verify_pid_alive, GuardError, InstanceGuard,
    InstanceRole, ResolverConfig,
};

#[cfg(windows)]
use dnsqb_service::{
    is_stale, quit_flag_is_set, read_heartbeat_file, read_watchdog_state, touch_heartbeat_file,
    write_watchdog_state, AdminClient, ChannelObs, Direction, Effect, HeartbeatFile,
    HeartbeatPipeClient, LoopDriver, PidCheck, WatchdogState, STATE_FILE_NAME,
};
#[cfg(windows)]
use std::time::SystemTime;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let app_data = match app_data_dir() {
        Ok(dir) => {
            init_logging("dnsqb-watcher", Some(&dir)); // T-184
            dir
        }
        Err(err) => {
            init_logging("dnsqb-watcher", None);
            tracing::error!("no app-data directory available, dnsqb-watcher cannot run: {err}");
            std::process::exit(1);
        }
    };

    // Held for the whole process lifetime; the OS frees the handle on exit
    // (SPEC.md §7.1 #2). Mirrors `dnsqb-service`'s own `acquire_service_guard`.
    let _guard = acquire_watcher_guard(&app_data);
    if let Err(err) = dnsqb_service::write_pid_file(&app_data, InstanceRole::Watcher) {
        tracing::warn!("could not write the watcher pid file: {err}");
    }

    // T-185: the entry-point process clears both lifecycle flags on startup —
    // a fresh launch (tile / login) is a clean slate. The heartbeat loop below
    // only *reads* `stop.flag`, never clears it there.
    clear_stop_flag(&app_data);
    clear_quit_flag(&app_data);

    let port = load_port(&app_data);

    // T-150 / T-187: bring up any sibling that isn't already running — once, at
    // startup. **Tray first**: the tile launches this watcher, so spawning the
    // tray before the (slower) service makes the icon appear in ~0.2 s instead
    // of after the whole stack is up. The tray is launcher-scope only, never
    // heartbeat-monitored (§7 mutual heartbeat is service <-> watcher);
    // re-checking it in the loop would stop the tray's own "Close" from ever
    // working.
    ensure_sibling_running(&app_data, InstanceRole::Tray);
    ensure_sibling_running(&app_data, InstanceRole::Service);

    run_watcher_to_service_watchdog(app_data, port).await;
}

/// Takes the `watcher` single-instance lock. A second watcher racing the first
/// over the pid files and the respawn logic is worse than not starting, so a
/// real lock error exits.
///
/// **T-187 — "clicking the tile again shows the icon".** The Start-menu tile
/// launches this binary; when a watcher is already running, the second
/// instance's only job is to make sure the tray is up (it may have been
/// closed) and then exit cleanly — `exit(0)`, not `exit(1)`. It never touches
/// the service or the watchdog state. It also clears a pending `quit.flag`
/// (T-185): the user relaunching the app cancels a quit that hasn't taken
/// effect yet. It leaves `stop.flag` alone — a re-click to see the icon must
/// not silently un-pause a deliberate pause.
fn acquire_watcher_guard(app_data: &Path) -> InstanceGuard {
    match acquire_instance_guard(app_data, InstanceRole::Watcher) {
        Ok(guard) => guard,
        Err(GuardError::AlreadyRunning(_)) => {
            tracing::info!(
                "a watcher is already running — ensuring the tray is up, then exiting (T-187)"
            );
            clear_quit_flag(app_data);
            ensure_sibling_running(app_data, InstanceRole::Tray);
            std::process::exit(0);
        }
        Err(err) => {
            tracing::error!("could not acquire the watcher single-instance lock: {err}");
            std::process::exit(1);
        }
    }
}

/// The `DoH` port `GET /health` and the admin channel live on. A missing or
/// unreadable `resolver_config.toml` falls back to the default port with a
/// warning — unlike `dnsqb-tray`, the watcher must still come up (and respawn
/// the service) even before the config file exists.
fn load_port(app_data: &Path) -> u16 {
    match ResolverConfig::load(&app_data.join("resolver_config.toml")) {
        Ok(config) => config.port,
        Err(err) => {
            let fallback = ResolverConfig::default().port;
            tracing::warn!(
                "could not load resolver_config.toml ({err}); using the default port {fallback}"
            );
            fallback
        }
    }
}

/// The shared heartbeat tick (SPEC.md §7.1 #8).
#[cfg(windows)]
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);

/// A peer channel counts as silent for one tick once its last signal is older
/// than two intervals; the `loop_driver`'s own three-miss threshold then
/// decides the vote.
#[cfg(windows)]
const WATCHDOG_CHANNEL_FRESH: Duration = Duration::from_secs(10);

/// Milliseconds since the Unix epoch, saturating — only ever compared as a
/// freshness delta.
#[cfg(windows)]
fn unix_millis(now: SystemTime) -> u64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

/// Whether `watchdog-state.json`'s own `mtime` is recent enough that resuming
/// its record makes sense — an older file is from a prior boot, start fresh.
/// Uses the file `mtime`, not `last_transition_at` (which is hours old in a
/// stable `Healthy` run by design). The window is 90 s: a watcher the *service*
/// restarts is only noticed and respawned ~40 s after it dies (three missed
/// beats plus the automaton's own transitions), so a tighter window would never
/// let a service-restarted watcher inherit the restart budget — the one case
/// `LoopDriver::restored` exists for. A minutes-old file from a prior boot is
/// still comfortably rejected.
#[cfg(windows)]
fn watchdog_state_is_fresh(app_data: &Path) -> bool {
    match std::fs::metadata(app_data.join(STATE_FILE_NAME)).and_then(|meta| meta.modified()) {
        Ok(mtime) => !is_stale(SystemTime::now(), mtime, Duration::from_secs(90)),
        Err(_) => false,
    }
}

/// The peer heartbeat file channel 2 **reads** in the `watcher -> service`
/// direction. The watcher touches its own `watcher.hb` and must read
/// `service.hb`, never the reverse — a swapped file makes the watcher read
/// its own beacon and always vote the service alive (review 1.4-B / T-203).
#[cfg(windows)]
fn peer_heartbeat_path(app_data: &Path) -> std::path::PathBuf {
    app_data.join(format!("{}.hb", InstanceRole::Service.as_str()))
}

/// Fold this tick's three raw channel readings (and the optional PID check)
/// into the [`ChannelObs`] the 2-of-3 vote consumes. Pure: the async pings
/// run in the loop, this is only the "raw reads -> observation" mapping the
/// vote depends on, split out so it is testable without the loop (review
/// 1.4-B / T-203). Channel 3 always exists in this direction, so
/// `health_signal` is always `Some` (unlike [`Direction::ServiceToWatcher`]).
#[cfg(windows)]
fn observe(
    ipc_answered: bool,
    peer_hb: &std::io::Result<HeartbeatFile>,
    health_ok: bool,
    pid: Option<PidCheck>,
    now: SystemTime,
) -> ChannelObs {
    ChannelObs {
        ipc_signal: ipc_answered,
        file_signal: match peer_hb {
            Ok(hb) => hb.marker_ok && !is_stale(now, hb.mtime, WATCHDOG_CHANNEL_FRESH),
            Err(_) => false,
        },
        health_signal: Some(health_ok),
        pid,
    }
}

/// The `watcher -> service` decision loop (SPEC.md §7): 2-of-3 silent vote over
/// channels 1 (IPC ping/pong), 2 (`service.hb` age) and 3 (`GET /health`); on a
/// confirmed-dead service, respawn it by absolute sibling path. Rewrites
/// `watchdog-state.json` every tick (§7.1 #7 — sole writer; freshness).
#[cfg(windows)]
async fn run_watcher_to_service_watchdog(app_data: std::path::PathBuf, port: u16) {
    let mut driver = match read_watchdog_state(&app_data) {
        Ok(file) if watchdog_state_is_fresh(&app_data) => {
            tracing::info!("resuming persisted watchdog state ({:?})", file.state);
            LoopDriver::restored(Direction::WatcherToService, &file)
        }
        _ => LoopDriver::new(Direction::WatcherToService),
    };

    let service_hb = peer_heartbeat_path(&app_data);
    let mut pipe: Option<HeartbeatPipeClient> = None;
    let mut admin: Option<AdminClient> = None;
    let mut seq: u64 = 0;

    loop {
        tokio::time::sleep(WATCHDOG_INTERVAL).await;
        let now = SystemTime::now();
        seq = seq.wrapping_add(1);

        // T-185: the user asked to quit. Stop the service (best-effort — it may
        // already be down), drop the quit flag, and exit. The tray has already
        // exited or is about to; the whole app is now down until the next launch.
        if quit_flag_is_set(&app_data) {
            tracing::info!(
                "watchdog: quit.flag present — stopping the service and exiting (T-185)"
            );
            if let Some(client) = admin.as_ref() {
                let _ = client.shutdown().await;
            }
            clear_quit_flag(&app_data);
            std::process::exit(0);
        }

        // T-193: a pause (`stop.flag`) no longer freezes supervision. The
        // service now *stays up* while paused — it reads the flag itself
        // (`pause_watch`) and serves the unfiltered baseline — so the normal
        // tick below is a no-op (all three channels answer, the vote stays
        // `Alive`, `RestartBudget` is never touched, no `Effect::Spawn`). This
        // is strictly better than the old freeze: if the service genuinely
        // crashes during a pause it now gets respawned, and the new process
        // comes back in bypass mode (it re-reads `stop.flag` on startup). The
        // freeze existed only because the pre-T-193 pause path killed the
        // service via `/admin/shutdown`.

        // Channel 1: IPC ping/pong. A failed ping drops the client so the next
        // tick reconnects.
        if pipe.is_none() {
            pipe = HeartbeatPipeClient::connect(&app_data).ok();
        }
        let ipc_signal = match pipe.as_mut() {
            Some(client) => {
                let answered = client.ping(seq, unix_millis(now)).await.is_ok();
                if !answered {
                    pipe = None;
                }
                answered
            }
            None => false,
        };

        // Channel 2: re-touch ours, read the service's.
        if let Err(err) = touch_heartbeat_file(&app_data, InstanceRole::Watcher) {
            tracing::warn!("could not touch watcher.hb: {err}");
        }
        let file_read = read_heartbeat_file(&service_hb);

        // Channel 3: GET /health through the cert-pinned client. Rebuilt after a
        // respawn (§7.1 #10 — the trust anchor can change under a rotation).
        if admin.is_none() {
            admin = AdminClient::new(&app_data, port).ok();
        }
        let health_signal = match admin.as_ref() {
            Some(client) => client.health().await.is_ok(),
            None => false,
        };

        let pid = if driver.state() == WatchdogState::VerifyingPid {
            read_pid_file(&app_data, InstanceRole::Service)
                .ok()
                .map(|record| verify_pid_alive(record.pid, &record.exe_path))
        } else {
            None
        };

        let obs = observe(ipc_signal, &file_read, health_signal, pid, now);
        apply_watchdog_effects(
            driver.tick(now, &obs).effects,
            &app_data,
            &mut pipe,
            &mut admin,
        );
    }
}

/// Carry out one tick's [`Effect`]s. Split out of
/// [`run_watcher_to_service_watchdog`] to keep that loop under the line cap;
/// it drops the cert-pinned clients after a respawn so the next tick rebuilds
/// them against the new process (§7.1 #10).
#[cfg(windows)]
fn apply_watchdog_effects(
    effects: Vec<Effect>,
    app_data: &Path,
    pipe: &mut Option<HeartbeatPipeClient>,
    admin: &mut Option<AdminClient>,
) {
    for effect in effects {
        match effect {
            // T-193: a paused service (`stop.flag`) stays running, so this loop
            // never actually reaches `Effect::Spawn` during a pause. And if it
            // did — a genuine crash mid-pause — respawning is the right move:
            // the new process re-reads `stop.flag` and comes up serving the
            // unfiltered baseline, rather than leaving DNS dead until resume.
            // The pre-T-193 `stop_flag_is_set` guard here (which suppressed the
            // respawn) is deliberately gone.
            Effect::Spawn => match spawn_sibling(InstanceRole::Service) {
                Ok(_child) => {
                    tracing::warn!("watchdog: respawned dnsqb-service");
                    *pipe = None;
                    *admin = None;
                }
                Err(err) => {
                    tracing::error!("watchdog: failed to respawn dnsqb-service: {err}");
                }
            },
            Effect::LogGaveUp => tracing::error!(
                "watchdog: gave up restarting dnsqb-service after the retry budget - \
                 manual recovery needed"
            ),
            Effect::WriteState(file) => {
                if let Err(err) = write_watchdog_state(app_data, &file) {
                    tracing::warn!("could not write watchdog-state.json: {err}");
                }
            }
            // The pid file is re-read next tick, driven by `driver.state()`.
            Effect::VerifyPid => {}
        }
    }
}

/// Non-Windows placeholder — `dnsqb-watcher`'s heartbeat is Windows-only in
/// Фаза 3 (the IPC pipe and the single-instance guard are `#[cfg(windows)]`).
/// `acquire_watcher_guard` already exits before this is reached on such a
/// target; the Фаза 6 port lifts the whole seam.
#[cfg(not(windows))]
async fn run_watcher_to_service_watchdog(_app_data: std::path::PathBuf, _port: u16) {
    tracing::error!("dnsqb-watcher heartbeat is not implemented on this platform (Фаза 6)");
}

#[cfg(all(test, windows))]
mod tests {
    use super::{observe, peer_heartbeat_path, WATCHDOG_CHANNEL_FRESH};
    use dnsqb_service::{HeartbeatFile, PidCheck};
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    // review 1.4-B: the one silent-bug risk is reading the wrong `.hb`. This
    // loop is the `watcher -> service` direction: it must read the *service's*
    // beacon, not its own.
    #[test]
    fn peer_heartbeat_path_names_the_service_file_not_the_watcher_file() {
        let path = peer_heartbeat_path(Path::new("app-data"));
        assert!(path.ends_with("service.hb"), "got {path:?}");
        assert!(
            !path.to_string_lossy().contains("watcher.hb"),
            "must not read its own beacon: {path:?}"
        );
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn hb(marker_ok: bool, mtime: SystemTime) -> HeartbeatFile {
        HeartbeatFile {
            marker_ok,
            role: None,
            mtime,
        }
    }

    #[test]
    fn observe_file_signal_is_true_only_for_a_fresh_well_marked_peer_heartbeat() {
        let now = at(1_000_000);
        let fresh = now; // 0s old, threshold (WATCHDOG_CHANNEL_FRESH) is 10s
        let stale = at(1_000_000 - WATCHDOG_CHANNEL_FRESH.as_secs() - 5);

        assert!(observe(false, &Ok(hb(true, fresh)), false, None, now).file_signal);
        assert!(!observe(false, &Ok(hb(true, stale)), false, None, now).file_signal);
        assert!(!observe(false, &Ok(hb(false, fresh)), false, None, now).file_signal);
        assert!(
            !observe(
                false,
                &Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
                false,
                None,
                now,
            )
            .file_signal
        );
    }

    #[test]
    fn observe_passes_the_other_three_channels_through_unchanged() {
        let now = at(1_000_000);
        let obs = observe(true, &Ok(hb(true, now)), false, Some(PidCheck::Alive), now);
        assert!(obs.ipc_signal);
        // Channel 3 exists in this direction — always `Some`, carrying the raw bool.
        assert_eq!(obs.health_signal, Some(false));
        assert_eq!(obs.pid, Some(PidCheck::Alive));

        let obs = observe(false, &Ok(hb(true, now)), true, None, now);
        assert!(!obs.ipc_signal);
        assert_eq!(obs.health_signal, Some(true));
        assert_eq!(obs.pid, None);
    }
}
