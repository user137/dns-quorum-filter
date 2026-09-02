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
    acquire_instance_guard, app_data_dir, plan_launch, read_pid_file, spawn_sibling,
    verify_pid_alive, GuardError, InstanceGuard, InstanceRole, LaunchAction, ResolverConfig,
};

#[cfg(windows)]
use dnsqb_service::{
    is_stale, read_heartbeat_file, read_watchdog_state, touch_heartbeat_file, write_watchdog_state,
    AdminClient, ChannelObs, Direction, Effect, HeartbeatPipeClient, LoopDriver, WatchdogState,
    STATE_FILE_NAME,
};
#[cfg(windows)]
use std::time::SystemTime;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt::init();

    let app_data = match app_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
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

    let port = load_port(&app_data);

    // T-150: bring up any sibling that isn't already running — once, at startup.
    // The tray is launcher-scope only, never heartbeat-monitored (§7 mutual
    // heartbeat is service <-> watcher); re-checking it in the loop would stop
    // the tray's own "Close" from ever working.
    ensure_sibling_running(&app_data, InstanceRole::Service);
    ensure_sibling_running(&app_data, InstanceRole::Tray);

    run_watcher_to_service_watchdog(app_data, port).await;
}

/// Takes the `watcher` single-instance lock, exiting the process on any failure
/// (a second watcher racing the first over the pid files and the respawn logic
/// is worse than not starting). Mirrors `dnsqb-service::main`'s
/// `acquire_service_guard`.
fn acquire_watcher_guard(app_data: &Path) -> InstanceGuard {
    match acquire_instance_guard(app_data, InstanceRole::Watcher) {
        Ok(guard) => guard,
        Err(GuardError::AlreadyRunning(role)) => {
            tracing::error!(
                "another {role} instance is already running on this app-data directory - \
                 not starting a second one (SPEC.md §7.1 #2)"
            );
            std::process::exit(1);
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

/// Spawns `role`'s sibling binary if no live, identity-matching instance is
/// already running (T-150). Idempotent: the check runs before the spawn.
fn ensure_sibling_running(app_data: &Path, role: InstanceRole) {
    let pid_file = read_pid_file(app_data, role).ok();
    let pid_check = pid_file
        .as_ref()
        .map(|record| verify_pid_alive(record.pid, &record.exe_path));
    match plan_launch(pid_file.as_ref(), pid_check) {
        LaunchAction::AlreadyRunning => {
            tracing::info!("{} is already running", role.as_str());
        }
        LaunchAction::Spawn => match spawn_sibling(role) {
            Ok(_child) => tracing::info!("started {}", role.as_str()),
            Err(err) => tracing::error!("could not start {}: {err}", role.as_str()),
        },
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
/// stable `Healthy` run by design).
#[cfg(windows)]
fn watchdog_state_is_fresh(app_data: &Path) -> bool {
    match std::fs::metadata(app_data.join(STATE_FILE_NAME)).and_then(|meta| meta.modified()) {
        Ok(mtime) => !is_stale(SystemTime::now(), mtime, Duration::from_secs(30)),
        Err(_) => false,
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

    let service_hb = app_data.join(format!("{}.hb", InstanceRole::Service.as_str()));
    let mut pipe: Option<HeartbeatPipeClient> = None;
    let mut admin: Option<AdminClient> = None;
    let mut seq: u64 = 0;

    loop {
        tokio::time::sleep(WATCHDOG_INTERVAL).await;
        let now = SystemTime::now();
        seq = seq.wrapping_add(1);

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
        let file_signal = match read_heartbeat_file(&service_hb) {
            Ok(hb) => hb.marker_ok && !is_stale(now, hb.mtime, WATCHDOG_CHANNEL_FRESH),
            Err(_) => false,
        };

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

        let obs = ChannelObs {
            ipc_signal,
            file_signal,
            health_signal: Some(health_signal),
            pid,
        };
        for effect in driver.tick(now, &obs).effects {
            match effect {
                Effect::Spawn => match spawn_sibling(InstanceRole::Service) {
                    Ok(_child) => {
                        tracing::warn!("watchdog: respawned dnsqb-service");
                        pipe = None;
                        admin = None;
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
                    if let Err(err) = write_watchdog_state(&app_data, &file) {
                        tracing::warn!("could not write watchdog-state.json: {err}");
                    }
                }
                // The pid file is re-read next tick, driven by `driver.state()`.
                Effect::VerifyPid => {}
            }
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
