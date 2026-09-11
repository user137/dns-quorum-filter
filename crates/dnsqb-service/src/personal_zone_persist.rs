//! T-138 (Батч 4.5, SPEC.md §5.1.1) — the background task that keeps
//! `personal-zone.enc` in step with [`crate::personal_zone_stats::PersonalZoneStats`]
//! while `[personal_zone].enabled` is on, and republishes the derived
//! personal `ZoneLists` (`AppState.rating_filter_personal_zone`) every cycle.
//!
//! Sibling of [`crate::log_persist`] / [`crate::cache_persist`] /
//! [`crate::zone_removal_persist`] — same serialize→seal→
//! [`crate::paths::write_atomic`] shape, same orphan-rename recovery via
//! [`crate::log_persist::rename_orphan`]. Sealed with the *separate*
//! personal-zone key ([`crate::key_store::load_or_create_personal_zone_key`]),
//! not the shared `persistence-key` — see `key_store`'s module doc for why.
//!
//! **One task does both jobs, every [`FLUSH_INTERVAL`]:** roll the stats
//! forward to today, re-derive the qualifying set from the *current*
//! `[personal_zone]` config, republish it, then persist the (now rotated)
//! snapshot. Recomputing the qualifying set every cycle even when nothing
//! changed is cheap — a re-sort over at most
//! `personal_zone_stats::MAX_TRACKED_DOMAINS` entries once a minute — so
//! there is no separate "did the calendar day actually change?" branch to
//! get wrong.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

use crate::config::PersonalZoneConfig;
use crate::dispatch::AppState;
use crate::encrypted_file::{open, seal, EncryptedFileError, FileKind};
use crate::key_store::load_or_create_personal_zone_key;
use crate::log_persist::rename_orphan;
use crate::paths::write_atomic;
use crate::personal_zone_stats::{
    window_len_from_config, DayIndex, PersistedPersonalZone, PersonalZoneStats,
};
use crate::rating_filter::{ZoneLists, ZoneSource, ZoneSourceKind};
use crate::upstream::ReqwestDohClient;

/// How often the running task rotates/republishes/persists — same cadence
/// as the sibling persisters.
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// The on-disk file name, under the app-data directory.
const FILE_NAME: &str = "personal-zone.enc";

/// Failure modes of [`persist_snapshot`] — payload-free (no domain names):
/// the `Write` variant's `io::Error` can only name the target *path*.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PersonalZonePersistError {
    /// The stats snapshot could not be serialized to JSON (not expected for
    /// [`PersistedPersonalZone`]'s field types).
    #[error("failed to serialize the personal zone: {0}")]
    Serialize(#[source] serde_json::Error),
    /// The plaintext could not be encrypted (a failing OS RNG).
    #[error("failed to encrypt the personal zone: {0}")]
    Seal(#[source] EncryptedFileError),
    /// The atomic write to `personal-zone.enc` failed.
    #[error("failed to write the encrypted personal zone to disk: {0}")]
    Write(#[source] std::io::Error),
}

/// Serialize → seal → atomic-write one snapshot of `stats`. The whole file
/// is rewritten each time, mirroring `log_persist::persist_snapshot`.
///
/// # Errors
///
/// [`PersonalZonePersistError::Serialize`], [`PersonalZonePersistError::Seal`]
/// or [`PersonalZonePersistError::Write`] as their doc comments describe.
pub(crate) fn persist_snapshot(
    stats: &PersonalZoneStats,
    key: &[u8; 32],
    path: &Path,
) -> Result<(), PersonalZonePersistError> {
    let plaintext =
        serde_json::to_vec(&stats.to_persisted()).map_err(PersonalZonePersistError::Serialize)?;
    let sealed =
        seal(key, FileKind::PersonalZone, &plaintext).map_err(PersonalZonePersistError::Seal)?;
    write_atomic(path, &sealed).map_err(PersonalZonePersistError::Write)
}

/// What [`load_persisted_personal_zone`] hands back to `orchestrate.rs`.
pub(crate) struct PersonalZoneInit {
    /// The stats to seed `AppState.personal_zone_stats` with — empty when
    /// disabled, no app-data directory, or no decryptable file existed.
    pub stats: PersonalZoneStats,
    /// The derived zone to seed `AppState.rating_filter_personal_zone` with
    /// — the qualifying set `stats` already implies, so the bubble is usable
    /// immediately after a restart, before the first cycle ticks.
    pub zone: ZoneLists,
    /// `Some((path, key))` to pass to [`run_personal_zone_task`] once the
    /// `AppState` exists; `None` when `[personal_zone]` is off at startup or
    /// no key could be obtained this run.
    pub flusher: Option<(PathBuf, Zeroizing<[u8; 32]>)>,
}

/// Why a persisted personal-zone file could not be restored.
#[derive(Debug, thiserror::Error)]
enum LoadError {
    #[error("could not read the file: {0}")]
    Read(#[source] std::io::Error),
    #[error("{0}")]
    Decrypt(#[source] EncryptedFileError),
    #[error("could not parse the decrypted contents: {0}")]
    Parse(#[source] serde_json::Error),
}

fn seed_from_file(path: &Path, key: &[u8; 32]) -> Result<PersistedPersonalZone, LoadError> {
    let raw = std::fs::read(path).map_err(LoadError::Read)?;
    let plaintext = open(key, FileKind::PersonalZone, &raw).map_err(LoadError::Decrypt)?;
    serde_json::from_slice(&plaintext).map_err(LoadError::Parse)
}

/// Builds the one-`ZoneSource` [`ZoneLists`] `zone_match` actually consults,
/// from whatever `stats` currently qualifies under `cfg`.
fn zone_from_stats(stats: &PersonalZoneStats, cfg: &PersonalZoneConfig) -> ZoneLists {
    let qualifying = stats.derive_qualifying_domains(cfg);
    ZoneLists::new(vec![ZoneSource::new(ZoneSourceKind::Personal, qualifying)])
}

/// Startup: read `personal-zone.enc` when `[personal_zone].enabled` and a
/// decryptable file exists. A missing key with a file present, or an
/// undecryptable / malformed file, is renamed aside and the store starts
/// empty — same "re-creatable, warn and proceed" posture as
/// `log_persist::load_persisted_query_log`.
#[must_use]
pub(crate) fn load_persisted_personal_zone(
    app_data: Option<&Path>,
    cfg: PersonalZoneConfig,
    now: SystemTime,
) -> PersonalZoneInit {
    let today = DayIndex::from_system_time(now);
    let window_len = window_len_from_config(&cfg);
    let empty = || PersonalZoneInit {
        stats: PersonalZoneStats::new(window_len, today),
        zone: ZoneLists::default(),
        flusher: None,
    };
    if !cfg.enabled {
        return empty();
    }
    let Some(dir) = app_data else {
        tracing::warn!(
            "[personal_zone] is enabled but no app-data directory is available; \
             the personal zone will not be persisted"
        );
        return empty();
    };
    let path = dir.join(FILE_NAME);
    let ciphertext_present = path.exists();
    let key = match load_or_create_personal_zone_key(dir, ciphertext_present) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(
                "could not obtain the personal-zone key ({err}); \
                 the personal zone will not be persisted this run"
            );
            return empty();
        }
    };
    let mut stats = PersonalZoneStats::new(window_len, today);
    if key.orphaned_ciphertext {
        rename_orphan(&path);
    } else if ciphertext_present {
        match seed_from_file(&path, &key.key) {
            Ok(persisted) => {
                stats = PersonalZoneStats::from_persisted(persisted, today, window_len);
                tracing::info!(
                    "restored {} personal-zone entries from disk",
                    stats.tracked_domain_count()
                );
            }
            Err(err) => {
                tracing::warn!(
                    "could not restore the persisted personal zone ({err}); \
                     starting empty and moving the file aside"
                );
                rename_orphan(&path);
            }
        }
    }
    let zone = zone_from_stats(&stats, &cfg);
    PersonalZoneInit {
        stats,
        zone,
        flusher: Some((path, key.key)),
    }
}

/// One cycle's work: rotate/republish via `AppState`, then persist the
/// result. Logs (never propagates) a persistence failure — a hiccup here
/// must not take down the service.
fn tick(state: &AppState<ReqwestDohClient>, key: &[u8; 32], path: &Path) {
    if !state.personal_zone_config_snapshot().enabled {
        return;
    }
    let today = DayIndex::from_system_time(SystemTime::now());
    let rotated = state.rotate_and_republish_personal_zone(today);
    if let Err(err) = persist_snapshot(&rotated, key, path) {
        tracing::warn!("personal-zone persistence flush failed: {err}");
    }
}

/// The running task: [`tick`] every [`FLUSH_INTERVAL`] or on
/// [`AppState::wake_personal_zone_refresh`] (an `/admin/reset` config
/// reload), and once more when the shutdown signal fires, then return.
/// Spawned by `orchestrate.rs` only when `[personal_zone]` was on at
/// startup and an app-data directory existed (see [`PersonalZoneInit::flusher`]).
pub(crate) async fn run_personal_zone_task(
    state: Arc<AppState<ReqwestDohClient>>,
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
) {
    let wake = state.personal_zone_refresh_wake_handle();
    let mut shutdown = state.shutdown_handle();
    loop {
        tokio::select! {
            () = tokio::time::sleep(FLUSH_INTERVAL) => {
                tick(&state, &key, &path);
            }
            () = wake.notified() => {
                tick(&state, &key, &path);
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tick(&state, &key, &path);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{load_persisted_personal_zone, persist_snapshot, seed_from_file};
    use crate::config::PersonalZoneConfig;
    use crate::encrypted_file::{open, FileKind};
    use crate::personal_zone_stats::{DayIndex, PersonalZoneStats};
    use std::collections::HashSet;
    use std::time::{Duration, SystemTime};

    fn cfg(enabled: bool) -> PersonalZoneConfig {
        PersonalZoneConfig {
            enabled,
            frequency_window_days: 30,
            frequency_top_n: 200,
            regularity_window_days: 14,
            regularity_min_days: 5,
        }
    }

    // ---- Happy path ----

    #[test]
    fn persist_snapshot_writes_a_file_that_decrypts_back_to_the_same_stats() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("personal-zone.enc");
        let key = [5u8; 32];
        let mut stats = PersonalZoneStats::new(7, DayIndex::from_system_time(SystemTime::now()));
        stats.record_visit(
            "learned.example",
            DayIndex::from_system_time(SystemTime::now()),
        );

        if let Err(err) = persist_snapshot(&stats, &key, &path) {
            panic!("persist_snapshot must succeed: {err}");
        }
        let raw = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("the file must exist: {err}"),
        };
        assert!(
            !raw.windows(b"learned.example".len())
                .any(|w| w == b"learned.example"),
            "the domain must not be readable in the file"
        );
        assert!(
            open(&key, FileKind::PersonalZone, &raw).is_ok(),
            "open must succeed with the same key"
        );
    }

    #[test]
    fn seed_from_file_round_trips_a_persisted_snapshot() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("personal-zone.enc");
        let key = [7u8; 32];
        let today = DayIndex::from_system_time(SystemTime::now());
        let mut stats = PersonalZoneStats::new(7, today);
        stats.record_visit("round-trip.example", today);
        if let Err(err) = persist_snapshot(&stats, &key, &path) {
            panic!("persist_snapshot: {err}");
        }

        let restored = match seed_from_file(&path, &key) {
            Ok(persisted) => PersonalZoneStats::from_persisted(persisted, today, 7),
            Err(err) => panic!("seed_from_file must succeed: {err}"),
        };
        assert_eq!(restored.tracked_domain_count(), 1);
    }

    // This is the one test here that goes through `load_or_create_personal_zone_key`
    // with a real app-data dir - i.e. the real OS credential store, which
    // races under concurrent access from this process even across distinct
    // entries (see key_store's own STORE_TEST_GUARD doc). Every other test
    // in this module either passes `enabled: false` / `app_data: None`
    // (never reaches the store) or supplies its own raw key directly.
    #[test]
    fn a_restart_preserves_a_learned_domain_across_the_day_boundary() {
        let _guard = crate::key_store::STORE_TEST_GUARD.lock();
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let now = SystemTime::now();
        let init = load_persisted_personal_zone(Some(dir.path()), cfg(true), now);
        let Some((path, key)) = init.flusher else {
            panic!("enabled with an app-data dir must yield a flusher");
        };
        let mut stats = init.stats;
        stats.record_visit("restart-me.example", DayIndex::from_system_time(now));
        if let Err(err) = persist_snapshot(&stats, &key, &path) {
            panic!("persist_snapshot: {err}");
        }

        // "Restart" a day later.
        let later = now + Duration::from_hours(25);
        let restored = load_persisted_personal_zone(Some(dir.path()), cfg(true), later);
        assert_eq!(
            restored
                .zone
                .zone_match("restart-me.example", &HashSet::default()),
            Some("restart-me.example"),
            "a domain visited before a restart must still qualify after it"
        );

        // Best-effort cleanup - a leaked test entry is harmless (unique per
        // temp-dir path hash), but tidy up when we can.
        let _ =
            crate::key_store::delete_secret(&crate::key_store::personal_zone_key_entry(dir.path()));
    }

    // ---- Misuse / fool ----

    #[test]
    fn load_persisted_personal_zone_skips_disk_entirely_when_disabled() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let now = SystemTime::now();
        let mut stats = PersonalZoneStats::new(7, DayIndex::from_system_time(now));
        stats.record_visit("x.example", DayIndex::from_system_time(now));
        let path = dir.path().join("personal-zone.enc");
        if let Err(err) = persist_snapshot(&stats, &[1u8; 32], &path) {
            panic!("seed: {err}");
        }
        let init = load_persisted_personal_zone(Some(dir.path()), cfg(false), now);
        assert!(init.zone.is_empty());
        assert!(init.flusher.is_none());
    }

    // ---- Error path ----

    #[test]
    fn load_persisted_personal_zone_with_no_app_data_dir_does_not_panic() {
        let init = load_persisted_personal_zone(None, cfg(true), SystemTime::now());
        assert!(init.zone.is_empty());
        assert!(init.flusher.is_none());
    }
}
