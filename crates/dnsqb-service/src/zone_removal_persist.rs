//! T-108 / Батч 4.5: the background task that keeps `zone-removals.enc` in
//! step with the in-memory `AppState.rating_filter_removed` overlay while
//! `[rating_filter].enabled` is on (SPEC.md §5.3).
//!
//! Sibling of [`crate::log_persist`] / [`crate::cache_persist`] — same
//! serialize→seal→[`crate::paths::write_atomic`] shape, same 60 s + shutdown
//! flush cadence, same orphan-rename recovery via
//! [`crate::log_persist::rename_orphan`]. Two differences worth naming:
//!
//! - **Gate is `[rating_filter].enabled`, not a dedicated persistence flag.**
//!   The overlay is operational state of an already-opted-in feature (which
//!   registrables quorum has already blocked), not new personal-browsing
//!   disclosure — so there is no separate "persist this?" toggle to hand-edit,
//!   unlike `persist_query_log`/`persist_cache`.
//! - **Reuses the existing shared `persistence-key`** (T-96/T-97), not the
//!   new personal-zone key (T-138) — the same privacy-tier reasoning as
//!   above: this store sits alongside the query log and cache, not the
//!   higher-tier personal learned zone.
//!
//! The persisted shape is a plain sorted `Vec<String>` (deduplicated by
//! construction, since it round-trips a `HashSet`) — no bespoke DTO needed,
//! unlike [`crate::persist_dto`]'s `LogEntry` mirror.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::dispatch::AppState;
use crate::encrypted_file::{open, seal, EncryptedFileError, FileKind};
use crate::key_store::load_or_create_persistence_key;
use crate::log_persist::rename_orphan;
use crate::paths::write_atomic;
use crate::upstream::ReqwestDohClient;

/// How often the running persister rewrites the file — same cadence as
/// [`crate::log_persist::run_query_log_persister`] / [`crate::cache_persist::run_cache_persister`].
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// The on-disk file name, under the app-data directory.
const FILE_NAME: &str = "zone-removals.enc";

/// Failure modes of [`persist_snapshot`] — payload-free (no domain names):
/// the `Write` variant's `io::Error` can only name the target *path*.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ZoneRemovalPersistError {
    /// The overlay could not be serialized to JSON (not expected for
    /// `Vec<String>`).
    #[error("failed to serialize the zone-removal overlay: {0}")]
    Serialize(#[source] serde_json::Error),
    /// The plaintext could not be encrypted (a failing OS RNG).
    #[error("failed to encrypt the zone-removal overlay: {0}")]
    Seal(#[source] EncryptedFileError),
    /// The atomic write to `zone-removals.enc` failed.
    #[error("failed to write the encrypted zone-removal overlay to disk: {0}")]
    Write(#[source] std::io::Error),
}

/// Serialize → seal → atomic-write one snapshot of the overlay. The whole
/// file is rewritten each time, mirroring `log_persist::persist_snapshot`.
///
/// # Errors
///
/// [`ZoneRemovalPersistError::Serialize`], [`ZoneRemovalPersistError::Seal`]
/// or [`ZoneRemovalPersistError::Write`] as their doc comments describe.
pub(crate) fn persist_snapshot(
    removed: &HashSet<String>,
    key: &[u8; 32],
    path: &Path,
) -> Result<(), ZoneRemovalPersistError> {
    let mut sorted: Vec<&str> = removed.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let plaintext = serde_json::to_vec(&sorted).map_err(ZoneRemovalPersistError::Serialize)?;
    let sealed =
        seal(key, FileKind::ZoneRemovals, &plaintext).map_err(ZoneRemovalPersistError::Seal)?;
    write_atomic(path, &sealed).map_err(ZoneRemovalPersistError::Write)
}

/// What [`load_persisted_zone_removals`] hands back to `orchestrate.rs`.
pub(crate) struct ZoneRemovalsInit {
    /// The overlay to seed `AppState.rating_filter_removed` with via
    /// [`AppState::restore_rating_filter_removed`] — empty when disabled, no
    /// app-data directory, or no decryptable file existed.
    pub removed: HashSet<String>,
    /// `Some((path, key))` to pass to [`run_zone_removal_persister`] once the
    /// `AppState` exists; `None` when `[rating_filter]` is off at startup or
    /// no key could be obtained this run (persistence still starts, or
    /// stops, correctly on a later toggle only after a restart — same
    /// startup-only wiring as `persist_query_log`/`persist_cache`).
    pub flusher: Option<(PathBuf, Zeroizing<[u8; 32]>)>,
}

/// Why a persisted overlay file could not be restored.
#[derive(Debug, thiserror::Error)]
enum LoadError {
    #[error("could not read the file: {0}")]
    Read(#[source] std::io::Error),
    #[error("{0}")]
    Decrypt(#[source] EncryptedFileError),
    #[error("could not parse the decrypted contents: {0}")]
    Parse(#[source] serde_json::Error),
}

/// Reads, decrypts and parses `path` into the overlay it held.
fn seed_from_file(path: &Path, key: &[u8; 32]) -> Result<HashSet<String>, LoadError> {
    let raw = std::fs::read(path).map_err(LoadError::Read)?;
    let plaintext = open(key, FileKind::ZoneRemovals, &raw).map_err(LoadError::Decrypt)?;
    let list: Vec<String> = serde_json::from_slice(&plaintext).map_err(LoadError::Parse)?;
    Ok(list.into_iter().collect())
}

/// Startup: read `zone-removals.enc` when `[rating_filter].enabled` and a
/// decryptable file exists. A missing key with a file present, or an
/// undecryptable / malformed file, is renamed aside and the overlay starts
/// empty — the overlay is re-derivable (quorum re-blocks the same domain on
/// its next query), so this warns and proceeds rather than aborting startup.
#[must_use]
pub(crate) fn load_persisted_zone_removals(
    app_data: Option<&Path>,
    rating_filter_enabled: bool,
) -> ZoneRemovalsInit {
    if !rating_filter_enabled {
        return ZoneRemovalsInit {
            removed: HashSet::new(),
            flusher: None,
        };
    }
    let Some(dir) = app_data else {
        tracing::warn!(
            "[rating_filter] is enabled but no app-data directory is available; \
             the T-108 removal overlay will not be persisted"
        );
        return ZoneRemovalsInit {
            removed: HashSet::new(),
            flusher: None,
        };
    };
    let path = dir.join(FILE_NAME);
    let ciphertext_present = path.exists();
    let key = match load_or_create_persistence_key(dir, ciphertext_present) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(
                "could not obtain the persistence key ({err}); \
                 the T-108 removal overlay will not be persisted this run"
            );
            return ZoneRemovalsInit {
                removed: HashSet::new(),
                flusher: None,
            };
        }
    };
    let mut removed = HashSet::new();
    if key.orphaned_ciphertext {
        rename_orphan(&path);
    } else if ciphertext_present {
        match seed_from_file(&path, &key.key) {
            Ok(set) => {
                tracing::info!("restored {} zone-removal entries from disk", set.len());
                removed = set;
            }
            Err(err) => {
                tracing::warn!(
                    "could not restore the persisted zone-removal overlay ({err}); \
                     starting empty and moving the file aside"
                );
                rename_orphan(&path);
            }
        }
    }
    ZoneRemovalsInit {
        removed,
        flusher: Some((path, key.key)),
    }
}

/// Rewrites `path` from the live overlay, logging (never propagating) any
/// failure. Also re-checks `[rating_filter].enabled` on every tick (not just
/// at startup) — toggling it off stops new flushes without a restart, the
/// same "re-read the config snapshot each cycle" discipline
/// `topn_updater::refresh_all_lists` already uses.
fn flush_now(state: &AppState<ReqwestDohClient>, key: &[u8; 32], path: &Path) {
    if !state.rating_filter_config_snapshot().enabled {
        return;
    }
    let removed = state.rating_filter_removed_snapshot();
    if let Err(err) = persist_snapshot(removed.as_ref(), key, path) {
        tracing::warn!("zone-removal overlay persistence flush failed: {err}");
    }
}

/// The running persister: flush every [`FLUSH_INTERVAL`], and once more when
/// the shutdown signal fires, then return. Spawned by `orchestrate.rs` only
/// when `[rating_filter]` was on at startup and an app-data directory
/// existed (see [`ZoneRemovalsInit::flusher`]).
pub(crate) async fn run_zone_removal_persister(
    state: Arc<AppState<ReqwestDohClient>>,
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
) {
    let mut shutdown = state.shutdown_handle();
    loop {
        tokio::select! {
            () = tokio::time::sleep(FLUSH_INTERVAL) => {
                flush_now(&state, &key, &path);
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    flush_now(&state, &key, &path);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{load_persisted_zone_removals, persist_snapshot, seed_from_file};
    use crate::encrypted_file::{open, FileKind};
    use std::collections::HashSet;

    fn set(domains: &[&str]) -> HashSet<String> {
        domains.iter().map(|d| (*d).to_string()).collect()
    }

    // ---- Happy path ----

    #[test]
    fn persist_snapshot_writes_a_file_that_decrypts_back_to_the_same_set() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("zone-removals.enc");
        let key = [4u8; 32];
        let removed = set(&["blocked.example", "also-blocked.example"]);

        if let Err(err) = persist_snapshot(&removed, &key, &path) {
            panic!("persist_snapshot must succeed: {err}");
        }

        let raw = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("the file must exist: {err}"),
        };
        assert!(
            !raw.windows(b"blocked.example".len())
                .any(|w| w == b"blocked.example"),
            "the domain must not be readable in the file"
        );

        let plaintext = match open(&key, FileKind::ZoneRemovals, &raw) {
            Ok(bytes) => bytes,
            Err(err) => panic!("open must succeed with the same key: {err}"),
        };
        let back: Vec<String> = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(err) => panic!("from_slice must succeed: {err}"),
        };
        assert_eq!(back.len(), 2);
        assert!(back.contains(&"blocked.example".to_string()));
    }

    #[test]
    fn seed_from_file_round_trips_a_persisted_snapshot() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("zone-removals.enc");
        let key = [6u8; 32];
        let removed = set(&["one.example", "two.example"]);
        if let Err(err) = persist_snapshot(&removed, &key, &path) {
            panic!("persist_snapshot: {err}");
        }

        match seed_from_file(&path, &key) {
            Ok(back) => assert_eq!(back, removed),
            Err(err) => panic!("seed_from_file must succeed: {err}"),
        }
    }

    // ---- Misuse / fool ----

    #[test]
    fn load_persisted_zone_removals_skips_disk_entirely_when_disabled() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        // Seed a file that would decrypt fine, to prove it's never touched.
        let path = dir.path().join("zone-removals.enc");
        if let Err(err) = persist_snapshot(&set(&["x.example"]), &[1u8; 32], &path) {
            panic!("seed: {err}");
        }
        let init = load_persisted_zone_removals(Some(dir.path()), false);
        assert!(init.removed.is_empty());
        assert!(init.flusher.is_none());
    }

    // ---- Error path ----

    #[test]
    fn seed_from_file_rejects_the_wrong_key() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("zone-removals.enc");
        if let Err(err) = persist_snapshot(&set(&["x.example"]), &[2u8; 32], &path) {
            panic!("seed: {err}");
        }
        match seed_from_file(&path, &[3u8; 32]) {
            Err(_) => {}
            Ok(_) => panic!("the wrong key must fail authentication"),
        }
    }

    #[test]
    fn load_persisted_zone_removals_with_no_app_data_dir_does_not_panic() {
        let init = load_persisted_zone_removals(None, true);
        assert!(init.removed.is_empty());
        assert!(init.flusher.is_none());
    }
}
