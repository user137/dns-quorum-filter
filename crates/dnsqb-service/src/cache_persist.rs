//! T-97: the background task that keeps `cache.enc` in step with the live
//! quorum-verdict cache while `persist_cache` is on (SPEC.md §4). Sibling of
//! [`crate::log_persist`]; see [`crate::cache_persist_dto`] for the on-disk
//! shape and why only `Allow` verdicts / still-fresh entries survive a round
//! trip.
//!
//! A full rewrite on a fixed interval and once more on graceful shutdown —
//! **not** append-only, so `cache.enc` tracks the live cache's size and a hard
//! crash loses at most one interval's warming.
//!
//! [`persist_cache_snapshot`] and [`load_persisted_cache`] are the testable
//! parts; [`run_cache_persister`] is the thin impure shell wiring the flush to
//! the timer, the live [`AppState`] and the shutdown signal — untested by the
//! same precedent as `log_persist::run_query_log_persister`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use zeroize::Zeroizing;

use crate::cache::{CacheEntry, CacheKey};
use crate::cache_persist_dto::{from_json, to_json};
use crate::dispatch::AppState;
use crate::encrypted_file::{open, seal, EncryptedFileError, FileKind};
use crate::key_store::load_or_create_persistence_key;
use crate::log_persist::rename_orphan;
use crate::paths::write_atomic;
use crate::upstream::ReqwestDohClient;

/// How often the running persister rewrites the file. A hard crash loses at
/// most this much of the cache's warming.
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Failure modes of [`persist_cache_snapshot`] — payload-free where it matters
/// (no plaintext, no key, no domain names); `Write`'s `io::Error` can name the
/// target *path* but never a cached domain.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PersistError {
    /// The cache snapshot could not be serialized to JSON (not expected for
    /// these field types).
    #[error("failed to serialize the cache: {0}")]
    Serialize(#[source] serde_json::Error),
    /// The plaintext could not be encrypted (a failing OS RNG, or an
    /// implausibly huge cache).
    #[error("failed to encrypt the cache: {0}")]
    Seal(#[source] EncryptedFileError),
    /// The atomic write to `cache.enc` failed.
    #[error("failed to write the encrypted cache to disk: {0}")]
    Write(#[source] std::io::Error),
}

/// Serialize → seal → atomic-write one snapshot of the cache. The whole file
/// is rewritten. `now_wall` / `now_mono` are injected (a real flush passes
/// [`SystemTime::now`] / [`Instant::now`]) so the `Instant` → wall-clock
/// deadline conversion in [`to_json`] is deterministically testable.
///
/// # Errors
///
/// [`PersistError::Serialize`], [`PersistError::Seal`] or [`PersistError::Write`]
/// as their doc comments describe.
pub(crate) fn persist_cache_snapshot(
    snapshot: &[(CacheKey, CacheEntry)],
    key: &[u8; 32],
    path: &Path,
    now_wall: SystemTime,
    now_mono: Instant,
) -> Result<(), PersistError> {
    let plaintext = to_json(snapshot, now_wall, now_mono).map_err(PersistError::Serialize)?;
    let sealed = seal(key, FileKind::Cache, &plaintext).map_err(PersistError::Seal)?;
    write_atomic(path, &sealed).map_err(PersistError::Write)
}

/// What [`load_persisted_cache`] hands back to `main.rs`.
pub struct CacheInit {
    /// Entries decrypted from `cache.enc` (already downtime-adjusted, stale
    /// and `Block` entries dropped), to hand to [`crate::cache::Cache::restore`]
    /// after `AppState::new` builds the cache. Empty when persistence is off
    /// or no usable file existed.
    pub restore: Vec<(CacheKey, CacheEntry)>,
    /// `Some((path, key))` to pass to [`run_cache_persister`] once the
    /// `AppState` exists; `None` when persistence is off or no key could be
    /// obtained this run.
    pub flusher: Option<(PathBuf, Zeroizing<[u8; 32]>)>,
}

/// Why a persisted-cache file could not be restored.
#[derive(Debug, thiserror::Error)]
enum LoadError {
    #[error("could not read the file: {0}")]
    Read(#[source] std::io::Error),
    #[error("{0}")]
    Decrypt(#[source] EncryptedFileError),
    #[error("could not parse the decrypted contents: {0}")]
    Parse(#[source] serde_json::Error),
}

/// Reads, decrypts and parses `path` into live `(key, entry)` pairs against
/// the current wall clock.
fn read_persisted(path: &Path, key: &[u8; 32]) -> Result<Vec<(CacheKey, CacheEntry)>, LoadError> {
    let raw = std::fs::read(path).map_err(LoadError::Read)?;
    let plaintext = open(key, FileKind::Cache, &raw).map_err(LoadError::Decrypt)?;
    from_json(&plaintext, SystemTime::now()).map_err(LoadError::Parse)
}

/// Startup: decrypt `cache.enc` into a set of entries to re-seed the cache
/// with, when `persist_cache` is on and a decryptable file exists. A missing
/// key with a file present, or an undecryptable / malformed file, is renamed
/// aside and the cache starts empty — a cache is re-creatable, so this warns
/// and proceeds rather than aborting startup (same posture as
/// `log_persist::load_persisted_query_log`).
#[must_use]
pub fn load_persisted_cache(app_data: Option<&Path>, persist_cache: bool) -> CacheInit {
    let empty = || CacheInit {
        restore: Vec::new(),
        flusher: None,
    };
    if !persist_cache {
        return empty();
    }
    let Some(dir) = app_data else {
        tracing::warn!(
            "persist_cache is set but no app-data directory is available; \
             the cache will not be persisted"
        );
        return empty();
    };
    let path = dir.join("cache.enc");
    let ciphertext_present = path.exists();
    let key = match load_or_create_persistence_key(dir, ciphertext_present) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(
                "could not obtain the persistence key ({err}); \
                 the cache will not be persisted this run"
            );
            return empty();
        }
    };
    let mut restore = Vec::new();
    if key.orphaned_ciphertext {
        rename_orphan(&path);
    } else if ciphertext_present {
        match read_persisted(&path, &key.key) {
            Ok(entries) => {
                tracing::info!("restored {} cache entries from disk", entries.len());
                restore = entries;
            }
            Err(err) => {
                tracing::warn!(
                    "could not restore the persisted cache ({err}); \
                     starting empty and moving the file aside"
                );
                rename_orphan(&path);
            }
        }
    }
    CacheInit {
        restore,
        flusher: Some((path, key.key)),
    }
}

/// Rewrites `path` from the live cache, logging (never propagating) any
/// failure — a persistence hiccup must not take down the service.
fn flush_now(state: &AppState<ReqwestDohClient>, key: &[u8; 32], path: &Path) {
    let snapshot = state.cache_snapshot();
    if let Err(err) =
        persist_cache_snapshot(&snapshot, key, path, SystemTime::now(), Instant::now())
    {
        tracing::warn!("cache persistence flush failed: {err}");
    }
}

/// The running persister: flush every [`FLUSH_INTERVAL`], and once more when
/// the shutdown signal fires, then return. Spawned by `main.rs` only when
/// `persist_cache` is on and an app-data directory exists.
pub async fn run_cache_persister(
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
                // `changed()` errs only once the sender is dropped; either
                // that or an observed `true` means we are shutting down.
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
    use super::{load_persisted_cache, persist_cache_snapshot, read_persisted};
    use crate::cache::{CacheEntry, CacheKey, Verdict};
    use hickory_proto::rr::RecordType;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant, SystemTime};

    fn sample() -> (CacheKey, CacheEntry) {
        let Ok(key) = CacheKey::new("persisted-cache-example.test", RecordType::A) else {
            panic!("valid fixture domain");
        };
        let entry = CacheEntry::new(
            Verdict::Allow(vec![Ipv4Addr::new(5, 6, 7, 8).into()]),
            Duration::from_secs(600),
        );
        (key, entry)
    }

    #[test]
    fn persist_cache_snapshot_writes_a_file_that_decrypts_back_to_the_same_entries() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("cache.enc");
        let key = [4u8; 32];

        if let Err(err) =
            persist_cache_snapshot(&[sample()], &key, &path, SystemTime::now(), Instant::now())
        {
            panic!("persist_cache_snapshot must succeed: {err}");
        }

        let raw = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("the file must exist: {err}"),
        };
        // Discriminating: the sealed file must not carry the domain in the
        // clear (same shape as
        // `encrypted_file::tests::sealed_bytes_do_not_contain_the_plaintext`).
        let needle = b"persisted-cache-example.test";
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "the cached domain must not be readable in the file"
        );

        let back = match read_persisted(&path, &key) {
            Ok(v) => v,
            Err(err) => panic!("read_persisted must succeed with the same key: {err}"),
        };
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].0.domain(), "persisted-cache-example.test");
        assert!(matches!(&back[0].1.verdict, Verdict::Allow(ips) if ips.len() == 1));
    }

    #[test]
    fn persist_cache_snapshot_overwrites_a_previous_file() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("cache.enc");
        let key = [6u8; 32];

        if let Err(err) = persist_cache_snapshot(
            &[sample(), sample()],
            &key,
            &path,
            SystemTime::now(),
            Instant::now(),
        ) {
            panic!("first write: {err}");
        }
        if let Err(err) =
            persist_cache_snapshot(&[], &key, &path, SystemTime::now(), Instant::now())
        {
            panic!("second write: {err}");
        }
        match read_persisted(&path, &key) {
            Ok(v) => assert!(v.is_empty(), "the file reflects only the latest snapshot"),
            Err(err) => panic!("read_persisted: {err}"),
        }
    }

    #[test]
    fn read_persisted_errors_on_a_corrupt_file() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("cache.enc");
        let key = [6u8; 32];
        if let Err(err) =
            persist_cache_snapshot(&[sample()], &key, &path, SystemTime::now(), Instant::now())
        {
            panic!("persist_cache_snapshot: {err}");
        }
        let mut raw = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("read: {err}"),
        };
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        if let Err(err) = std::fs::write(&path, &raw) {
            panic!("rewrite: {err}");
        }
        assert!(read_persisted(&path, &key).is_err());
    }

    #[test]
    fn load_persisted_cache_is_a_no_op_when_disabled() {
        let init = load_persisted_cache(None, false);
        assert!(init.flusher.is_none());
        assert!(init.restore.is_empty());
    }

    #[test]
    fn load_persisted_cache_disables_itself_with_no_app_data_dir() {
        let init = load_persisted_cache(None, true);
        assert!(
            init.flusher.is_none(),
            "persistence needs an app-data directory"
        );
        assert!(init.restore.is_empty());
    }
}
