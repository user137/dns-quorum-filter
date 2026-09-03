//! T-146: the background task that keeps `query-log.enc` in step with the
//! in-memory ring buffer while `persist_query_log` is on (SPEC.md §6).
//!
//! The buffer is snapshotted, serialized ([`crate::persist_dto`]), sealed
//! ([`crate::encrypted_file`]) and written atomically
//! ([`crate::paths::write_atomic`]) on a fixed interval and once more on
//! graceful shutdown. **Not** append-only: a full rewrite each time, so the
//! file's size tracks the bounded window (1000 / 24 h), and a hard crash
//! loses at most one interval's entries — an accepted trade for the
//! simplicity of matching the ring buffer's own snapshot semantics.
//!
//! [`persist_snapshot`] and [`load_persisted_query_log`] are the testable
//! parts; [`run_query_log_persister`] is the thin impure shell wiring the
//! flush to the timer, the live [`AppState`] and the shutdown signal —
//! untested by design, the same split `run_geoip_updater` /
//! `run_reachability_prober` already use.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::dispatch::AppState;
use crate::encrypted_file::{open, seal, EncryptedFileError, FileKind};
use crate::key_store::load_or_create_persistence_key;
use crate::paths::write_atomic;
use crate::persist_dto::{from_json, to_json};
use crate::query_log::{LogEntry, QueryLog};
use crate::upstream::ReqwestDohClient;

/// How often the running persister rewrites the file. A hard crash loses at
/// most this much of the tail (see the module docs).
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Failure modes of [`persist_snapshot`] — payload-free where it matters (no
/// plaintext, no key, no domain names); the `Write` variant's `io::Error`
/// can name the target *path* but never a query domain.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PersistError {
    /// The log snapshot could not be serialized to JSON (not expected for
    /// these field types).
    #[error("failed to serialize the query log: {0}")]
    Serialize(#[source] serde_json::Error),
    /// The plaintext could not be encrypted (a failing OS RNG, or an
    /// implausibly huge log).
    #[error("failed to encrypt the query log: {0}")]
    Seal(#[source] EncryptedFileError),
    /// The atomic write to `query-log.enc` failed.
    #[error("failed to write the encrypted query log to disk: {0}")]
    Write(#[source] std::io::Error),
}

/// Serialize → seal → atomic-write one snapshot of the log. The whole file
/// is rewritten; `entries` is expected to be a
/// [`crate::query_log::QueryLog::snapshot`] result (already age-bounded).
///
/// # Errors
///
/// [`PersistError::Serialize`], [`PersistError::Seal`] or
/// [`PersistError::Write`] as their doc comments describe.
pub(crate) fn persist_snapshot(
    entries: &[LogEntry],
    key: &[u8; 32],
    path: &Path,
) -> Result<(), PersistError> {
    let plaintext = to_json(entries).map_err(PersistError::Serialize)?;
    let sealed = seal(key, FileKind::QueryLog, &plaintext).map_err(PersistError::Seal)?;
    write_atomic(path, &sealed).map_err(PersistError::Write)
}

/// What [`load_persisted_query_log`] hands back to `main.rs`.
pub struct QueryLogInit {
    /// The query log — seeded from `query-log.enc` when persistence was on
    /// and a decryptable file existed, empty otherwise. Hand this to
    /// `AppState::new`.
    pub log: QueryLog,
    /// `Some((path, key))` to pass to [`run_query_log_persister`] once the
    /// `AppState` exists; `None` when persistence is off or no key could be
    /// obtained this run.
    pub flusher: Option<(PathBuf, Zeroizing<[u8; 32]>)>,
}

/// Why a persisted-log file could not be restored.
#[derive(Debug, thiserror::Error)]
enum LoadError {
    #[error("could not read the file: {0}")]
    Read(#[source] std::io::Error),
    #[error("{0}")]
    Decrypt(#[source] EncryptedFileError),
    #[error("could not parse the decrypted contents: {0}")]
    Parse(#[source] serde_json::Error),
}

/// Renames an un-decryptable / malformed persisted file (`query-log.enc`, or
/// `cache.enc` — T-97 reuses this) to `<path>.orphaned-<unix_ts>` so the next
/// flush does not overwrite (and destroy) whatever it held — a key might
/// resurface. Best-effort: a failed rename is logged, not fatal.
pub(crate) fn rename_orphan(path: &Path) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut orphan = path.as_os_str().to_owned();
    orphan.push(format!(".orphaned-{ts}"));
    let orphan = PathBuf::from(orphan);
    match std::fs::rename(path, &orphan) {
        Ok(()) => tracing::warn!("moved an un-decryptable query-log file aside to {orphan:?}"),
        Err(err) => tracing::warn!("could not move the un-decryptable query-log file aside: {err}"),
    }
}

/// Reads, decrypts and parses `path`, seeding `log` with what it held.
/// Returns the entry count on success.
fn seed_from_file(log: &QueryLog, path: &Path, key: &[u8; 32]) -> Result<usize, LoadError> {
    let raw = std::fs::read(path).map_err(LoadError::Read)?;
    let plaintext = open(key, FileKind::QueryLog, &raw).map_err(LoadError::Decrypt)?;
    let entries = from_json(&plaintext).map_err(LoadError::Parse)?;
    let count = entries.len();
    log.restore(entries, SystemTime::now());
    Ok(count)
}

/// Startup: build the query log, seeding it from `query-log.enc` when
/// `persist_query_log` is on and a decryptable file exists. A missing key
/// with a file present, or an undecryptable / malformed file, is renamed
/// aside and the log starts empty — a query log is re-creatable, so this
/// warns and proceeds rather than aborting startup (advisor kickoff #1).
#[must_use]
pub fn load_persisted_query_log(app_data: Option<&Path>, persist_query_log: bool) -> QueryLogInit {
    let log = QueryLog::default();
    if !persist_query_log {
        return QueryLogInit { log, flusher: None };
    }
    let Some(dir) = app_data else {
        tracing::warn!(
            "persist_query_log is set but no app-data directory is available; \
             the query log will not be persisted"
        );
        return QueryLogInit { log, flusher: None };
    };
    let path = dir.join("query-log.enc");
    let ciphertext_present = path.exists();
    let key = match load_or_create_persistence_key(dir, ciphertext_present) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(
                "could not obtain the persistence key ({err}); \
                 the query log will not be persisted this run"
            );
            return QueryLogInit { log, flusher: None };
        }
    };
    if key.orphaned_ciphertext {
        rename_orphan(&path);
    } else if ciphertext_present {
        match seed_from_file(&log, &path, &key.key) {
            Ok(count) => tracing::info!("restored {count} query-log entries from disk"),
            Err(err) => {
                tracing::warn!(
                    "could not restore the persisted query log ({err}); \
                     starting empty and moving the file aside"
                );
                rename_orphan(&path);
            }
        }
    }
    QueryLogInit {
        log,
        flusher: Some((path, key.key)),
    }
}

/// Rewrites `path` from the live log, logging (never propagating) any
/// failure — a persistence hiccup must not take down the service.
fn flush_now(state: &AppState<ReqwestDohClient>, key: &[u8; 32], path: &Path) {
    let entries = state.query_log_snapshot(SystemTime::now());
    if let Err(err) = persist_snapshot(&entries, key, path) {
        tracing::warn!("query-log persistence flush failed: {err}");
    }
}

/// The running persister: flush every [`FLUSH_INTERVAL`], and once more when
/// the shutdown signal fires, then return. Spawned by `main.rs` only when
/// `persist_query_log` is on and an app-data directory exists.
pub async fn run_query_log_persister(
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
    use super::{load_persisted_query_log, persist_snapshot, seed_from_file};
    use crate::encrypted_file::{open, FileKind};
    use crate::persist_dto::from_json;
    use crate::query_log::{Decision, DecisionSource, LogEntry, QueryLog};
    use hickory_proto::rr::RecordType;
    use std::time::SystemTime;

    fn sample() -> LogEntry {
        LogEntry {
            // Recent, so `QueryLog::restore`'s 24 h age bound keeps it.
            timestamp: SystemTime::now(),
            domain: "persisted-example.test".to_string(),
            qtype: RecordType::A,
            decision: Decision::Allowed,
            decision_source: DecisionSource::Quorum,
            voters: Vec::new(),
            geoip_country: None,
            resolved_ip_country: Some("DE".to_string()),
            latency_ms: 7,
        }
    }

    #[test]
    fn persist_snapshot_writes_a_file_that_decrypts_back_to_the_same_entries() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("query-log.enc");
        let key = [3u8; 32];
        let entries = vec![sample()];

        if let Err(err) = persist_snapshot(&entries, &key, &path) {
            panic!("persist_snapshot must succeed: {err}");
        }

        let raw = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("the file must exist: {err}"),
        };
        // Not plaintext on disk.
        assert!(
            !raw.windows(b"persisted-example.test".len())
                .any(|w| w == b"persisted-example.test"),
            "the domain must not be readable in the file"
        );

        let plaintext = match open(&key, FileKind::QueryLog, &raw) {
            Ok(bytes) => bytes,
            Err(err) => panic!("open must succeed with the same key: {err}"),
        };
        let back = match from_json(&plaintext) {
            Ok(v) => v,
            Err(err) => panic!("from_json must succeed: {err}"),
        };
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].domain, "persisted-example.test");
        assert_eq!(back[0].resolved_ip_country.as_deref(), Some("DE"));
    }

    #[test]
    fn persist_snapshot_overwrites_a_previous_file() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("query-log.enc");
        let key = [9u8; 32];

        if let Err(err) = persist_snapshot(&[sample(), sample()], &key, &path) {
            panic!("first write: {err}");
        }
        if let Err(err) = persist_snapshot(&[sample()], &key, &path) {
            panic!("second write: {err}");
        }
        let raw = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("read back: {err}"),
        };
        let plaintext = match open(&key, FileKind::QueryLog, &raw) {
            Ok(bytes) => bytes,
            Err(err) => panic!("open: {err}"),
        };
        match from_json(&plaintext) {
            Ok(v) => assert_eq!(v.len(), 1, "the file reflects only the latest snapshot"),
            Err(err) => panic!("from_json: {err}"),
        }
    }

    #[test]
    fn seed_from_file_round_trips_a_persisted_snapshot_into_a_fresh_log() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("query-log.enc");
        let key = [5u8; 32];
        if let Err(err) = persist_snapshot(&[sample(), sample()], &key, &path) {
            panic!("persist_snapshot: {err}");
        }

        let log = QueryLog::default();
        match seed_from_file(&log, &path, &key) {
            Ok(count) => assert_eq!(count, 2),
            Err(err) => panic!("seed_from_file must succeed: {err}"),
        }
        assert_eq!(log.snapshot(SystemTime::now()).len(), 2);
    }

    #[test]
    fn seed_from_file_errors_on_a_corrupt_file_without_touching_the_log() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("query-log.enc");
        let key = [5u8; 32];
        if let Err(err) = persist_snapshot(&[sample()], &key, &path) {
            panic!("persist_snapshot: {err}");
        }
        // Flip a byte in the ciphertext body.
        let mut raw = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("read: {err}"),
        };
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        if let Err(err) = std::fs::write(&path, &raw) {
            panic!("rewrite: {err}");
        }

        let log = QueryLog::default();
        assert!(seed_from_file(&log, &path, &key).is_err());
        assert!(
            log.snapshot(SystemTime::now()).is_empty(),
            "a failed restore must leave the log empty"
        );
    }

    #[test]
    fn load_persisted_query_log_is_a_no_op_when_disabled() {
        let init = load_persisted_query_log(None, false);
        assert!(init.flusher.is_none());
        assert!(init.log.snapshot(SystemTime::now()).is_empty());
    }

    #[test]
    fn load_persisted_query_log_disables_itself_with_no_app_data_dir() {
        let init = load_persisted_query_log(None, true);
        assert!(
            init.flusher.is_none(),
            "persistence needs an app-data directory"
        );
    }
}
