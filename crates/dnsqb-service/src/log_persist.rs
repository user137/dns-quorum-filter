//! T-146 / T-291: the encrypted on-disk copy of the query log while
//! `persist_query_log` is on (SPEC.md §6).
//!
//! One file per UTC day, `query-log/d<days-since-epoch>.enc`, each a
//! [`crate::persist_dto`] snapshot of that day's entries, sealed
//! ([`crate::encrypted_file`]) under the `key_store` persistence key and
//! written atomically ([`crate::paths::write_atomic`]). A flush rewrites only
//! the days that received entries since the previous one — normally just
//! today, so a 30-day window costs one day's file per flush, not the whole
//! history (T-146's single `query-log.enc` was rewritten whole every 60 s,
//! fine at 1000 entries, ~23 MB per flush at 30 days). Days that fell out of
//! the window are deleted by filename. A hard crash loses at most one flush
//! interval.
//!
//! Safety rules this module is built around (T-291 advisor review):
//! - **Never overwrite history this process has not taken in.** Until the
//!   existing files were restored into memory (or moved aside as
//!   undecryptable) nothing is written — else enabling persistence at
//!   runtime, or a key that failed to load at startup and loaded later,
//!   would replace a day file with only what memory holds.
//! - **Clearing the log erases the disk copy in the same locked step** —
//!   `AppState`'s io lock serialises every [`QueryLogDisk`] call, so a flush
//!   that read the policy before a clear cannot write afterwards and bring
//!   "cleared" history back at the next start.
//! - **Erasure failures are returned, never swallowed** — the caller reports
//!   them to the user on the action itself.
//!
//! [`QueryLogDisk`] and [`load_persisted_query_log`] are the testable parts;
//! [`run_query_log_persister`] is the thin impure timer shell.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::dispatch::AppState;
use crate::encrypted_file::{open, seal, EncryptedFileError, FileKind};
use crate::key_store::{load_or_create_persistence_key, KeyStoreError};
use crate::paths::write_atomic;
use crate::persist_dto::{from_json, to_json};
use crate::query_log::{LogEntry, LogRetention, QueryLog, QueryLogPolicy};
use crate::upstream::ReqwestDohClient;

/// How often the running persister flushes. A hard crash loses at most this
/// much of the tail (see the module docs).
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// The per-day segment directory, under the app-data directory.
const SEGMENT_DIR: &str = "query-log";

/// T-146's single-file format — migrated into segments once, then deleted.
const LEGACY_FILE: &str = "query-log.enc";

/// Present while an erase has not finished: the next flush (or start)
/// finishes it before writing or restoring anything, so a failed clear can
/// never be undone by a later flush or a reboot.
const ERASE_MARKER: &str = "query-log.erase-pending";

const SECS_PER_DAY: u64 = 86_400;

/// Days since the Unix epoch (UTC) — a segment's name. A pre-epoch clock
/// maps to day 0 rather than failing.
#[must_use]
pub(crate) fn utc_day(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() / SECS_PER_DAY)
}

fn segment_name(day: u64) -> String {
    format!("d{day}.enc")
}

/// Strict `d<digits>.enc` — anything else in the directory (a
/// `write_atomic` `.tmp` leftover, an `.orphaned-<ts>` file) is not a
/// segment and is never read or pruned.
fn parse_segment_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix('d')?.strip_suffix(".enc")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Every well-formed segment in `dir`, oldest day first. A missing directory
/// is an empty list.
fn list_segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut segments = Vec::new();
    for entry in read_dir {
        let entry = entry?;
        if let Some(day) = entry.file_name().to_str().and_then(parse_segment_name) {
            segments.push((day, entry.path()));
        }
    }
    segments.sort_unstable_by_key(|(day, _)| *day);
    Ok(segments)
}

/// A query-history file loose in the app-data root besides the legacy file:
/// one moved aside (`query-log*.orphaned-*`) or a legacy `write_atomic`
/// temp file left by a crash. Both are encrypted browsing history.
fn is_loose_history(name: &str) -> bool {
    name.starts_with("query-log")
        && (name.contains(".orphaned-") || name == concat!("query-log.enc", ".tmp"))
}

/// Whether any persisted query history exists under `app_data`: the legacy
/// file, anything in the segment directory, or a loose history file.
fn history_present(app_data: &Path) -> io::Result<bool> {
    if app_data.join(LEGACY_FILE).try_exists()? {
        return Ok(true);
    }
    match std::fs::read_dir(app_data.join(SEGMENT_DIR)) {
        Ok(mut read_dir) => {
            if read_dir.next().is_some() {
                return Ok(true);
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let read_dir = match std::fs::read_dir(app_data) {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    for entry in read_dir {
        if entry?.file_name().to_str().is_some_and(is_loose_history) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `remove_file`, treating "already gone" as success.
fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

/// The first day still inside `retention`'s window at `now`.
fn oldest_kept_day(retention: LogRetention, now: SystemTime) -> u64 {
    now.checked_sub(retention.max_age()).map_or(0, utc_day)
}

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
    /// The atomic write failed.
    #[error("failed to write the encrypted query log to disk: {0}")]
    Write(#[source] io::Error),
}

/// Serialize → seal → atomic-write `entries` to `path`, replacing it.
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

/// Why a persisted-log file could not be restored.
#[derive(Debug, thiserror::Error)]
enum LoadError {
    #[error("could not read the file: {0}")]
    Read(#[source] io::Error),
    #[error("{0}")]
    Decrypt(#[source] EncryptedFileError),
    #[error("could not parse the decrypted contents: {0}")]
    Parse(#[source] serde_json::Error),
}

/// Reads, decrypts and parses one persisted file.
fn read_entries(path: &Path, key: &[u8; 32]) -> Result<Vec<LogEntry>, LoadError> {
    let raw = std::fs::read(path).map_err(LoadError::Read)?;
    let plaintext = open(key, FileKind::QueryLog, &raw).map_err(LoadError::Decrypt)?;
    from_json(&plaintext).map_err(LoadError::Parse)
}

/// One file for [`QueryLogDisk::adopt`]: its entries; `None` when it does
/// not decrypt or parse and was moved aside (the rest still load). A read
/// error, or a move-aside that fails, aborts the adoption instead: the file
/// may be fine, and adopting without it would let the next flush overwrite
/// it.
fn read_or_move_aside(path: &Path, key: &[u8; 32]) -> Result<Option<Vec<LogEntry>>, DiskError> {
    match read_entries(path, key) {
        Ok(entries) => Ok(Some(entries)),
        Err(LoadError::Read(err)) => Err(DiskError::Io(err)),
        Err(err) => {
            tracing::warn!("could not restore a query-log file ({err}); moving it aside");
            move_aside(path).map_err(DiskError::Io)?;
            Ok(None)
        }
    }
}

/// Why a flush or adoption failed — reported as `query_log_disk: FAILED`.
#[derive(Debug, thiserror::Error)]
enum DiskError {
    #[error("no app-data directory is available")]
    NoAppData,
    #[error("could not obtain the persistence key: {0}")]
    Key(#[source] KeyStoreError),
    #[error("{0}")]
    Io(#[source] io::Error),
    #[error("{0}")]
    Persist(#[source] PersistError),
}

/// Renames an un-decryptable / malformed persisted file (a query-log
/// segment, `cache.enc` — T-97 reuses this) to `<path>.orphaned-<unix_ts>`
/// so the next flush does not overwrite (and destroy) whatever it held — a
/// key might resurface. Best-effort: a failed rename is logged, not fatal.
pub(crate) fn rename_orphan(path: &Path) {
    match move_aside(path) {
        Ok(orphan) => tracing::warn!("moved an un-decryptable persisted file aside to {orphan:?}"),
        Err(err) => tracing::warn!("could not move the un-decryptable persisted file aside: {err}"),
    }
}

/// Renames `path` (a file or a directory) to `<path>.orphaned-<unix_ts>` and
/// returns the new path. Shared by [`rename_orphan`] and the хвиля 13b
/// config reset.
pub(crate) fn move_aside(path: &Path) -> io::Result<PathBuf> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut orphan = path.as_os_str().to_owned();
    orphan.push(format!(".orphaned-{ts}"));
    let orphan = PathBuf::from(orphan);
    std::fs::rename(path, &orphan)?;
    Ok(orphan)
}

/// What the `/admin/ui` log card shows about the disk copy (T-291) — the
/// `persisted: false` pattern for this store: a failure is visible, never a
/// silent "7 days" that does not survive a reboot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiskHealth {
    /// The last flush, key fetch or erase failed.
    pub failed: bool,
    /// Persistence is off but history from an earlier run is still on disk.
    pub leftover: bool,
}

/// The query log's disk copy and what this process knows about it. Lives
/// behind `AppState`'s io lock; every method assumes that lock is held.
pub struct QueryLogDisk {
    app_data: Option<PathBuf>,
    key: Option<Zeroizing<[u8; 32]>>,
    /// The files on disk were restored into memory or moved aside — writing
    /// is safe. See the module docs' first rule.
    adopted: bool,
    /// [`QueryLog::next_seq`] at the last successful flush: entries at or
    /// above it are not on disk yet.
    synced_seq: u64,
    /// Days to rewrite on the next flush whatever arrived — set when
    /// history was merged in at runtime or migrated from the legacy file.
    pending_days: BTreeSet<u64>,
    /// The legacy `query-log.enc` was restored; delete it once its days are
    /// written as segments.
    legacy_pending: bool,
    /// An erase failed part-way: retried before any flush writes or
    /// restores anything (also recorded on disk as [`ERASE_MARKER`]).
    erase_pending: bool,
    health: DiskHealth,
}

impl std::fmt::Debug for QueryLogDisk {
    /// Never prints the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryLogDisk")
            .field("app_data", &self.app_data)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .field("adopted", &self.adopted)
            .field("health", &self.health)
            .finish_non_exhaustive()
    }
}

impl QueryLogDisk {
    /// A disk copy nothing has been read from yet (persistence off, or
    /// before [`load_persisted_query_log`] ran).
    #[must_use]
    pub fn detached(app_data: Option<PathBuf>) -> Self {
        Self {
            app_data,
            key: None,
            adopted: false,
            synced_seq: 0,
            pending_days: BTreeSet::new(),
            legacy_pending: false,
            erase_pending: false,
            health: DiskHealth::default(),
        }
    }

    /// Test constructor with a fixed key — no OS credential store involved.
    #[cfg(test)]
    fn with_key(app_data: &Path, key: [u8; 32]) -> Self {
        Self {
            key: Some(Zeroizing::new(key)),
            ..Self::detached(Some(app_data.to_path_buf()))
        }
    }

    /// The current health for the status view.
    #[must_use]
    pub fn health(&self) -> DiskHealth {
        self.health
    }

    /// Obtains the persistence key once. When none was stored but history
    /// files exist (the key store was cleared), those files can never be
    /// decrypted: they are moved aside, not overwritten — the T-146
    /// orphan rule, kept for a runtime switch-on too. Cheap (no history
    /// read), so the policy route calls it to report a key failure at once.
    fn ensure_key(&mut self) -> Result<&[u8; 32], DiskError> {
        if self.key.is_none() {
            let dir = self.app_data.as_deref().ok_or(DiskError::NoAppData)?;
            let present = history_present(dir).map_err(DiskError::Io)?;
            let loaded = load_or_create_persistence_key(dir, present).map_err(DiskError::Key)?;
            self.key = Some(loaded.key);
            if loaded.orphaned_ciphertext {
                // Not adopted until every file is really out of the way: a
                // file left under its name would be overwritten by the next
                // flush. If a move fails, the next adoption meets the file
                // under the new key, fails to decrypt it and retries.
                for path in [dir.join(SEGMENT_DIR), dir.join(LEGACY_FILE)] {
                    if path.exists() {
                        let orphan = move_aside(&path).map_err(DiskError::Io)?;
                        tracing::warn!("moved query history without its key aside to {orphan:?}");
                    }
                }
                self.adopted = true;
            }
        }
        self.key.as_deref().ok_or(DiskError::NoAppData)
    }

    /// [`Self::ensure_key`] for the policy route, recording a failure in
    /// [`Self::health`].
    pub fn prepare(&mut self) {
        if self.retry_erase().is_err() {
            return;
        }
        let failed = self.ensure_key().is_err();
        self.health.failed = failed;
    }

    /// Finishes an earlier erase that failed part-way, if any. While it
    /// keeps failing nothing may be written or restored: the files it left
    /// are history the user already cleared.
    fn retry_erase(&mut self) -> io::Result<()> {
        if !self.erase_pending {
            return Ok(());
        }
        let outcome = self.erase();
        if let Err(err) = &outcome {
            tracing::warn!("query-log erase still incomplete: {err}");
        }
        outcome
    }

    /// Restores every readable file inside `retention`'s window into `log`
    /// (merging with whatever it already holds) and marks the disk adopted.
    /// A file that does not decrypt or parse is moved aside, the rest still
    /// load. Returns how many entries were restored.
    fn adopt(
        &mut self,
        log: &QueryLog,
        retention: LogRetention,
        now: SystemTime,
    ) -> Result<usize, DiskError> {
        let key = Zeroizing::new(*self.ensure_key()?);
        if self.adopted {
            return Ok(0);
        }
        let dir = self.app_data.clone().ok_or(DiskError::NoAppData)?;
        // Memory may already hold entries the disk does not (persistence was
        // off until now): their days must be rewritten to include them.
        let live_days = log.keys_since(0, |entry| utc_day(entry.timestamp));
        let oldest = oldest_kept_day(retention, now);
        let mut restored = Vec::new();
        let segments = list_segments(&dir.join(SEGMENT_DIR)).map_err(DiskError::Io)?;
        let segment_days: BTreeSet<u64> = segments.iter().map(|(day, _)| *day).collect();
        for (day, path) in segments {
            if day < oldest {
                continue;
            }
            if let Some(entries) = read_or_move_aside(&path, &key)? {
                restored.extend(entries);
            }
        }
        let legacy = dir.join(LEGACY_FILE);
        let mut legacy_days = BTreeSet::new();
        if legacy.exists() {
            if let Some(entries) = read_or_move_aside(&legacy, &key)? {
                // A migration interrupted after writing some days: those
                // days already hold these entries.
                let unmigrated = entries
                    .into_iter()
                    .filter(|e| !segment_days.contains(&utc_day(e.timestamp)));
                for entry in unmigrated {
                    legacy_days.insert(utc_day(entry.timestamp));
                    restored.push(entry);
                }
                self.legacy_pending = true;
            }
        }
        let count = restored.len();
        log.restore(restored, now);
        self.synced_seq = log.next_seq();
        self.pending_days.extend(live_days);
        self.pending_days.extend(legacy_days);
        self.adopted = true;
        Ok(count)
    }

    /// One flush (see the module docs). A no-op while `policy.persist` is
    /// off. Records the outcome in [`Self::health`].
    pub fn flush(&mut self, log: &QueryLog, policy: QueryLogPolicy, now: SystemTime) {
        if self.retry_erase().is_err() || !policy.persist {
            return;
        }
        let outcome = self.try_flush(log, policy.retention, now);
        if let Err(err) = &outcome {
            tracing::warn!("query-log persistence flush failed: {err}");
        }
        self.health = DiskHealth {
            failed: outcome.is_err(),
            leftover: false,
        };
    }

    fn try_flush(
        &mut self,
        log: &QueryLog,
        retention: LogRetention,
        now: SystemTime,
    ) -> Result<(), DiskError> {
        self.adopt(log, retention, now)?;
        let key = Zeroizing::new(*self.ensure_key()?);
        let dir = self.app_data.clone().ok_or(DiskError::NoAppData)?;
        let segments = dir.join(SEGMENT_DIR);
        // Read before scanning: an entry pushed during the writes below is
        // at or above `mark`, so the next flush writes it again.
        let mark = log.next_seq();
        let mut days = log.keys_since(self.synced_seq, |entry| utc_day(entry.timestamp));
        days.extend(self.pending_days.iter().copied());
        let oldest = oldest_kept_day(retention, now);
        if !days.is_empty() {
            std::fs::create_dir_all(&segments).map_err(DiskError::Io)?;
        }
        for day in days.into_iter().filter(|day| *day >= oldest) {
            let entries = log.entries_matching(now, |entry| utc_day(entry.timestamp) == day);
            let path = segments.join(segment_name(day));
            if entries.is_empty() {
                remove_file_if_present(&path).map_err(DiskError::Io)?;
            } else {
                persist_snapshot(&entries, &key, &path).map_err(DiskError::Persist)?;
            }
        }
        self.pending_days.clear();
        self.synced_seq = mark;
        if self.legacy_pending {
            remove_file_if_present(&dir.join(LEGACY_FILE)).map_err(DiskError::Io)?;
            self.legacy_pending = false;
        }
        for (day, path) in list_segments(&segments).map_err(DiskError::Io)? {
            if day < oldest {
                remove_file_if_present(&path).map_err(DiskError::Io)?;
            }
        }
        Ok(())
    }

    /// Deletes every persisted copy of the query history: the segment
    /// directory, the legacy file and any `query-log*.orphaned-*` file or
    /// directory moved aside earlier. Memory is the caller's to clear (or
    /// keep). Whatever memory still holds is written again by the next flush
    /// if persistence is (re-)enabled.
    ///
    /// # Errors
    ///
    /// The first filesystem error; already-missing items are not errors.
    /// The failure is also recorded in [`Self::health`].
    pub fn erase(&mut self) -> io::Result<()> {
        let outcome = self.erase_with_marker();
        self.erase_pending = outcome.is_err();
        self.health = DiskHealth {
            failed: outcome.is_err(),
            leftover: outcome.is_err() && self.health.leftover,
        };
        outcome
    }

    /// The marker goes down first and comes off last, so an erase cut short
    /// by a failure or a crash is finished at the next start.
    fn erase_with_marker(&mut self) -> io::Result<()> {
        let Some(dir) = self.app_data.clone() else {
            return Ok(());
        };
        let marker = dir.join(ERASE_MARKER);
        if let Err(err) = std::fs::write(&marker, b"") {
            // Without the marker the erase still runs; only the
            // finish-at-next-start guarantee is lost, and an erase that
            // also fails stays retried in memory.
            tracing::warn!("could not record a pending query-log erase: {err}");
        }
        self.try_erase()?;
        remove_file_if_present(&marker)
    }

    fn try_erase(&mut self) -> io::Result<()> {
        let Some(dir) = self.app_data.clone() else {
            return Ok(());
        };
        match std::fs::remove_dir_all(dir.join(SEGMENT_DIR)) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
            _ => {}
        }
        remove_file_if_present(&dir.join(LEGACY_FILE))?;
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };
        for entry in read_dir {
            let entry = entry?;
            if !entry.file_name().to_str().is_some_and(is_loose_history) {
                continue;
            }
            if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(entry.path())?;
            } else {
                remove_file_if_present(&entry.path())?;
            }
        }
        // Nothing left on disk to protect; memory's days are rewritten from
        // scratch if persistence is on.
        self.adopted = true;
        self.synced_seq = 0;
        self.pending_days.clear();
        self.legacy_pending = false;
        Ok(())
    }
}

/// What [`load_persisted_query_log`] hands back to `orchestrate::run`.
pub struct QueryLogInit {
    /// The query log, bounded by the configured retention and seeded from
    /// disk when persistence is on. Hand this to `AppState::new`.
    pub log: QueryLog,
    /// The disk copy's state — install it with
    /// `AppState::install_query_log_disk` once the state exists.
    pub disk: QueryLogDisk,
}

/// Startup: build the query log **with the configured retention first** (a
/// 24 h default here would drop restored 3–30 day history on every boot),
/// then restore every readable day file when persistence is on. A missing
/// key with files present, or an undecryptable file, is moved aside and the
/// rest still loads — a query log is re-creatable, so this warns and
/// proceeds rather than aborting startup.
#[must_use]
pub fn load_persisted_query_log(app_data: Option<&Path>, policy: QueryLogPolicy) -> QueryLogInit {
    let log = QueryLog::with_retention(policy.retention);
    let mut disk = QueryLogDisk::detached(app_data.map(Path::to_path_buf));
    let Some(dir) = app_data else {
        if policy.persist {
            tracing::warn!(
                "persist_query_log is set but no app-data directory is available; \
                 the query log will not be persisted"
            );
            disk.health.failed = true;
        }
        return QueryLogInit { log, disk };
    };
    if dir.join(ERASE_MARKER).exists() {
        disk.erase_pending = true;
        if let Err(err) = disk.retry_erase() {
            tracing::warn!("a pending query-log erase could not be finished at start: {err}");
            return QueryLogInit { log, disk };
        }
    }
    if !policy.persist {
        disk.health.leftover = match history_present(dir) {
            Ok(present) => present,
            Err(err) => {
                tracing::warn!("could not check for a leftover query-log history: {err}");
                false
            }
        };
        return QueryLogInit { log, disk };
    }
    match disk.adopt(&log, policy.retention, SystemTime::now()) {
        Ok(count) => tracing::info!("restored {count} query-log entries from disk"),
        Err(err) => {
            tracing::warn!("could not restore the persisted query log ({err}); starting empty");
            disk.health.failed = true;
        }
    }
    QueryLogInit { log, disk }
}

/// The running persister: flush every [`FLUSH_INTERVAL`] or when woken (a
/// policy change), and once more on shutdown. Always spawned when an
/// app-data directory exists — a flush is a no-op while persistence is off,
/// so switching it on needs no restart. Each flush runs on a blocking
/// thread (file I/O under the io lock).
pub async fn run_query_log_persister(state: Arc<AppState<ReqwestDohClient>>) {
    let mut shutdown = state.shutdown_handle();
    let wake = state.query_log_flush_wake();
    loop {
        tokio::select! {
            () = tokio::time::sleep(FLUSH_INTERVAL) => flush_blocking(&state).await,
            () = wake.notified() => flush_blocking(&state).await,
            changed = shutdown.changed() => {
                // `changed()` errs only once the sender is dropped; either
                // that or an observed `true` means we are shutting down.
                if changed.is_err() || *shutdown.borrow() {
                    flush_blocking(&state).await;
                    return;
                }
            }
        }
    }
}

async fn flush_blocking(state: &Arc<AppState<ReqwestDohClient>>) {
    let state = Arc::clone(state);
    if let Err(err) = tokio::task::spawn_blocking(move || state.flush_query_log()).await {
        tracing::warn!("query-log flush task failed: {err}");
    }
}

/// ARCH-11 (б) check shared by the four persisters' loader tests: nothing is
/// left at `path`, and exactly one `<file>.orphaned-*` sibling still holds
/// `bytes` — the un-loadable file was moved aside, never overwritten.
#[cfg(test)]
pub(crate) fn assert_moved_aside_intact(path: &Path, bytes: &[u8]) {
    assert!(!path.exists(), "the original file must be moved away");
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        panic!("path must have a parent and a file name");
    };
    let prefix = format!("{}.orphaned-", name.to_string_lossy());
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        panic!("must be able to list {dir:?}");
    };
    let orphans: Vec<PathBuf> = read_dir
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(&prefix))
        })
        .collect();
    let [orphan] = orphans.as_slice() else {
        panic!("expected exactly one orphan, found {orphans:?}");
    };
    let Ok(kept) = std::fs::read(orphan) else {
        panic!("must be able to read {orphan:?}");
    };
    assert_eq!(kept, bytes, "the orphan must hold the original bytes");
}

#[cfg(test)]
mod tests {
    use super::{
        list_segments, load_persisted_query_log, parse_segment_name, persist_snapshot,
        read_entries, segment_name, utc_day, QueryLogDisk, ERASE_MARKER, LEGACY_FILE, SEGMENT_DIR,
    };
    use crate::encrypted_file::{open, FileKind};
    use crate::persist_dto::from_json;
    use crate::query_log::{
        Decision, DecisionSource, LogEntry, LogRetention, QueryLog, QueryLogPolicy,
    };
    use hickory_proto::rr::RecordType;
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const KEY: [u8; 32] = [3u8; 32];

    fn entry(domain: &str, timestamp: SystemTime) -> LogEntry {
        LogEntry {
            timestamp,
            domain: domain.to_string(),
            qtype: RecordType::A,
            decision: Decision::Allowed,
            decision_source: DecisionSource::Quorum,
            voters: Vec::new(),
            geoip_country: None,
            resolved_ip_country: Some("DE".to_string()),
            latency_ms: 7,
        }
    }

    fn sample() -> LogEntry {
        entry("persisted-example.test", SystemTime::now())
    }

    fn ago(now: SystemTime, hours: u64) -> SystemTime {
        let Some(at) = now.checked_sub(Duration::from_hours(hours)) else {
            panic!("valid fixture timestamp");
        };
        at
    }

    fn on(retention: LogRetention) -> QueryLogPolicy {
        QueryLogPolicy {
            retention,
            persist: true,
        }
    }

    fn tempdir() -> tempfile::TempDir {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        dir
    }

    fn segment_days(dir: &Path) -> Vec<u64> {
        match list_segments(&dir.join(SEGMENT_DIR)) {
            Ok(list) => list.into_iter().map(|(day, _)| day).collect(),
            Err(err) => panic!("list: {err}"),
        }
    }

    fn domains_in_day(dir: &Path, day: u64) -> Vec<String> {
        let path = dir.join(SEGMENT_DIR).join(segment_name(day));
        match read_entries(&path, &KEY) {
            Ok(entries) => entries.into_iter().map(|e| e.domain).collect(),
            Err(err) => panic!("read {path:?}: {err}"),
        }
    }

    /// A fresh process: new log, new disk, files adopted from `dir`.
    fn restart(dir: &Path, retention: LogRetention, now: SystemTime) -> (QueryLog, QueryLogDisk) {
        let log = QueryLog::with_retention(retention);
        let mut disk = QueryLogDisk::with_key(dir, KEY);
        if let Err(err) = disk.adopt(&log, retention, now) {
            panic!("adopt: {err}");
        }
        (log, disk)
    }

    fn names(log: &QueryLog, now: SystemTime) -> Vec<String> {
        log.snapshot(now).into_iter().map(|e| e.domain).collect()
    }

    // ---- Happy path ----

    #[test]
    fn persist_snapshot_writes_a_file_that_decrypts_back_to_the_same_entries() {
        let dir = tempdir();
        let path = dir.path().join("x.enc");
        if let Err(err) = persist_snapshot(&[sample()], &KEY, &path) {
            panic!("persist_snapshot must succeed: {err}");
        }
        let raw = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("the file must exist: {err}"),
        };
        assert!(
            !raw.windows(b"persisted-example.test".len())
                .any(|w| w == b"persisted-example.test"),
            "the domain must not be readable in the file"
        );
        let plaintext = match open(&KEY, FileKind::QueryLog, &raw) {
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
    fn a_flush_writes_one_file_per_day_and_a_restart_reads_them_back() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::with_retention(LogRetention::SevenDays);
        log.push(entry("three-days.example", ago(now, 72)));
        log.push(entry("today.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::SevenDays), now);
        assert!(!disk.health().failed);
        assert_eq!(
            segment_days(dir.path()),
            vec![utc_day(ago(now, 72)), utc_day(now)]
        );

        let (back, _) = restart(dir.path(), LogRetention::SevenDays, now);
        assert_eq!(
            names(&back, now),
            vec!["three-days.example", "today.example"]
        );
    }

    #[test]
    fn a_flush_rewrites_only_days_that_got_new_entries() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::with_retention(LogRetention::SevenDays);
        log.push(entry("old.example", ago(now, 72)));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::SevenDays), now);
        let old_day = dir
            .path()
            .join(SEGMENT_DIR)
            .join(segment_name(utc_day(ago(now, 72))));
        if let Err(err) = std::fs::remove_file(&old_day) {
            panic!("remove: {err}");
        }

        log.push(entry("new.example", now));
        disk.flush(&log, on(LogRetention::SevenDays), now);

        assert!(!old_day.exists(), "an untouched day is not rewritten");
        assert_eq!(
            domains_in_day(dir.path(), utc_day(now)),
            vec!["new.example"]
        );
    }

    #[test]
    fn nothing_is_written_while_persistence_is_off() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::default();
        log.push(entry("a.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(
            &log,
            QueryLogPolicy {
                retention: LogRetention::Day,
                persist: false,
            },
            now,
        );
        assert!(!dir.path().join(SEGMENT_DIR).exists());
    }

    #[test]
    fn a_seven_day_window_survives_a_restart_and_a_day_window_drops_older_files() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::with_retention(LogRetention::SevenDays);
        log.push(entry("three-days.example", ago(now, 72)));
        log.push(entry("today.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::SevenDays), now);

        let (back, mut disk) = restart(dir.path(), LogRetention::Day, now);
        assert_eq!(names(&back, now), vec!["today.example"]);
        disk.flush(&back, on(LogRetention::Day), now);
        assert!(
            !segment_days(dir.path()).contains(&utc_day(ago(now, 72))),
            "a day outside the window is pruned"
        );
    }

    #[test]
    fn the_legacy_single_file_is_migrated_then_deleted() {
        let dir = tempdir();
        let now = SystemTime::now();
        let legacy = dir.path().join(LEGACY_FILE);
        if let Err(err) = persist_snapshot(&[entry("legacy.example", now)], &KEY, &legacy) {
            panic!("seed: {err}");
        }
        let (log, mut disk) = restart(dir.path(), LogRetention::Day, now);
        assert_eq!(names(&log, now), vec!["legacy.example"]);
        assert!(legacy.exists(), "kept until its days are written");

        disk.flush(&log, on(LogRetention::Day), now);
        assert!(!legacy.exists());
        assert_eq!(
            domains_in_day(dir.path(), utc_day(now)),
            vec!["legacy.example"]
        );
    }

    // ---- Security & boundary ----

    #[test]
    fn segment_names_are_parsed_strictly() {
        assert_eq!(parse_segment_name("d20000.enc"), Some(20000));
        assert_eq!(parse_segment_name(&segment_name(7)), Some(7));
        for bad in [
            "d.enc",
            "d1.enc.tmp",
            "d1.enc.orphaned-5",
            "x1.enc",
            "d-1.enc",
            "d1a.enc",
            "d+1.enc",
            "d1.ENC",
            "d99999999999999999999999.enc",
        ] {
            assert_eq!(parse_segment_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn utc_day_counts_whole_days_and_clamps_before_the_epoch() {
        assert_eq!(utc_day(SystemTime::UNIX_EPOCH), 0);
        assert_eq!(
            utc_day(SystemTime::UNIX_EPOCH + Duration::from_secs(86_399)),
            0
        );
        assert_eq!(
            utc_day(SystemTime::UNIX_EPOCH + Duration::from_hours(24)),
            1
        );
        let before = SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(5));
        assert_eq!(before.map(utc_day), Some(0));
    }

    // ---- Misuse: history that is not ours yet is never overwritten ----

    #[test]
    fn switching_persistence_on_at_runtime_merges_existing_day_files() {
        let dir = tempdir();
        // Both entries must share a UTC day even when the test runs just after
        // midnight UTC, so the earlier one is a minute back from a `now` held at
        // least two minutes into the day.
        let real = SystemTime::now();
        let day_start = UNIX_EPOCH + Duration::from_hours(24 * utc_day(real));
        let now = real.max(day_start + Duration::from_mins(2));
        // An earlier run left today's file.
        let earlier = QueryLog::default();
        earlier.push(entry("from-disk.example", now - Duration::from_mins(1)));
        let mut first = QueryLogDisk::with_key(dir.path(), KEY);
        first.flush(&earlier, on(LogRetention::Day), now);

        // This run started with persistence off, then the user turned it on.
        let log = QueryLog::default();
        log.push(entry("live.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::Day), now);

        assert_eq!(
            domains_in_day(dir.path(), utc_day(now)),
            vec!["from-disk.example", "live.example"]
        );
        assert_eq!(names(&log, now), vec!["from-disk.example", "live.example"]);
    }

    #[test]
    fn a_failed_adoption_writes_nothing() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::default();
        log.push(entry("live.example", now));
        // No key available and no app-data dir: adoption cannot happen.
        let mut disk = QueryLogDisk::detached(None);
        disk.flush(&log, on(LogRetention::Day), now);
        assert!(disk.health().failed);
        assert!(!dir.path().join(SEGMENT_DIR).exists());
    }

    // ---- Error path ----

    #[test]
    fn a_corrupt_day_file_is_moved_aside_and_the_rest_still_load() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::with_retention(LogRetention::SevenDays);
        log.push(entry("old.example", ago(now, 72)));
        log.push(entry("today.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::SevenDays), now);
        let bad = dir
            .path()
            .join(SEGMENT_DIR)
            .join(segment_name(utc_day(ago(now, 72))));
        if let Err(err) = std::fs::write(&bad, b"not a DQF1 file") {
            panic!("corrupt: {err}");
        }

        let (back, _) = restart(dir.path(), LogRetention::SevenDays, now);
        assert_eq!(names(&back, now), vec!["today.example"]);
        crate::log_persist::assert_moved_aside_intact(&bad, b"not a DQF1 file");
    }

    #[test]
    fn erase_removes_every_copy_and_nothing_else() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::default();
        log.push(entry("a.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::Day), now);
        let write = |name: &str| {
            if let Err(err) = std::fs::write(dir.path().join(name), b"x") {
                panic!("seed {name}: {err}");
            }
        };
        write(LEGACY_FILE);
        write("query-log.enc.tmp");
        write("query-log.enc.orphaned-1");
        write("resolver_config.toml");
        write("cache.enc");
        if let Err(err) = std::fs::create_dir(dir.path().join("query-log.orphaned-2")) {
            panic!("seed dir: {err}");
        }

        if let Err(err) = disk.erase() {
            panic!("erase: {err}");
        }

        let mut left: Vec<String> = match std::fs::read_dir(dir.path()) {
            Ok(read) => read
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(err) => panic!("list: {err}"),
        };
        left.sort();
        assert_eq!(left, vec!["cache.enc", "resolver_config.toml"]);
        assert!(!disk.health().failed);
    }

    #[test]
    fn a_cleared_log_does_not_come_back_after_a_restart() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::default();
        log.push(entry("secret.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::Day), now);

        log.clear();
        if let Err(err) = disk.erase() {
            panic!("erase: {err}");
        }
        disk.flush(&log, on(LogRetention::Day), now);

        let (back, _) = restart(dir.path(), LogRetention::Day, now);
        assert!(names(&back, now).is_empty());
    }

    #[test]
    fn after_erase_with_memory_kept_a_re_enable_writes_memory_again() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::default();
        log.push(entry("kept.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::Day), now);
        if let Err(err) = disk.erase() {
            panic!("erase: {err}");
        }
        assert!(!dir.path().join(SEGMENT_DIR).exists());
        disk.flush(&log, on(LogRetention::Day), now);
        assert_eq!(
            domains_in_day(dir.path(), utc_day(now)),
            vec!["kept.example"]
        );
    }

    /// Holds `path` open with no sharing, so Windows refuses to read,
    /// rename or delete it until the handle drops (a scanner or indexer
    /// doing the same is what makes an erase fail in the field).
    #[cfg(windows)]
    fn lock(path: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
        {
            Ok(file) => file,
            Err(err) => panic!("lock {path:?}: {err}"),
        }
    }

    // ---- Error path (T-291 independent review) ----

    #[cfg(windows)]
    #[test]
    fn a_failed_erase_stays_failed_and_is_retried_before_any_write() {
        let dir = tempdir();
        let now = SystemTime::now();
        let old = ago(now, 48);
        let log = QueryLog::with_retention(LogRetention::SevenDays);
        log.push(entry("before-clear.example", old));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::SevenDays), now);
        let old_file = dir
            .path()
            .join(SEGMENT_DIR)
            .join(segment_name(utc_day(old)));

        let held = lock(&old_file);
        log.clear();
        assert!(disk.erase().is_err());
        assert!(disk.health().failed);
        assert!(dir.path().join(ERASE_MARKER).exists());

        log.push(entry("after-clear.example", now));
        disk.flush(&log, on(LogRetention::SevenDays), now);
        assert!(
            disk.health().failed,
            "a flush must not hide an unfinished erase"
        );
        assert_eq!(names(&log, now), vec!["after-clear.example"]);

        drop(held);
        disk.flush(&log, on(LogRetention::SevenDays), now);
        assert!(!disk.health().failed);
        assert!(!old_file.exists());
        assert!(!dir.path().join(ERASE_MARKER).exists());
        assert_eq!(segment_days(dir.path()), vec![utc_day(now)]);
        let (back, _) = restart(dir.path(), LogRetention::SevenDays, now);
        assert_eq!(names(&back, now), vec!["after-clear.example"]);
    }

    #[test]
    fn a_pending_erase_marker_is_honoured_at_startup() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::default();
        log.push(entry("cleared-before-reboot.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&log, on(LogRetention::Day), now);
        if let Err(err) = std::fs::write(dir.path().join(ERASE_MARKER), b"") {
            panic!("seed marker: {err}");
        }

        let init = load_persisted_query_log(
            Some(dir.path()),
            QueryLogPolicy {
                retention: LogRetention::Day,
                persist: false,
            },
        );
        assert!(!dir.path().join(SEGMENT_DIR).exists());
        assert!(!dir.path().join(ERASE_MARKER).exists());
        assert!(!init.disk.health().leftover);
        assert!(!init.disk.health().failed);
    }

    #[cfg(windows)]
    #[test]
    fn an_unreadable_day_file_aborts_adoption_without_moving_or_overwriting_it() {
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::default();
        log.push(entry("kept.example", now));
        QueryLogDisk::with_key(dir.path(), KEY).flush(&log, on(LogRetention::Day), now);
        let file = dir
            .path()
            .join(SEGMENT_DIR)
            .join(segment_name(utc_day(now)));

        let held = lock(&file);
        let fresh = QueryLog::default();
        fresh.push(entry("new.example", now));
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        disk.flush(&fresh, on(LogRetention::Day), now);
        assert!(disk.health().failed);
        drop(held);

        assert_eq!(
            domains_in_day(dir.path(), utc_day(now)),
            vec!["kept.example"]
        );
        let siblings = match std::fs::read_dir(dir.path().join(SEGMENT_DIR)) {
            Ok(read) => read.count(),
            Err(err) => panic!("list: {err}"),
        };
        assert_eq!(siblings, 1, "nothing moved aside");
        disk.flush(&fresh, on(LogRetention::Day), now);
        assert!(!disk.health().failed);
        assert_eq!(
            domains_in_day(dir.path(), utc_day(now)),
            vec!["kept.example", "new.example"]
        );
    }

    #[test]
    fn legacy_entries_already_migrated_are_not_restored_twice() {
        let dir = tempdir();
        let now = SystemTime::now();
        let old = ago(now, 48);
        let log = QueryLog::default();
        log.push(entry("migrated.example", now));
        QueryLogDisk::with_key(dir.path(), KEY).flush(&log, on(LogRetention::Day), now);
        let legacy = [
            entry("not-yet.example", old),
            entry("migrated.example", now),
        ];
        if let Err(err) = persist_snapshot(&legacy, &KEY, &dir.path().join(LEGACY_FILE)) {
            panic!("seed: {err}");
        }

        let (back, _) = restart(dir.path(), LogRetention::SevenDays, now);
        assert_eq!(
            names(&back, now),
            vec!["not-yet.example", "migrated.example"]
        );
    }

    #[test]
    fn a_stray_legacy_temp_file_counts_as_leftover_history() {
        let dir = tempdir();
        if let Err(err) = std::fs::write(dir.path().join("query-log.enc.tmp"), b"x") {
            panic!("seed: {err}");
        }
        let init = load_persisted_query_log(
            Some(dir.path()),
            QueryLogPolicy {
                retention: LogRetention::Day,
                persist: false,
            },
        );
        assert!(init.disk.health().leftover);
    }

    // ---- The real key-store path ----

    #[test]
    fn load_with_persistence_off_flags_leftover_history() {
        let dir = tempdir();
        if let Err(err) = std::fs::write(dir.path().join(LEGACY_FILE), b"x") {
            panic!("seed: {err}");
        }
        let init = load_persisted_query_log(
            Some(dir.path()),
            QueryLogPolicy {
                retention: LogRetention::Day,
                persist: false,
            },
        );
        assert!(init.disk.health().leftover);
        assert!(!init.disk.health().failed);
    }

    #[test]
    fn load_restores_with_the_configured_window_through_the_real_key_store() {
        let dir = crate::key_store::StoreTestDir::new();
        let now = SystemTime::now();
        let first = load_persisted_query_log(Some(dir.path()), on(LogRetention::SevenDays));
        first.log.push(entry("three-days.example", ago(now, 72)));
        let mut disk = first.disk;
        disk.flush(&first.log, on(LogRetention::SevenDays), now);
        assert!(!disk.health().failed);

        let second = load_persisted_query_log(Some(dir.path()), on(LogRetention::SevenDays));
        assert_eq!(names(&second.log, now), vec!["three-days.example"]);
    }

    #[test]
    fn files_without_their_key_are_moved_aside_and_never_overwritten() {
        let dir = crate::key_store::StoreTestDir::new();
        let legacy = dir.path().join(LEGACY_FILE);
        if let Err(err) = std::fs::write(&legacy, b"not a DQF1 file") {
            panic!("seed: {err}");
        }
        let init = load_persisted_query_log(Some(dir.path()), on(LogRetention::Day));
        assert!(init.log.snapshot(SystemTime::now()).is_empty());
        assert!(
            !init.disk.health().failed,
            "a fresh key still enables persistence"
        );
        crate::log_persist::assert_moved_aside_intact(&legacy, b"not a DQF1 file");
    }

    #[test]
    fn load_is_inert_without_an_app_data_dir() {
        let off = load_persisted_query_log(None, QueryLogPolicy::default());
        assert!(!off.disk.health().failed);
        let on_without_dir = load_persisted_query_log(None, on(LogRetention::Day));
        assert!(
            on_without_dir.disk.health().failed,
            "persistence was asked for and cannot work"
        );
    }

    /// T-291 measurement, not a gate: restoring a full 30-day log (the
    /// 100 000-entry cap, three voters per entry) on the boot path. Run with
    /// `cargo test --release -p dnsqb-service --lib -- --ignored --nocapture
    /// restore_time_at_the_30_day_cap`.
    #[test]
    #[ignore = "measurement; prints timings"]
    fn restore_time_at_the_30_day_cap() {
        use crate::quorum::{VoterRecord, VoterVerdict};
        let dir = tempdir();
        let now = SystemTime::now();
        let log = QueryLog::with_retention(LogRetention::ThirtyDays);
        let total: u64 = 100_000;
        let span = Duration::from_hours(29 * 24).as_secs();
        for i in 0..total {
            let Some(at) = now.checked_sub(Duration::from_secs(span - span * i / total)) else {
                panic!("valid fixture timestamp");
            };
            let mut e = entry(&format!("host-{i}.example-site.test"), at);
            e.voters = ["quad9", "cloudflare-malware", "adguard"]
                .iter()
                .map(|id| VoterRecord {
                    provider_id: (*id).to_string(),
                    verdict: VoterVerdict::Allow,
                    allow_ip_count: Some(2),
                    error_message: None,
                })
                .collect();
            log.push(e);
        }
        let mut disk = QueryLogDisk::with_key(dir.path(), KEY);
        let started = std::time::Instant::now();
        disk.flush(&log, on(LogRetention::ThirtyDays), now);
        let flushed = started.elapsed();
        let Ok(listing) = std::fs::read_dir(dir.path().join(SEGMENT_DIR)) else {
            panic!("the flush must have written the segment directory");
        };
        let bytes: u64 = listing
            .filter_map(Result::ok)
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum();
        let fresh = QueryLog::with_retention(LogRetention::ThirtyDays);
        let mut reader = QueryLogDisk::with_key(dir.path(), KEY);
        let started = std::time::Instant::now();
        let restored = reader.adopt(&fresh, LogRetention::ThirtyDays, now);
        let took = started.elapsed();
        println!(
            "full flush {flushed:?}; {bytes} bytes on disk; restore {took:?}, {restored:?} entries"
        );
        assert!(matches!(restored, Ok(n) if n as u64 == total));
    }
}
