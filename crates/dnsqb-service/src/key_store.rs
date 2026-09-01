//! T-67 / T-163: this crate's secrets in platform secure storage instead of
//! plaintext files on disk (SPEC.md §2: "Приватний ключ — у платформному secure
//! storage … **ніколи не plaintext-файлом поруч із конфігом**"; the ACL-locked
//! plaintext files were the explicitly-tracked MVP fallback, "технічний борг …
//! а не дефолт назавжди"). Two secrets go through here: the local `DoH`
//! listener's TLS private key (T-67, [`tls_key_entry`]) and the optional
//! `MaxMind GeoLite2` download credentials (T-163, [`maxmind_credentials_entry`]).
//!
//! This is the crate's single boundary to the OS secret store — the only
//! module that names [`keyring`]. `keyring` (`v1` feature) resolves per
//! platform: Windows Credential Manager (DPAPI-backed) now, macOS Keychain /
//! Linux Secret Service when T-71 ports the rest of the service — so the
//! `unsafe` FFI stays entirely inside `windows-native-keyring-store`, and this
//! crate's `#![forbid(unsafe_code)]` is untouched. macOS/Linux back ends are
//! abstracted but **unverified** here (no build/test access — DECISIONS.md
//! 2026-08-25); T-71 owns them.
//!
//! **Entry names are derived from the app-data directory, not fixed constants.**
//! A Credential Manager entry is per-Windows-user and machine-global — it does
//! *not* live under `%LOCALAPPDATA%`. Running an isolated `dnsqb-service.exe`
//! with `LOCALAPPDATA` pointed at a scratch directory (this project's standard
//! verification technique) would otherwise make that instance read and
//! overwrite the real install's stored secrets, and two instances would fight
//! over one entry. A short SHA-1 of the directory path gives every install —
//! real or scratch — its own stable entries with no operator bookkeeping.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use keyring::Entry;
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

/// The `keyring` "service" component, shared by every entry this crate creates.
const KEY_STORE_SERVICE: &str = "dns-quorum-filter";

/// Serializes every test that touches the real OS credential store, across all
/// modules (`key_store`, `geoip_credentials`, `dispatch`, `tls`). The Windows
/// Credential Manager backend is not safe for concurrent add/read/delete from
/// one process even on distinct entries — a parallel run intermittently sees a
/// just-written secret as absent. Each such test takes this lock on its first
/// line and holds it (RAII drop order puts it last, after any per-test cleanup
/// guard). Not `#[cfg(test)]`-gated behind a feature; it is only referenced
/// from `#[cfg(test)]` code.
#[cfg(test)]
pub(crate) static STORE_TEST_GUARD: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Errors from the OS credential store, other than "no such entry" (which every
/// function below maps to `Ok(None)` / `Ok(())` before it can reach here).
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// The OS credential store rejected the operation — backend unavailable,
    /// access denied, an ambiguous match.
    ///
    /// The wrapped [`keyring::Error`]'s `Display` describes *store access*
    /// failures; it never carries a domain name or query string the way
    /// [`reqwest::Error`] does (CLAUDE.md's "no domain names in service logs"
    /// gotcha). Keeping the real payload is therefore both safe and genuinely
    /// useful for diagnosing a Credential Manager failure — do **not**
    /// "harmonise" this into a payload-free variant by analogy with
    /// `overrides::InvalidReason` / `OverrideError::Parse`, which redact domain
    /// text that this type structurally cannot contain.
    #[error("OS credential store error: {0}")]
    Backend(#[from] keyring::Error),
}

/// The `keyring` "user" component for the secret named by `prefix` in the
/// install rooted at `app_data_dir` — `<prefix>:<first 8 bytes of
/// SHA-1(normalized path), hex>`. See the module documentation for why this is
/// path-derived rather than constant.
///
/// The path is normalized before hashing — lowercased (Windows paths are
/// case-insensitive) and trailing separators stripped — so `dnsqb-service` and
/// `dnsqb-tray` (which runs cert rotation in a **separate process**) derive the
/// same entry even if one holds `…\Local\dns-quorum-filter` and the other
/// `…\local\dns-quorum-filter\`. Residual, not covered: an 8.3 short path in one
/// process vs. the long form in the other would still diverge — both resolve
/// the directory from the same `%LOCALAPPDATA%` env var via
/// `paths::app_data_dir`, so this is a theoretical gap, not an observed one.
fn entry_name(prefix: &str, app_data_dir: &Path) -> String {
    use std::fmt::Write;

    let normalized = app_data_dir
        .to_string_lossy()
        .to_lowercase()
        .trim_end_matches(['/', '\\'])
        .to_owned();
    let hex = Sha1::digest(normalized.as_bytes()).iter().take(8).fold(
        String::with_capacity(16),
        |mut acc, byte| {
            // Writing a byte to a `String` via `write!` is infallible; the
            // `fmt::Error` branch is unreachable for this sink.
            let _ = write!(acc, "{byte:02x}");
            acc
        },
    );
    format!("{prefix}:{hex}")
}

/// Credential-store entry holding the local `DoH` listener's TLS private key
/// (T-67) for the install rooted at `app_data_dir`.
pub(crate) fn tls_key_entry(app_data_dir: &Path) -> String {
    entry_name("doh-tls-private-key", app_data_dir)
}

/// Credential-store entry holding the optional `MaxMind GeoLite2` download
/// credentials (T-163) for the install rooted at `app_data_dir`.
pub(crate) fn maxmind_credentials_entry(app_data_dir: &Path) -> String {
    entry_name("maxmind-credentials", app_data_dir)
}

/// Store `bytes` under `entry`, overwriting any existing value — so this is
/// also the rotation / credentials-update write path.
///
/// # Errors
///
/// Returns [`KeyStoreError::Backend`] if the OS credential store rejects the
/// write (e.g. the secret exceeds the platform's per-entry size limit — for
/// Windows Credential Manager, `CRED_MAX_CREDENTIAL_BLOB_SIZE` = 2560 bytes;
/// this project's ECDSA P-256 key DER is ~121 bytes and its `MaxMind`
/// credentials JSON blob is ~60).
pub(crate) fn store_secret(entry: &str, bytes: &[u8]) -> Result<(), KeyStoreError> {
    Entry::new(KEY_STORE_SERVICE, entry)?.set_secret(bytes)?;
    Ok(())
}

/// Load the secret stored under `entry`, or `Ok(None)` if the store holds no
/// such entry (first run, or the entry was deleted).
///
/// The returned bytes are wrapped in [`Zeroizing`] so the in-memory copy is
/// wiped on drop.
///
/// # Errors
///
/// Returns [`KeyStoreError::Backend`] for any store failure other than a
/// missing entry.
pub(crate) fn load_secret(entry: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
    match Entry::new(KEY_STORE_SERVICE, entry)?.get_secret() {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Delete the entry, if it exists. A missing entry is `Ok(())` (idempotent), so
/// an uninstaller, a repeated rotation, or the `MaxMind`-credentials "switch
/// back to DB-IP Lite" route can call this unconditionally.
///
/// # Errors
///
/// Returns [`KeyStoreError::Backend`] for any store failure other than a
/// missing entry.
pub(crate) fn delete_secret(entry: &str) -> Result<(), KeyStoreError> {
    match Entry::new(KEY_STORE_SERVICE, entry)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Truncate `path` in place and overwrite it with zeros, flushing to disk
/// (`sync_all`) before returning. Truncate-in-place (rather than
/// delete-and-recreate) keeps the file's existing restrictive ACL for the
/// short window before it is removed. Bounded at 64 KiB — the pre-migration
/// plaintext files this scrubs (`key.pem`, `geoip_maxmind.toml`) are a few
/// hundred bytes.
///
/// **Best-effort scrub, not a guarantee** (same honesty as the `zeroize`
/// vetting row): it defeats a naive undelete that scrapes freed clusters, but
/// not VSS shadow copies, SSD wear-levelling / TRIM remapping, or a filesystem
/// that had already journalled the original bytes elsewhere.
///
/// # Errors
///
/// Propagates any I/O error from stat/create/write/sync.
pub(crate) fn overwrite_with_zeros(path: &Path) -> io::Result<()> {
    let len = usize::try_from(fs::metadata(path)?.len().min(64 * 1024)).unwrap_or(0);
    let mut file = File::create(path)?;
    file.write_all(&vec![0u8; len])?;
    file.sync_all()
}

/// [`overwrite_with_zeros`] then delete. A bare unlink leaves the secret bytes
/// readable on disk. A failed overwrite is logged but not fatal — the removal
/// is what takes the file off disk regardless.
///
/// # Errors
///
/// Propagates the I/O error from `remove_file` (the overwrite failure is only
/// logged).
pub(crate) fn erase_and_remove(path: &Path) -> io::Result<()> {
    if let Err(err) = overwrite_with_zeros(path) {
        tracing::warn!("could not zero {path:?} before removal: {err}");
    }
    fs::remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::{
        delete_secret, erase_and_remove, load_secret, maxmind_credentials_entry,
        overwrite_with_zeros, store_secret, tls_key_entry,
    };
    use std::path::Path;

    /// A distinct `keyring` entry name per test run, so a real dev machine's or
    /// CI session's stored secrets are never touched and parallel tests don't
    /// collide. Deleted by [`ScratchEntry`]'s `Drop`. Also holds
    /// [`super::STORE_TEST_GUARD`] for its lifetime, so credential-store tests
    /// across the whole crate run one at a time (the Windows backend races
    /// under concurrent access even on distinct entries).
    struct ScratchEntry {
        name: String,
        _guard: parking_lot::MutexGuard<'static, ()>,
    }

    impl ScratchEntry {
        fn new(tag: &str) -> Self {
            let guard = super::STORE_TEST_GUARD.lock();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            Self {
                name: format!("test:{tag}:{nanos}:{:?}", std::thread::current().id()),
                _guard: guard,
            }
        }
        fn name(&self) -> &str {
            &self.name
        }
    }

    impl Drop for ScratchEntry {
        fn drop(&mut self) {
            // Best-effort cleanup; a leaked test entry is harmless and a
            // panic here would mask the real test failure.
            let _ = delete_secret(&self.name);
        }
    }

    #[test]
    fn entry_name_is_stable_path_specific_and_normalized() {
        let a = tls_key_entry(Path::new(r"C:\Users\x\AppData\Local\dns-quorum-filter"));
        let b = tls_key_entry(Path::new(r"C:\Users\x\AppData\Local\dns-quorum-filter"));
        let c = tls_key_entry(Path::new(r"C:\scratch\dns-quorum-filter"));
        // Trailing separator + case differ but must not change the entry — the
        // cross-process (service vs. tray) stability guarantee.
        let d = tls_key_entry(Path::new(r"C:\Users\x\AppData\local\dns-quorum-filter\"));
        assert_eq!(a, b, "same path must yield the same entry");
        assert_ne!(a, c, "a different path must yield a different entry");
        assert_eq!(a, d, "case / trailing separator must be normalized away");
        assert!(a.starts_with("doh-tls-private-key:"));
    }

    #[test]
    fn tls_and_maxmind_entries_differ_for_the_same_dir() {
        let dir = Path::new(r"C:\Users\x\AppData\Local\dns-quorum-filter");
        let key = tls_key_entry(dir);
        let creds = maxmind_credentials_entry(dir);
        assert_ne!(key, creds, "the two secrets must not share one entry");
        assert!(creds.starts_with("maxmind-credentials:"));
        // Same dir hash suffix, different prefix.
        assert_eq!(
            key.rsplit(':').next(),
            creds.rsplit(':').next(),
            "both entries are derived from the same normalized path"
        );
    }

    #[test]
    fn round_trips_a_binary_secret() {
        let entry = ScratchEntry::new("round-trip");
        let payload = [0u8, 1, 2, 250, 255, 0, 7];
        if let Err(err) = store_secret(entry.name(), &payload) {
            panic!("store must succeed against the OS credential store: {err}");
        }
        match load_secret(entry.name()) {
            Ok(Some(got)) => assert_eq!(got.as_slice(), payload),
            Ok(None) => panic!("load must return the stored bytes, got Ok(None)"),
            Err(err) => panic!("load must return the stored bytes, got Err({err})"),
        }
    }

    #[test]
    fn set_secret_overwrites_an_existing_entry() {
        let entry = ScratchEntry::new("overwrite");
        if let Err(err) = store_secret(entry.name(), b"first") {
            panic!("first store must succeed: {err}");
        }
        if let Err(err) = store_secret(entry.name(), b"second-value") {
            panic!("overwriting store must succeed: {err}");
        }
        match load_secret(entry.name()) {
            Ok(Some(got)) => assert_eq!(got.as_slice(), b"second-value"),
            Ok(None) => panic!("load must return the overwritten bytes, got Ok(None)"),
            Err(err) => panic!("load must return the overwritten bytes, got Err({err})"),
        }
    }

    #[test]
    fn load_of_an_unknown_entry_is_ok_none_not_err() {
        let entry = ScratchEntry::new("absent");
        match load_secret(entry.name()) {
            Ok(None) => {}
            Ok(Some(got)) => panic!(
                "a missing entry must be Ok(None), got Ok(Some(_)) ({} bytes)",
                got.len()
            ),
            Err(err) => panic!("a missing entry must be Ok(None), got Err({err})"),
        }
    }

    #[test]
    fn delete_is_idempotent() {
        let entry = ScratchEntry::new("delete");
        if let Err(err) = store_secret(entry.name(), b"x") {
            panic!("store must succeed: {err}");
        }
        if let Err(err) = delete_secret(entry.name()) {
            panic!("first delete must succeed: {err}");
        }
        if let Err(err) = delete_secret(entry.name()) {
            panic!("second delete of a now-absent entry must still be Ok: {err}");
        }
        match load_secret(entry.name()) {
            Ok(None) => {}
            Ok(Some(got)) => panic!(
                "entry must be gone after delete, got Ok(Some(_)) ({} bytes)",
                got.len()
            ),
            Err(err) => panic!("entry must be gone after delete, got Err({err})"),
        }
    }

    #[test]
    fn overwrite_with_zeros_replaces_every_byte_with_zero() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let path = dir.path().join("secret.bin");
        let original = b"an ACL-locked plaintext secret that must be scrubbed";
        if let Err(err) = std::fs::write(&path, original) {
            panic!("must be able to write the fixture: {err}");
        }
        if let Err(err) = overwrite_with_zeros(&path) {
            panic!("overwrite_with_zeros must succeed: {err}");
        }
        let after = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("must be able to read the file back: {err}"),
        };
        assert_eq!(
            after.len(),
            original.len(),
            "length must be preserved (truncate-in-place, then rewrite)"
        );
        assert!(
            after.iter().all(|&b| b == 0),
            "every byte must be zero, got {after:?}"
        );
    }

    #[test]
    fn erase_and_remove_deletes_the_file() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let path = dir.path().join("secret.bin");
        if let Err(err) = std::fs::write(&path, b"secret") {
            panic!("must be able to write the fixture: {err}");
        }
        if let Err(err) = erase_and_remove(&path) {
            panic!("erase_and_remove must succeed: {err}");
        }
        assert!(!path.exists(), "file must be gone after erase_and_remove");
    }
}
