//! T-67: the local `DoH` listener's TLS **private key** in platform secure
//! storage instead of a plaintext PEM on disk (SPEC.md §2: "Приватний ключ — у
//! платформному secure storage … **ніколи не plaintext-файлом поруч із
//! конфігом**"; the ACL-locked `key.pem` was the explicitly-tracked MVP
//! fallback, "технічний борг … а не дефолт назавжди").
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
//! **Entry name is derived from the app-data directory, not a fixed constant.**
//! A Credential Manager entry is per-Windows-user and machine-global — it does
//! *not* live under `%LOCALAPPDATA%`. Running an isolated `dnsqb-service.exe`
//! with `LOCALAPPDATA` pointed at a scratch directory (this project's standard
//! verification technique) would otherwise make that instance read and
//! overwrite the real install's stored key, and two instances would fight over
//! one entry. A short SHA-1 of the directory path gives every install — real or
//! scratch — its own stable entry with no operator bookkeeping.

use std::path::Path;

use keyring::Entry;
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

/// The `keyring` "service" component, shared by every entry this crate creates.
const KEY_STORE_SERVICE: &str = "dns-quorum-filter";

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

/// The `keyring` "user" component for the install rooted at `app_data_dir` —
/// `doh-tls-private-key:<first 8 bytes of SHA-1(normalized path), hex>`. See the
/// module documentation for why this is path-derived rather than constant.
///
/// The path is normalized before hashing — lowercased (Windows paths are
/// case-insensitive) and trailing separators stripped — so `dnsqb-service` and
/// `dnsqb-tray` (which runs cert rotation in a **separate process**) derive the
/// same entry even if one holds `…\Local\dns-quorum-filter` and the other
/// `…\local\dns-quorum-filter\`. Residual, not covered: an 8.3 short path in one
/// process vs. the long form in the other would still diverge — both resolve
/// the directory from the same `%LOCALAPPDATA%` env var via
/// `paths::app_data_dir`, so this is a theoretical gap, not an observed one.
pub(crate) fn entry_name_for_dir(app_data_dir: &Path) -> String {
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
    format!("doh-tls-private-key:{hex}")
}

/// Store `der` (a PKCS#8 private key) under `entry`, overwriting any existing
/// value — so this is also the rotation write path.
///
/// # Errors
///
/// Returns [`KeyStoreError::Backend`] if the OS credential store rejects the
/// write (e.g. the secret exceeds the platform's per-entry size limit — for
/// Windows Credential Manager, `CRED_MAX_CREDENTIAL_BLOB_SIZE` = 2560 bytes;
/// this project's ECDSA P-256 key DER is ~121 bytes).
pub(crate) fn store_private_key(entry: &str, der: &[u8]) -> Result<(), KeyStoreError> {
    Entry::new(KEY_STORE_SERVICE, entry)?.set_secret(der)?;
    Ok(())
}

/// Load the PKCS#8 private key stored under `entry`, or `Ok(None)` if the store
/// holds no such entry (first run, or the entry was deleted).
///
/// The returned bytes are wrapped in [`Zeroizing`] so the in-memory copy is
/// wiped on drop.
///
/// # Errors
///
/// Returns [`KeyStoreError::Backend`] for any store failure other than a
/// missing entry.
pub(crate) fn load_private_key(entry: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
    match Entry::new(KEY_STORE_SERVICE, entry)?.get_secret() {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Delete the entry, if it exists. A missing entry is `Ok(())` (idempotent), so
/// an uninstaller or a repeated rotation can call this unconditionally.
///
/// Test-only for now — the first non-test caller is the uninstaller task (a
/// left-behind stored key after the app is removed is the credential-store
/// analogue of the left-behind trust-store cert `trust_store::uninstall`
/// already guards against). Same `#[cfg(test)]` staging as
/// `geoip_credentials::LicenseKey::new`.
///
/// # Errors
///
/// Returns [`KeyStoreError::Backend`] for any store failure other than a
/// missing entry.
#[cfg(test)]
pub(crate) fn delete_private_key(entry: &str) -> Result<(), KeyStoreError> {
    match Entry::new(KEY_STORE_SERVICE, entry)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{delete_private_key, entry_name_for_dir, load_private_key, store_private_key};
    use std::path::Path;

    /// A distinct `keyring` entry name per test run, so a real dev machine's or
    /// CI session's stored key is never touched and parallel tests don't
    /// collide. Deleted by [`ScratchEntry`]'s `Drop`.
    struct ScratchEntry(String);

    impl ScratchEntry {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            Self(format!(
                "test:{tag}:{nanos}:{:?}",
                std::thread::current().id()
            ))
        }
        fn name(&self) -> &str {
            &self.0
        }
    }

    impl Drop for ScratchEntry {
        fn drop(&mut self) {
            // Best-effort cleanup; a leaked test entry is harmless and a
            // panic here would mask the real test failure.
            let _ = delete_private_key(&self.0);
        }
    }

    #[test]
    fn entry_name_is_stable_path_specific_and_normalized() {
        let a = entry_name_for_dir(Path::new(r"C:\Users\x\AppData\Local\dns-quorum-filter"));
        let b = entry_name_for_dir(Path::new(r"C:\Users\x\AppData\Local\dns-quorum-filter"));
        let c = entry_name_for_dir(Path::new(r"C:\scratch\dns-quorum-filter"));
        // Trailing separator + case differ but must not change the entry — the
        // cross-process (service vs. tray) stability guarantee.
        let d = entry_name_for_dir(Path::new(r"C:\Users\x\AppData\local\dns-quorum-filter\"));
        assert_eq!(a, b, "same path must yield the same entry");
        assert_ne!(a, c, "a different path must yield a different entry");
        assert_eq!(a, d, "case / trailing separator must be normalized away");
        assert!(a.starts_with("doh-tls-private-key:"));
    }

    #[test]
    fn round_trips_a_binary_secret() {
        let entry = ScratchEntry::new("round-trip");
        let payload = [0u8, 1, 2, 250, 255, 0, 7];
        if let Err(err) = store_private_key(entry.name(), &payload) {
            panic!("store must succeed against the OS credential store: {err}");
        }
        match load_private_key(entry.name()) {
            Ok(Some(got)) => assert_eq!(got.as_slice(), payload),
            other => panic!("load must return the stored bytes, got {other:?}"),
        }
    }

    #[test]
    fn set_secret_overwrites_an_existing_entry() {
        let entry = ScratchEntry::new("overwrite");
        if let Err(err) = store_private_key(entry.name(), b"first") {
            panic!("first store must succeed: {err}");
        }
        if let Err(err) = store_private_key(entry.name(), b"second-value") {
            panic!("overwriting store must succeed: {err}");
        }
        match load_private_key(entry.name()) {
            Ok(Some(got)) => assert_eq!(got.as_slice(), b"second-value"),
            other => panic!("load must return the overwritten bytes, got {other:?}"),
        }
    }

    #[test]
    fn load_of_an_unknown_entry_is_ok_none_not_err() {
        let entry = ScratchEntry::new("absent");
        match load_private_key(entry.name()) {
            Ok(None) => {}
            other => panic!("a missing entry must be Ok(None), got {other:?}"),
        }
    }

    #[test]
    fn delete_is_idempotent() {
        let entry = ScratchEntry::new("delete");
        if let Err(err) = store_private_key(entry.name(), b"x") {
            panic!("store must succeed: {err}");
        }
        if let Err(err) = delete_private_key(entry.name()) {
            panic!("first delete must succeed: {err}");
        }
        if let Err(err) = delete_private_key(entry.name()) {
            panic!("second delete of a now-absent entry must still be Ok: {err}");
        }
        match load_private_key(entry.name()) {
            Ok(None) => {}
            other => panic!("entry must be gone after delete, got {other:?}"),
        }
    }
}
