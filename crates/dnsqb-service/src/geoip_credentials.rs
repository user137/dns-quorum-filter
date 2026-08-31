//! Optional `MaxMind GeoLite2` download credentials (T-80), held in platform
//! secure storage (T-163, [`crate::key_store`]) — the Windows Credential
//! Manager entry [`crate::key_store::maxmind_credentials_entry`], keyed on the
//! app-data directory.
//!
//! **Why not a table in `resolver_config.toml`.** `config::ResolverConfig::save()`
//! has several callers (`POST /admin/config`, `POST /admin/reset`, the
//! `/admin/geoip/*` add/remove routes) that each re-serialize the *whole* file
//! and must read-and-echo every unrelated field first — the recurring
//! cross-field-read bug class in this project (T-57 / T-139 / T-149 / T-47 /
//! T-77). A dedicated secret-store entry with a single writer ([`save`] /
//! [`clear`]) has no such hazard, and it keeps `config.rs`'s decision to log the
//! full `toml::de::Error` line snippet sound (justified there by
//! "`resolver_config.toml` never contains a domain name" — a license key would
//! break that).
//!
//! **Pre-T-163 installs kept the credentials in a plaintext `geoip_maxmind.toml`**
//! (ACL-restricted to the user as interim MVP tech debt). [`migrate_legacy_credentials_file`]
//! copies such a file into the OS store once at startup and then erases it —
//! delete-after-store is safe here (unlike the TLS key's deferred delete): a
//! `store_secret` `Ok` *is* the confirmation, and a credential the operator can
//! re-type from the `MaxMind` portal is not an irreplaceable cryptographic
//! identity.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::key_store;

/// Upper bound on a leftover `geoip_maxmind.toml`'s on-disk size, checked
/// before the file is read into memory during migration (SPEC.md §8.1: bound
/// the allocation, don't measure a length after the fact) — two short string
/// fields, so 8 KiB is already generous even for a heavily hand-commented file.
pub(crate) const MAX_CREDENTIALS_FILE_SIZE: u64 = 8 * 1024;

/// A `MaxMind` license key. Newtype with a **hand-written redacting `Debug`**
/// and no `Display` / `Serialize` — so any type that derives `Debug` and holds
/// one (`MaxmindCredentials`, `geoip_updater::GeoipSource`) can't leak the key
/// through `tracing::warn!(?value)` / `format!("{value:?}")`, the same
/// accidental-`Debug`-leak path `overrides::InvalidEntry`'s own redacting
/// `Debug` guards against.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct LicenseKey(String);

impl LicenseKey {
    /// Wraps a raw key. Test-only — the `#[ignore]`d live tests build
    /// credentials from environment variables; production credentials arrive
    /// as `&str` through [`save`] and are never wrapped outside this module.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(key: String) -> Self {
        Self(key)
    }

    /// The raw key, for the one place it's legitimately needed: the
    /// `Authorization: Basic` password on the `MaxMind` download request
    /// (`geoip_updater::fetch_bounded_authed`). Named `expose_secret`
    /// deliberately — reaching the plaintext is a conscious call, not an
    /// accidental deref.
    #[must_use]
    pub(crate) fn expose_secret(&self) -> &str {
        &self.0
    }

    fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for LicenseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LicenseKey(\"<redacted>\")")
    }
}

/// `MaxMind GeoLite2` download credentials — both fields are required for the
/// modern `download.maxmind.com/geoip/databases/...` endpoint's HTTP Basic
/// auth (account id : license key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxmindCredentials {
    /// `MaxMind` account id (the Basic-auth username). Not itself a secret, but
    /// still this service's own configuration — never logged.
    pub account_id: String,
    /// `MaxMind` license key (the Basic-auth password).
    pub license_key: LicenseKey,
}

/// Errors loading, storing, or migrating `MaxMind` credentials. The parse
/// variant is payload-free by design — see the module doc for why a license
/// key must not reach a log line the way `config::ConfigError::Toml`'s snippet
/// legitimately can.
#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    /// Failed to read or erase a leftover `geoip_maxmind.toml` during
    /// migration (anything other than "file does not exist").
    #[error("failed to read the legacy MaxMind credentials file: {0}")]
    Io(#[source] io::Error),
    /// The stored blob, or a leftover `geoip_maxmind.toml`, isn't in the
    /// expected `account_id` + `license_key` shape, or a field is blank.
    #[error("MaxMind credentials are malformed or have a blank field")]
    Malformed,
    /// A leftover `geoip_maxmind.toml` exceeds [`MAX_CREDENTIALS_FILE_SIZE`] —
    /// rejected before being read into memory.
    #[error("the legacy MaxMind credentials file exceeds the {MAX_CREDENTIALS_FILE_SIZE}-byte size limit")]
    TooLarge,
    /// The OS credential store rejected storing, reading, or deleting the
    /// credentials. [`key_store::KeyStoreError`]'s payload describes *store
    /// access* failures and carries no secret.
    #[error("MaxMind credentials secure storage failed: {0}")]
    KeyStore(#[from] key_store::KeyStoreError),
}

/// Loads `MaxMind` credentials for the install rooted at `app_data_dir` from
/// the OS credential store.
///
/// - No entry → `Ok(None)`: the ordinary state for the default DB-IP Lite mode.
/// - Present and complete (both fields non-blank) → `Ok(Some(_))`: `MaxMind`
///   advanced mode.
/// - Present but a malformed blob or a blank field → `Err`: should not happen
///   for a store [`save`] wrote, but a corrupted entry is surfaced rather than
///   silently treated as "not configured".
///
/// # Errors
///
/// [`CredentialsError::KeyStore`] for a store failure, or
/// [`CredentialsError::Malformed`] for a bad blob / a blank field.
pub fn load(app_data_dir: &Path) -> Result<Option<MaxmindCredentials>, CredentialsError> {
    let entry = key_store::maxmind_credentials_entry(app_data_dir);
    let Some(bytes) = key_store::load_secret(&entry)? else {
        return Ok(None);
    };
    let stored: StoredCredentials =
        serde_json::from_slice(&bytes).map_err(|_| CredentialsError::Malformed)?;
    if stored.account_id.trim().is_empty() || stored.license_key.is_blank() {
        return Err(CredentialsError::Malformed);
    }
    Ok(Some(MaxmindCredentials {
        account_id: stored.account_id,
        license_key: stored.license_key,
    }))
}

/// Stores `account_id` + `license_key` for the install rooted at
/// `app_data_dir` as a single JSON blob in the OS credential store (T-163) —
/// the single writer, `POST /admin/geoip/maxmind`. Overwrites any existing
/// entry wholesale; there is no read-modify-write, so no lock is needed
/// against a concurrent operator POST (correctly last-writer-wins).
///
/// # Errors
///
/// [`CredentialsError::Malformed`] if either field is blank (the same rule
/// [`load`] enforces on read), or [`CredentialsError::KeyStore`] if the store
/// rejects the write.
pub(crate) fn save(
    app_data_dir: &Path,
    account_id: &str,
    license_key: &str,
) -> Result<(), CredentialsError> {
    if account_id.trim().is_empty() || license_key.trim().is_empty() {
        return Err(CredentialsError::Malformed);
    }
    let blob = Zeroizing::new(
        serde_json::to_vec(&StoredCredentialsOut {
            account_id,
            license_key,
        })
        .map_err(|_| CredentialsError::Malformed)?,
    );
    let entry = key_store::maxmind_credentials_entry(app_data_dir);
    key_store::store_secret(&entry, &blob)?;
    Ok(())
}

/// The JSON blob [`save`] writes — a throwaway `Serialize` mirror over borrowed
/// `&str`s. [`LicenseKey`] itself is deliberately **not** `Serialize` (so it
/// can never leak through a response DTO); writing the plaintext into its own
/// OS-store entry is the one legitimate exposure, the same conscious call
/// `expose_secret` makes for the auth header.
#[derive(Serialize)]
struct StoredCredentialsOut<'a> {
    account_id: &'a str,
    license_key: &'a str,
}

/// Removes the stored `MaxMind` credentials for the install rooted at
/// `app_data_dir` (T-163) — the operator switching back to the default DB-IP
/// Lite source. A missing entry is `Ok(())`, the same "not an error" tolerance
/// [`load`] applies.
///
/// # Errors
///
/// [`CredentialsError::KeyStore`] if the store rejects the delete.
pub(crate) fn clear(app_data_dir: &Path) -> Result<(), CredentialsError> {
    let entry = key_store::maxmind_credentials_entry(app_data_dir);
    key_store::delete_secret(&entry)?;
    Ok(())
}

/// What [`migrate_legacy_credentials_file`] did — for logging/tests; no caller
/// branches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// No leftover `geoip_maxmind.toml`, nothing to change.
    NothingToMigrate,
    /// A leftover `geoip_maxmind.toml` was copied into the store and erased.
    Migrated,
    /// The store already held credentials; a stale `geoip_maxmind.toml` was
    /// present and has been erased (the store's copy wins).
    StalePlaintextPresent,
}

/// Copies a pre-T-163 plaintext `geoip_maxmind.toml` in `app_data_dir` into the
/// OS credential store, exactly once, then erases the file.
///
/// - Store already has credentials + a stale file present ⇒ `warn!` naming
///   which copy wins, erase the file, `Ok(StalePlaintextPresent)`.
/// - Store empty + a valid file present ⇒ store it, erase the file,
///   `Ok(Migrated)`.
/// - No file ⇒ `Ok(NothingToMigrate)`.
///
/// Unlike the TLS key's `cert::discard_legacy_key_file`, the file is erased in
/// the same step it's stored: a `store_secret` `Ok` confirms the copy, and a
/// re-typeable credential is not an irreplaceable identity.
///
/// # Errors
///
/// [`CredentialsError::Io`] if reading or erasing the file fails,
/// [`CredentialsError::TooLarge`] past [`MAX_CREDENTIALS_FILE_SIZE`],
/// [`CredentialsError::Malformed`] for bad TOML / a blank field, or
/// [`CredentialsError::KeyStore`] if the store rejects a read or write.
pub fn migrate_legacy_credentials_file(
    app_data_dir: &Path,
) -> Result<MigrationOutcome, CredentialsError> {
    let legacy = app_data_dir.join("geoip_maxmind.toml");
    if !legacy.exists() {
        return Ok(MigrationOutcome::NothingToMigrate);
    }

    let entry = key_store::maxmind_credentials_entry(app_data_dir);
    if key_store::load_secret(&entry)?.is_some() {
        tracing::warn!(
            "a plaintext geoip_maxmind.toml was found; the credentials already in the OS \
             credential store are kept and the file removed"
        );
        key_store::erase_and_remove(&legacy).map_err(CredentialsError::Io)?;
        return Ok(MigrationOutcome::StalePlaintextPresent);
    }

    let raw = read_legacy_bounded(&legacy)?;
    let (account_id, license_key) = parse_legacy_toml(&raw).ok_or(CredentialsError::Malformed)?;
    let blob = Zeroizing::new(
        serde_json::to_vec(&StoredCredentialsOut {
            account_id: &account_id,
            license_key: &license_key,
        })
        .map_err(|_| CredentialsError::Malformed)?,
    );
    key_store::store_secret(&entry, &blob)?;
    key_store::erase_and_remove(&legacy).map_err(CredentialsError::Io)?;
    tracing::info!(
        "migrated MaxMind credentials from geoip_maxmind.toml into the OS credential store"
    );
    Ok(MigrationOutcome::Migrated)
}

/// Bounded read of a leftover `geoip_maxmind.toml` — same reasoning as
/// `config::ResolverConfig::load`: the size check has to be enforced by the
/// call that actually allocates.
fn read_legacy_bounded(path: &Path) -> Result<String, CredentialsError> {
    let mut handle = File::open(path).map_err(CredentialsError::Io)?;
    let mut raw = String::new();
    let read = handle
        .by_ref()
        .take(MAX_CREDENTIALS_FILE_SIZE + 1)
        .read_to_string(&mut raw)
        .map_err(CredentialsError::Io)?;
    if u64::try_from(read).unwrap_or(u64::MAX) > MAX_CREDENTIALS_FILE_SIZE {
        return Err(CredentialsError::TooLarge);
    }
    Ok(raw)
}

/// Parses a pre-T-163 two-key TOML file. `None` on bad TOML, an unknown key,
/// or a blank field — the caller maps that to [`CredentialsError::Malformed`].
fn parse_legacy_toml(raw: &str) -> Option<(String, String)> {
    let file: LegacyCredentialsFile = toml::from_str(raw).ok()?;
    if file.account_id.trim().is_empty() || file.license_key.trim().is_empty() {
        return None;
    }
    Some((file.account_id, file.license_key))
}

/// Pre-T-163 on-disk shape — a flat two-key TOML file. `deny_unknown_fields`
/// rejects a typo'd key; a missing key is a `serde` error. Read only by
/// [`migrate_legacy_credentials_file`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCredentialsFile {
    account_id: String,
    license_key: String,
}

/// The stored JSON blob's shape on read. `deny_unknown_fields` so a
/// future-versioned blob fails loudly rather than silently dropping a field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredentials {
    account_id: String,
    license_key: LicenseKey,
}

#[cfg(test)]
mod tests {
    use super::{
        clear, load, migrate_legacy_credentials_file, save, CredentialsError, MigrationOutcome,
        MAX_CREDENTIALS_FILE_SIZE,
    };
    use crate::key_store;
    use std::path::{Path, PathBuf};

    /// A scratch app-data dir whose derived `maxmind-credentials` entry is
    /// deleted on drop, so the real per-install entry is never touched and
    /// parallel tests don't collide. The dir path is unique per run. Also
    /// holds [`key_store::STORE_TEST_GUARD`] for its lifetime, so
    /// credential-store tests across the whole crate run serially (the Windows
    /// backend races under concurrent access even on distinct entries).
    struct ScratchDir {
        _tmp: tempfile::TempDir,
        _guard: parking_lot::MutexGuard<'static, ()>,
        path: PathBuf,
    }

    impl ScratchDir {
        fn new() -> Self {
            let guard = key_store::STORE_TEST_GUARD.lock();
            let Ok(tmp) = tempfile::tempdir() else {
                panic!("must be able to create a temp dir");
            };
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            // A sub-directory unique per run: the entry name is derived from
            // the path, so two concurrent tests must not share one.
            let path = tmp
                .path()
                .join(format!("install-{nanos}-{:?}", std::thread::current().id()));
            if let Err(err) = std::fs::create_dir_all(&path) {
                panic!("must be able to create the scratch install dir: {err}");
            }
            Self {
                _tmp: tmp,
                _guard: guard,
                path,
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let entry = key_store::maxmind_credentials_entry(&self.path);
            let _ = key_store::delete_secret(&entry);
        }
    }

    #[test]
    fn load_of_an_unconfigured_install_is_ok_none() {
        let dir = ScratchDir::new();
        match load(dir.path()) {
            Ok(None) => {}
            other => panic!("expected Ok(None) for an unconfigured install, got {other:?}"),
        }
    }

    #[test]
    fn save_then_load_roundtrips_both_fields() {
        let dir = ScratchDir::new();
        if let Err(err) = save(dir.path(), "acct-123", "the-license-key") {
            panic!("save must succeed: {err}");
        }
        match load(dir.path()) {
            Ok(Some(creds)) => {
                assert_eq!(creds.account_id, "acct-123");
                assert_eq!(creds.license_key.expose_secret(), "the-license-key");
            }
            other => panic!("expected Ok(Some(_)) after save, got {other:?}"),
        }
    }

    #[test]
    fn save_rejects_a_blank_field_and_stores_nothing() {
        let dir = ScratchDir::new();
        assert!(matches!(
            save(dir.path(), "acct", "   "),
            Err(CredentialsError::Malformed)
        ));
        assert!(
            matches!(load(dir.path()), Ok(None)),
            "a rejected save must not have stored anything"
        );
    }

    #[test]
    fn clear_removes_the_entry_and_is_ok_when_already_absent() {
        let dir = ScratchDir::new();
        if let Err(err) = save(dir.path(), "acct", "key") {
            panic!("save must succeed: {err}");
        }
        if let Err(err) = clear(dir.path()) {
            panic!("clear must succeed: {err}");
        }
        assert!(matches!(load(dir.path()), Ok(None)));
        if let Err(err) = clear(dir.path()) {
            panic!("clear of an already-absent entry must be Ok: {err}");
        }
    }

    #[test]
    fn a_corrupt_stored_blob_is_malformed_not_silently_unconfigured() {
        let dir = ScratchDir::new();
        let entry = key_store::maxmind_credentials_entry(dir.path());
        if let Err(err) = key_store::store_secret(&entry, b"{not valid json") {
            panic!("storing the corrupt fixture must succeed: {err}");
        }
        assert!(matches!(load(dir.path()), Err(CredentialsError::Malformed)));
    }

    fn write_legacy(dir: &Path, body: &str) {
        if let Err(err) = std::fs::write(dir.join("geoip_maxmind.toml"), body) {
            panic!("must be able to write the legacy fixture: {err}");
        }
    }

    #[test]
    fn migration_of_no_file_is_nothing_to_migrate() {
        let dir = ScratchDir::new();
        match migrate_legacy_credentials_file(dir.path()) {
            Ok(MigrationOutcome::NothingToMigrate) => {}
            other => panic!("expected NothingToMigrate, got {other:?}"),
        }
    }

    #[test]
    fn migration_moves_a_legacy_file_into_the_store_and_erases_it() {
        let dir = ScratchDir::new();
        write_legacy(
            dir.path(),
            "account_id = \"123456\"\nlicense_key = \"abcdEFGH_the_key\"\n",
        );
        match migrate_legacy_credentials_file(dir.path()) {
            Ok(MigrationOutcome::Migrated) => {}
            other => panic!("expected Migrated, got {other:?}"),
        }
        assert!(
            !dir.path().join("geoip_maxmind.toml").exists(),
            "the legacy file must be gone after migration"
        );
        match load(dir.path()) {
            Ok(Some(creds)) => {
                assert_eq!(creds.account_id, "123456");
                assert_eq!(creds.license_key.expose_secret(), "abcdEFGH_the_key");
            }
            other => panic!("credentials must be readable from the store, got {other:?}"),
        }
    }

    #[test]
    fn migration_erases_a_stale_file_when_the_store_already_has_credentials() {
        let dir = ScratchDir::new();
        if let Err(err) = save(dir.path(), "store-acct", "store-key") {
            panic!("seeding the store must succeed: {err}");
        }
        write_legacy(
            dir.path(),
            "account_id = \"file-acct\"\nlicense_key = \"file-key\"\n",
        );
        match migrate_legacy_credentials_file(dir.path()) {
            Ok(MigrationOutcome::StalePlaintextPresent) => {}
            other => panic!("expected StalePlaintextPresent, got {other:?}"),
        }
        assert!(!dir.path().join("geoip_maxmind.toml").exists());
        match load(dir.path()) {
            Ok(Some(creds)) => {
                assert_eq!(creds.account_id, "store-acct", "the store's copy must win");
                assert_eq!(creds.license_key.expose_secret(), "store-key");
            }
            other => panic!("the store's credentials must be intact, got {other:?}"),
        }
    }

    #[test]
    fn migration_rejects_an_oversized_legacy_file_and_leaves_it_in_place() {
        let dir = ScratchDir::new();
        let oversized = format!(
            "account_id = \"1\"\nlicense_key = \"k\"\n# {}\n",
            "x".repeat(usize::try_from(MAX_CREDENTIALS_FILE_SIZE).unwrap_or(usize::MAX))
        );
        write_legacy(dir.path(), &oversized);
        assert!(matches!(
            migrate_legacy_credentials_file(dir.path()),
            Err(CredentialsError::TooLarge)
        ));
        assert!(
            dir.path().join("geoip_maxmind.toml").exists(),
            "an oversized file must be left for the operator to inspect"
        );
    }

    #[test]
    fn migration_rejects_a_blank_field_in_the_legacy_file() {
        let dir = ScratchDir::new();
        write_legacy(
            dir.path(),
            "account_id = \"123456\"\nlicense_key = \"   \"\n",
        );
        assert!(matches!(
            migrate_legacy_credentials_file(dir.path()),
            Err(CredentialsError::Malformed)
        ));
    }

    // The regression this guards: a derived `Debug` on `LicenseKey` (or any
    // struct holding one) would print the key straight into a `tracing`
    // diagnostic line. Same shape as `overrides::tests::
    // invalid_entry_debug_output_never_contains_the_raw_pattern_text`.
    #[test]
    fn debug_output_never_contains_the_key_text() {
        let secret = "super-secret-license-key-value";
        let creds = super::MaxmindCredentials {
            account_id: "acct".to_string(),
            license_key: super::LicenseKey::new(secret.to_string()),
        };
        let key_debug = format!("{:?}", creds.license_key);
        let struct_debug = format!("{creds:?}");
        assert!(!key_debug.contains(secret));
        assert!(!struct_debug.contains(secret));
        assert!(!struct_debug.contains("license-key-value"));
        assert!(
            struct_debug.contains("acct"),
            "the non-secret field is fine to show"
        );
    }
}
