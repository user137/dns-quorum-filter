//! T-80: optional `MaxMind GeoLite2` credentials, read from a dedicated
//! `geoip_maxmind.toml` in the app-data directory — deliberately **not** a
//! table inside `resolver_config.toml`.
//!
//! **Why a separate file.** `config::ResolverConfig::save()` has several
//! callers (`POST /admin/config`, `POST /admin/reset`, the `/admin/geoip/*`
//! add/remove routes) that each re-serialize the *whole* file and must
//! read-and-echo every unrelated field first — the recurring cross-field-read
//! bug class in this project (T-57 / T-139 / T-149 / T-47 / T-77). Putting a
//! secret in that file would make "silently wipe the operator's `MaxMind`
//! credentials on an unrelated cache-config save" the next instance. A
//! dedicated file has no such writer — in fact nothing in this task writes it
//! at all; it is hand-edited (T-162 adds an admin route + secure storage).
//! It also keeps `config.rs`'s decision to log the full `toml::de::Error`
//! line snippet sound (justified there by "`resolver_config.toml` never
//! contains a domain name" — a license key would break that), and it mirrors
//! `MaxMind`'s own `GeoIP.conf` convention.
//!
//! **Plaintext on disk is explicit MVP tech debt**, the same posture as the
//! TLS private key (`SECURITY.md`: "plaintext PEM … explicit MVP tech debt").
//! Platform secure storage (DPAPI) is deferred to T-162, not silently the
//! intended end state.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use serde::Deserialize;

/// Upper bound on `geoip_maxmind.toml`'s on-disk size, checked before the
/// file is read into memory (SPEC.md §8.1: bound the allocation, don't
/// measure a length after the fact) — two short string fields, so 8 KiB is
/// already generous even for a heavily hand-commented file.
pub(crate) const MAX_CREDENTIALS_FILE_SIZE: u64 = 8 * 1024;

/// A `MaxMind` license key. Newtype with a **hand-written redacting `Debug`**
/// and no `Display` — so any type that derives `Debug` and holds one
/// (`MaxmindCredentials`, `geoip_updater::GeoipSource`) can't leak the key
/// through `tracing::warn!(?value)` / `format!("{value:?}")`, the same
/// accidental-`Debug`-leak path `overrides::InvalidEntry`'s own redacting
/// `Debug` guards against.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct LicenseKey(String);

impl LicenseKey {
    /// Wraps a raw key. Test-only for now — the `#[ignore]`d live tests build
    /// credentials from environment variables; the first non-test caller
    /// (an admin route holding the plaintext) arrives with T-162.
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

/// Errors loading `geoip_maxmind.toml`. Payload-free by design — see the
/// module doc comment for why this file's parse error, unlike
/// `config::ConfigError::Toml`, must not carry a `toml::de::Error` snippet.
#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    /// Failed to read the file (anything other than "file does not exist",
    /// which is `Ok(None)` — see [`load`]).
    #[error("failed to read MaxMind credentials file: {0}")]
    Io(#[source] io::Error),
    /// The file isn't valid TOML in the expected `account_id` +
    /// `license_key` shape, or a field is present but blank.
    #[error("MaxMind credentials file is malformed or has a blank field")]
    Malformed,
    /// The file exceeds [`MAX_CREDENTIALS_FILE_SIZE`] — rejected before being
    /// read into memory.
    #[error("MaxMind credentials file exceeds the {MAX_CREDENTIALS_FILE_SIZE}-byte size limit")]
    TooLarge,
}

/// Loads `MaxMind` credentials from `path`.
///
/// - Missing file → `Ok(None)`: the ordinary state for the default DB-IP Lite
///   mode, not an error (same "no file yet" tolerance as
///   `overrides::OverrideLists::load` / `config::ResolverConfig::load`).
/// - Present and complete (both fields non-blank) → `Ok(Some(_))`: `MaxMind`
///   advanced mode.
/// - Present but malformed, oversized, or with a blank field → `Err`: a
///   hand-edited file the operator needs to fix. `main.rs` logs the
///   (payload-free) error and falls back to DB-IP Lite rather than refusing
///   to start.
///
/// This does blocking file I/O — call at startup, not from a hot path.
///
/// # Errors
///
/// [`CredentialsError::Io`] for a read failure other than "not found",
/// [`CredentialsError::TooLarge`] past [`MAX_CREDENTIALS_FILE_SIZE`], or
/// [`CredentialsError::Malformed`] for bad TOML / a blank field.
pub fn load(path: &Path) -> Result<Option<MaxmindCredentials>, CredentialsError> {
    let mut handle = match File::open(path) {
        Ok(handle) => handle,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(CredentialsError::Io(err)),
    };
    // Bounded read, not metadata-then-read - same reasoning as
    // `config::ResolverConfig::load`: the size check has to be enforced by
    // the call that actually allocates.
    let mut raw = String::new();
    let read = handle
        .by_ref()
        .take(MAX_CREDENTIALS_FILE_SIZE + 1)
        .read_to_string(&mut raw)
        .map_err(CredentialsError::Io)?;
    if u64::try_from(read).unwrap_or(u64::MAX) > MAX_CREDENTIALS_FILE_SIZE {
        return Err(CredentialsError::TooLarge);
    }
    let file: CredentialsFile = toml::from_str(&raw).map_err(|_| CredentialsError::Malformed)?;
    if file.account_id.trim().is_empty() || file.license_key.is_blank() {
        return Err(CredentialsError::Malformed);
    }
    Ok(Some(MaxmindCredentials {
        account_id: file.account_id,
        license_key: file.license_key,
    }))
}

/// On-disk shape — a flat two-key TOML file. `deny_unknown_fields` rejects a
/// typo'd key loudly; a missing key is a `serde` error mapped to
/// [`CredentialsError::Malformed`] (both fields are mandatory, no
/// `#[serde(default)]`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialsFile {
    account_id: String,
    license_key: LicenseKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("geoip_maxmind.toml");
        if let Err(err) = std::fs::write(&path, body) {
            panic!("must be able to write the fixture: {err}");
        }
        path
    }

    fn tmp() -> tempfile::TempDir {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        dir
    }

    #[test]
    fn load_of_a_missing_file_is_ok_none() {
        let dir = tmp();
        let missing = dir.path().join("does-not-exist.toml");
        match load(&missing) {
            Ok(None) => {}
            other => panic!("expected Ok(None) for a missing file, got {other:?}"),
        }
    }

    #[test]
    fn load_of_a_complete_file_parses_both_fields() {
        let dir = tmp();
        let path = write(
            &dir,
            "account_id = \"123456\"\nlicense_key = \"abcdEFGH_the_key\"\n",
        );
        match load(&path) {
            Ok(Some(creds)) => {
                assert_eq!(creds.account_id, "123456");
                assert_eq!(creds.license_key.expose_secret(), "abcdEFGH_the_key");
            }
            other => panic!("expected Ok(Some(_)), got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_a_file_missing_the_license_key() {
        let dir = tmp();
        let path = write(&dir, "account_id = \"123456\"\n");
        assert!(matches!(load(&path), Err(CredentialsError::Malformed)));
    }

    #[test]
    fn load_rejects_a_blank_field() {
        let dir = tmp();
        let path = write(&dir, "account_id = \"123456\"\nlicense_key = \"   \"\n");
        assert!(matches!(load(&path), Err(CredentialsError::Malformed)));
    }

    #[test]
    fn load_rejects_an_unknown_key() {
        let dir = tmp();
        let path = write(
            &dir,
            "account_id = \"1\"\nlicense_key = \"k\"\naccountid = \"typo\"\n",
        );
        assert!(matches!(load(&path), Err(CredentialsError::Malformed)));
    }

    #[test]
    fn load_rejects_a_file_one_byte_over_the_size_limit() {
        let dir = tmp();
        let oversized = format!(
            "account_id = \"1\"\nlicense_key = \"k\"\n# {}\n",
            "x".repeat(usize::try_from(MAX_CREDENTIALS_FILE_SIZE).unwrap_or(usize::MAX))
        );
        let path = write(&dir, &oversized);
        assert!(matches!(load(&path), Err(CredentialsError::TooLarge)));
    }

    // The regression this guards: a derived `Debug` on `LicenseKey` (or any
    // struct holding one) would print the key straight into a `tracing`
    // diagnostic line. Same shape as `overrides::tests::
    // invalid_entry_debug_output_never_contains_the_raw_pattern_text`.
    #[test]
    fn debug_output_never_contains_the_key_text() {
        let secret = "super-secret-license-key-value";
        let creds = MaxmindCredentials {
            account_id: "acct".to_string(),
            license_key: LicenseKey::new(secret.to_string()),
        };
        let key_debug = format!("{:?}", creds.license_key);
        let struct_debug = format!("{creds:?}");
        assert!(!key_debug.contains(secret));
        assert!(!struct_debug.contains(secret));
        // A shared substring long enough to prove it isn't just a formatting
        // coincidence.
        assert!(!struct_debug.contains("license-key-value"));
        assert!(
            struct_debug.contains("acct"),
            "the non-secret field is fine to show"
        );
    }
}
