//! Self-signed leaf certificate generation (SPEC.md §2, T-48) and disk
//! persistence (T-50) for the local `DoH` listener. This module deliberately
//! does not: install the cert into an OS trust store (`trust_store.rs`,
//! T-49 — a confirm-gated `dnsqb-tray` action, not a manual `certutil`
//! recipe, as of T-49), rotate an existing cert (T-69), or decide whether to
//! load a previously-persisted cert instead of regenerating one (a future
//! `main.rs` listener-wiring decision). Same "backend primitive ready, wiring
//! later" pattern as every prior module in this crate.
//!
//! **The private key goes to platform secure storage, not a file next to the
//! config (SPEC.md §2, T-67).** [`write_cert_and_key_to_app_data`] writes only
//! the public `cert.pem` to disk; the key is handed to [`key_store`] (Windows
//! Credential Manager via `keyring`). A pre-T-67 install's ACL-locked plaintext
//! `key.pem` is picked up once by [`migrate_legacy_key_file`], moved into the
//! store, and erased. The ACL helpers below ([`write_user_restricted_file`] and
//! friends) stay — `geoip_maxmind.toml` (T-162) still relies on them.
//!
//! **Leaf, never a CA** (SPEC.md §2's largest stated attack-surface
//! decision): a compromised private key for this cert can only spoof
//! `127.0.0.1`, not arbitrary domains, precisely because it is not a CA that
//! could sign other certificates. Uses `IsCa::ExplicitNoCa`, not the plain
//! `IsCa::NoCa` default — confirmed empirically that `NoCa` omits the
//! `BasicConstraints` extension entirely rather than encoding `CA:FALSE`, so
//! a test asserting "not a CA" against a `NoCa`-generated cert would pass
//! against *any* certificate lacking the extension, not specifically against
//! this one's actual encoded bytes. `ExplicitNoCa` makes the property
//! verifiable from the DER itself.
//!
//! **Validity window is a stated, provisional decision, not a library
//! default.** `rcgen`'s own unexamined default (`1975-01-01`..`4096-01-01`,
//! confirmed empirically, not assumed from docs) is not used. This module
//! instead sets an explicit 100-year window (`2020-01-01`..`2120-01-01`) —
//! long-lived per SPEC.md §2, without reproducing rcgen's own odd `4096`
//! upper bound. The window is **absolute dates, not generation-time-relative
//! (`now()` + N years)**, even though `std::time::SystemTime::now().into()`
//! would work without any new dependency (confirmed empirically) — chosen
//! instead so this module's own tests can assert an exact expected
//! timestamp rather than a fuzzy "far enough in the future" range. **T-51**'s
//! empirical Chrome/Firefox CT-policy check may still force a different
//! window; **T-69** (certificate rotation) is where switching to a
//! generation-relative window would become worth it, since each rotation
//! calls this function fresh.

use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use rcgen::{CertificateParams, CertifiedKey, DistinguishedName, DnType, IsCa, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::PrivateKeyDer;
use zeroize::{Zeroize, Zeroizing};

use crate::key_store;
use crate::paths;

/// Subject `CommonName` this project's leaf certificate always carries —
/// shared with `trust_store.rs`, which matches on it to enumerate every
/// `CurrentUser\Root` entry this project has ever installed (T-49). A fixed
/// CN is exactly what makes that enumeration correct there; it is
/// deliberately *not* used as a precise "is this exact cert trusted?" check
/// (`trust_store.rs` uses the certificate's own SHA-1 thumbprint for that —
/// see its module doc comment for why CN alone would be wrong there).
pub(crate) const CERT_COMMON_NAME: &str = "dns-quorum-filter local DoH";

/// Errors generating the self-signed leaf certificate.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// Underlying `rcgen` failure (key generation or certificate signing).
    #[error("failed to generate self-signed certificate: {0}")]
    Generation(#[from] rcgen::Error),
    /// `%LOCALAPPDATA%` is not set — can't resolve the app-data directory to
    /// write the cert/key into. Not `#[from] paths::PathsError` — that type
    /// is `pub(crate)` (the `paths` module is private, T-50), and wrapping it
    /// directly in this `pub` enum would leak a private type through a
    /// public API (`private_interfaces` lint).
    #[error("%LOCALAPPDATA% environment variable is not set")]
    MissingLocalAppData,
    /// Failed to create the app-data directory or write the cert/key files.
    #[error("failed to write certificate files: {0}")]
    Io(#[source] io::Error),
    /// `%SystemRoot%` is not set — can't locate `icacls.exe` by absolute path.
    #[error("%SystemRoot% environment variable is not set")]
    MissingSystemRoot,
    /// `%USERNAME%` is not set — can't name the ACL grant target.
    #[error("%USERNAME% environment variable is not set")]
    MissingUserIdentity,
    /// Failed to spawn `icacls.exe` to restrict the private-key file's ACL.
    #[error("failed to spawn icacls to restrict the private key file: {0}")]
    IcaclsSpawn(#[source] io::Error),
    /// `icacls.exe` ran but reported failure restricting the private-key
    /// file's ACL.
    #[error("icacls failed to restrict the private key file (exit code {0:?})")]
    IcaclsFailed(Option<i32>),
    /// The OS credential store rejected storing or reading the private key.
    #[error("private key secure storage failed: {0}")]
    KeyStore(#[from] key_store::KeyStoreError),
    /// A pre-T-67 `key.pem` was found but its contents don't decode as a PEM
    /// private key. Payload-free: the file holds key material, so its decode
    /// error is not something to surface verbatim. The caller falls back to
    /// regenerating a fresh cert/key pair.
    #[error("existing key.pem could not be decoded as a private key")]
    LegacyKeyDecode,
}

/// Generate the local `DoH` listener's self-signed leaf certificate
/// (SPEC.md §2): SAN `IP:127.0.0.1`, `IP:::1`, `DNS:localhost`, not a CA,
/// long-lived (see this module's doc comment for the validity-window
/// reasoning). Takes no parameters — SPEC.md hardcodes the SAN list, so
/// there is nothing for a caller to configure.
///
/// # Errors
///
/// Returns [`CertError::Generation`] if key generation or self-signing
/// fails at the `rcgen`/crypto-backend level.
pub fn generate_self_signed_cert() -> Result<CertifiedKey<KeyPair>, CertError> {
    let mut params = CertificateParams::new(vec![
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "localhost".to_string(),
    ])?;
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2120, 1, 1);
    params.is_ca = IsCa::ExplicitNoCa;

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, CERT_COMMON_NAME);
    params.distinguished_name = distinguished_name;

    let signing_key = KeyPair::generate()?;
    let cert = params.self_signed(&signing_key)?;
    Ok(CertifiedKey { cert, signing_key })
}

/// Path of the certificate file written by [`write_cert_and_key_to_app_data`].
/// The private key is not a file — see [`key_store`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFiles {
    /// Path to the PEM-encoded certificate (public — no restricted ACL).
    pub cert_path: PathBuf,
}

/// Write the public `cert.pem` to `%LOCALAPPDATA%\dns-quorum-filter\` and hand
/// the private key to platform secure storage ([`key_store`]; Windows
/// Credential Manager via `keyring`) under the entry derived from that
/// directory (SPEC.md §2, T-67). Takes `certified_key` **by value**: this
/// function is where the key's storage/zeroize lifecycle starts and ends.
/// After the key bytes are handed off it clears the in-memory copies —
/// `signing_key.zeroize()` (rcgen's `zeroize` feature, which wipes only the
/// `KeyPair`'s internal DER bytes) and dropping the serialized DER via
/// [`Zeroizing`] — best-effort in-memory hygiene, not a guarantee.
///
/// **Unconditionally overwrites** any existing `cert.pem` and stored key on
/// every call. Deciding whether to load an existing cert instead of
/// regenerating one (so a user's manual trust-store install at T-49 isn't
/// silently invalidated on every service restart) is the listener-wiring
/// caller's job ([`crate::tls::load_or_generate_server_config`]), not this
/// function's.
///
/// # Errors
///
/// Returns [`CertError`] if the app-data directory can't be resolved or
/// created, if writing `cert.pem` fails, or if the OS credential store rejects
/// storing the key.
pub fn write_cert_and_key_to_app_data(
    certified_key: CertifiedKey<KeyPair>,
) -> Result<CertFiles, CertError> {
    let CertifiedKey {
        cert,
        mut signing_key,
    } = certified_key;

    let dir = paths::app_data_dir().map_err(|_| CertError::MissingLocalAppData)?;
    fs::create_dir_all(&dir).map_err(CertError::Io)?;

    let cert_path = dir.join("cert.pem");
    fs::write(&cert_path, cert.pem()).map_err(CertError::Io)?;

    let key_der = Zeroizing::new(signing_key.serialize_der());
    key_store::store_private_key(&key_store::entry_name_for_dir(&dir), &key_der)?;
    signing_key.zeroize();

    Ok(CertFiles { cert_path })
}

/// Pick up a pre-T-67 plaintext `key.pem` in `dir` exactly once: if the OS
/// credential store has no key yet but the file exists, decode it, store the
/// key, and erase the file. If the store already holds a key, a stale `key.pem`
/// is erased without being read. See [`migration_action`] for the decision and
/// [`erase_and_remove`] for why a bare unlink is not enough.
///
/// # Errors
///
/// [`CertError::KeyStore`] if the credential store rejects a read or write;
/// [`CertError::LegacyKeyDecode`] if `key.pem` exists but doesn't parse (the
/// file is **left in place** for inspection); [`CertError::Io`] if reading or
/// removing the file fails.
pub(crate) fn migrate_legacy_key_file(dir: &Path) -> Result<MigrationOutcome, CertError> {
    let entry = key_store::entry_name_for_dir(dir);
    let legacy = dir.join("key.pem");
    let store_has_key = key_store::load_private_key(&entry)?.is_some();

    match migration_action(store_has_key, legacy.exists()) {
        MigrationAction::Nothing => {
            if store_has_key && legacy.exists() {
                tracing::warn!(
                    "a plaintext key.pem is present but the OS credential store already holds the \
                     private key; erasing the stale plaintext copy"
                );
                erase_and_remove(&legacy)?;
                return Ok(MigrationOutcome::StalePlaintextRemoved);
            }
            Ok(MigrationOutcome::NothingToMigrate)
        }
        MigrationAction::Migrate => {
            let pem = Zeroizing::new(fs::read(&legacy).map_err(CertError::Io)?);
            // This project's own `key.pem` was always PKCS#8
            // (`rcgen::KeyPair::serialize_pem` → `-----BEGIN PRIVATE KEY-----`).
            // Any other encoding was not written by us — reject rather than
            // guess; the caller then regenerates a fresh pair.
            let Ok(PrivateKeyDer::Pkcs8(key_der)) = PrivateKeyDer::from_pem_slice(&pem) else {
                return Err(CertError::LegacyKeyDecode);
            };
            key_store::store_private_key(&entry, key_der.secret_pkcs8_der())?;
            erase_and_remove(&legacy)?;
            tracing::info!(
                "migrated the TLS private key from key.pem into the OS credential store"
            );
            Ok(MigrationOutcome::Migrated)
        }
    }
}

/// Whether [`migrate_legacy_key_file`] has anything to move. Pure, so the
/// decision is testable without an OS credential store (same pure/impure split
/// as `tls::cert_origin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationAction {
    /// Store already has the key, or there is no legacy file — nothing to move.
    Nothing,
    /// Store is empty and a legacy `key.pem` exists — move it in.
    Migrate,
}

/// What [`migrate_legacy_key_file`] actually did — for logging/tests; no caller
/// branches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationOutcome {
    /// No legacy file, and nothing to change.
    NothingToMigrate,
    /// A legacy `key.pem` was moved into the store and erased.
    Migrated,
    /// The store already held the key; a stale `key.pem` was erased unread.
    StalePlaintextRemoved,
}

/// `Migrate` iff the store has no key yet but a legacy plaintext `key.pem`
/// exists.
pub(crate) fn migration_action(store_has_key: bool, legacy_pem_present: bool) -> MigrationAction {
    if !store_has_key && legacy_pem_present {
        MigrationAction::Migrate
    } else {
        MigrationAction::Nothing
    }
}

/// Overwrite `path` with zeros (bounded at 64 KiB — a `key.pem` is ~240 bytes),
/// then delete it. A bare unlink leaves the key bytes readable on disk,
/// defeating the point of T-67; a truncate-in-place write keeps the file's
/// existing user-only ACL (confirmed empirically for
/// [`write_user_restricted_file`]'s create-restrict-write ordering).
fn erase_and_remove(path: &Path) -> Result<(), CertError> {
    if let Ok(meta) = fs::metadata(path) {
        let len = usize::try_from(meta.len().min(64 * 1024)).unwrap_or(0);
        // A failed overwrite is not fatal — the removal below is what actually
        // takes the key off disk; proceed to it regardless.
        let _ = fs::write(path, vec![0u8; len]);
    }
    fs::remove_file(path).map_err(CertError::Io)
}

/// Write `contents` to `path` behind an ACL restricted to Full Control for
/// the current user only — creating the file empty, restricting it, *then*
/// writing, so the bytes never sit on disk under the parent directory's
/// inherited (wider) ACL even briefly. Used for `geoip_maxmind.toml` (T-162,
/// [`crate::geoip_credentials::save`]) — a plaintext secret on disk as
/// explicit MVP tech debt (`SECURITY.md`).
pub(crate) fn write_user_restricted_file(path: &Path, contents: &[u8]) -> Result<(), CertError> {
    // The handle itself is unused — this call exists only to make `path`
    // exist as an empty file for `restrict_to_current_user` to ACL, before
    // any secret bytes are written to it.
    File::create(path).map_err(CertError::Io)?;
    restrict_to_current_user(path)?;
    fs::write(path, contents).map_err(CertError::Io)
}

/// Absolute path to `icacls.exe` (`%SystemRoot%\System32\icacls.exe`), never
/// a bare `PATH` lookup, per this project's standing convention for spawned
/// system processes.
fn icacls_path() -> Result<PathBuf, CertError> {
    let system_root = env::var_os("SystemRoot").ok_or(CertError::MissingSystemRoot)?;
    Ok(Path::new(&system_root).join("System32").join("icacls.exe"))
}

/// Restrict `path`'s ACL to Full Control for the current user only, via
/// `icacls.exe` — not the Windows ACL `WinAPI` directly, which is `unsafe`
/// FFI and this crate is `#![forbid(unsafe_code)]`. The grant target is the
/// bare `%USERNAME%` — confirmed empirically (not assumed) that `icacls`
/// resolves an unqualified account name against the local machine first, so
/// no `%USERDOMAIN%` lookup (and no second failure mode for it) is needed.
///
/// **Two phases, not one.** `/inheritance:r /grant:r <user>:F` alone is not
/// sufficient: `/inheritance:r` only removes *inherited* ACEs, and
/// `/grant:r` only replaces the *same principal's own* prior explicit grant
/// — it does not touch other principals' pre-existing explicit grants. This
/// was assumed sufficient on the strength of a local empirical probe (where
/// the temp file's only pre-existing ACEs happened to be inherited), but CI
/// caught the gap: on the GitHub-hosted Windows runner image, a freshly
/// created file already carries explicit (non-inherited) `SYSTEM`/
/// `Administrators`/local-admin grants, which phase one alone left in place
/// alongside the intended user. Phase two reads the ACL back and explicitly
/// `/remove:g`s every principal that isn't the target user, so the result is
/// self-correcting against whatever a given Windows image's default DACL for
/// new files happens to be, rather than hardcoding a denylist of expected
/// group names.
fn restrict_to_current_user(path: &Path) -> Result<(), CertError> {
    let icacls = icacls_path()?;
    let user = env::var("USERNAME").map_err(|_| CertError::MissingUserIdentity)?;
    let grant = format!("{user}:F");

    let status = Command::new(&icacls)
        .args([
            path.as_os_str(),
            OsStr::new("/inheritance:r"),
            OsStr::new("/grant:r"),
            OsStr::new(&grant),
        ])
        .status()
        .map_err(CertError::IcaclsSpawn)?;
    if !status.success() {
        return Err(CertError::IcaclsFailed(status.code()));
    }

    let extra_principals = other_principals(&icacls, path, &user)?;
    if extra_principals.is_empty() {
        return Ok(());
    }

    let status = Command::new(&icacls)
        .arg(path)
        .arg("/remove:g")
        .args(&extra_principals)
        .status()
        .map_err(CertError::IcaclsSpawn)?;
    if status.success() {
        Ok(())
    } else {
        Err(CertError::IcaclsFailed(status.code()))
    }
}

/// Read `path`'s current ACL via `icacls <path>` (no modify flags) and
/// return every granted principal name other than `keep`. Parses the same
/// output shape as the restriction step itself: a first line of
/// `"<path> <principal>:(perms)"`, zero or more indented continuation lines
/// of `"<principal>:(perms)"`, a blank line, then a `"Successfully
/// processed..."` summary.
fn other_principals(icacls: &Path, path: &Path, keep: &str) -> Result<Vec<String>, CertError> {
    let output = Command::new(icacls)
        .arg(path)
        .output()
        .map_err(CertError::IcaclsSpawn)?;
    if !output.status.success() {
        return Err(CertError::IcaclsFailed(output.status.code()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let path_prefix = path.display().to_string();

    let mut extra = Vec::new();
    for (index, line) in stdout.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Successfully processed") {
            continue;
        }
        let entry = if index == 0 {
            line.strip_prefix(path_prefix.as_str())
                .unwrap_or(line)
                .trim()
        } else {
            trimmed
        };
        let Some((principal, _perms)) = entry.split_once(':') else {
            continue;
        };
        // `icacls` prints the granted principal qualified with a
        // machine/domain prefix (e.g. `DESKTOP-PA\Pa`), while `keep` is the
        // bare `%USERNAME%` value used to grant it — an exact-equality
        // check here would treat our own just-granted principal as "extra"
        // and strip it, defeating the whole restriction (caught by this
        // module's own tests failing when first written this way).
        let is_kept_user = principal
            .rsplit('\\')
            .next()
            .is_some_and(|unqualified| unqualified.eq_ignore_ascii_case(keep));
        if !is_kept_user {
            extra.push(principal.to_string());
        }
    }
    Ok(extra)
}

#[cfg(test)]
mod tests {
    use super::generate_self_signed_cert;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::{FromDer, X509Certificate};

    /// Generates a cert and hands back its owned DER bytes — callers parse
    /// from that owned buffer themselves, so the parsed `X509Certificate<'_>`
    /// can borrow from a value that outlives the calling test function.
    fn generate_der() -> Vec<u8> {
        match generate_self_signed_cert() {
            Ok(ck) => ck.cert.der().to_vec(),
            Err(err) => panic!("generation must succeed: {err}"),
        }
    }

    fn parse(der: &[u8]) -> X509Certificate<'_> {
        match X509Certificate::from_der(der) {
            Ok((_, cert)) => cert,
            Err(err) => panic!("generated DER must parse as a valid X.509 certificate: {err}"),
        }
    }

    #[test]
    fn generated_cert_has_exactly_the_san_entries_spec_requires() {
        let der = generate_der();
        let cert = parse(&der);

        let san_ext = cert
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => Some(san),
                _ => None,
            })
            .unwrap_or_else(|| panic!("certificate must carry a SubjectAlternativeName extension"));

        assert_eq!(
            san_ext.general_names.len(),
            3,
            "expected exactly 3 SAN entries, got {:?}",
            san_ext.general_names
        );

        match &san_ext.general_names[0] {
            GeneralName::IPAddress(bytes) => assert_eq!(*bytes, [127, 0, 0, 1]),
            other => {
                panic!("first SAN entry must be the typed IPv4 address 127.0.0.1, got {other:?}")
            }
        }
        match &san_ext.general_names[1] {
            GeneralName::IPAddress(bytes) => {
                assert_eq!(*bytes, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            }
            other => panic!("second SAN entry must be the typed IPv6 address ::1, got {other:?}"),
        }
        match &san_ext.general_names[2] {
            GeneralName::DNSName(name) => assert_eq!(*name, "localhost"),
            other => panic!("third SAN entry must be the typed DNS name localhost, got {other:?}"),
        }
    }

    #[test]
    fn generated_cert_is_a_leaf_never_a_ca() {
        let der = generate_der();
        let cert = parse(&der);

        // `ExplicitNoCa` (not the plain `NoCa` default) makes rcgen encode the
        // `BasicConstraints` extension with `cA=FALSE` explicitly, so this
        // asserts the actual encoded bytes rather than merely the absence of
        // an extension — see this module's doc comment for why that
        // distinction matters.
        let basic_constraints = cert
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::BasicConstraints(bc) => Some(bc),
                _ => None,
            })
            .unwrap_or_else(|| {
                panic!("certificate must explicitly carry a BasicConstraints extension")
            });
        assert!(
            !basic_constraints.ca,
            "SPEC.md §2: this cert must never be a CA"
        );
        assert!(!cert.is_ca(), "SPEC.md §2: this cert must never be a CA");

        let carries_key_cert_sign = cert.extensions().iter().any(|ext| {
            matches!(
                ext.parsed_extension(),
                ParsedExtension::KeyUsage(usage) if usage.key_cert_sign()
            )
        });
        assert!(
            !carries_key_cert_sign,
            "a leaf cert must never carry the keyCertSign KeyUsage bit"
        );
    }

    #[test]
    fn generated_cert_carries_an_identifying_subject_not_rcgens_placeholder_cn() {
        let der = generate_der();
        let cert = parse(&der);

        // T-49's manual trust-store install and T-69/T-70's rotation/removal
        // all depend on a human (or a future automated uninstaller) being
        // able to recognize this cert in the OS store — rcgen's own
        // placeholder CN ("rcgen self signed cert") would not identify it as
        // belonging to this project.
        let subject = cert.subject().to_string();
        assert!(
            subject.contains("dns-quorum-filter"),
            "subject must identify this project, got {subject:?}"
        );
    }

    #[test]
    fn generated_cert_uses_the_stated_hundred_year_validity_window_not_rcgens_raw_default() {
        let der = generate_der();
        let cert = parse(&der);

        let validity = cert.validity();
        assert_eq!(
            validity.not_before.timestamp(),
            rcgen::date_time_ymd(2020, 1, 1).unix_timestamp(),
            "not_before must be the stated 2020-01-01 anchor, not rcgen's raw 1975 default"
        );
        assert_eq!(
            validity.not_after.timestamp(),
            rcgen::date_time_ymd(2120, 1, 1).unix_timestamp(),
            "not_after must be the stated 2120-01-01 anchor, not rcgen's raw 4096 default"
        );
    }

    #[test]
    fn cert_pem_decodes_to_the_same_certificate_as_the_der_it_was_derived_from() {
        let certified_key = match generate_self_signed_cert() {
            Ok(ck) => ck,
            Err(err) => panic!("generation must succeed: {err}"),
        };

        let pem_text = certified_key.cert.pem();
        let (_, pem) = match x509_parser::pem::parse_x509_pem(pem_text.as_bytes()) {
            Ok(parsed) => parsed,
            Err(err) => panic!("cert.pem() must produce a valid PEM block: {err}"),
        };

        assert_eq!(
            pem.contents,
            certified_key.cert.der().as_ref(),
            "PEM-decoded DER must match cert.der() byte-for-byte"
        );
    }

    #[test]
    fn write_user_restricted_file_creates_a_file_restricted_to_the_current_user_only() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let path = dir.path().join("secret.toml");

        if let Err(err) = super::write_user_restricted_file(&path, b"placeholder-secret-bytes") {
            panic!("write_user_restricted_file must succeed: {err}");
        }

        match std::fs::read(&path) {
            Ok(contents) => assert_eq!(contents, b"placeholder-secret-bytes"),
            Err(err) => panic!("written file must be readable back: {err}"),
        }

        // Real `icacls` read-back, not a trust-the-call-succeeded assertion —
        // same standard the SAN/`IsCa` tests hold `rcgen` to.
        let output = match std::process::Command::new("icacls").arg(&path).output() {
            Ok(output) => output,
            Err(err) => panic!("icacls must be runnable to verify the ACL: {err}"),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);

        let username = match std::env::var("USERNAME") {
            Ok(name) => name,
            Err(err) => panic!("USERNAME must be set on Windows: {err}"),
        };

        // Structural check, not a substring denylist: a denylist of group
        // names (`"SYSTEM"`, `"Everyone"`, ...) can't distinguish "no
        // residual grant" from "the string just doesn't happen to appear",
        // and would false-fail on a machine whose hostname/account name
        // happens to contain one of those words. `icacls`'s own output shape
        // (confirmed empirically against a real restricted file) is: one ACE
        // line per grant, a blank line, then a "Successfully processed..."
        // summary — so counting non-blank, non-summary lines is a direct
        // proof of "exactly one grant," which a substring check is not.
        let ace_lines: Vec<&str> = stdout
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.contains("Successfully processed"))
            .collect();
        assert_eq!(
            ace_lines.len(),
            1,
            "expected exactly one ACE after restriction, got: {stdout}"
        );
        assert!(
            ace_lines[0].contains(&format!("{username}:(F)")),
            "expected the sole ACE to grant the current user Full Control, got: {stdout}"
        );
    }

    #[test]
    fn migration_action_moves_only_when_store_empty_and_legacy_present() {
        use super::{migration_action, MigrationAction};
        assert_eq!(migration_action(false, true), MigrationAction::Migrate);
        assert_eq!(migration_action(false, false), MigrationAction::Nothing);
        assert_eq!(migration_action(true, true), MigrationAction::Nothing);
        assert_eq!(migration_action(true, false), MigrationAction::Nothing);
    }

    #[test]
    fn erase_and_remove_zeroes_then_deletes() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let path = dir.path().join("key.pem");
        if let Err(err) = std::fs::write(&path, b"-----BEGIN PRIVATE KEY-----\nsecret\n") {
            panic!("must be able to write the fixture: {err}");
        }
        if let Err(err) = super::erase_and_remove(&path) {
            panic!("erase_and_remove must succeed: {err}");
        }
        assert!(!path.exists(), "file must be gone after erase_and_remove");
    }

    #[test]
    fn restrict_to_current_user_strips_pre_existing_explicit_grants_to_other_principals() {
        // Reproduces what CI caught and a local dev-machine probe didn't:
        // on some Windows images a freshly created file already carries
        // explicit (non-inherited) SYSTEM/Administrators grants, which
        // `/inheritance:r` (only strips *inherited* ACEs) plus a bare
        // `/grant:r` (only replaces the *same* principal's own prior grant)
        // leaves untouched. Simulate that starting condition explicitly
        // rather than relying on it happening to occur on this machine.
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let key_path = dir.path().join("key.pem");
        if let Err(err) = std::fs::File::create(&key_path) {
            panic!("must be able to create the file: {err}");
        }

        let icacls = match super::icacls_path() {
            Ok(path) => path,
            Err(err) => panic!("must be able to locate icacls.exe: {err}"),
        };
        for principal in ["SYSTEM", "Administrators"] {
            let status = std::process::Command::new(&icacls)
                .arg(&key_path)
                .arg("/grant")
                .arg(format!("{principal}:F"))
                .status();
            match status {
                Ok(status) if status.success() => {}
                other => panic!("setup: granting {principal} must succeed, got: {other:?}"),
            }
        }

        if let Err(err) = super::restrict_to_current_user(&key_path) {
            panic!("restrict_to_current_user must succeed: {err}");
        }

        let output = match std::process::Command::new(&icacls).arg(&key_path).output() {
            Ok(output) => output,
            Err(err) => panic!("icacls must be runnable to verify the ACL: {err}"),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let username = match std::env::var("USERNAME") {
            Ok(name) => name,
            Err(err) => panic!("USERNAME must be set on Windows: {err}"),
        };
        let ace_lines: Vec<&str> = stdout
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.contains("Successfully processed"))
            .collect();
        assert_eq!(
            ace_lines.len(),
            1,
            "expected the pre-existing SYSTEM/Administrators grants to be stripped, got: {stdout}"
        );
        assert!(
            ace_lines[0].contains(&format!("{username}:(F)")),
            "expected the sole remaining ACE to grant the current user, got: {stdout}"
        );
    }
}
