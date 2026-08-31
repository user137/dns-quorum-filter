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
//! `key.pem` is copied once into the store by [`migrate_legacy_key_into_store`]
//! and then erased by [`discard_legacy_key_file`] — but only after the stored
//! key has been proven to load against `cert.pem`, so a mismatched plaintext
//! key is never destroyed before it's known redundant. Secret-file scrubbing
//! ([`key_store::overwrite_with_zeros`] / [`key_store::erase_and_remove`]) now
//! lives with the secret-store module. The `icacls`-based ACL helpers that
//! guarded the old plaintext files went out with the last of those files when
//! T-163 moved the `MaxMind` credentials into the OS store too — nothing this
//! crate writes to disk is secret any more.
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

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
    key_store::store_secret(&key_store::tls_key_entry(&dir), &key_der)?;
    signing_key.zeroize();

    Ok(CertFiles { cert_path })
}

/// Pick a pre-T-67 plaintext `key.pem` in `dir` up into the OS credential store,
/// exactly once: if the store has no key yet but the file exists, decode and
/// store it. This function **never deletes `key.pem`** — that is
/// [`discard_legacy_key_file`]'s job, and the caller only runs it once the
/// stored key has been proven to load against `cert.pem`, so an
/// unread/mismatched plaintext key is never destroyed before it's known to be
/// redundant. See [`migration_action`] for the decision.
///
/// # Errors
///
/// [`CertError::KeyStore`] if the credential store rejects a read or write;
/// [`CertError::LegacyKeyDecode`] if `key.pem` exists but doesn't parse (left
/// in place); [`CertError::Io`] if reading the file fails.
pub(crate) fn migrate_legacy_key_into_store(dir: &Path) -> Result<MigrationOutcome, CertError> {
    let entry = key_store::tls_key_entry(dir);
    let legacy = dir.join("key.pem");
    let store_has_key = key_store::load_secret(&entry)?.is_some();

    match migration_action(store_has_key, legacy.exists()) {
        MigrationAction::Nothing => {
            if store_has_key && legacy.exists() {
                tracing::warn!(
                    "a plaintext key.pem is present but the OS credential store already holds a \
                     private key; it will be erased once the stored key is confirmed usable"
                );
                return Ok(MigrationOutcome::StalePlaintextPresent);
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
            key_store::store_secret(&entry, key_der.secret_pkcs8_der())?;
            tracing::info!("copied the TLS private key from key.pem into the OS credential store");
            Ok(MigrationOutcome::Migrated)
        }
    }
}

/// Erase and remove `dir`'s `key.pem` if present — best-effort, never fatal.
/// The caller ([`crate::tls::load_or_generate_server_config`]) runs this **only
/// after** a `ServerConfig` has been built from `cert.pem` + the stored key, so
/// the plaintext file is provably redundant by the time it is destroyed.
pub(crate) fn discard_legacy_key_file(dir: &Path) {
    let legacy = dir.join("key.pem");
    if !legacy.exists() {
        return;
    }
    match key_store::erase_and_remove(&legacy) {
        Ok(()) => tracing::info!("removed the now-redundant plaintext key.pem"),
        // Not fatal: the key is already in the store and in use. Surface it so
        // an operator can delete the file by hand.
        Err(err) => tracing::warn!("could not remove the redundant key.pem: {err}"),
    }
}

/// Whether [`migrate_legacy_key_into_store`] has a key to copy. Pure, so the
/// decision is testable without an OS credential store (same pure/impure split
/// as `tls::cert_origin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationAction {
    /// Store already has the key, or there is no legacy file — nothing to copy.
    Nothing,
    /// Store is empty and a legacy `key.pem` exists — copy it in.
    Migrate,
}

/// What [`migrate_legacy_key_into_store`] did — for logging/tests; no caller
/// branches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationOutcome {
    /// No legacy file, and nothing to change.
    NothingToMigrate,
    /// A legacy `key.pem` was copied into the store (not yet deleted).
    Migrated,
    /// The store already held a key; a stale `key.pem` is present, to be
    /// discarded after the stored key is confirmed usable.
    StalePlaintextPresent,
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
    fn migration_action_moves_only_when_store_empty_and_legacy_present() {
        use super::{migration_action, MigrationAction};
        assert_eq!(migration_action(false, true), MigrationAction::Migrate);
        assert_eq!(migration_action(false, false), MigrationAction::Nothing);
        assert_eq!(migration_action(true, true), MigrationAction::Nothing);
        assert_eq!(migration_action(true, false), MigrationAction::Nothing);
    }
}
