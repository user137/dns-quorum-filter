//! `rustls::ServerConfig` construction from the persisted cert/key (T-142) —
//! the load-vs-regenerate decision `cert::write_cert_and_key_to_app_data`
//! (T-50) explicitly left for "the future listener-wiring caller." Actual
//! TCP accept / request dispatch (`hyper`, `DoH` GET/POST parsing → `pipeline::
//! handle_query`) is a separate, later task — this module only produces the
//! TLS material a real listener will need.
//!
//! Uses `rustls::pki_types::{CertificateDer, PrivateKeyDer}::from_pem_slice`
//! (re-exported by `rustls` itself — confirmed via `rustls`'s `lib.rs`,
//! `pub mod pki_types { pub use pki_types::*; }` — gated on `rustls`'s own
//! `std` feature, which this crate already enables) rather than a separate
//! `pem` crate dependency: one less place two PEM parsers could disagree,
//! and `PrivateKeyDer::from_pem_slice` reads the PEM tag itself
//! (`"PRIVATE KEY"` → Pkcs8, `"RSA PRIVATE KEY"` → Pkcs1, `"EC PRIVATE
//! KEY"` → Sec1) instead of this module assuming a fixed encoding for
//! whatever ends up on disk.
//!
//! Builds every `ServerConfig` via `builder_with_provider(aws_lc_rs::
//! default_provider())`, never the plain `ServerConfig::builder()`. The
//! plain form resolves the process-default crypto provider from whichever
//! `rustls` crypto-backend crate features are enabled across the *whole*
//! dependency graph, and `.expect()`s that resolution to be unambiguous
//! (confirmed by reading `rustls` 0.23.43's own source,
//! `CryptoProvider::get_default_or_install_from_crate_features`) — true
//! today (only `aws_lc_rs` is active in this workspace, confirmed via
//! `cargo tree -f "{p} {f}" -p rustls`), but that's a fact about the current
//! dependency graph, not something this module's own code proves. A future
//! dependency enabling `ring` anywhere in the graph would silently turn that
//! `.expect()` into a runtime panic on the `DoH` server's startup path.
//! Naming the provider explicitly makes this module correct independent of
//! what else the crate graph does — the same "provable from the line
//! itself" standard this project already holds bounds/index checks to.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{CertifiedKey, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

use crate::cert::{self, CertError};
use crate::paths;

/// Errors producing a [`ServerConfig`] from the local certificate.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Generating or persisting a fresh certificate failed.
    #[error("failed to generate or persist certificate: {0}")]
    Cert(#[from] CertError),
    /// Reading `cert.pem`/`key.pem` back off disk failed.
    #[error("failed to read {path:?}: {source}")]
    Io {
        /// The file that failed to read.
        path: PathBuf,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// `cert.pem`/`key.pem` did not contain a well-formed PEM block of the
    /// expected kind.
    #[error("{path:?} is not a valid PEM file: {source}")]
    Pem {
        /// The file that failed to parse.
        path: PathBuf,
        /// The underlying PEM-decode error.
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    /// `rustls` rejected the certificate/key pair — e.g. the key's
    /// `SubjectPublicKeyInfo` does not match the certificate's.
    #[error("TLS configuration rejected the certificate/key: {0}")]
    Rustls(#[from] rustls::Error),
    /// `%LOCALAPPDATA%` is not set — can't resolve the app-data directory to
    /// look for a persisted certificate. Not `#[from] paths::PathsError` —
    /// that type is `pub(crate)` (same `private_interfaces` constraint
    /// `cert::CertError` already documents for the same reason).
    #[error("%LOCALAPPDATA% environment variable is not set")]
    MissingLocalAppData,
}

/// Build a [`ServerConfig`] from an in-memory freshly generated cert/key —
/// pure, no filesystem involved. Takes a **shared borrow**: both
/// `cert.der()` and `signing_key.serialize_der()` are non-consuming
/// (confirmed by reading `rcgen` 0.14.9's source), so the caller can still
/// hand the owned `certified_key` to
/// [`cert::write_cert_and_key_to_app_data`] afterward.
pub(crate) fn server_config_from_certified_key(
    certified_key: &CertifiedKey<KeyPair>,
) -> Result<ServerConfig, TlsError> {
    let cert_der = certified_key.cert.der().clone();
    // rcgen 0.14.9's `KeyPair::serialize_der()`/`serialize_pem()` are
    // PKCS#8 (confirmed by reading `key_pair.rs`'s doc comments and its own
    // `PrivatePkcs8KeyDer` `From` impl), never PKCS#1/SEC1 — safe to tag
    // directly here rather than round-tripping through PEM just to let the
    // tag be read back, unlike the on-disk load path below where the file's
    // actual header must be trusted instead of assumed.
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified_key.signing_key.serialize_der(),
    ));
    build_server_config(vec![cert_der], key_der)
}

/// Load `cert.pem`/`key.pem` from `dir` and build a [`ServerConfig`] — pure,
/// parameterized by directory (mirrors `paths.rs`'s own pure/impure split
/// for testability) so tests don't need to touch the real app-data
/// directory. Any missing/unreadable/unparseable file, or a `rustls`
/// rejection, is `Err` — callers decide what "no usable certificate" means;
/// this function doesn't guess.
pub(crate) fn load_server_config_from_dir(dir: &Path) -> Result<ServerConfig, TlsError> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    let cert_bytes = std::fs::read(&cert_path).map_err(|source| TlsError::Io {
        path: cert_path.clone(),
        source,
    })?;
    let cert_der = CertificateDer::from_pem_slice(&cert_bytes).map_err(|source| TlsError::Pem {
        path: cert_path,
        source,
    })?;

    let key_bytes = std::fs::read(&key_path).map_err(|source| TlsError::Io {
        path: key_path.clone(),
        source,
    })?;
    let key_der = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|source| TlsError::Pem {
        path: key_path,
        source,
    })?;

    build_server_config(vec![cert_der], key_der)
}

/// Shared builder tail for both the fresh-generation and load-from-disk
/// paths — see this module's own doc comment for why the crypto provider is
/// named explicitly (`builder_with_provider`) rather than relying on
/// `ServerConfig::builder()`'s ambient crate-feature resolution.
fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;
    // Without an ALPN offer, the handshake completes with no protocol
    // selected and a strict client's HTTP/2 negotiation isn't guaranteed to
    // land predictably (T-143) — h2 preferred, http/1.1 as fallback, matching
    // hyper-util's `auto` builder's own ability to serve either.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Where this run's certificate came from — extracted out of
/// [`load_or_generate_server_config`] as a pure decision so the
/// user-safety-relevant branch (an existing certificate being silently
/// replaced) is provable by a test, not just asserted in a doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertOrigin {
    /// Loaded from disk — no regeneration needed.
    Loaded,
    /// `cert.pem`/`key.pem` didn't exist yet — first run.
    GeneratedFirstRun,
    /// `cert.pem`/`key.pem` existed but couldn't be used, so they were
    /// regenerated and overwritten. SPEC.md's user-safety principle: this
    /// must be visible, not silent — it could mean a user's T-49 manual
    /// trust-store install is about to be invalidated.
    Replaced,
}

/// `load_succeeded` alone decides `Loaded` vs. not: a load can only succeed
/// if the files existed and parsed, so `existing_files_present` only
/// distinguishes the two failure origins.
fn cert_origin(existing_files_present: bool, load_succeeded: bool) -> CertOrigin {
    match (existing_files_present, load_succeeded) {
        (_, true) => CertOrigin::Loaded,
        (true, false) => CertOrigin::Replaced,
        (false, false) => CertOrigin::GeneratedFirstRun,
    }
}

/// Load the certificate persisted at `%LOCALAPPDATA%\dns-quorum-filter\`, or
/// generate and persist a fresh one if none exists or the existing one
/// can't be used (SPEC.md §2; T-50 left this decision to "the future
/// listener-wiring caller" — this is that caller). See [`CertOrigin`] for
/// the decision logging is based on.
///
/// Not directly unit-tested against the real app-data path — same
/// reasoning as `paths::app_data_dir` and
/// `cert::write_cert_and_key_to_app_data` themselves, both already
/// untested for the same "hardcoded real path" reason.
/// [`server_config_from_certified_key`], [`load_server_config_from_dir`],
/// and [`cert_origin`] carry the actual test coverage for the logic this
/// function orchestrates.
///
/// # Errors
///
/// Returns [`TlsError`] if the app-data directory can't be resolved,
/// generating/persisting a fresh certificate fails, or `rustls` rejects the
/// resulting certificate/key pair.
pub fn load_or_generate_server_config() -> Result<ServerConfig, TlsError> {
    let dir = paths::app_data_dir().map_err(|_| TlsError::MissingLocalAppData)?;
    let existing_files_present = dir.join("cert.pem").exists() && dir.join("key.pem").exists();
    let load_result = load_server_config_from_dir(&dir);

    match cert_origin(existing_files_present, load_result.is_ok()) {
        CertOrigin::Loaded => tracing::info!("using existing TLS certificate"),
        CertOrigin::GeneratedFirstRun => {
            tracing::info!("no existing certificate found, generating one (first run)");
        }
        CertOrigin::Replaced => {
            let load_err = load_result.as_ref().err().map(ToString::to_string);
            tracing::warn!("existing certificate could not be used, regenerating: {load_err:?}");
        }
    }

    if let Ok(config) = load_result {
        Ok(config)
    } else {
        let certified_key = cert::generate_self_signed_cert()?;
        let config = server_config_from_certified_key(&certified_key)?;
        cert::write_cert_and_key_to_app_data(certified_key)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cert_origin, load_server_config_from_dir, server_config_from_certified_key, CertOrigin,
        TlsError,
    };
    use crate::cert::generate_self_signed_cert;
    use rcgen::CertifiedKey;

    #[test]
    fn cert_origin_is_loaded_whenever_load_succeeds_regardless_of_existing_files() {
        assert_eq!(cert_origin(true, true), CertOrigin::Loaded);
        assert_eq!(cert_origin(false, true), CertOrigin::Loaded);
    }

    #[test]
    fn cert_origin_is_first_run_when_no_files_existed_and_load_failed() {
        assert_eq!(cert_origin(false, false), CertOrigin::GeneratedFirstRun);
    }

    #[test]
    fn cert_origin_is_replaced_when_files_existed_but_load_failed() {
        // The safety-relevant branch: an on-disk cert existed but couldn't
        // be used, so it's about to be silently overwritten unless the
        // caller logs a `warn!` distinct from the ordinary first-run case.
        assert_eq!(cert_origin(true, false), CertOrigin::Replaced);
    }

    #[test]
    fn server_config_advertises_h2_then_http1_1_via_alpn() {
        let certified_key = match generate_self_signed_cert() {
            Ok(ck) => ck,
            Err(err) => panic!("generation must succeed: {err}"),
        };
        let config = match server_config_from_certified_key(&certified_key) {
            Ok(config) => config,
            Err(err) => panic!("a matching cert/key pair must build a ServerConfig: {err}"),
        };
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn server_config_builds_from_a_freshly_generated_matching_cert_and_key() {
        let certified_key = match generate_self_signed_cert() {
            Ok(ck) => ck,
            Err(err) => panic!("generation must succeed: {err}"),
        };
        if let Err(err) = server_config_from_certified_key(&certified_key) {
            panic!("a matching cert/key pair must build a ServerConfig: {err}");
        }
    }

    #[test]
    fn server_config_rejects_a_mismatched_cert_and_key_pair() {
        let a = match generate_self_signed_cert() {
            Ok(ck) => ck,
            Err(err) => panic!("generation must succeed: {err}"),
        };
        let b = match generate_self_signed_cert() {
            Ok(ck) => ck,
            Err(err) => panic!("generation must succeed: {err}"),
        };
        // Cross-paired on purpose: `a`'s cert with `b`'s key. rustls's
        // `with_single_cert` verifies the key's SubjectPublicKeyInfo matches
        // the cert's - this proves this function actually surfaces that
        // check, not just that it succeeds for a self-consistent pair.
        let mismatched = CertifiedKey {
            cert: a.cert,
            signing_key: b.signing_key,
        };
        match server_config_from_certified_key(&mismatched) {
            Err(TlsError::Rustls(_)) => {}
            other => panic!("mismatched cert/key must be rejected by rustls, got: {other:?}"),
        }
    }

    #[test]
    fn load_server_config_from_dir_succeeds_against_freshly_written_pem_files() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let certified_key = match generate_self_signed_cert() {
            Ok(ck) => ck,
            Err(err) => panic!("generation must succeed: {err}"),
        };
        // Written directly, bypassing `cert::write_cert_and_key_to_app_data`'s
        // ACL-restriction step entirely - not needed to prove the *load*
        // path, and avoids a slow `icacls` call in this test.
        if let Err(err) = std::fs::write(dir.path().join("cert.pem"), certified_key.cert.pem()) {
            panic!("must be able to write cert.pem: {err}");
        }
        if let Err(err) = std::fs::write(
            dir.path().join("key.pem"),
            certified_key.signing_key.serialize_pem(),
        ) {
            panic!("must be able to write key.pem: {err}");
        }

        if let Err(err) = load_server_config_from_dir(dir.path()) {
            panic!("loading a freshly written matching cert/key must succeed: {err}");
        }
    }

    #[test]
    fn load_server_config_from_dir_fails_when_no_files_exist() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        assert!(matches!(
            load_server_config_from_dir(dir.path()),
            Err(TlsError::Io { .. })
        ));
    }

    #[test]
    fn load_server_config_from_dir_fails_on_corrupt_pem_content() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        if let Err(err) = std::fs::write(dir.path().join("cert.pem"), b"not a pem file") {
            panic!("must be able to write cert.pem: {err}");
        }
        if let Err(err) = std::fs::write(dir.path().join("key.pem"), b"not a pem file") {
            panic!("must be able to write key.pem: {err}");
        }
        assert!(matches!(
            load_server_config_from_dir(dir.path()),
            Err(TlsError::Pem { .. })
        ));
    }
}
