//! Certificate rotation (SPEC.md §2, T-69) — re-issue the local `DoH` leaf
//! certificate and refresh its `CurrentUser\Root` trust-store entry without
//! accumulating stale ones.
//!
//! This module owns no new primitive. It is purely the ordered composition of
//! [`cert::generate_self_signed_cert`], [`trust_store::uninstall`],
//! [`cert::write_cert_and_key_to_app_data`] and [`trust_store::ensure_installed`]
//! — the piece `TASKS.md`'s T-69 note calls "rotation itself calling
//! `uninstall()` automatically, not a new removal primitive."
//!
//! **The step order is forced, not a preference.** [`trust_store::uninstall`]
//! removes every `CurrentUser\Root` entry under [`cert::CERT_COMMON_NAME`], and
//! every certificate this project generates carries that same `CommonName` — so
//! the old entry must be cleared *before* the new certificate is written and
//! installed, never after (which would delete the just-installed new one too).
//! Generation runs first only because it is pure and in-memory: a generation
//! failure then aborts with no disk or trust-store change at all. If generation
//! and clearing both succeed but a later step fails, "Встановити сертифікат"
//! (the tray's install action) reinstalls the still-on-disk original — a clean
//! rollback to the pre-rotation state.
//!
//! **Partial-failure states, by step:**
//! - generate fails → nothing changed.
//! - clear fails → nothing changed; the existing certificate is still trusted.
//! - persist fails → the old `CurrentUser\Root` entry is gone and `cert.pem`
//!   holds a new certificate, but the OS credential store still holds the
//!   *previous* private key (or [`cert::write_cert_and_key_to_app_data`]'s
//!   store write half-completed).
//!   `cert.pem` and the stored key are a mismatched pair; the next
//!   `dnsqb-service` start regenerates both (`tls`'s `CertOrigin::Replaced`
//!   path), after which the tray's install action trusts that regenerated
//!   certificate.
//! - install fails → a fresh, valid `cert.pem` + stored-key pair exists but is
//!   not trusted; the tray's install action fixes it.
//!
//! Because generation needs no input and persistence creates both files,
//! rotation works even where `dnsqb-service` has never run and no `cert.pem`
//! exists yet — it does **not** share [`trust_store::local_cert_thumbprint`]'s
//! "start the service once first" precondition.
//!
//! The mutating steps shell out to `certutil`/`icacls`; like `trust_store.rs`'s
//! own [`trust_store::uninstall`]/[`trust_store::ensure_installed`], the public
//! [`rotate_certificate`] entry point is **never called from an automated
//! test**. [`rotate_with`] takes the four steps as closures so the ordering and
//! partial-failure logic is unit-tested without touching a real trust store.

use std::fmt;
use std::path::Path;

use rcgen::{CertifiedKey, KeyPair};

use crate::cert::{self, CertError, CertFiles};
use crate::trust_store::{self, TrustStoreError, TrustStoreOutcome};

/// Result of a successful [`rotate_certificate`], for the caller to display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationReport {
    /// Whether [`trust_store::ensure_installed`] had to run `certutil -addstore`
    /// ([`TrustStoreOutcome::Installed`]) or found the freshly written
    /// certificate already trusted ([`TrustStoreOutcome::AlreadyInstalled`] —
    /// only reachable if an identical thumbprint somehow survived the clear
    /// step, e.g. a concurrent reinstall).
    pub install_outcome: TrustStoreOutcome,
}

impl fmt::Display for RotationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "certificate reissued: new key generated, old CurrentUser\\Root \
             entries removed, new certificate {:?}. Restart dnsqb-service for \
             the new certificate to take effect.",
            self.install_outcome
        )
    }
}

/// Why [`rotate_certificate`] stopped. Each variant names the step that failed
/// and the resulting on-disk / trust-store state — deliberately a state, not a
/// remediation verb, and in English: the tray's confirm dialog and its
/// success/failure dialog carry the user-facing (Ukrainian) guidance.
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    /// Step 1 — generating the new self-signed certificate failed. Nothing
    /// changed: no disk write, no trust-store change.
    #[error("failed to generate the new certificate (nothing changed): {0}")]
    Generate(#[source] CertError),
    /// Step 2 — clearing this project's existing `CurrentUser\Root` entries
    /// failed. Nothing changed; the existing certificate is still trusted and
    /// `cert.pem`/`key.pem` are untouched.
    #[error(
        "failed to clear the old trust-store entries \
         (nothing changed; the existing certificate is still trusted): {0}"
    )]
    TrustStoreClear(#[source] TrustStoreError),
    /// Step 3 — writing the new `cert.pem` / storing the new key failed. The old
    /// `CurrentUser\Root` entries are already gone and `cert.pem` holds a new
    /// certificate, but the stored key is still the previous one (or the store
    /// write half-completed) — a mismatched pair, unusable until the next
    /// `dnsqb-service` start regenerates both.
    #[error(
        "failed to persist the new certificate \
         (old trust-store entries already removed; cert.pem and the stored key are \
         now a mismatched pair until dnsqb-service regenerates them on next start): {0}"
    )]
    Persist(#[source] CertError),
    /// Step 4 — installing the new certificate into `CurrentUser\Root` failed.
    /// A fresh, valid `cert.pem` + stored-key pair exists but is not trusted.
    #[error(
        "failed to install the new certificate \
         (a valid cert.pem and stored key were written but are not trusted): {0}"
    )]
    Install(#[source] TrustStoreError),
}

/// Re-issue the local `DoH` leaf certificate and refresh its `CurrentUser\Root`
/// trust-store entry. See this module's documentation for the fixed step order
/// and the per-step partial-failure states.
///
/// **Never call this from an automated test** — steps 2 and 4 mutate the real
/// `CurrentUser\Root` store, the same rule `trust_store.rs`'s own mutating
/// functions carry. [`rotate_with`] is the unit-testable core.
///
/// # Errors
///
/// Returns the [`RotationError`] variant for whichever of the four steps failed;
/// each variant's message states the resulting on-disk and trust-store state.
pub fn rotate_certificate() -> Result<RotationReport, RotationError> {
    rotate_with(
        cert::generate_self_signed_cert,
        trust_store::uninstall,
        cert::write_cert_and_key_to_app_data,
        trust_store::ensure_installed,
    )
}

/// The ordered rotation itself, with each step injected so a test can drive it
/// without a real certificate store (mirrors `trust_store::uninstall_loop`).
fn rotate_with<G, U, P, I>(
    generate: G,
    clear_trust_store: U,
    persist: P,
    install: I,
) -> Result<RotationReport, RotationError>
where
    G: FnOnce() -> Result<CertifiedKey<KeyPair>, CertError>,
    U: FnOnce() -> Result<(), TrustStoreError>,
    P: FnOnce(CertifiedKey<KeyPair>) -> Result<CertFiles, CertError>,
    I: FnOnce(&Path) -> Result<TrustStoreOutcome, TrustStoreError>,
{
    let certified_key = generate().map_err(RotationError::Generate)?;
    clear_trust_store().map_err(RotationError::TrustStoreClear)?;
    let cert_files = persist(certified_key).map_err(RotationError::Persist)?;
    let install_outcome = install(&cert_files.cert_path).map_err(RotationError::Install)?;
    Ok(RotationReport { install_outcome })
}

#[cfg(test)]
mod tests {
    use super::{rotate_with, RotationError, RotationReport};
    use crate::cert::{generate_self_signed_cert, CertError, CertFiles};
    use crate::trust_store::{TrustStoreError, TrustStoreOutcome};
    use rcgen::{CertifiedKey, KeyPair};
    use std::cell::RefCell;
    use std::path::PathBuf;

    fn fake_cert_files() -> CertFiles {
        CertFiles {
            cert_path: PathBuf::from("test-only/cert.pem"),
        }
    }

    fn real_key() -> CertifiedKey<KeyPair> {
        match generate_self_signed_cert() {
            Ok(ck) => ck,
            Err(err) => panic!("generation must succeed in a test fixture: {err}"),
        }
    }

    #[test]
    fn steps_run_in_order_generate_clear_persist_install() {
        let log = RefCell::new(Vec::new());
        let result = rotate_with(
            || {
                log.borrow_mut().push("generate");
                Ok(real_key())
            },
            || {
                log.borrow_mut().push("clear");
                Ok(())
            },
            |_ck| {
                log.borrow_mut().push("persist");
                Ok(fake_cert_files())
            },
            |_path| {
                log.borrow_mut().push("install");
                Ok(TrustStoreOutcome::Installed)
            },
        );
        if let Err(err) = result {
            panic!("happy path must succeed: {err}");
        }
        assert_eq!(*log.borrow(), ["generate", "clear", "persist", "install"]);
    }

    #[test]
    fn happy_path_report_names_the_install_outcome() {
        let report = match rotate_with(
            || Ok(real_key()),
            || Ok(()),
            |_ck| Ok(fake_cert_files()),
            |_path| Ok(TrustStoreOutcome::Installed),
        ) {
            Ok(report) => report,
            Err(err) => panic!("happy path must succeed: {err}"),
        };
        assert!(
            report.to_string().contains("Installed"),
            "report must name the install outcome: {report}"
        );
    }

    #[test]
    fn generate_failure_aborts_before_any_other_step() {
        let log = RefCell::new(Vec::new());
        let result = rotate_with(
            || {
                log.borrow_mut().push("generate");
                Err(CertError::MissingLocalAppData)
            },
            || {
                log.borrow_mut().push("clear");
                Ok(())
            },
            |_ck| {
                log.borrow_mut().push("persist");
                Ok(fake_cert_files())
            },
            |_path| {
                log.borrow_mut().push("install");
                Ok(TrustStoreOutcome::Installed)
            },
        );
        assert!(
            matches!(result, Err(RotationError::Generate(_))),
            "expected Generate, got {result:?}"
        );
        assert_eq!(*log.borrow(), ["generate"]);
    }

    #[test]
    fn clear_failure_leaves_persist_and_install_uncalled() {
        let log = RefCell::new(Vec::new());
        let result = rotate_with(
            || {
                log.borrow_mut().push("generate");
                Ok(real_key())
            },
            || {
                log.borrow_mut().push("clear");
                Err(TrustStoreError::MissingSystemRoot)
            },
            |_ck| {
                log.borrow_mut().push("persist");
                Ok(fake_cert_files())
            },
            |_path| {
                log.borrow_mut().push("install");
                Ok(TrustStoreOutcome::Installed)
            },
        );
        match result {
            Err(RotationError::TrustStoreClear(_)) => {}
            other => panic!("expected TrustStoreClear, got {other:?}"),
        }
        assert_eq!(*log.borrow(), ["generate", "clear"]);
    }

    #[test]
    fn persist_failure_leaves_install_uncalled_and_names_the_mismatched_pair() {
        let log = RefCell::new(Vec::new());
        let result = rotate_with(
            || Ok(real_key()),
            || Ok(()),
            |_ck| {
                log.borrow_mut().push("persist");
                Err(CertError::MissingLocalAppData)
            },
            |_path| {
                log.borrow_mut().push("install");
                Ok(TrustStoreOutcome::Installed)
            },
        );
        match result {
            Err(RotationError::Persist(_)) => {}
            other => panic!("expected Persist, got {other:?}"),
        }
        assert_eq!(*log.borrow(), ["persist"]);
        let message = RotationError::Persist(CertError::MissingLocalAppData).to_string();
        assert!(
            message.contains("mismatched pair"),
            "Persist message must name the mismatched-pair state: {message}"
        );
    }

    #[test]
    fn install_failure_reports_pair_written_but_untrusted() {
        let result = rotate_with(
            || Ok(real_key()),
            || Ok(()),
            |_ck| Ok(fake_cert_files()),
            |_path| Err(TrustStoreError::MissingSystemRoot),
        );
        match result {
            Err(RotationError::Install(_)) => {}
            other => panic!("expected Install, got {other:?}"),
        }
        let message = RotationError::Install(TrustStoreError::MissingSystemRoot).to_string();
        assert!(
            message.contains("not trusted"),
            "Install message must say the pair is not trusted: {message}"
        );
    }

    #[test]
    fn all_library_facing_messages_are_ascii_english() {
        let messages = [
            RotationError::Generate(CertError::MissingLocalAppData).to_string(),
            RotationError::TrustStoreClear(TrustStoreError::MissingSystemRoot).to_string(),
            RotationError::Persist(CertError::MissingLocalAppData).to_string(),
            RotationError::Install(TrustStoreError::MissingSystemRoot).to_string(),
            RotationReport {
                install_outcome: TrustStoreOutcome::Installed,
            }
            .to_string(),
            RotationReport {
                install_outcome: TrustStoreOutcome::AlreadyInstalled,
            }
            .to_string(),
        ];
        for message in messages {
            assert!(
                message.is_ascii(),
                "library-facing text must be ASCII/English: {message}"
            );
        }
    }
}
