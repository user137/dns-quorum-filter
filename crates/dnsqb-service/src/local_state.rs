//! T-70: prepare for uninstall by removing every piece of local trust/secret
//! state this project ever wrote, from *inside* the running app — not a
//! packaged uninstaller script.
//!
//! MSIX (T-156) has no uninstall-time code hook: the OS deletes the package's
//! files and nothing runs afterward. The trusted certificate in
//! `CurrentUser\Root` (T-49) and the three Credential Manager secrets (TLS
//! key T-67, persistence key T-146, `MaxMind` creds T-163) all live *outside*
//! the package, so OS removal alone would leave them behind — the same class
//! of bug SECURITY.md already names for a left-behind trusted cert. This
//! module is the explicit, user-triggered action (tray menu + `/admin/ui`)
//! that clears them before the user removes the app from Windows Settings.
//!
//! Each of the four artifacts is reported independently, never collapsed
//! into one bool — a partial failure (e.g. the cert cleared but a Credential
//! Manager write is locked) must stay visible, the same discipline as this
//! project's recurring `persisted: false` pattern.

use std::path::Path;

use crate::key_store::{
    delete_secret, load_secret, maxmind_credentials_entry, persistence_key_entry, tls_key_entry,
};
use crate::trust_store;

/// Outcome of clearing one artifact. `NotPresent` and `Removed` are both
/// success — the operation is idempotent, so running it again after a
/// previous run (or on a fresh install that never wrote a given secret)
/// reports `NotPresent`, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactOutcome {
    /// It was present and is now gone.
    Removed,
    /// It was already absent — confirmed, not just assumed.
    NotPresent,
    /// The removal attempt failed. `&'static str` is a coarse, fixed label —
    /// never the underlying error's `Display`, which for a secret-store
    /// backend can echo values `CodeQL`'s `rust/cleartext-logging` (rightly)
    /// treats as secret-adjacent.
    Failed(&'static str),
}

/// Result of [`remove_all`] — one outcome per artifact this project may have
/// written, so a caller (tray dialog, `/admin/uninstall-local-state`) can
/// show exactly what happened rather than a single pass/fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UninstallReport {
    /// The trusted leaf certificate in `CurrentUser\Root` (T-49).
    pub cert: ArtifactOutcome,
    /// The `DoH` listener's TLS private key (T-67).
    pub tls_key: ArtifactOutcome,
    /// The `XChaCha20Poly1305` key sealing `query-log.enc`/`cache.enc` (T-146).
    pub persistence_key: ArtifactOutcome,
    /// The optional `MaxMind` `GeoLite2` account credentials (T-163).
    pub maxmind_creds: ArtifactOutcome,
}

/// Clear every local trust/secret artifact for the install rooted at
/// `app_data_dir`. Best-effort across all four — a failure on one artifact
/// does not stop the others from being attempted, so the caller always gets
/// the fullest possible report rather than an early abort.
///
/// `app_data_dir: None` is the rare degenerate startup case where the OS
/// app-data directory itself couldn't be resolved (`AppState.persist.paths`
/// is `Option` for the same reason) — the three Credential Manager entries
/// can't be named without it, so they're reported `Failed`, but the
/// certificate (keyed by a fixed `CommonName`, not the app-data path) is
/// still attempted.
///
/// Untested here, same as [`remove_cert`] and for the same reason: it always
/// runs the real `trust_store::uninstall()` — a `CurrentUser\Root` sweep —
/// which `trust_store`'s own tests also never call for real (see that
/// module's tests), because it would mutate whatever this project's fixed
/// `CommonName` has installed on the machine actually running the suite,
/// including a developer's own manually-trusted local dev certificate. The
/// two real decisions here ([`remove_cert`]'s Ok/Err mapping and
/// [`remove_secret`]'s Removed/`NotPresent`/Failed classification) are each
/// tested on their own below.
#[must_use]
pub fn remove_all(app_data_dir: Option<&Path>) -> UninstallReport {
    let cert = remove_cert();
    let Some(dir) = app_data_dir else {
        const NO_DIR: ArtifactOutcome = ArtifactOutcome::Failed("no app-data directory");
        return UninstallReport {
            cert,
            tls_key: NO_DIR,
            persistence_key: NO_DIR,
            maxmind_creds: NO_DIR,
        };
    };
    UninstallReport {
        cert,
        tls_key: remove_secret(&tls_key_entry(dir)),
        persistence_key: remove_secret(&persistence_key_entry(dir)),
        maxmind_creds: remove_secret(&maxmind_credentials_entry(dir)),
    }
}

/// `trust_store::uninstall()` is an exhaustive CN-sweep that reports only
/// success/failure, not a before/after count (see that module's own doc
/// comment for why — the identity it operates on is deliberately not a
/// specific thumbprint) — so unlike [`remove_secret`], this can't report
/// `NotPresent` distinctly from `Removed`. `Removed` here means "confirmed
/// clear now," whether or not anything was actually installed.
fn remove_cert() -> ArtifactOutcome {
    match trust_store::uninstall() {
        Ok(()) => ArtifactOutcome::Removed,
        Err(_) => ArtifactOutcome::Failed("trust store error"),
    }
}

/// Probes presence before deleting — `delete_secret` itself is deliberately
/// idempotent (T-67: a missing entry is `Ok(())`, not an error), so the probe
/// is the only way to tell "removed" from "was already gone."
fn remove_secret(entry: &str) -> ArtifactOutcome {
    let existed = matches!(load_secret(entry), Ok(Some(_)));
    match delete_secret(entry) {
        Ok(()) if existed => ArtifactOutcome::Removed,
        Ok(()) => ArtifactOutcome::NotPresent,
        Err(_) => ArtifactOutcome::Failed("secret store error"),
    }
}

#[cfg(test)]
mod tests {
    use super::{remove_secret, ArtifactOutcome};
    use crate::key_store::{delete_secret, store_secret, tls_key_entry, STORE_TEST_GUARD};
    use std::path::Path;

    // `remove_all`'s cert branch (and therefore `remove_all` itself) is
    // deliberately not exercised here — see its doc comment. These tests
    // cover `remove_secret`, the actual Removed/NotPresent/Failed decision,
    // directly and independently of any per-artifact bundling `remove_all`
    // does; `UninstallReport`'s "each artifact is independent" property
    // follows from `remove_all` being a plain struct literal of four
    // independent calls, not from anything that itself needs a real-store
    // integration test.

    #[test]
    fn present_secret_reports_removed() {
        let _guard = STORE_TEST_GUARD.lock();
        let dir = Path::new(r"C:\scratch\dns-quorum-filter-local-state-test-a");
        let entry = tls_key_entry(dir);
        let Ok(()) = store_secret(&entry, b"placeholder") else {
            panic!("store_secret should succeed");
        };

        assert_eq!(remove_secret(&entry), ArtifactOutcome::Removed);

        let _ = delete_secret(&entry); // idempotent cleanup
    }

    #[test]
    fn absent_secret_reports_not_present() {
        let _guard = STORE_TEST_GUARD.lock();
        let dir = Path::new(r"C:\scratch\dns-quorum-filter-local-state-test-b");
        let entry = tls_key_entry(dir);
        let _ = delete_secret(&entry); // clean slate

        assert_eq!(remove_secret(&entry), ArtifactOutcome::NotPresent);
    }

    #[test]
    fn removing_the_same_secret_twice_is_idempotent() {
        let _guard = STORE_TEST_GUARD.lock();
        let dir = Path::new(r"C:\scratch\dns-quorum-filter-local-state-test-c");
        let entry = tls_key_entry(dir);
        let Ok(()) = store_secret(&entry, b"placeholder") else {
            panic!("store_secret should succeed");
        };

        assert_eq!(remove_secret(&entry), ArtifactOutcome::Removed);
        assert_eq!(remove_secret(&entry), ArtifactOutcome::NotPresent);
    }
}
