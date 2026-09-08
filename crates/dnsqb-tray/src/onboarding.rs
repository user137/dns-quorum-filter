//! T-188 — first-run onboarding: a one-time offer to install the local
//! certificate and open the browser-setup page.
//!
//! On a fresh MSIX install the app has no way to walk a non-technical user
//! through the two remaining manual steps (trust the local cert, point the
//! browser at the local `DoH` address) — the tray's cert menu items assume the
//! user already knows they exist. This module holds the tiny bits of state and
//! the one pure decision that gate the wizard; `main.rs` owns the `rfd` dialog
//! and the actions it leads to.
//!
//! `onboarding.seen` is a marker file in the app-data directory, in the shape
//! of the `lifecycle` flags — but deliberately **not** in `lifecycle.rs`: that
//! module's invariant is "the entry-point process clears both flags on
//! startup", and this marker must survive every launch. It is written on
//! «Пізніше» and on a *successful* install, never on a failed one (a failed
//! install on a machine with no trusted cert should re-offer next launch); the
//! "Майстер налаштування" menu item is the manual re-entry regardless.

use std::path::{Path, PathBuf};

/// File name of the "onboarding shown" marker under the app-data directory.
pub const ONBOARDING_SEEN_NAME: &str = "onboarding.seen";

fn seen_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(ONBOARDING_SEEN_NAME)
}

/// Whether the first-run wizard has already been shown (or dismissed) once.
#[must_use]
pub fn onboarding_seen(app_data_dir: &Path) -> bool {
    seen_path(app_data_dir).exists()
}

/// Record that the wizard has been shown. Best-effort: the worst case of a
/// failed write is the wizard offering itself again on the next launch, which
/// the user can dismiss — so this logs and returns rather than propagating.
pub fn mark_onboarding_seen(app_data_dir: &Path) {
    if let Err(err) = std::fs::write(seen_path(app_data_dir), []) {
        tracing::warn!("could not write {ONBOARDING_SEEN_NAME}: {err}");
    }
}

/// Whether to offer the first-run wizard now.
///
/// `cert_confirmed` — the trust-watch thread has had at least one conclusive
/// `certutil` answer (not the optimistic seed). `cert_trusted` — that answer
/// said the local cert is trusted. `seen` — the marker file exists.
///
/// The wizard fires only when the cert is **provably** not trusted and the
/// user hasn't seen the offer: an unconfirmed reading ("unknown", e.g.
/// `cert.pem` not written yet on a fresh install) never triggers it, matching
/// the trust icon's own "unknown ≠ untrusted" rule (T-191).
#[must_use]
pub fn should_offer_onboarding(cert_confirmed: bool, cert_trusted: bool, seen: bool) -> bool {
    cert_confirmed && !cert_trusted && !seen
}

#[cfg(test)]
mod tests {
    use super::{mark_onboarding_seen, onboarding_seen, should_offer_onboarding};

    fn tempdir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("tempdir: {err}"),
        }
    }

    // Happy path: a confirmed "not trusted" reading, wizard not yet seen.
    #[test]
    fn offers_the_wizard_when_the_cert_is_confirmed_untrusted_and_unseen() {
        assert!(should_offer_onboarding(true, false, false));
    }

    // Security/boundary: a confirmed "trusted" reading must never nag.
    #[test]
    fn does_not_offer_the_wizard_once_the_cert_is_trusted() {
        assert!(!should_offer_onboarding(true, true, false));
    }

    // Misuse/fool: an unconfirmed reading is "unknown", not "untrusted" — the
    // fresh-install case where cert.pem does not exist yet (T-187). Must not
    // fire regardless of the seeded `cert_trusted` value.
    #[test]
    fn does_not_offer_the_wizard_before_a_conclusive_certutil_answer() {
        assert!(!should_offer_onboarding(false, false, false));
        assert!(!should_offer_onboarding(false, true, false));
    }

    // Error/idempotency: once the marker exists the wizard is never re-offered
    // automatically, whatever the trust state; and writing the marker is a
    // round trip that a second write does not break.
    #[test]
    fn a_written_marker_suppresses_the_automatic_offer_and_round_trips() {
        assert!(!should_offer_onboarding(true, false, true));

        let dir = tempdir();
        assert!(!onboarding_seen(dir.path()));
        mark_onboarding_seen(dir.path());
        assert!(onboarding_seen(dir.path()));
        mark_onboarding_seen(dir.path()); // must not panic or error out
        assert!(onboarding_seen(dir.path()));
    }
}
