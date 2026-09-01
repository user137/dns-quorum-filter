//! `CurrentUser\Root` trust-store install/uninstall for the local `DoH`
//! listener's self-signed leaf certificate (SPEC.md §2, T-49). Wraps
//! `certutil.exe` (`%SystemRoot%\System32\certutil.exe`, absolute path, never
//! a bare `PATH` lookup, same convention as `cert.rs`'s `icacls.exe` calls) —
//! not the Windows `CryptoAPI` directly, which is `unsafe` FFI and this crate
//! is `#![forbid(unsafe_code)]`.
//!
//! **Target store is `CurrentUser\Root`, decided by a live probe this
//! session, not `TrustedPeople` (failed on a real Chrome test) or
//! `LocalMachine` (needs admin elevation, unneeded here)** — see SPEC.md §2
//! and `TASKS-DONE.md`'s T-49 entry for the full record.
//!
//! **Install and uninstall key on different identities, deliberately.**
//! Install must be *precise*: "is exactly the cert `cert.pem` holds right
//! now trusted?" — matching by subject `CommonName`
//! (`cert::CERT_COMMON_NAME`, fixed across every certificate this project
//! ever generates) would answer a different, wrong question, because
//! `tls::load_or_generate_server_config`'s `CertOrigin::Replaced` path
//! silently regenerates `cert.pem`/`key.pem` in place when the existing pair
//! can't be loaded — same CN, different key material. A CN-only
//! [`ensure_installed`] would see the *old* cert still trusted under that CN
//! and report `AlreadyInstalled` forever, while the actual on-disk cert the
//! `DoH` listener now serves stays untrusted — a silent failure, not a
//! degraded-but-visible one. [`local_cert_thumbprint`] (the certificate's own
//! SHA-1 hash, read straight from the current `cert.pem`) is the identity
//! [`ensure_installed`] actually checks.
//!
//! Uninstall must be the opposite: *exhaustive*, "remove everything this
//! project ever trusted." Keying it on `cert.pem`'s *current* thumbprint
//! would reproduce the same bug in the other direction — install cert A,
//! let it silently regenerate to cert B, click uninstall, and cert A (no
//! longer matching B's thumbprint) stays trusted in `Root` forever. SPEC.md
//! §2 names exactly this outcome as its own separate security bug ("a
//! trusted certificate left behind after removal"). [`uninstall`] therefore
//! takes no certificate at all — it enumerates every `Root` entry whose
//! subject CN matches [`CERT_COMMON_NAME`]
//! (the one place CN matching is the *correct* tool, precisely because a
//! fixed CN is what makes it a complete set) and deletes each one by its own
//! thumbprint.
//!
//! **Never call the two mutating functions ([`ensure_installed`],
//! [`uninstall`]) from an automated test, including in CI.** Unlike
//! `cert.rs`'s `icacls` tests (which mutate an ephemeral tempfile, harmless),
//! these would mutate the *real* `CurrentUser\Root` store of whatever
//! account runs the test suite. Every previous cert-trust probe this project
//! has run was written by the agent and *run by the user*; this module keeps
//! that split — see `TASKS-DONE.md`'s T-49 entry for the manual verification
//! record.
//!
//! **Deliberately no `main.rs` auto-install wiring.** Whether
//! `certutil -addstore -user Root` shows the OS's own confirmation dialog
//! (as an earlier, different probe this session observed for *some*
//! install path — never pinned down to this exact command) or installs
//! silently was never verified for `certutil.exe` specifically. A
//! fire-and-forget install on every `dnsqb-service` startup would risk
//! adding a trust anchor with zero user consent if it turns out to be
//! silent — the opposite of SPEC.md §2's explicit-consent framing. Both
//! [`ensure_installed`] and [`uninstall`] are wired instead as two
//! symmetric, confirm-gated `dnsqb-tray` menu actions (`crates/dnsqb-tray`),
//! matching the existing "Зупинити фільтрацію" pattern.

use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

use crate::cert::CERT_COMMON_NAME;

/// Certificate-store operations never loop more than this many times
/// looking for more matching entries to remove — a provable bound, not an
/// unbounded `loop` relying on `certutil` always shrinking the list on
/// every call. No legitimate use of this project ever installs anywhere
/// near this many certificates under the same `CommonName`.
const MAX_MATCHING_ENTRIES: usize = 16;

/// `certutil -store`'s exit code when nothing matches the given `CertId` —
/// confirmed empirically 2026-08-29 (`0x80090011 NTE_NOT_FOUND` / "Object was
/// not found") for a `CommonName`-based lookup against `CurrentUser\Root`
/// specifically. [`confirmed_thumbprints_for_common_name`] is the one place
/// this constant is load-bearing (it must tell a genuine "confirmed nothing
/// there" apart from "certutil failed for some other reason"); if a future
/// caller reuses it against a different lookup form and this code turns out
/// not to generalize, that needs its own empirical check, not an assumption
/// that it carries over.
const NOT_FOUND_EXIT_CODE: i32 = 17;

/// Errors installing/uninstalling the local `DoH` certificate in
/// `CurrentUser\Root`.
#[derive(Debug, thiserror::Error)]
pub enum TrustStoreError {
    /// `%SystemRoot%` is not set — can't locate `certutil.exe` by absolute
    /// path.
    #[error("%SystemRoot% environment variable is not set")]
    MissingSystemRoot,
    /// Failed to spawn `certutil.exe`.
    #[error("failed to spawn certutil: {0}")]
    Spawn(#[source] std::io::Error),
    /// `certutil -dump` on the local `cert.pem` didn't succeed, or its
    /// output didn't contain a `Cert Hash(sha1):` line in the expected
    /// format — including the common first-run case where `cert.pem`
    /// doesn't exist yet because `dnsqb-service` has never been started.
    #[error(
        "could not read the local certificate's thumbprint from {path:?} — \
         if dnsqb-service has never been run, start it once first so \
         cert.pem exists"
    )]
    LocalThumbprint {
        /// The `cert.pem` path that was read.
        path: std::path::PathBuf,
    },
    /// `certutil -addstore` ran but reported failure.
    #[error("certutil failed to install the certificate (exit code {0:?})")]
    InstallFailed(Option<i32>),
    /// `certutil -delstore` ran but reported failure for a reason other than
    /// "not found" (a genuine "not found" is not an error — see
    /// [`uninstall`]).
    #[error("certutil failed to remove a certificate (exit code {0:?})")]
    UninstallFailed(Option<i32>),
    /// [`uninstall`] kept finding more matching entries past
    /// [`MAX_MATCHING_ENTRIES`] — stops rather than looping unboundedly;
    /// almost certainly means `certutil -delstore` isn't actually shrinking
    /// the store the way this module assumes.
    #[error("more than {MAX_MATCHING_ENTRIES} matching certificate-store entries found — stopping rather than looping unboundedly")]
    TooManyMatchingEntries,
    /// `certutil -store` failed for a reason [`uninstall`] could not confirm
    /// was "nothing matches" (see [`NOT_FOUND_EXIT_CODE`]) — surfaced as a
    /// real error rather than silently treated as "nothing left to remove,"
    /// unlike [`ensure_installed`]'s own, deliberately more lenient list
    /// lookup (see this module's doc comment for why the two callers need
    /// different bias).
    #[error("could not confirm whether any matching certificates remain (exit code {0:?})")]
    ListFailed(Option<i32>),
}

/// Outcome of [`ensure_installed`], for the caller to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStoreOutcome {
    /// The certificate at the given path was already the one trusted in
    /// `CurrentUser\Root` — no `certutil` mutation happened.
    AlreadyInstalled,
    /// The certificate was not already trusted (either nothing under this
    /// project's `CommonName` was present, or a different, stale one was —
    /// see this module's doc comment) and has now been installed.
    Installed,
}

/// Absolute path to `certutil.exe`.
fn certutil_path() -> Result<std::path::PathBuf, TrustStoreError> {
    let system_root = env::var_os("SystemRoot").ok_or(TrustStoreError::MissingSystemRoot)?;
    Ok(Path::new(&system_root)
        .join("System32")
        .join("certutil.exe"))
}

/// The SHA-1 thumbprint (`certutil`'s own "Cert Hash(sha1)" field) of the
/// certificate currently at `cert_path`, read via `certutil -dump` — a
/// read-only operation, safe to call freely (including from tests). Never
/// caches a previously computed value; always reflects whatever is on disk
/// right now, since that's the whole point of not keying identity on a
/// fixed name (see this module's doc comment).
///
/// # Errors
///
/// Returns [`TrustStoreError::LocalThumbprint`] if `cert_path` doesn't exist
/// or isn't a certificate `certutil -dump` can parse, and
/// [`TrustStoreError::Spawn`]/[`TrustStoreError::MissingSystemRoot`] for the
/// usual process-spawning failure modes.
pub(crate) fn local_cert_thumbprint(cert_path: &Path) -> Result<String, TrustStoreError> {
    let certutil = certutil_path()?;
    let output = Command::new(&certutil)
        .arg("-dump")
        .arg(cert_path)
        .output()
        .map_err(TrustStoreError::Spawn)?;
    if !output.status.success() {
        return Err(TrustStoreError::LocalThumbprint {
            path: cert_path.to_path_buf(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_cert_hash_sha1(&stdout).ok_or_else(|| TrustStoreError::LocalThumbprint {
        path: cert_path.to_path_buf(),
    })
}

/// Extracts the value of the first `Cert Hash(sha1): <hex>` line from
/// `certutil -dump`'s stdout — pure, so it's testable against a fabricated
/// string without spawning a process. Confirmed empirically (not assumed
/// from docs) against a real `certutil -dump` run over a throwaway,
/// never-installed local file: the line has no separators in the hex value
/// and is prefixed with exactly `"Cert Hash(sha1): "`.
fn parse_cert_hash_sha1(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Cert Hash(sha1): ")
            .map(str::to_string)
    })
}

/// Runs `certutil -store -user Root <common_name>` and hands back the raw
/// process output — read-only, shared by both lookup flavors below so the
/// `Command` construction lives in exactly one place.
fn store_lookup_output(common_name: &str) -> Result<std::process::Output, TrustStoreError> {
    let certutil = certutil_path()?;
    Command::new(&certutil)
        .args([
            OsStr::new("-store"),
            OsStr::new("-user"),
            OsStr::new("Root"),
            OsStr::new(common_name),
        ])
        .output()
        .map_err(TrustStoreError::Spawn)
}

/// Every `Cert Hash(sha1):` line in `certutil -store`'s stdout — `certutil`
/// may print more than one matching entry back to back (its own `-?` text:
/// "many of the above may result in multiple matches") when a past
/// regeneration (`CertOrigin::Replaced`) left a stale entry behind a new
/// one; every line found is collected, not just the first.
fn parse_thumbprints(output: &std::process::Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("Cert Hash(sha1): ")
                .map(str::to_string)
        })
        .collect()
}

/// Every `CurrentUser\Root` entry whose subject `CommonName` matches
/// `common_name` — takes an explicit parameter (rather than hardcoding
/// [`CERT_COMMON_NAME`]) purely so tests can exercise the real
/// parsing/empty-list logic against a sentinel `CommonName` guaranteed
/// absent from the real store, without depending on this project's own
/// `CommonName` being absent too; [`ensure_installed`] always calls it with
/// [`CERT_COMMON_NAME`].
///
/// **Deliberately lenient — used only by [`ensure_installed`], never by
/// [`uninstall`].** Any failed/non-zero `-store` call here is treated as
/// "nothing found," not just a confirmed not-found exit code, because
/// `ensure_installed`'s own bias (worst case: one extra, harmless
/// `-addstore` attempt) tolerates that ambiguity. `uninstall` cannot afford
/// the same bias — see [`confirmed_thumbprints_for_common_name`], the
/// function it uses instead, and this module's doc comment.
fn thumbprints_for_common_name(common_name: &str) -> Result<Vec<String>, TrustStoreError> {
    let output = store_lookup_output(common_name)?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    Ok(parse_thumbprints(&output))
}

/// Every `CurrentUser\Root` entry whose subject `CommonName` matches
/// [`CERT_COMMON_NAME`], distinguishing a **confirmed** empty result (exit
/// code [`NOT_FOUND_EXIT_CODE`]) from any other failure, which becomes a real
/// [`TrustStoreError::ListFailed`] instead of being silently treated as
/// "nothing left." Used by [`uninstall`], which must never report success
/// on a store it couldn't actually confirm is empty — see this module's doc
/// comment for why install and uninstall need opposite ambiguity handling.
fn confirmed_thumbprints_for_common_name(
    common_name: &str,
) -> Result<Vec<String>, TrustStoreError> {
    let output = store_lookup_output(common_name)?;
    if output.status.success() {
        return Ok(parse_thumbprints(&output));
    }
    if output.status.code() == Some(NOT_FOUND_EXIT_CODE) {
        return Ok(Vec::new());
    }
    Err(TrustStoreError::ListFailed(output.status.code()))
}

/// Ensures the certificate currently at `cert_path` is trusted in
/// `CurrentUser\Root`, installing it (`certutil -addstore`) only if it isn't
/// already — see this module's doc comment for why identity here is the
/// certificate's own thumbprint, not its `CommonName`. A stale, different-
/// thumbprint entry under this project's `CommonName` (left by a past
/// certificate regeneration) is logged via `tracing::warn!`, not silently
/// ignored — removing it is [`uninstall`]'s job, not this function's.
///
/// **Mutates the real trust store — never call this from an automated
/// test.**
///
/// # Errors
///
/// Returns [`TrustStoreError`] if the local certificate's thumbprint can't
/// be read (including the common first-run case where `cert.pem` doesn't
/// exist yet) or if `certutil -addstore` itself fails.
pub fn ensure_installed(cert_path: &Path) -> Result<TrustStoreOutcome, TrustStoreError> {
    let local_thumbprint = local_cert_thumbprint(cert_path)?;
    let installed = thumbprints_for_common_name(CERT_COMMON_NAME)?;

    if installed
        .iter()
        .any(|thumbprint| thumbprint.eq_ignore_ascii_case(&local_thumbprint))
    {
        return Ok(TrustStoreOutcome::AlreadyInstalled);
    }
    if !installed.is_empty() {
        tracing::warn!(
            "found {} stale dns-quorum-filter certificate(s) in CurrentUser\\Root that don't \
             match the current cert.pem — installing the current one anyway; removing the stale \
             entries needs the tray's uninstall action",
            installed.len()
        );
    }

    let certutil = certutil_path()?;
    let output = Command::new(&certutil)
        .args([
            OsStr::new("-addstore"),
            OsStr::new("-user"),
            OsStr::new("Root"),
        ])
        .arg(cert_path)
        .output()
        .map_err(TrustStoreError::Spawn)?;
    if output.status.success() {
        Ok(TrustStoreOutcome::Installed)
    } else {
        Err(TrustStoreError::InstallFailed(output.status.code()))
    }
}

/// Removes every `CurrentUser\Root` entry belonging to this project — see
/// this module's doc comment for why this is CN-based (exhaustive), unlike
/// [`ensure_installed`]'s thumbprint-based (precise) check. Idempotent: an
/// empty `Root` (nothing installed, or a repeat call after everything was
/// already removed) is `Ok(())`, not an error.
///
/// **Mutates the real trust store — never call this from an automated
/// test.**
///
/// # Errors
///
/// Returns [`TrustStoreError::UninstallFailed`] if `certutil -delstore`
/// fails for a matching entry, or
/// [`TrustStoreError::TooManyMatchingEntries`] if more than
/// [`MAX_MATCHING_ENTRIES`] matching entries are found (see that constant's
/// doc comment).
pub fn uninstall() -> Result<(), TrustStoreError> {
    let certutil = certutil_path()?;
    uninstall_loop(
        // Confirmed-empty, not the lenient `thumbprints_for_common_name` —
        // `uninstall` must never report success on a store it couldn't
        // actually confirm is empty (see this module's doc comment).
        || confirmed_thumbprints_for_common_name(CERT_COMMON_NAME),
        |thumbprint| {
            let output = Command::new(&certutil)
                .args([
                    OsStr::new("-delstore"),
                    OsStr::new("-user"),
                    OsStr::new("Root"),
                    OsStr::new(thumbprint),
                ])
                .output()
                .map_err(TrustStoreError::Spawn)?;
            if output.status.success() {
                Ok(())
            } else {
                Err(TrustStoreError::UninstallFailed(output.status.code()))
            }
        },
    )
}

/// The actual list-then-delete-one loop, parameterized over `list`/`delete`
/// so the iteration-count boundary is provable by a test without touching a
/// real certificate store — [`uninstall`] is the one real caller.
///
/// `0..=MAX_MATCHING_ENTRIES`, not `0..MAX_MATCHING_ENTRIES`: deleting
/// `MAX_MATCHING_ENTRIES` real entries takes that many loop bodies, plus one
/// more iteration afterward to actually observe the store empty and return
/// `Ok`. An exclusive bound would delete every one of exactly
/// `MAX_MATCHING_ENTRIES` entries successfully and still fall through to
/// `TooManyMatchingEntries` below — an ordinary success path reported as a
/// failure (caught by `advisor` review of this diff before commit, not by
/// any test that existed at the time).
fn uninstall_loop<L, D>(mut list: L, mut delete: D) -> Result<(), TrustStoreError>
where
    L: FnMut() -> Result<Vec<String>, TrustStoreError>,
    D: FnMut(&str) -> Result<(), TrustStoreError>,
{
    for _ in 0..=MAX_MATCHING_ENTRIES {
        let installed = list()?;
        let Some(thumbprint) = installed.first() else {
            return Ok(());
        };
        delete(thumbprint)?;
    }
    Err(TrustStoreError::TooManyMatchingEntries)
}

#[cfg(test)]
mod tests {
    use super::{
        local_cert_thumbprint, parse_cert_hash_sha1, uninstall_loop, MAX_MATCHING_ENTRIES,
    };

    #[test]
    fn uninstall_loop_succeeds_when_exactly_max_matching_entries_are_all_deleted() {
        // The off-by-one this test guards: exactly `MAX_MATCHING_ENTRIES`
        // real entries must still end in `Ok(())`, not
        // `TooManyMatchingEntries` - proven here without touching a real
        // certificate store.
        // `Cell`, not a plain `mut` capture: both closures need to touch the
        // same counter, and `uninstall_loop` takes two separate `FnMut`
        // parameters (a shared reference to a `Cell` sidesteps the
        // can't-borrow-`remaining`-mutably-twice conflict a plain `mut`
        // capture in both closures would hit).
        let remaining = std::cell::Cell::new(MAX_MATCHING_ENTRIES);
        let result = uninstall_loop(
            || {
                Ok(if remaining.get() == 0 {
                    Vec::new()
                } else {
                    vec!["thumbprint".to_string()]
                })
            },
            |_thumbprint| {
                remaining.set(remaining.get() - 1);
                Ok(())
            },
        );
        assert!(
            result.is_ok(),
            "deleting exactly MAX_MATCHING_ENTRIES entries must succeed, got {result:?}"
        );
        assert_eq!(
            remaining.get(),
            0,
            "every entry must actually have been deleted"
        );
    }

    #[test]
    fn uninstall_loop_reports_too_many_when_the_list_never_actually_shrinks() {
        // A `delete` that reports success without the store ever actually
        // shrinking (e.g. `-delstore` silently no-opping) must not be
        // mistaken for done - it must stop and report, not loop unboundedly
        // or claim success.
        let result = uninstall_loop(|| Ok(vec!["thumbprint".to_string()]), |_thumbprint| Ok(()));
        assert!(
            matches!(result, Err(super::TrustStoreError::TooManyMatchingEntries)),
            "a list that never shrinks must report TooManyMatchingEntries, got {result:?}"
        );
    }

    #[test]
    fn parse_cert_hash_sha1_extracts_the_value_from_a_realistic_dump_fixture() {
        // Fixture shape confirmed empirically against a real `certutil
        // -dump` run over a throwaway, never-installed local certificate
        // file this session — see this module's doc comment.
        let fixture = "X509 Certificate:\r\nVersion: 3\r\n\
             Serial Number: 317931e2427087d4c5f5c01c38680610e9f604d3\r\n\
             ...\r\nCert Hash(sha1): 7c8d919d62f7d064fc515a9a6073d9406f974f27\r\n\
             Signature Hash: 850fe0af...\r\n";
        assert_eq!(
            parse_cert_hash_sha1(fixture).as_deref(),
            Some("7c8d919d62f7d064fc515a9a6073d9406f974f27")
        );
    }

    #[test]
    fn parse_cert_hash_sha1_returns_none_when_the_line_is_absent() {
        assert_eq!(parse_cert_hash_sha1("no such line here\r\n"), None);
    }

    #[test]
    fn local_cert_thumbprint_of_a_freshly_generated_cert_matches_the_dump_format() {
        // Real `certutil -dump` call against a real cert.pem this project
        // actually generates (not the openssl fixture used while designing
        // the parser above) — read-only, no store mutation, safe to run
        // from an automated test unlike `ensure_installed`/`uninstall`.
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let cert_path = dir.path().join("cert.pem");
        let certified_key = match crate::cert::generate_self_signed_cert() {
            Ok(ck) => ck,
            Err(err) => panic!("generation must succeed: {err}"),
        };
        if let Err(err) = std::fs::write(&cert_path, certified_key.cert.pem()) {
            panic!("must be able to write cert.pem: {err}");
        }

        let thumbprint = match local_cert_thumbprint(&cert_path) {
            Ok(thumbprint) => thumbprint,
            Err(err) => panic!("local_cert_thumbprint must succeed: {err}"),
        };
        assert_eq!(
            thumbprint.len(),
            40,
            "a SHA-1 thumbprint must be exactly 40 hex characters, got {thumbprint:?}"
        );
        assert!(
            thumbprint.chars().all(|c| c.is_ascii_hexdigit()),
            "thumbprint must be pure hex, got {thumbprint:?}"
        );
    }

    #[test]
    fn local_cert_thumbprint_reports_a_helpful_error_when_the_file_is_missing() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let missing_path = dir.path().join("does-not-exist.pem");
        match local_cert_thumbprint(&missing_path) {
            Err(super::TrustStoreError::LocalThumbprint { path }) => {
                assert_eq!(path, missing_path);
            }
            Ok(_) => panic!(
                "expected LocalThumbprint, but the thumbprint call unexpectedly succeeded \
                 on a missing file"
            ),
            Err(err) => panic!("expected LocalThumbprint, got a different Err: {err}"),
        }
    }

    #[test]
    fn thumbprints_for_common_name_is_empty_for_a_name_certain_to_be_absent() {
        // Exercises the real function (parsing/empty-list logic included),
        // not just a raw `certutil` call - read-only, `certutil -store`
        // never mutates anything. Uses a sentinel CommonName this project
        // never generates, so this is safe to run on any machine (dev box
        // or CI runner) regardless of that machine's real CurrentUser\Root
        // contents.
        match super::thumbprints_for_common_name(
            "dns-quorum-filter-test-sentinel-never-a-real-cert",
        ) {
            Ok(thumbprints) => assert!(
                thumbprints.is_empty(),
                "a certain-to-be-absent CommonName must yield no thumbprints, got {thumbprints:?}"
            ),
            Err(err) => panic!("thumbprints_for_common_name must succeed (empty, not Err): {err}"),
        }
    }
}
