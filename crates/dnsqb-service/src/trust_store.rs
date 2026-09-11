//! `CurrentUser\Root` trust-store install/uninstall for the local `DoH`
//! listener's self-signed leaf certificate (SPEC.md §2, T-49). Wraps
//! `certutil.exe` (`%SystemRoot%\System32\certutil.exe`, absolute path, never
//! a bare `PATH` lookup, same convention as `cert.rs`'s `icacls.exe` calls) —
//! not the Windows `CryptoAPI` directly, which is `unsafe` FFI and this crate
//! is `#![forbid(unsafe_code)]`. **Exception: [`local_cert_thumbprint`]
//! (2026-09-12) computes the local certificate's own SHA-1 thumbprint in
//! pure Rust instead of shelling out — see its doc comment for why a
//! packaged (MSIX) build's `certutil.exe` child can't be handed this file's
//! path at all.**
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
//!
//! [`is_trusted`] (T-191) is the read-only public counterpart: it only
//! *reads* trust state — [`local_cert_thumbprint`]'s pure-Rust hash plus the
//! same `certutil -store` call the install path already makes to decide
//! whether it has work to do — never mutates, and so is safe to call
//! unattended, including from a background poll. The `dnsqb-tray` status
//! icon uses it to turn red when the certificate the `DoH` listener serves
//! isn't trusted (the browser's own `DoH` connection would then fail
//! silently). No HTTP route wraps it; the tray calls it directly, exactly as
//! it already does for [`ensure_installed`].

use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use sha1::{Digest, Sha1};

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
    /// The local `cert.pem` couldn't be read or parsed as a certificate
    /// (see [`local_cert_thumbprint`]) — including the common first-run
    /// case where it doesn't exist yet because `dnsqb-service` has never
    /// been started.
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
    /// [`ensure_installed`] couldn't stage the temporary `%SystemRoot%\Temp`
    /// copy `-addstore` needs (see [`addstore_temp_path`]'s doc comment) —
    /// distinct from [`TrustStoreError::Spawn`], which is specifically about
    /// `certutil.exe` itself failing to start.
    #[error("could not write a temporary certificate copy for certutil to install: {0}")]
    TempCopy(#[source] std::io::Error),
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

/// `%SystemRoot%` itself (e.g. `C:\Windows`) — shared by [`certutil_path`]
/// and [`addstore_temp_path`].
fn system_root_dir() -> Result<PathBuf, TrustStoreError> {
    let system_root = env::var_os("SystemRoot").ok_or(TrustStoreError::MissingSystemRoot)?;
    Ok(PathBuf::from(system_root))
}

/// Absolute path to `certutil.exe`.
fn certutil_path() -> Result<PathBuf, TrustStoreError> {
    Ok(system_root_dir()?.join("System32").join("certutil.exe"))
}

/// A `Command` for `certutil.exe` that never flashes a console window.
///
/// `certutil` is a console-subsystem binary; spawned from the GUI tray
/// (`windows_subsystem = "windows"`, no console of its own) a plain
/// `Command::new` pops a console window for the child's lifetime. Invisible
/// when this was only reached on an explicit menu click, but T-191's
/// `status::spawn_trust_watch` polls `is_trusted` on a back-off ladder — two
/// `certutil` spawns per poll — so on a fresh install the window flashed every
/// few seconds. `CREATE_NO_WINDOW` runs the child with no console at all;
/// stdout/stderr are still captured through the pipes.
fn certutil_command(certutil: &Path) -> Command {
    let mut command = Command::new(certutil);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        /// `CREATE_NO_WINDOW` (winbase.h) — same shape as `watchdog::spawn`'s
        /// named `DETACHED_PROCESS`/`CREATE_BREAKAWAY_FROM_JOB` constants.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// The SHA-1 thumbprint (`certutil`'s own "Cert Hash(sha1)" field — verified
/// empirically 2026-09-12 to be exactly SHA-1 over the certificate's DER
/// encoding, not its PEM text or file bytes: `.NET`'s
/// `X509Certificate2.Thumbprint` on a real generated `cert.pem` matched this
/// function's output exactly) of the certificate currently at `cert_path`.
///
/// **Deliberately computed in Rust, not via `certutil -dump <cert_path>`.**
/// A packaged (MSIX) build's own file I/O sees `cert_path` (built from the
/// logical `%LOCALAPPDATA%\dns-quorum-filter` path,
/// [`crate::paths::app_data_dir`]) transparently redirected by Windows to
/// its real on-disk location — but a spawned `certutil.exe` **child**
/// process does not get that redirection and reports the path as missing
/// (`ERROR_FILE_NOT_FOUND`), confirmed empirically against a live packaged
/// `dnsqb-service` (2026-09-12: `/admin/cert-status` stuck at `UNKNOWN` for
/// 20+ minutes / ~20 poll cycles — not a startup race — while an external
/// `certutil -dump` on the identical logical path reproduced the same
/// error, and the same file's real physical path dumped successfully).
/// Reusing `CertificateDer::from_pem_slice` (the same PEM→DER primitive
/// `tls.rs`/`cert.rs` already use for this exact file) instead of a
/// hand-rolled parser sidesteps the whole class of problem, at the cost of
/// no longer round-tripping through `certutil` for this one read — the
/// mutating calls elsewhere in this module (`-store`/`-addstore`/
/// `-delstore`, none of which take this file's path as an argument) are
/// unaffected and still shell out.
///
/// Read-only, safe to call freely (including from tests). Never caches a
/// previously computed value; always reflects whatever is on disk right
/// now, since that's the whole point of not keying identity on a fixed name
/// (see this module's doc comment).
///
/// # Errors
///
/// Returns [`TrustStoreError::LocalThumbprint`] if `cert_path` doesn't exist
/// or isn't a certificate this can parse.
pub(crate) fn local_cert_thumbprint(cert_path: &Path) -> Result<String, TrustStoreError> {
    use std::fmt::Write;

    let make_err = || TrustStoreError::LocalThumbprint {
        path: cert_path.to_path_buf(),
    };
    let pem = std::fs::read(cert_path).map_err(|_| make_err())?;
    let der = CertificateDer::from_pem_slice(&pem).map_err(|_| make_err())?;

    Ok(Sha1::digest(der.as_ref())
        .iter()
        .fold(String::with_capacity(40), |mut acc, byte| {
            // Writing a byte to a `String` via `write!` is infallible; the
            // `fmt::Error` branch is unreachable for this sink.
            let _ = write!(acc, "{byte:02x}");
            acc
        }))
}

/// Runs `certutil -store -user Root <common_name>` and hands back the raw
/// process output — read-only, shared by both lookup flavors below so the
/// `Command` construction lives in exactly one place.
fn store_lookup_output(common_name: &str) -> Result<std::process::Output, TrustStoreError> {
    let certutil = certutil_path()?;
    certutil_command(&certutil)
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

/// Shared read-only core of [`is_trusted`] and [`ensure_installed`]. Returns a
/// pair: whether the certificate currently at `cert_path` is trusted, and
/// every `CurrentUser\Root` thumbprint found under this project's fixed
/// `CommonName`. The [`Vec`] half is consumed only by [`ensure_installed`]'s
/// stale-entry warning; [`is_trusted`] discards it. Kept as one function so
/// the thumbprint-vs-CN identity distinction (this module's whole doc comment)
/// can never drift between the two callers. Read-only — `certutil -dump` +
/// `certutil -store`.
fn trusted_state(cert_path: &Path) -> Result<(bool, Vec<String>), TrustStoreError> {
    let local_thumbprint = local_cert_thumbprint(cert_path)?;
    let installed = thumbprints_for_common_name(CERT_COMMON_NAME)?;
    let trusted = installed
        .iter()
        .any(|thumbprint| thumbprint.eq_ignore_ascii_case(&local_thumbprint));
    Ok((trusted, installed))
}

/// Read-only: is the certificate currently at `cert_path` the exact one
/// trusted in `CurrentUser\Root`? Never mutates the store, so — unlike
/// [`ensure_installed`] / [`uninstall`] — it's safe to call unattended,
/// including from a background poll (the `dnsqb-tray` status icon). See this
/// module's doc comment.
///
/// # Errors
///
/// [`TrustStoreError::LocalThumbprint`] if `cert_path` is absent or isn't a
/// certificate `certutil -dump` can parse — including the common first-run
/// case where `dnsqb-service` has never generated `cert.pem`. A caller must
/// treat that as "unknown", never as "untrusted". Plus the usual
/// [`TrustStoreError::Spawn`] / [`TrustStoreError::MissingSystemRoot`].
pub fn is_trusted(cert_path: &Path) -> Result<bool, TrustStoreError> {
    Ok(trusted_state(cert_path)?.0)
}

/// Where [`ensure_installed`] stages a temporary copy of `cert.pem`'s bytes
/// so `certutil -addstore` — which must open the file itself, unlike
/// [`local_cert_thumbprint`]'s pure-Rust read — can actually see it. Pure:
/// no I/O, just path construction, so it's unit-testable without touching
/// disk (the write/spawn/cleanup around it is the untested impure shell,
/// same split as [`local_cert_thumbprint`] vs. its caller).
///
/// `%SystemRoot%\Temp`, deliberately not `std::env::temp_dir()` — the latter
/// resolves under `%LOCALAPPDATA%\Temp`, the same virtualized prefix
/// [`local_cert_thumbprint`]'s doc comment describes the bug living in;
/// `%SystemRoot%\Temp` is a shared, per-machine folder no per-package
/// redirection touches, confirmed empirically 2026-09-12 (`certutil -dump` a
/// copy placed there succeeded). Named by `thumbprint` — content-addressed,
/// so it's unique per real certificate and not guessable ahead of computing
/// it; the file holds a public certificate (no private key material, that
/// stays in `key_store`), so the property this heads off is a stale/
/// substituted file, not disclosure.
fn addstore_temp_path(system_root: &Path, thumbprint: &str) -> PathBuf {
    system_root
        .join("Temp")
        .join(format!("dnsqb-cert-{thumbprint}.pem"))
}

/// Ensures the certificate currently at `cert_path` is trusted in
/// `CurrentUser\Root`, installing it (`certutil -addstore`) only if it isn't
/// already — see this module's doc comment for why identity here is the
/// certificate's own thumbprint, not its `CommonName`. A stale, different-
/// thumbprint entry under this project's `CommonName` (left by a past
/// certificate regeneration) is logged via `tracing::warn!`, not silently
/// ignored — removing it is [`uninstall`]'s job, not this function's.
///
/// **`-addstore` runs against a temporary copy of `cert.pem`
/// ([`addstore_temp_path`]), not `cert_path` itself** — same reason as
/// [`local_cert_thumbprint`]: a packaged (MSIX) build's `certutil.exe` child
/// can't resolve `cert_path`'s virtualized location at all.
///
/// **Mutates the real trust store — never call this from an automated
/// test.**
///
/// # Errors
///
/// Returns [`TrustStoreError`] if the local certificate's thumbprint can't
/// be read (including the common first-run case where `cert.pem` doesn't
/// exist yet), if the temporary copy can't be written
/// ([`TrustStoreError::TempCopy`]), or if `certutil -addstore` itself fails.
pub fn ensure_installed(cert_path: &Path) -> Result<TrustStoreOutcome, TrustStoreError> {
    let (already_trusted, installed) = trusted_state(cert_path)?;

    if already_trusted {
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

    let thumbprint = local_cert_thumbprint(cert_path)?;
    let pem = std::fs::read(cert_path).map_err(|_| TrustStoreError::LocalThumbprint {
        path: cert_path.to_path_buf(),
    })?;
    let temp_path = addstore_temp_path(&system_root_dir()?, &thumbprint);
    std::fs::write(&temp_path, &pem).map_err(TrustStoreError::TempCopy)?;

    let certutil = certutil_path()?;
    let output = certutil_command(&certutil)
        .args([
            OsStr::new("-addstore"),
            OsStr::new("-user"),
            OsStr::new("Root"),
        ])
        .arg(&temp_path)
        .output()
        .map_err(TrustStoreError::Spawn)?;

    // Best-effort cleanup: the install attempt above already happened by
    // this point (succeeded or failed), and this is a public certificate
    // (see `addstore_temp_path`'s doc comment) — a leftover copy is not a
    // secrecy risk, only ever observed to transiently fail on a real-time
    // scanner briefly locking a new file under `%SystemRoot%\Temp`, not an
    // ACL/permission problem worth surfacing to the caller.
    let _ = std::fs::remove_file(&temp_path);

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
            let output = certutil_command(&certutil)
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
        addstore_temp_path, certutil_command, certutil_path, is_trusted, local_cert_thumbprint,
        uninstall_loop, MAX_MATCHING_ENTRIES,
    };
    use std::path::Path;

    #[test]
    fn addstore_temp_path_is_content_addressed_under_system_root_temp() {
        let path = addstore_temp_path(Path::new(r"C:\Windows"), "abc123");
        assert_eq!(path, Path::new(r"C:\Windows\Temp\dnsqb-cert-abc123.pem"));
        // Two different certificates (different thumbprints) must never
        // collide on the same temp path — the whole point of naming by
        // content, not a fixed name.
        let other = addstore_temp_path(Path::new(r"C:\Windows"), "def456");
        assert_ne!(path, other);
    }

    #[test]
    fn certutil_command_targets_the_given_path() {
        // The shared spawn helper (`CREATE_NO_WINDOW` on Windows) exists and
        // runs the certutil at the path it's handed. It does not, on its own,
        // prove every call site routes through it — a stray direct
        // `Command::new` elsewhere would still compile.
        let command = certutil_command(Path::new("X:\\System32\\certutil.exe"));
        assert_eq!(command.get_program(), "X:\\System32\\certutil.exe");
    }

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
    fn local_cert_thumbprint_matches_a_real_certutil_dump_of_the_same_file() {
        // Cross-validates the pure-Rust SHA-1-over-DER computation against
        // certutil's own ground truth for the same file — this is the whole
        // reason this function is trusted to have replaced `certutil -dump
        // <cert_path>` (2026-09-12, see this function's doc comment) without
        // silently drifting from what `Cert Hash(sha1)` actually means.
        // Spawning certutil here is safe (read-only, no store mutation) and,
        // unlike the function under test, is exactly what it's checking
        // against — not a redundant self-comparison.
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

        let Ok(certutil) = certutil_path() else {
            panic!("%SystemRoot% must be set on any Windows test runner");
        };
        let output = match certutil_command(&certutil)
            .arg("-dump")
            .arg(&cert_path)
            .output()
        {
            Ok(output) => output,
            Err(err) => panic!("certutil must spawn on this Windows test runner: {err}"),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let Some(certutil_hash) = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("Cert Hash(sha1): "))
        else {
            panic!("certutil -dump output had no Cert Hash(sha1) line:\n{stdout}");
        };
        // Case-insensitive: this function emits lowercase hex (matching the
        // rest of the crate's hex output, e.g. `paths::app_data_dir_hash`),
        // certutil prints uppercase — `trusted_state`'s real comparison is
        // already `eq_ignore_ascii_case` for the same reason.
        assert!(
            thumbprint.eq_ignore_ascii_case(certutil_hash),
            "Rust SHA-1(DER) {thumbprint:?} must match certutil's own \
             Cert Hash(sha1) {certutil_hash:?}"
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

    #[test]
    fn is_trusted_is_false_for_a_freshly_generated_never_installed_cert() {
        // T-191. Real `certutil -dump` + `-store` calls against a real
        // cert.pem this project actually generates — read-only, no store
        // mutation (the whole reason `is_trusted` is safe to call from a
        // test, unlike `ensure_installed`). A cert generated right here has a
        // random key, so its SHA-1 thumbprint is certainly not in the test
        // account's real CurrentUser\Root — the answer must be a clean
        // `Ok(false)`, never an `Err` and never a spurious `true`.
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
        match is_trusted(&cert_path) {
            Ok(trusted) => assert!(
                !trusted,
                "a freshly generated, never-installed cert must not report as trusted"
            ),
            Err(err) => panic!("is_trusted must succeed (Ok(false), not Err): {err}"),
        }
    }

    #[test]
    fn is_trusted_errors_when_cert_pem_is_absent() {
        // T-191. First run — `dnsqb-service` has never generated `cert.pem`.
        // This must be a distinguishable error, never a silent `Ok(false)`:
        // the caller (the tray icon) treats "unknown" and "untrusted"
        // differently — see `is_trusted`'s doc comment.
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let missing_path = dir.path().join("cert.pem");
        match is_trusted(&missing_path) {
            Err(super::TrustStoreError::LocalThumbprint { path }) => {
                assert_eq!(path, missing_path);
            }
            Ok(_) => panic!("expected LocalThumbprint on a missing cert.pem, got Ok"),
            Err(err) => panic!("expected LocalThumbprint, got a different Err: {err}"),
        }
    }
}
