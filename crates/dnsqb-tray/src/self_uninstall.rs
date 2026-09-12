//! T-195 — the tray's "Повністю видалити" erases the whole app-data
//! directory once the app itself has exited.
//!
//! [`dnsqb_service::remove_all_local_state`] (T-70) clears the trusted
//! certificate and the three Credential Manager secrets — state that lives
//! *outside* `%LOCALAPPDATA%`. It never touches
//! `%LOCALAPPDATA%\dns-quorum-filter` itself (`cert.pem`, the encrypted
//! query-log / cache, `resolver_config.toml`, `logs\`), and no DNS-QF process
//! can delete that directory while it is running: the tray holds `tray.lock`
//! open (`share_mode(0)`), the watcher and service hold theirs, and `tao`'s
//! event loop never returns, so there is no post-run point at which the tray
//! could drop its guard and clean up.
//!
//! So a detached helper does it. A hidden `powershell.exe`, spawned
//! `DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB` (mirroring
//! `watchdog::spawn::spawn_detached`, T-182 — the MSIX process tree is
//! job-contained) so it outlives the tray, first *waits* up to 20 s for all
//! three DNS-QF processes to exit — `stop.flag` / `quit.flag` are plain
//! unlocked files in that directory, and deleting them before the watcher's
//! next tick reads `quit.flag` would leave the watcher respawning the service
//! into a directory being erased. If any process survives the wait the helper
//! `exit`s *without* deleting; otherwise it loops `Remove-Item -Recurse
//! -Force` until the directory is gone.
//!
//! **T-222 (found 2026-09-12 smoke test, fixed 2026-09-13): the same
//! MSIX-virtualization gap T-219 found in `trust_store.rs`, in this
//! completely different subsystem.** `app_data` (the *logical*
//! `%LOCALAPPDATA%\dns-quorum-filter`) is transparently redirected to its
//! real physical location
//! (`%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Local\
//! dns-quorum-filter`) only for a process that itself has package identity —
//! `dnsqb-tray.exe` running packaged does, the spawned unpackaged
//! `powershell.exe` above does not (confirmed for `certutil.exe`
//! specifically at T-219; never checked for this module's own spawn until
//! this fix). The helper's own `Test-Path` therefore always saw the logical
//! path as absent and its wait-then-delete loop bailed out on the very
//! first check, silently, `Remove-Item` never once invoked. [`resolve_target`]
//! is the fix: resolve the real physical directory from *this* (packaged)
//! process's own view before spawning the helper, and hand that path to the
//! script instead — the same "give the unpackaged child a path it can
//! actually see" shape T-219's `-addstore` fix already used, applied to a
//! whole-directory delete instead of a single staged file.

use std::path::{Path, PathBuf};
use std::process::Command;

/// This process's own MSIX `PackageFamilyName` (`<Name>_<PublisherHash>`),
/// parsed from `exe_dir_name` — the `WindowsApps\<Name>_<Version>_<Arch>__
/// <PublisherHash>\` install-folder naming convention. Pure string parsing,
/// no filesystem access, so it's unit-testable without a real install.
///
/// `None` for anything that doesn't match this shape (`target\debug`/
/// `target\release` for an unpackaged dev/CI build has no `__` at all) —
/// [`resolve_target`]'s caller falls back to the logical `app_data` path
/// unchanged in that case, which is already correct for an unpackaged
/// build.
///
/// **Never hardcode a specific hash.** A different code-signing certificate
/// (an ephemeral `pack-msix.ps1` test build with no `-PfxPath`) gets a
/// genuinely different `PublisherHash` each time it's repacked — confirmed
/// this session (the real release's hash and the scenario-24 update-test
/// build's hash differed). This must be resolved fresh every run, never
/// cached or assumed stable across builds.
fn package_family_name(exe_dir_name: &str) -> Option<String> {
    let (left, hash) = exe_dir_name.rsplit_once("__")?;
    let (name, _version_and_arch) = left.split_once('_')?;
    if name.is_empty() || hash.is_empty() {
        return None;
    }
    Some(format!("{name}_{hash}"))
}

/// Pure: the real, unvirtualized physical directory an MSIX-packaged
/// process's own `app_data` (the logical `%LOCALAPPDATA%\dns-quorum-filter`)
/// redirects to for that process, given `local_app_data`/`exe_dir_name`
/// explicitly rather than reading the environment here — same reasoning as
/// `paths::resolve_app_data_dir`'s own doc comment: testable without
/// mutating the real process environment, which `std::env::set_var` can't
/// do safely under `#![forbid(unsafe_code)]` on this toolchain regardless
/// (it's an `unsafe fn`). Does **not** check whether the result exists on
/// disk — that real I/O stays in [`resolve_target`], the impure shell.
///
/// `None` when this doesn't look like a packaged install
/// ([`package_family_name`] returned `None`) — [`resolve_target`] falls
/// back to `app_data` unchanged in that case, correct for an unpackaged
/// build.
fn physical_app_data_dir(
    local_app_data: &std::ffi::OsStr,
    exe_dir_name: &str,
    app_data: &Path,
) -> Option<PathBuf> {
    let pfn = package_family_name(exe_dir_name)?;
    Some(
        Path::new(local_app_data)
            .join("Packages")
            .join(pfn)
            .join("LocalCache")
            .join("Local")
            .join(app_data.file_name()?),
    )
}

/// The impure shell around [`physical_app_data_dir`]: reads this process's
/// own `current_exe()` and `%LOCALAPPDATA%`, resolves the physical path if
/// this is a packaged install **and** that directory actually exists, and
/// falls back to `app_data` itself in every other case (an unpackaged
/// build, `current_exe()`/`%LOCALAPPDATA%` unavailable, or a computed path
/// that isn't actually there — never fatal, the caller is about to spawn a
/// best-effort helper regardless).
fn resolve_target(app_data: &Path) -> PathBuf {
    let resolved = (|| {
        let exe = std::env::current_exe().ok()?;
        let exe_dir_name = exe.parent()?.file_name()?.to_str()?;
        let local_app_data = std::env::var_os("LOCALAPPDATA")?;
        let candidate = physical_app_data_dir(&local_app_data, exe_dir_name, app_data)?;
        candidate.is_dir().then_some(candidate)
    })();
    if let Some(candidate) = resolved {
        tracing::info!("app-data wipe: using packaged-physical path");
        candidate
    } else {
        tracing::info!(
            "app-data wipe: using logical path (unpackaged build, or no packaged-physical \
             directory found)"
        );
        app_data.to_path_buf()
    }
}

/// Absolute path to `powershell.exe`, resolved from `%SystemRoot%` — the same
/// never-a-PATH-lookup discipline as [`crate::browser`]'s `rundll32.exe`.
fn powershell_exe() -> PathBuf {
    let system_root =
        std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".to_string().into());
    PathBuf::from(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

/// The PowerShell one-liner that wipes `dir`, or `None` if `dir` fails
/// validation. Split from [`spawn_app_data_dir_wipe`] so the guard and the
/// shell-quoting are testable without spawning anything.
///
/// Validation (a detached force-delete of an interpolated path is worth
/// fencing): `dir` must sit under `%LOCALAPPDATA%` **and** its final component
/// must be exactly `dns-quorum-filter`, so a degenerate or empty `app_data`
/// can never widen the target.
pub fn build_wipe_script(dir: &Path) -> Option<String> {
    let localappdata = std::env::var_os("LOCALAPPDATA")?;
    build_wipe_script_for(dir, Path::new(&localappdata))
}

fn build_wipe_script_for(dir: &Path, localappdata: &Path) -> Option<String> {
    if localappdata.as_os_str().is_empty() || !dir.starts_with(localappdata) {
        return None;
    }
    if dir.file_name()?.to_str()? != "dns-quorum-filter" {
        return None;
    }
    // Single-quoted in the script, so only a literal `'` needs escaping
    // (doubled). `%LOCALAPPDATA%` paths don't contain one in practice; guard
    // anyway.
    let quoted = dir.to_str()?.replace('\'', "''");
    // 1. Wait up to 20 s (well past the watcher's 5 s tick) for every DNS-QF
    //    process to exit. 2. If any survived the wait, `exit` *without*
    //    deleting — removing `stop.flag` / `quit.flag` from under a live
    //    watcher would leave it respawning the service into a directory being
    //    erased. 3. Otherwise loop `Remove-Item` until the directory is gone.
    Some(format!(
        "$p='dnsqb-service','dnsqb-watcher','dnsqb-tray'; \
         $i=0; while ((Get-Process $p -ErrorAction SilentlyContinue) -and $i -lt 40) \
         {{ Start-Sleep -Milliseconds 500; $i++ }}; \
         if (Get-Process $p -ErrorAction SilentlyContinue) {{ exit 1 }}; \
         $j=0; while ((Test-Path -LiteralPath '{quoted}') -and $j -lt 30) {{ \
         Remove-Item -LiteralPath '{quoted}' -Recurse -Force -ErrorAction SilentlyContinue; \
         Start-Sleep -Milliseconds 500; $j++ }}"
    ))
}

/// Spawn the detached wipe helper for `app_data`. Best-effort: a validation
/// failure or a spawn error is logged, not propagated — the tray is about to
/// exit regardless.
///
/// **T-222:** the path actually handed to the spawned (unpackaged) helper is
/// [`resolve_target`]'s result, not `app_data` itself — on a packaged
/// install that's the real physical directory, never the logical alias the
/// helper can't see. `build_wipe_script`'s own validation still runs against
/// whichever path this resolves to (it accepts both — see that function's
/// own doc for why).
pub fn spawn_app_data_dir_wipe(app_data: &Path) {
    let target = resolve_target(app_data);
    let Some(script) = build_wipe_script(&target) else {
        tracing::warn!("app-data wipe skipped: the directory failed validation");
        return;
    };
    let powershell = powershell_exe();
    let build = || {
        let mut command = Command::new(&powershell);
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &script,
        ]);
        command
    };

    #[cfg(not(windows))]
    match build().spawn() {
        Ok(_child) => tracing::info!("app-data directory wipe scheduled"),
        Err(err) => tracing::warn!("could not spawn the app-data wipe helper: {err}"),
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Mirror `watchdog::spawn::spawn_detached` (T-182): the MSIX /
        // Start-menu process tree is job-contained, so `DETACHED_PROCESS`
        // alone would let this helper be killed with the tray — inside its own
        // wait loop, before deleting anything, with only an `info!` line as a
        // trace. `CREATE_BREAKAWAY_FROM_JOB` lifts it out; on a job that
        // forbids that (`ERROR_ACCESS_DENIED`) we still try in-job, but say so
        // loudly — unlike the watchdog case, an in-job wipe helper is likely a
        // no-op, not merely degraded. (`CREATE_NO_WINDOW` is deliberately
        // absent — Windows ignores it beside `DETACHED_PROCESS`; `-WindowStyle
        // Hidden` covers the window.)
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        match build()
            .creation_flags(DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB)
            .spawn()
        {
            Ok(_child) => {
                tracing::info!("app-data directory wipe scheduled");
                return;
            }
            Err(err) if err.raw_os_error() == Some(5) => {
                tracing::warn!(
                    "the job object forbids CREATE_BREAKAWAY_FROM_JOB; the app-data wipe helper \
                     may be terminated with the tray before it finishes"
                );
            }
            Err(err) => {
                tracing::warn!("could not spawn the app-data wipe helper: {err}");
                return;
            }
        }
        match build().creation_flags(DETACHED_PROCESS).spawn() {
            Ok(_child) => tracing::info!("app-data directory wipe scheduled (in-job)"),
            Err(err) => tracing::warn!("could not spawn the app-data wipe helper: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_wipe_script_for, package_family_name, physical_app_data_dir, powershell_exe,
    };
    use std::path::Path;

    const LOCALAPPDATA: &str = "C:\\Users\\x\\AppData\\Local";

    fn target() -> String {
        format!("{LOCALAPPDATA}\\dns-quorum-filter")
    }

    // T-222 regression coverage — see this module's own doc comment for the
    // full root-cause story (same MSIX-virtualization class as T-219).

    #[test]
    fn package_family_name_parses_a_real_windowsapps_install_dir_name() {
        // The exact shape observed live this session for both the real
        // release and a differently-signed scenario-24 test build.
        assert_eq!(
            package_family_name("dns-quorum-filter_0.4.1.0_x64__8d78tvs37tgae"),
            Some("dns-quorum-filter_8d78tvs37tgae".to_string())
        );
    }

    #[test]
    fn package_family_name_is_none_for_an_unpackaged_dev_build_dir() {
        // `target\debug`/`target\release` - no `__` separator at all.
        assert_eq!(package_family_name("debug"), None);
        assert_eq!(package_family_name("release"), None);
    }

    #[test]
    fn package_family_name_is_none_for_a_malformed_shape() {
        // No underscore before the `__` split - can't separate name from
        // version/arch.
        assert_eq!(package_family_name("noNameSeparator__somehash"), None);
        // No `__` at all.
        assert_eq!(package_family_name("dns-quorum-filter_0.4.1.0_x64"), None);
    }

    #[test]
    fn physical_app_data_dir_builds_the_packages_localcache_path() {
        let resolved = physical_app_data_dir(
            std::ffi::OsStr::new(LOCALAPPDATA),
            "dns-quorum-filter_0.4.1.0_x64__8d78tvs37tgae",
            Path::new(&target()),
        );
        assert_eq!(
            resolved,
            Some(Path::new(
                r"C:\Users\x\AppData\Local\Packages\dns-quorum-filter_8d78tvs37tgae\LocalCache\Local\dns-quorum-filter"
            ).to_path_buf())
        );
    }

    #[test]
    fn physical_app_data_dir_is_none_for_an_unpackaged_exe_dir() {
        assert_eq!(
            physical_app_data_dir(
                std::ffi::OsStr::new(LOCALAPPDATA),
                "release",
                Path::new(&target())
            ),
            None
        );
    }

    #[test]
    fn powershell_exe_joins_under_system_root() {
        let path = powershell_exe();
        assert!(path
            .to_string_lossy()
            .ends_with(r"System32\WindowsPowerShell\v1.0\powershell.exe"));
    }

    #[test]
    fn wipe_script_waits_and_bails_before_it_deletes() {
        let Some(script) = build_wipe_script_for(Path::new(&target()), Path::new(LOCALAPPDATA))
        else {
            panic!("a valid app-data path must produce a script");
        };
        let wait_at = script.find("while ((Get-Process $p").unwrap_or(usize::MAX);
        let bail_at = script.find("{ exit 1 }").unwrap_or(usize::MAX);
        let delete_at = script.find("Remove-Item").unwrap_or(0);
        assert!(
            wait_at < bail_at && bail_at < delete_at,
            "wait loop, then the bail-if-still-running guard, then the delete loop"
        );
        assert!(script.contains(&format!("-LiteralPath '{}'", target())));
    }

    #[test]
    fn wipe_script_doubles_a_single_quote_in_the_path() {
        let dir = "C:\\Users\\o'brien\\AppData\\Local\\dns-quorum-filter";
        let lad = "C:\\Users\\o'brien\\AppData\\Local";
        let Some(script) = build_wipe_script_for(Path::new(dir), Path::new(lad)) else {
            panic!("a valid app-data path must produce a script");
        };
        assert!(script.contains("o''brien"));
        assert!(!script.contains("o'brien'"));
    }

    #[test]
    fn wipe_script_rejects_a_path_outside_localappdata() {
        assert!(
            build_wipe_script_for(Path::new("C:\\Windows\\System32"), Path::new(LOCALAPPDATA))
                .is_none()
        );
    }

    #[test]
    fn wipe_script_rejects_a_final_component_that_is_not_dns_quorum_filter() {
        let evil = format!("{LOCALAPPDATA}\\evil");
        assert!(build_wipe_script_for(Path::new(&evil), Path::new(LOCALAPPDATA)).is_none());
    }

    #[test]
    fn wipe_script_is_none_for_empty_paths() {
        assert!(build_wipe_script_for(Path::new(""), Path::new("")).is_none());
    }
}
