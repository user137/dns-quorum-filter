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
//! `DETACHED_PROCESS` so it outlives the tray, first *waits* for all three
//! DNS-QF processes to exit — `stop.flag` / `quit.flag` are plain unlocked
//! files in that directory, and deleting them before the watcher's next tick
//! reads `quit.flag` would leave the watcher respawning the service into a
//! directory being erased — then loops `Remove-Item -Recurse -Force` until the
//! directory is gone.

use std::path::{Path, PathBuf};
use std::process::Command;

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
    Some(format!(
        "$i=0; while ((Get-Process dnsqb-service,dnsqb-watcher,dnsqb-tray \
         -ErrorAction SilentlyContinue) -and $i -lt 40) {{ Start-Sleep -Milliseconds 500; $i++ }}; \
         $j=0; while ((Test-Path -LiteralPath '{quoted}') -and $j -lt 30) {{ \
         Remove-Item -LiteralPath '{quoted}' -Recurse -Force -ErrorAction SilentlyContinue; \
         Start-Sleep -Milliseconds 500; $j++ }}"
    ))
}

/// Spawn the detached wipe helper for `app_data`. Best-effort: a validation
/// failure or a spawn error is logged, not propagated — the tray is about to
/// exit regardless.
pub fn spawn_app_data_dir_wipe(app_data: &Path) {
    let Some(script) = build_wipe_script(app_data) else {
        tracing::warn!("app-data wipe skipped: the directory failed validation");
        return;
    };
    let powershell = powershell_exe();
    let mut command = Command::new(&powershell);
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle",
        "Hidden",
        "-Command",
        &script,
    ]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        /// `DETACHED_PROCESS` — the child gets no console and is not tied to
        /// this process's lifetime (same value as `watchdog::spawn`'s). Not
        /// paired with `CREATE_NO_WINDOW`, which Windows ignores alongside
        /// `DETACHED_PROCESS`; `-WindowStyle Hidden` is the belt on top.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        command.creation_flags(DETACHED_PROCESS);
    }
    match command.spawn() {
        Ok(_child) => tracing::info!("app-data directory wipe scheduled"),
        Err(err) => tracing::warn!("could not spawn the app-data wipe helper: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{build_wipe_script_for, powershell_exe};
    use std::path::Path;

    const LOCALAPPDATA: &str = "C:\\Users\\x\\AppData\\Local";

    fn target() -> String {
        format!("{LOCALAPPDATA}\\dns-quorum-filter")
    }

    #[test]
    fn powershell_exe_joins_under_system_root() {
        let path = powershell_exe();
        assert!(path
            .to_string_lossy()
            .ends_with(r"System32\WindowsPowerShell\v1.0\powershell.exe"));
    }

    #[test]
    fn wipe_script_waits_for_the_processes_before_deleting() {
        let Some(script) = build_wipe_script_for(Path::new(&target()), Path::new(LOCALAPPDATA))
        else {
            panic!("a valid app-data path must produce a script");
        };
        let wait_at = script
            .find("Get-Process dnsqb-service")
            .unwrap_or(usize::MAX);
        let delete_at = script.find("Remove-Item").unwrap_or(0);
        assert!(
            wait_at < delete_at,
            "the process-wait loop must come before the delete loop"
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
