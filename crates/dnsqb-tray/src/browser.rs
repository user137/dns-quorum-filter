//! Opens the embedded web UI (`dnsqb-service`'s `/admin/ui`, T-149) in the
//! user's default browser.
//!
//! `rundll32.exe url.dll,FileProtocolHandler` is the well-known Win32 idiom
//! for "open this URL in whatever the user's default browser is" — spawned
//! by an absolute path resolved from `%SystemRoot%`, never a bare PATH
//! lookup, the same discipline `cert.rs`'s `icacls.exe` invocation already
//! established (CLAUDE.md: "any spawned system process uses an absolute
//! path, never PATH lookup" — PATH is attacker-influenceable input, not a
//! trusted constant). One well-known idiom doesn't justify a new dependency
//! (`open`/`opener`).

use std::path::PathBuf;
use std::process::Command;

/// Opens `url` in the user's default browser. Failures are logged, not
/// propagated — this is always triggered from a tray menu click with no
/// synchronous UI to surface an error into.
pub fn open_in_default_browser(url: &str) {
    let rundll32 = system32_exe("rundll32.exe");
    match Command::new(&rundll32)
        .arg("url.dll,FileProtocolHandler")
        .arg(url)
        .spawn()
    {
        Ok(_child) => {}
        Err(err) => tracing::warn!("failed to open the default browser: {err}"),
    }
}

/// Resolves `exe` under `%SystemRoot%\System32`, falling back to the
/// conventional `C:\Windows` only if `SystemRoot` itself is unset — the same
/// tolerance a bare environment-variable read needs on any real Windows
/// install, never a PATH search.
fn system32_exe(exe: &str) -> PathBuf {
    let system_root =
        std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".to_string().into());
    PathBuf::from(system_root).join("System32").join(exe)
}

#[cfg(test)]
mod tests {
    use super::system32_exe;

    #[test]
    fn system32_exe_joins_under_system_root() {
        let path = system32_exe("rundll32.exe");
        let path_str = path.to_string_lossy();
        assert!(path_str.ends_with(r"System32\rundll32.exe"));
    }
}
