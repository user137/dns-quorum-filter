//! T-243 (хвиля 3) — the MSIX autostart task's state, for `/admin/ui`.
//! `packaging/AppxManifest.template.xml` declares a `windows.startupTask`
//! for `dnsqb-watcher.exe`; Windows registers it only after the app's first
//! launch, and the user can switch it off in Settings → Apps → Startup. Its
//! state lives at `HKCU\…\AppModel\SystemAppData\<PFN>\<TaskId>`, value
//! `State` (`Windows.ApplicationModel.StartupTaskState`) — read through
//! `winreg` (no `unsafe` in this crate, same as `install_region`). Pure core
//! here, one `#[cfg(windows)]` impure shell, the `install_region` split.

use crate::admin::StartupTaskView;

/// The manifest's `TaskId` — a test below keeps it in sync with the template.
pub(crate) const STARTUP_TASK_ID: &str = "DnsqbWatcherStartup";

/// The package family name (`<Name>_<PublisherId>`) from the package's
/// install directory name, `<Name>_<Version>_<Arch>_<ResourceId>_<PublisherId>`
/// (`ResourceId` usually empty). `None` for anything else — a dev build in
/// `target\debug` is not a package. Both halves are validated against the
/// MSIX character sets, so the result is safe to put into a registry path.
pub(crate) fn package_family_name(install_dir_name: &str) -> Option<String> {
    let parts: Vec<&str> = install_dir_name.split('_').collect();
    let [name, _version, _arch, _resource_id, publisher_id] = parts.as_slice() else {
        return None;
    };
    let name_ok = (3..=50).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let publisher_ok = publisher_id.len() == 13
        && publisher_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    (name_ok && publisher_ok).then(|| format!("{name}_{publisher_id}"))
}

/// Maps the registry `State` DWORD to the DTO: 2 `Enabled` / 4
/// `EnabledByPolicy` → on; 0 `Disabled` / 1 `DisabledByUser` → off;
/// 3 `DisabledByPolicy` → off, not fixable in Settings; absent or unknown →
/// [`StartupTaskView::Unknown`] (a missing key can be a first launch that
/// has not registered the task yet — never a fabricated warning).
pub(crate) fn view_from_state(state: Option<u32>) -> StartupTaskView {
    match state {
        Some(2 | 4) => StartupTaskView::Enabled,
        Some(0 | 1) => StartupTaskView::Disabled,
        Some(3) => StartupTaskView::DisabledByPolicy,
        _ => StartupTaskView::Unknown,
    }
}

/// Reads this package's startup-task state. [`StartupTaskView::Unknown`] when
/// the running exe is not inside an installed package or the value can't be
/// read. Cheap (one registry read; the package name is resolved once) —
/// called on every status build.
#[cfg(windows)]
pub(crate) fn read_startup_task() -> StartupTaskView {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    static PFN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let pfn = PFN.get_or_init(|| {
        std::env::current_exe().ok().and_then(|exe| {
            exe.parent()
                .and_then(std::path::Path::file_name)
                .and_then(std::ffi::OsStr::to_str)
                .and_then(package_family_name)
        })
    });
    let Some(pfn) = pfn else {
        return StartupTaskView::Unknown;
    };
    let path = format!(
        r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\{pfn}\{STARTUP_TASK_ID}"
    );
    let state = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(path)
        .and_then(|key| key.get_value::<u32, _>("State"))
        .ok();
    view_from_state(state)
}

/// Non-Windows builds have no MSIX startup task — the Фаза 6 seam stays
/// visible here (`CLAUDE.md`'s "Current phase boundaries").
#[cfg(not(windows))]
pub(crate) fn read_startup_task() -> StartupTaskView {
    StartupTaskView::Unknown
}

#[cfg(test)]
mod tests {
    use super::{package_family_name, view_from_state, STARTUP_TASK_ID};
    use crate::admin::StartupTaskView;

    // Happy path — the real 0.8.0 install directory (empty ResourceId).
    #[test]
    fn package_family_name_from_the_installed_directory() {
        assert_eq!(
            package_family_name("dns-quorum-filter_0.8.0.0_x64__8d78tvs37tgae").as_deref(),
            Some("dns-quorum-filter_8d78tvs37tgae")
        );
    }

    // Security & Boundary — anything that would not be a clean registry path
    // segment is rejected, not escaped.
    #[test]
    fn package_family_name_rejects_bad_characters() {
        for dir in [
            r"dns\quorum_0.8.0.0_x64__8d78tvs37tgae",
            "dns-quorum-filter_0.8.0.0_x64__8d78tvs37tga\\",
            "dns-quorum-filter_0.8.0.0_x64__8D78TVS37TGAE",
            "dns quorum_0.8.0.0_x64__8d78tvs37tgae",
            "ab_0.8.0.0_x64__8d78tvs37tgae",
        ] {
            assert_eq!(package_family_name(dir), None, "{dir}");
        }
    }

    // Misuse & Fool — a dev build directory or a wrong segment count.
    #[test]
    fn package_family_name_is_none_outside_a_package() {
        for dir in [
            "debug",
            "release",
            "",
            "dns-quorum-filter_0.8.0.0_x64_8d78tvs37tgae",
            "dns-quorum-filter_0.8.0.0_x64___8d78tvs37tgae",
            "dns-quorum-filter_0.8.0.0_x64__8d78tvs37tga",
        ] {
            assert_eq!(package_family_name(dir), None, "{dir:?}");
        }
    }

    #[test]
    fn view_from_state_covers_every_documented_value() {
        assert_eq!(view_from_state(Some(0)), StartupTaskView::Disabled);
        assert_eq!(view_from_state(Some(1)), StartupTaskView::Disabled);
        assert_eq!(view_from_state(Some(2)), StartupTaskView::Enabled);
        assert_eq!(view_from_state(Some(3)), StartupTaskView::DisabledByPolicy);
        assert_eq!(view_from_state(Some(4)), StartupTaskView::Enabled);
    }

    // Error path — absent key or an undocumented value never warns.
    #[test]
    fn view_from_state_unknown_for_absent_or_undocumented() {
        assert_eq!(view_from_state(None), StartupTaskView::Unknown);
        assert_eq!(view_from_state(Some(5)), StartupTaskView::Unknown);
        assert_eq!(view_from_state(Some(u32::MAX)), StartupTaskView::Unknown);
    }

    #[test]
    fn task_id_matches_the_manifest_template() {
        let manifest = include_str!("../../../packaging/AppxManifest.template.xml");
        assert!(manifest.contains(&format!("TaskId=\"{STARTUP_TASK_ID}\"")));
    }

    #[test]
    fn startup_task_view_wire_strings() {
        let json = |v: StartupTaskView| serde_json::to_string(&v).ok();
        assert_eq!(
            json(StartupTaskView::Disabled).as_deref(),
            Some("\"DISABLED\"")
        );
        assert_eq!(
            json(StartupTaskView::DisabledByPolicy).as_deref(),
            Some("\"DISABLED_BY_POLICY\"")
        );
    }
}
