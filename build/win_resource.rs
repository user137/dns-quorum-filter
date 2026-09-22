// Shared build-script body for the three `dnsqb-*` binaries — `include!`d
// by each crate's `build.rs`. Generates a Windows `VERSIONINFO` + app-icon
// resource script and links it into that crate's executable only
// (`embed-resource` emits `cargo:rustc-link-arg-bins`, so nothing leaks
// through the `dnsqb-service` rlib into the tray/watcher binaries). T-177.
//
// No-op on non-Windows targets.

use std::{env, fs, path::PathBuf};

/// `file_description` / `original_filename` are the only per-binary fields;
/// everything else is shared and the version is read from Cargo.
/// `app_manifest` is `Some(<name>.manifest)` (a file in this same `build/`
/// directory) only for a binary that shows native GUI dialogs - today just
/// `dnsqb-tray` (T-241 follow-up: this is what actually turns on Windows
/// 10/11-style `TaskDialogIndirect` rendering for rfd's dialogs, on top of
/// its own `common-controls-v6` Cargo feature). `dnsqb-service`/
/// `dnsqb-watcher` are headless and pass `None`.
fn embed_windows_resource(file_description: &str, original_filename: &str, app_manifest: Option<&str>) {
    if env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));

    let icon = manifest_dir.join("../../assets/icon/app.ico");
    // rc.exe and windres both accept forward slashes; backslashes in an .rc
    // string would be read as escape sequences.
    let icon_literal = icon.to_string_lossy().replace('\\', "/");

    // RT_MANIFEST (24) at resource ID 1 (CREATEPROCESS_MANIFEST_RESOURCE_ID)
    // is the well-known slot Windows reads an embedded application manifest
    // from - same forward-slash-escaping reasoning as the icon path above.
    let manifest_rc_line = app_manifest
        .map(|name| {
            let path = manifest_dir.join("../../build").join(name);
            let literal = path.to_string_lossy().replace('\\', "/");
            format!(r#"1 24 "{literal}""#)
        })
        .unwrap_or_default();

    let major = env::var("CARGO_PKG_VERSION_MAJOR").expect("set by cargo");
    let minor = env::var("CARGO_PKG_VERSION_MINOR").expect("set by cargo");
    let patch = env::var("CARGO_PKG_VERSION_PATCH").expect("set by cargo");
    let version_str = env::var("CARGO_PKG_VERSION").expect("set by cargo");
    let version_quad = format!("{major},{minor},{patch},0");

    let rc = format!(
        r#"#include <winresrc.h>

1 ICON "{icon_literal}"

{manifest_rc_line}

1 VERSIONINFO
FILEVERSION {version_quad}
PRODUCTVERSION {version_quad}
FILEOS VOS__WINDOWS32
FILETYPE VFT_APP
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "DNS Quorum Filter project"
            VALUE "FileDescription", "{file_description}"
            VALUE "FileVersion", "{version_str}"
            VALUE "InternalName", "{original_filename}"
            VALUE "LegalCopyright", "Licensed under the Apache License 2.0"
            VALUE "OriginalFilename", "{original_filename}"
            VALUE "ProductName", "DNS Quorum Filter"
            VALUE "ProductVersion", "{version_str}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
    );

    let rc_path = out_dir.join("dnsqb-version.rc");
    fs::write(&rc_path, rc).expect("write generated .rc");

    println!("cargo:rerun-if-changed=../../assets/icon/app.ico");
    println!("cargo:rerun-if-changed=../../build/win_resource.rs");
    if let Some(name) = app_manifest {
        println!("cargo:rerun-if-changed=../../build/{name}");
    }

    match embed_resource::compile(&rc_path, embed_resource::NONE) {
        embed_resource::CompilationResult::Ok | embed_resource::CompilationResult::NotWindows => {}
        // Windows target but no resource compiler on PATH (rc.exe / windres):
        // don't break the build for such a contributor, but make it loud —
        // CI has the compiler and must produce the real thing.
        embed_resource::CompilationResult::NotAttempted(why) => {
            println!("cargo:warning=app icon/version not embedded: {why}");
        }
        embed_resource::CompilationResult::Failed(err) => {
            panic!("embedding the Windows resource failed: {err}");
        }
    }
}
