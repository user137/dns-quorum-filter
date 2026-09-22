// T-177 — see build/win_resource.rs. No-op off Windows.
include!("../../build/win_resource.rs");

fn main() {
    // Plain ASCII hyphen, not an em dash: the generated .rc file is written
    // as raw UTF-8 with no BOM (see win_resource.rs), and rc.exe/windres
    // read a BOM-less .rc as the system ANSI codepage regardless of the
    // StringFileInfo codepage block declared inside it - a non-ASCII byte
    // here becomes mojibake in Task Manager (found in v0.5.0 smoke test,
    // T-241) even though the compiled resource is correctly tagged
    // Unicode. ASCII sidesteps the encoding question on both rc.exe (MSVC
    // CI) and windres (this dev box's windows-gnu host) instead of relying
    // on either compiler's BOM handling.
    embed_windows_resource(
        "DNS Quorum Filter - tray icon",
        "dnsqb-tray.exe",
        Some("dnsqb-tray.manifest"),
    );
}
