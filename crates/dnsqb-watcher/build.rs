// T-177 — see build/win_resource.rs. No-op off Windows.
include!("../../build/win_resource.rs");

fn main() {
    // Plain ASCII hyphen - see the identical comment in dnsqb-tray/build.rs
    // (T-241) for why an em dash here becomes Task Manager mojibake.
    embed_windows_resource("DNS Quorum Filter - watchdog", "dnsqb-watcher.exe", None);
}
