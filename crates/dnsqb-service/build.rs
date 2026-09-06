// T-177 — see build/win_resource.rs. No-op off Windows.
include!("../../build/win_resource.rs");

fn main() {
    embed_windows_resource(
        "DNS Quorum Filter — local DoH resolver service",
        "dnsqb-service.exe",
    );
}
