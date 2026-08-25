//! RFC 8484 — DNS Queries over HTTPS (DoH): GET requests carry the wire
//! message as an unpadded base64url `dns=` query parameter (§4.1.1)
//! (SPEC.md §1, §3).

use dnsqb_service::doh_get_url;

#[test]
#[ignore = "Крок 0 red until T-24 (Фаза 1)"]
fn get_url_uses_unpadded_base64url_dns_parameter() {
    let message_bytes = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    let url = doh_get_url("https://dns.quad9.net/dns-query", message_bytes);

    assert!(url.starts_with("https://dns.quad9.net/dns-query?dns="));
    let encoded = url
        .strip_prefix("https://dns.quad9.net/dns-query?dns=")
        .expect("dns= parameter present");
    // base64url alphabet only, no '+' '/' '=' padding (RFC 4648 §5).
    assert!(!encoded.contains('+'));
    assert!(!encoded.contains('/'));
    assert!(!encoded.contains('='));
}
