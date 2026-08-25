//! RFC 6891 — Extension Mechanisms for DNS (EDNS(0)): outgoing queries
//! advertise a UDP payload size large enough to avoid needless truncation
//! over the loopback DoH path (SPEC.md §3.4).

use dnsqb_service::edns_udp_payload_size;

#[test]
#[ignore = "Крок 0 red until T-24 (Фаза 1)"]
fn advertises_a_payload_size_above_the_512_byte_legacy_minimum() {
    // RFC 6891 §6.2.3: values under 512 provide no benefit over no-EDNS.
    assert!(edns_udp_payload_size() > 512);
}
