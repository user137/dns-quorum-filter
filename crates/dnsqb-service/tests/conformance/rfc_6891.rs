//! RFC 6891 — Extension Mechanisms for DNS (EDNS(0)): outgoing queries
//! advertise a UDP payload size large enough to avoid needless truncation
//! over the loopback DoH path (SPEC.md §3.4).

use dnsqb_service::{attach_edns, EDNS_UDP_PAYLOAD_SIZE};
use hickory_proto::op::Message;

// RFC 6891 §6.2.3: values under 512 provide no benefit over no-EDNS.
const _: () = assert!(EDNS_UDP_PAYLOAD_SIZE > 512);

#[test]
fn attach_edns_adds_an_opt_record_above_the_512_byte_legacy_minimum() {
    let mut query = Message::query();
    attach_edns(&mut query);

    let edns = query.edns.expect("attach_edns must add an OPT record");
    assert_eq!(edns.max_payload(), EDNS_UDP_PAYLOAD_SIZE);
}
