//! RFC 6303 — Locally Served DNS Zones (plus RFC 7793's `100.64/10`):
//! reverse lookups of private, loopback and documentation addresses are
//! answered here, never sent to a provider (T-305 batch 3a).

use crate::rfc_6761::local_reply;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

#[test]
fn private_reverse_lookups_are_nxdomain_locally() {
    for name in [
        "1.1.168.192.in-addr.arpa.",
        "5.0.0.10.in-addr.arpa.",
        "1.0.0.127.in-addr.arpa.",
        "9.9.20.172.in-addr.arpa.",
        "1.1.254.169.in-addr.arpa.",
        "1.0.64.100.in-addr.arpa.",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
        "1.0.0.0.d.f.ip6.arpa.",
    ] {
        let reply = local_reply(name, RecordType::PTR).expect("answered locally");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NXDomain,
            "{name}"
        );
    }
}

#[test]
fn a_locally_served_zone_apex_has_no_data() {
    let reply = local_reply("10.in-addr.arpa.", RecordType::SOA).expect("answered locally");
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
}

#[test]
fn public_reverse_lookups_go_out() {
    assert!(local_reply("1.1.1.1.in-addr.arpa.", RecordType::PTR).is_none());
    assert!(local_reply("9.9.15.172.in-addr.arpa.", RecordType::PTR).is_none());
}
