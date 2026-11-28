//! RFC 6761 (special-use names), with RFC 6762 `.local`, RFC 7686 `.onion`
//! and RFC 8375 `home.arpa`: answered here, never sent to a provider
//! (T-305 batch 3a).

use dnsqb_service::{precheck_query, QueryPrecheck};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub(crate) fn local_reply(name: &str, qtype: RecordType) -> Option<Message> {
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str(name).expect("valid fixture name"),
        qtype,
    ));
    match precheck_query(&query) {
        QueryPrecheck::Reply(reply) => Some(reply),
        QueryPrecheck::Resolve => None,
        QueryPrecheck::Drop => panic!("a query is never dropped"),
    }
}

// RFC 6761 §6.3: localhost names resolve to loopback, without a lookup.
#[test]
fn localhost_resolves_to_loopback_locally() {
    let a = local_reply("app.localhost.", RecordType::A).expect("answered locally");
    assert_eq!(a.metadata.response_code, ResponseCode::NoError);
    assert!(matches!(
        a.answers.first().map(|r| &r.data),
        Some(RData::A(addr)) if addr.0 == Ipv4Addr::LOCALHOST
    ));
    let aaaa = local_reply("localhost.", RecordType::AAAA).expect("answered locally");
    assert!(matches!(
        aaaa.answers.first().map(|r| &r.data),
        Some(RData::AAAA(addr)) if addr.0 == Ipv6Addr::LOCALHOST
    ));
    let mx = local_reply("localhost.", RecordType::MX).expect("answered locally");
    assert_eq!(mx.metadata.response_code, ResponseCode::NoError);
    assert!(mx.answers.is_empty());
}

// RFC 6761 §6.4, RFC 6762 §3, RFC 7686 §2, RFC 8375 §4.
#[test]
fn special_use_names_are_nxdomain_locally() {
    for name in [
        "x.invalid.",
        "printer.local.",
        "abcdefghijklmnop.onion.",
        "router.home.arpa.",
    ] {
        let reply = local_reply(name, RecordType::A).expect("answered locally");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NXDomain,
            "{name}"
        );
    }
}

// Single-label address queries (OS search lists, typos) stay here; a TLD
// and the root still go out, so DNSSEC chains keep working.
#[test]
fn single_label_names_stay_local_but_tlds_and_the_root_go_out() {
    let reply = local_reply("printer.", RecordType::A).expect("answered locally");
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(local_reply("com.", RecordType::A).is_none());
    assert!(local_reply("com.", RecordType::DS).is_none());
    assert!(local_reply(".", RecordType::NS).is_none());
    assert!(local_reply("example.com.", RecordType::A).is_none());
}
