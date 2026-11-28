//! RFC 8482 — Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY:
//! answered locally with one synthesized HINFO record, never proxied to an
//! upstream (amplification on plain DNS, T-305).

use dnsqb_service::{precheck_query, QueryPrecheck};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::str::FromStr;

#[test]
fn any_gets_one_synthesized_hinfo_record() {
    let name = Name::from_str("example.com.").expect("valid fixture name");
    let mut query = Message::query();
    query.add_query(Query::query(name.clone(), RecordType::ANY));

    let QueryPrecheck::Reply(reply) = precheck_query(&query) else {
        panic!("ANY must be answered locally");
    };
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.answers.len(), 1);
    let record = &reply.answers[0];
    assert_eq!(record.name, name);
    match &record.data {
        RData::HINFO(hinfo) => assert_eq!(&*hinfo.cpu, b"RFC8482"),
        other => panic!("expected HINFO, got {other:?}"),
    }
}
