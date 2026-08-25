//! RFC 1035 — Domain Names, Implementation and Specification. Base wire
//! format: the foundation `hickory-proto` provides (SPEC.md §"Крок 0",
//! table row RFC 1035; §1, §3).

use dnsqb_service::decode_wire_message;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use std::str::FromStr;

#[test]
#[ignore = "Крок 0 red until T-21 (Фаза 1)"]
fn decodes_basic_a_query_without_mangling_it() {
    let name = Name::from_str("example.com.").expect("valid fixture name");
    let mut query = Query::new();
    query.set_name(name.clone());
    query.set_query_type(RecordType::A);
    query.set_query_class(DNSClass::IN);

    let mut message = Message::query();
    message.add_query(query);
    let bytes = message.to_vec().expect("encode fixture");

    let decoded = decode_wire_message(&bytes).expect("RFC 1035 wire-format query must round-trip");
    let decoded_query = decoded
        .queries
        .first()
        .expect("query section preserved through decode");

    assert_eq!(decoded_query.name(), &name);
    assert_eq!(decoded_query.query_type(), RecordType::A);
    assert_eq!(decoded_query.query_class(), DNSClass::IN);
}
