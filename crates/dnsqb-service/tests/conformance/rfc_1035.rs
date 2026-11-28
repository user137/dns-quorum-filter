//! RFC 1035 — Domain Names, Implementation and Specification. Base wire
//! format: the foundation `hickory-proto` provides (SPEC.md §"Крок 0",
//! table row RFC 1035; §1, §3).

use dnsqb_service::{decode_wire_message, precheck_query, QueryPrecheck};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use std::str::FromStr;

#[test]
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

// T-305: checks every query passes before the pipeline, on every transport.

fn a_query(name: &str) -> Message {
    let mut message = Message::query();
    message.add_query(Query::query(
        Name::from_str(name).expect("valid fixture name"),
        RecordType::A,
    ));
    message
}

fn reply_code(query: &Message) -> ResponseCode {
    match precheck_query(query) {
        QueryPrecheck::Reply(reply) => {
            assert_eq!(reply.metadata.id, query.metadata.id);
            assert_eq!(reply.metadata.message_type, MessageType::Response);
            reply.metadata.response_code
        }
        other => panic!("expected a local reply, got {other:?}"),
    }
}

// §4.1.1 QR: a message that is itself a response is never answered (no
// reflection loops between two resolvers).
#[test]
fn a_response_is_dropped() {
    let mut message = a_query("example.com.");
    message.metadata.message_type = MessageType::Response;
    assert!(matches!(precheck_query(&message), QueryPrecheck::Drop));
}

// §4.1.1 OPCODE / RCODE 4: only standard queries are implemented.
#[test]
fn a_non_query_opcode_gets_notimp() {
    for op_code in [OpCode::Status, OpCode::Notify, OpCode::Update] {
        let mut message = a_query("example.com.");
        message.metadata.op_code = op_code;
        assert_eq!(reply_code(&message), ResponseCode::NotImp, "{op_code:?}");
    }
}

// Zone transfers (RFC 5936 / 1995) are never served or proxied.
#[test]
fn a_zone_transfer_is_refused() {
    for qtype in [RecordType::AXFR, RecordType::IXFR] {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_str("example.com.").expect("valid fixture name"),
            qtype,
        ));
        assert_eq!(reply_code(&message), ResponseCode::Refused, "{qtype:?}");
    }
}

// §3.2.4: only class IN is resolved; CHAOS (`version.bind`) and the rest
// would otherwise reach the baseline and describe it.
#[test]
fn a_non_internet_class_is_refused() {
    let mut message = a_query("version.bind.");
    if let Some(query) = message.queries.first_mut() {
        query.set_query_class(DNSClass::CH);
    }
    assert_eq!(reply_code(&message), ResponseCode::Refused);
}

#[test]
fn an_ordinary_query_goes_on_to_the_pipeline() {
    assert!(matches!(
        precheck_query(&a_query("example.com.")),
        QueryPrecheck::Resolve
    ));
}
