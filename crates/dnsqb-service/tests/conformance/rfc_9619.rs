//! RFC 9619 — In the DNS, QDCOUNT Is (Usually) One: a query with any other
//! question count gets FORMERR, never a proxy to an upstream (T-305).

use dnsqb_service::{precheck_query, QueryPrecheck};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;

fn question(name: &str) -> Query {
    Query::query(
        Name::from_str(name).expect("valid fixture name"),
        RecordType::A,
    )
}

fn reply_code(query: &Message) -> ResponseCode {
    match precheck_query(query) {
        QueryPrecheck::Reply(reply) => {
            assert_eq!(reply.metadata.id, query.metadata.id);
            reply.metadata.response_code
        }
        other => panic!("expected a local reply, got {other:?}"),
    }
}

#[test]
fn a_query_without_a_question_is_formerr() {
    assert_eq!(reply_code(&Message::query()), ResponseCode::FormErr);
}

#[test]
fn a_query_with_two_questions_is_formerr() {
    let mut query = Message::query();
    query.add_query(question("example.com."));
    query.add_query(question("example.org."));
    assert_eq!(reply_code(&query), ResponseCode::FormErr);
}

#[test]
fn the_formerr_reply_does_not_echo_the_questions() {
    let mut query = Message::query();
    query.add_query(question("example.com."));
    query.add_query(question("example.org."));
    let QueryPrecheck::Reply(reply) = precheck_query(&query) else {
        panic!("expected a local reply");
    };
    assert!(
        reply.queries.is_empty(),
        "a reply must not carry QDCOUNT > 1"
    );
}

#[test]
fn a_query_with_exactly_one_question_goes_on_to_the_pipeline() {
    let mut query = Message::query();
    query.add_query(question("example.com."));
    assert!(matches!(precheck_query(&query), QueryPrecheck::Resolve));
}

// T-305 batch 3a: a header claiming 65535 questions is answered from the
// header alone — never decoded (the decoder would reserve a slot for each).
#[test]
fn a_header_with_many_questions_gets_formerr_without_decoding() {
    use dnsqb_service::{decode_wire_message, precheck_raw, RawPrecheck};
    let header = [0x0b, 0xad, 0x01, 0x00, 0xff, 0xff, 0, 0, 0, 0, 0, 0];
    let RawPrecheck::Reply(bytes) = precheck_raw(&header) else {
        panic!("QDCOUNT 65535 must be answered from the header");
    };
    let reply = decode_wire_message(&bytes).expect("the reply decodes");
    assert_eq!(reply.metadata.id, 0x0bad);
    assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
    assert!(reply.queries.is_empty());
}
