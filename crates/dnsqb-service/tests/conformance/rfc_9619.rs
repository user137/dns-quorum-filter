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
fn a_query_with_exactly_one_question_goes_on_to_the_pipeline() {
    let mut query = Message::query();
    query.add_query(question("example.com."));
    assert!(matches!(precheck_query(&query), QueryPrecheck::Resolve));
}
