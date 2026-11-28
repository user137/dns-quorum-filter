//! RFC 6891 — Extension Mechanisms for DNS (EDNS(0)): outgoing queries
//! advertise a UDP payload size large enough to avoid needless truncation
//! over the loopback DoH path (SPEC.md §3.4).

use dnsqb_service::{
    attach_edns, decode_wire_message, encode_wire_message, forward_response, precheck_query,
    QueryPrecheck, EDNS_UDP_PAYLOAD_SIZE,
};
use hickory_proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;

// RFC 6891 §6.2.3: values under 512 provide no benefit over no-EDNS.
const _: () = assert!(EDNS_UDP_PAYLOAD_SIZE > 512);

#[test]
fn attach_edns_adds_an_opt_record_above_the_512_byte_legacy_minimum() {
    let mut query = Message::query();
    attach_edns(&mut query);

    let edns = query.edns.expect("attach_edns must add an OPT record");
    assert_eq!(edns.max_payload(), EDNS_UDP_PAYLOAD_SIZE);
}

fn query_with_edns(version: u8, dnssec_ok: bool) -> Message {
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("example.com.").expect("valid fixture name"),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.set_version(version);
    edns.set_dnssec_ok(dnssec_ok);
    query.set_edns(edns);
    query
}

// §6.1.1: "If an OPT record is present in a received request, compliant
// responders MUST include an OPT record in their respective responses."
// Our own payload size and version 0, the DO bit copied (RFC 3225 §3), and
// none of the upstream's options (cookies, padding, NSID, ECS) passed on.
#[test]
fn a_response_carries_our_own_opt_when_the_query_had_one() {
    for dnssec_ok in [false, true] {
        let query = query_with_edns(0, dnssec_ok);
        let mut upstream = Message::response(query.metadata.id, OpCode::Query);
        let mut upstream_edns = Edns::new();
        upstream_edns.set_max_payload(4096);
        upstream_edns.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Cookie),
            vec![1; 16],
        ));
        upstream.set_edns(upstream_edns);

        let response = forward_response(&query, &upstream);
        let edns = response
            .edns
            .expect("the query had OPT, so must the response");
        assert_eq!(edns.max_payload(), EDNS_UDP_PAYLOAD_SIZE);
        assert_eq!(edns.version(), 0);
        assert_eq!(edns.flags().dnssec_ok, dnssec_ok);
        assert!(
            edns.options().as_ref().is_empty(),
            "no upstream option passes through"
        );
    }
}

#[test]
fn a_response_has_no_opt_when_the_query_had_none() {
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("example.com.").expect("valid fixture name"),
        RecordType::A,
    ));
    let upstream = Message::response(query.metadata.id, OpCode::Query);
    assert!(forward_response(&query, &upstream).edns.is_none());
}

// §6.1.3: a version this responder doesn't implement gets BADVERS (16, its
// high bits carried in OPT) with OPT version 0 — checked numerically after a
// wire round trip, since 16 also means BADSIG and hickory decodes it as such.
#[test]
fn an_unknown_edns_version_gets_badvers() {
    let QueryPrecheck::Reply(reply) = precheck_query(&query_with_edns(1, false)) else {
        panic!("EDNS version 1 must be answered locally");
    };
    let edns = reply.edns.as_ref().expect("BADVERS travels in OPT");
    assert_eq!(edns.version(), 0);
    let bytes = encode_wire_message(&reply).expect("encode");
    let decoded = decode_wire_message(&bytes).expect("decode");
    assert_eq!(u16::from(decoded.metadata.response_code), 16);
}

// §7: a query with more than one OPT is malformed. hickory refuses to decode
// it, so DoH answers HTTP 400; plain DNS will build FORMERR from the raw
// header (T-305 batch 3).
#[test]
fn a_query_with_two_opt_records_does_not_decode() {
    let query = query_with_edns(0, false);
    let mut bytes = encode_wire_message(&query).expect("encode");
    // Append a second, empty OPT RR and bump ARCOUNT (bytes 10..12).
    bytes.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    let arcount = u16::from_be_bytes([bytes[10], bytes[11]]) + 1;
    bytes[10..12].copy_from_slice(&arcount.to_be_bytes());
    assert!(decode_wire_message(&bytes).is_err());
}

#[test]
fn badvers_takes_precedence_over_the_question_checks() {
    let mut query = query_with_edns(1, false);
    query.queries.clear();
    let QueryPrecheck::Reply(reply) = precheck_query(&query) else {
        panic!("must be answered locally");
    };
    assert_eq!(reply.metadata.response_code, ResponseCode::BADVERS);
}
