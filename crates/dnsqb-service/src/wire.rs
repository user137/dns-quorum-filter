//! DNS wire-format decode/encode and response construction (RFC 1035, T-21;
//! RFC 6891 EDNS(0), T-7; RFC 4033-4035 AD-bit passthrough, T-12; block
//! response format, SPEC.md §3.2, T-26; query prechecks and the OPT echo,
//! T-305).

use hickory_proto::op::{Edns, Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, HINFO};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::ProtoError;
use std::net::{Ipv4Addr, Ipv6Addr};

/// RFC 1035 (T-21): decode a raw wire-format `DoH` request body into a
/// `Message` without mangling it — the foundation `hickory-proto` provides
/// (SPEC.md §1, §3).
///
/// # Errors
///
/// Returns `Err` if `bytes` is not a well-formed DNS wire-format message.
pub fn decode_wire_message(bytes: &[u8]) -> Result<Message, ProtoError> {
    Ok(Message::from_vec(bytes)?)
}

/// Encode a `Message` to `DoH` wire-format response bytes (RFC 8484, T-21).
///
/// # Errors
///
/// Returns `Err` if `message` cannot be serialized (malformed internal state).
pub fn encode_wire_message(message: &Message) -> Result<Vec<u8>, ProtoError> {
    message.to_vec()
}

/// RFC 6891 §6.2.3 (T-7): the post-DNS-Flag-Day-2020 safe UDP payload size —
/// large enough to avoid needless truncation, small enough to avoid IP
/// fragmentation (SPEC.md §3.4). `hickory-proto`'s own EDNS default is 512,
/// the pre-EDNS legacy minimum.
pub const EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

/// Attach EDNS(0) with `EDNS_UDP_PAYLOAD_SIZE` to an outgoing upstream query
/// (T-24).
pub fn attach_edns(query: &mut Message) {
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_UDP_PAYLOAD_SIZE);
    query.set_edns(edns);
}

/// RFC 8482 §4.2: TTL of the synthesized HINFO answer to `ANY`.
const ANY_HINFO_TTL: u32 = 3600;

/// What [`precheck_query`] decided for one decoded query (T-305).
#[derive(Debug)]
pub enum QueryPrecheck {
    /// A response, not a query (QR=1): never answered, so two resolvers can't
    /// reflect messages at each other. `DoH` answers HTTP 400.
    Drop,
    /// Answered locally; nothing leaves the machine and nothing is logged.
    Reply(Message),
    /// An ordinary query: on to consent and the pipeline.
    Resolve,
}

/// Transport-independent checks every decoded query passes before consent and
/// the pipeline (T-305; SPEC.md RFC table). Order, first match wins: QR=1 →
/// drop; EDNS version > 0 → BADVERS (RFC 6891 §6.1.3); opcode other than
/// QUERY → NOTIMP; question count other than one → FORMERR (RFC 9619); class
/// other than IN → REFUSED; AXFR/IXFR → REFUSED; ANY → one synthesized HINFO
/// (RFC 8482). None of them reach a third party, so they sit before the
/// consent gate.
#[must_use]
pub fn precheck_query(query: &Message) -> QueryPrecheck {
    if query.metadata.message_type == MessageType::Response {
        return QueryPrecheck::Drop;
    }
    if query.edns.as_ref().is_some_and(|edns| edns.version() > 0) {
        return QueryPrecheck::Reply(build_error_response(query, ResponseCode::BADVERS));
    }
    if query.metadata.op_code != OpCode::Query {
        return QueryPrecheck::Reply(build_error_response(query, ResponseCode::NotImp));
    }
    let [question] = query.queries.as_slice() else {
        return QueryPrecheck::Reply(build_error_response(query, ResponseCode::FormErr));
    };
    if question.query_class() != DNSClass::IN {
        return QueryPrecheck::Reply(build_error_response(query, ResponseCode::Refused));
    }
    match question.query_type() {
        RecordType::AXFR | RecordType::IXFR => {
            QueryPrecheck::Reply(build_error_response(query, ResponseCode::Refused))
        }
        RecordType::ANY => {
            let mut response = response_shell(query);
            response.answers.push(Record::from_rdata(
                question.name().clone(),
                ANY_HINFO_TTL,
                RData::HINFO(HINFO::new("RFC8482".to_owned(), String::new())),
            ));
            QueryPrecheck::Reply(response)
        }
        _ => QueryPrecheck::Resolve,
    }
}

/// A local refusal or error with `code` and no records.
fn build_error_response(query: &Message, code: ResponseCode) -> Message {
    let mut response = response_shell(query);
    response.metadata.response_code = code;
    response
}

/// Every response is built on this. RFC 6891 §6.1.1: a query with OPT gets a
/// response with OPT — our own, built fresh (version 0, our payload size, the
/// DO bit copied per RFC 3225 §3), never an upstream's, so no upstream option
/// (cookie, padding, NSID, ECS) reaches the client.
fn response_shell(query: &Message) -> Message {
    let mut response = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    response.metadata = Metadata::response_from_request(&query.metadata);
    response.queries.clone_from(&query.queries);
    if let Some(query_edns) = &query.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_UDP_PAYLOAD_SIZE);
        edns.set_dnssec_ok(query_edns.flags().dnssec_ok);
        response.set_edns(edns);
    }
    response
}

/// RFC 4033–4035 (T-12): forward an upstream ALLOW answer to the client,
/// preserving the upstream's AD bit exactly as received — never fabricated,
/// never cleared locally (SPEC.md §3.4). This is the only place the AD bit
/// crosses from upstream response to client response.
#[must_use]
pub fn forward_response(query: &Message, upstream_response: &Message) -> Message {
    let mut response = response_shell(query);
    response.metadata.authentic_data = upstream_response.metadata.authentic_data;
    response.metadata.response_code = upstream_response.metadata.response_code;
    response.answers.clone_from(&upstream_response.answers);
    response
        .authorities
        .clone_from(&upstream_response.authorities);
    response
}

/// SPEC.md §3.2 (T-26): block response — NULL blocking (`0.0.0.0`/`::`) for
/// A/AAAA, never NXDOMAIN (some browsers fall back to a different resolver on
/// NXDOMAIN, silently bypassing the filter). NODATA (success, empty answers)
/// for every other query type — `0.0.0.0` is semantically meaningless for
/// e.g. MX/TXT. Never sets the AD bit: a synthesized answer isn't
/// authenticated data.
#[must_use]
pub fn build_block_response(query: &Message, ttl: u32) -> Message {
    let mut response = response_shell(query);
    response.metadata.authentic_data = false;

    let Some(question) = query.queries.first() else {
        return response;
    };

    let rdata = match question.query_type() {
        RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
        RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
        _ => None,
    };
    if let Some(rdata) = rdata {
        response
            .answers
            .push(Record::from_rdata(question.name().clone(), ttl, rdata));
    }
    response
}

/// T-39: an honest "resolution failed" response — used when the pipeline has
/// no usable data at all to answer with (every upstream unresponsive under
/// fail-open, or a baseline-only lookup itself failed). Never NODATA/NoError
/// in this case: an empty success answer reads to the browser as "this
/// domain has no record," a silently wrong answer, not as "resolution
/// failed" (SPEC.md §3.2's own reasoning about misleading responses applies
/// here too, not only to the synthesized-block case). Same shell as
/// [`build_block_response`], no answers, no AD bit — a synthesized response
/// is never authenticated data.
#[must_use]
pub fn build_servfail_response(query: &Message) -> Message {
    let mut response = response_shell(query);
    response.metadata.authentic_data = false;
    response.metadata.response_code = ResponseCode::ServFail;
    response
}

/// T-39: a resolved answer built directly from `records`, not forwarded from
/// an upstream `Message` — used to reconstruct a response from a cached
/// `cache::Verdict::Allow` (no upstream `Message` survives a cache
/// round-trip, only the IPs and a TTL already baked into `records`). An
/// empty `records` produces a NODATA-shaped answer (`NoError`, no answers);
/// a cached NXDOMAIN replays through [`build_nxdomain_response`] instead.
/// Never sets the AD bit, same principle as [`build_block_response`]: a
/// reconstructed answer isn't authenticated data either.
#[must_use]
pub fn build_answer_response(query: &Message, records: Vec<Record>) -> Message {
    let mut response = response_shell(query);
    response.metadata.authentic_data = false;
    response.answers = records;
    response
}

/// A cached NXDOMAIN replayed (T-305, RFC 2308): no records, no AD bit — a
/// reconstructed answer isn't authenticated data. Carries no SOA, so a client
/// doesn't cache it negatively itself.
#[must_use]
pub fn build_nxdomain_response(query: &Message) -> Message {
    let mut response = response_shell(query);
    response.metadata.authentic_data = false;
    response.metadata.response_code = ResponseCode::NXDomain;
    response
}

#[cfg(test)]
mod tests {
    use super::{
        build_answer_response, build_block_response, build_servfail_response, decode_wire_message,
        encode_wire_message, RecordType,
    };
    use crate::min_rrset_ttl;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn query_of_type(qtype: RecordType) -> Message {
        let mut question = Query::new();
        question.set_query_type(qtype);
        let mut message = Message::query();
        message.add_query(question);
        message
    }

    #[test]
    fn a_query_gets_unspecified_ipv4() {
        let response = build_block_response(&query_of_type(RecordType::A), 60);
        let Some(answer) = response.answers.first() else {
            panic!("expected exactly one answer for a blocked A query");
        };
        assert!(matches!(answer.data, RData::A(a) if a.0 == Ipv4Addr::UNSPECIFIED));
        assert_eq!(answer.ttl, 60);
    }

    #[test]
    fn aaaa_query_gets_unspecified_ipv6() {
        let response = build_block_response(&query_of_type(RecordType::AAAA), 60);
        let Some(answer) = response.answers.first() else {
            panic!("expected exactly one answer for a blocked AAAA query");
        };
        assert!(matches!(answer.data, RData::AAAA(a) if a.0 == Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn non_a_aaaa_query_gets_nodata_not_null_ip() {
        // SPEC.md §3.2: 0.0.0.0 is semantically meaningless for e.g. MX/TXT.
        let response = build_block_response(&query_of_type(RecordType::MX), 60);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn block_response_never_sets_ad_bit() {
        // A synthesized answer isn't authenticated data, regardless of what
        // any upstream said (SPEC.md §3.2/§3.4).
        for qtype in [RecordType::A, RecordType::AAAA, RecordType::MX] {
            let response = build_block_response(&query_of_type(qtype), 60);
            assert!(!response.metadata.authentic_data);
        }
    }

    #[test]
    fn servfail_response_has_no_answers_and_no_ad_bit() {
        let response = build_servfail_response(&query_of_type(RecordType::A));
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(response.answers.is_empty());
        assert!(!response.metadata.authentic_data);
    }

    #[test]
    fn answer_response_carries_the_given_records_and_no_ad_bit() {
        let record = Record::from_rdata(
            Name::root(),
            60,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        let response = build_answer_response(&query_of_type(RecordType::A), vec![record]);
        assert_eq!(response.answers.len(), 1);
        assert!(!response.metadata.authentic_data);
    }

    #[test]
    fn answer_response_with_no_records_is_nodata_shaped() {
        let response = build_answer_response(&query_of_type(RecordType::A), Vec::new());
        assert!(response.answers.is_empty());
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }

    #[test]
    fn hickory_proto_does_not_reconcile_rrset_ttls_on_decode() {
        // T-33/RFC 2181 §5.2: same-name/same-type records may legitimately
        // arrive with disagreeing TTLs (misconfiguration or manipulation) —
        // this is this project's own responsibility to reconcile, not
        // something `hickory-proto` normalizes for us during wire decode.
        // Proven empirically, not assumed from reading the source.
        let Ok(name) = Name::from_str("example.com.") else {
            panic!("valid fixture name");
        };
        let mut message = Message::new(1, MessageType::Response, hickory_proto::op::OpCode::Query);
        message.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        message.answers.push(Record::from_rdata(
            name,
            60,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 35))),
        ));

        let Ok(bytes) = encode_wire_message(&message) else {
            panic!("valid message encodes");
        };
        let Ok(decoded) = decode_wire_message(&bytes) else {
            panic!("valid wire bytes decode");
        };

        let ttls: Vec<u32> = decoded.answers.iter().map(|r| r.ttl).collect();
        assert_eq!(
            ttls,
            vec![300, 60],
            "hickory-proto must not silently collapse disagreeing RRset TTLs on decode"
        );
        assert_eq!(min_rrset_ttl(&decoded.answers), Some(60));
    }

    #[test]
    fn decode_wire_message_rejects_truncated_and_garbage_bytes() {
        // T-198 (1.1-D): the decode-path tests were all positive (a
        // round-tripped valid message). A body shorter than the 12-byte DNS
        // header, and a header that promises a question section it doesn't
        // carry, must both surface as `Err` — never a panic, never a bogus
        // `Message`.
        let shorter_than_the_header: &[u8] = &[0xff, 0xff, 0xff];
        assert!(decode_wire_message(shorter_than_the_header).is_err());

        // id=1, flags=0, QDCOUNT=1, AN/NS/AR=0 — then nothing where the one
        // promised question should be.
        let header_promises_a_question_it_lacks: &[u8] = &[
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(decode_wire_message(header_promises_a_question_it_lacks).is_err());
    }

    // T-198 (1.1-D): `decode_wire_message` is the first thing raw, untrusted
    // wire bytes from a `DoH` POST body reach — its Ok/Err split is covered
    // above; this property only proves the absence of a panic on any input
    // shape. Vector capped well under `dispatch::MAX_MESSAGE_SIZE`, 64 cases
    // (this crate's `proptest` is `default-features = false`, no timeout
    // tail), same discipline as `dispatch::wire_bytes_from_get_never_panics_*`.
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]
        #[test]
        fn decode_wire_message_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)
        ) {
            let _ = decode_wire_message(&bytes);
        }
    }
}
