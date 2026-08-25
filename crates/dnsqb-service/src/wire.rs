//! DNS wire-format decode/encode and response construction (RFC 1035, T-21;
//! RFC 6891 EDNS(0), T-7; RFC 4033-4035 AD-bit passthrough, T-12; block
//! response format, SPEC.md §3.2, T-26).

use hickory_proto::op::{Edns, Message, MessageType, Metadata, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
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

fn response_shell(query: &Message) -> Message {
    let mut response = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    response.metadata = Metadata::response_from_request(&query.metadata);
    response.queries.clone_from(&query.queries);
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
/// empty `records` produces a NODATA-shaped answer (`NoError`, no answers) —
/// this is also how a cached genuine NXDOMAIN replays (SPEC.md §4: the cache
/// doesn't preserve `response_code`, a deliberate, documented tradeoff).
/// Never sets the AD bit, same principle as [`build_block_response`]: a
/// reconstructed answer isn't authenticated data either.
#[must_use]
pub fn build_answer_response(query: &Message, records: Vec<Record>) -> Message {
    let mut response = response_shell(query);
    response.metadata.authentic_data = false;
    response.answers = records;
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
}
