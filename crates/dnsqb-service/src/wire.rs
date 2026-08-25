//! DNS wire-format decode/encode and response construction (RFC 1035, T-21;
//! RFC 6891 EDNS(0), T-7; RFC 4033-4035 AD-bit passthrough, T-12; block
//! response format, SPEC.md §3.2, T-26).

use hickory_proto::op::{Edns, Message, MessageType, Metadata};
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

#[cfg(test)]
mod tests {
    use super::{build_block_response, RecordType};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::RData;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
}
