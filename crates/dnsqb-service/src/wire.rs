//! DNS wire-format decode/encode and response construction (RFC 1035, T-21;
//! RFC 6891 EDNS(0), T-7; RFC 4033-4035 AD-bit passthrough, T-12; block
//! response format, SPEC.md §3.2, T-26; query prechecks and the OPT echo,
//! T-305).

use crate::local_names::{local_answer, LocalAnswer, LocalReply};
use hickory_proto::op::{Edns, Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, HINFO, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
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

/// The query an upstream receives for `query` (T-305 batch 3a): the question
/// and the RD/CD/AD flags, nothing else. ID 0 (RFC 8484 §4.1), no answer,
/// authority or additional records, and — when the client sent OPT — our own
/// OPT with only the DO bit copied, so no client option (ECS, cookie,
/// padding, NSID) reaches a provider.
#[must_use]
pub fn upstream_query(query: &Message) -> Message {
    let mut upstream = Message::new(0, MessageType::Query, query.metadata.op_code);
    upstream.metadata.recursion_desired = query.metadata.recursion_desired;
    upstream.metadata.checking_disabled = query.metadata.checking_disabled;
    upstream.metadata.authentic_data = query.metadata.authentic_data;
    upstream.queries.clone_from(&query.queries);
    if let Some(query_edns) = &query.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_UDP_PAYLOAD_SIZE);
        edns.set_dnssec_ok(query_edns.flags().dnssec_ok);
        upstream.set_edns(edns);
    }
    upstream
}

/// RFC 1035 §4.1.1: the fixed header length.
const HEADER_LEN: usize = 12;

/// RFC 1035 §4.1.2: the smallest question — the root name (1 byte), QTYPE
/// and QCLASS (2 each).
const MIN_QUESTION_LEN: usize = 5;

/// What [`precheck_raw`] decided from the header bytes alone (T-305 batch
/// 3a), before any decoding.
#[derive(Debug, PartialEq, Eq)]
pub enum RawPrecheck {
    /// Decode it; [`precheck_query`] decides the rest.
    Decode,
    /// FORMERR from the header alone, wire bytes.
    Reply(Vec<u8>),
    /// Shorter than a header, or QR=1: nothing to answer.
    Drop,
}

/// Header-only checks that run before `hickory-proto` decodes a message:
/// its decoder reserves one question slot per QDCOUNT up front, so a
/// 12-byte packet claiming 65535 questions would allocate megabytes. Only a
/// QDCOUNT the bytes can't hold is answered here (FORMERR, no sections, no
/// OPT); every other message decodes, so [`precheck_query`] builds the
/// reply with OPT, CD and BADVERS as RFC 6891 asks.
#[must_use]
pub fn precheck_raw(wire: &[u8]) -> RawPrecheck {
    let Some(header) = wire.first_chunk::<HEADER_LEN>() else {
        return RawPrecheck::Drop;
    };
    if header[2] & 0x80 != 0 {
        return RawPrecheck::Drop;
    }
    let questions = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let room = wire.len().saturating_sub(HEADER_LEN);
    if questions.saturating_mul(MIN_QUESTION_LEN) > room {
        return RawPrecheck::Reply(reply_from_header(header, ResponseCode::FormErr));
    }
    RawPrecheck::Decode
}

/// FORMERR for a message that does not decode, built from its header (for
/// the plain-DNS transport, which has no HTTP 400). `None` if `wire` is
/// shorter than a header or is itself a response.
#[must_use]
pub fn formerr_for_undecodable(wire: &[u8]) -> Option<Vec<u8>> {
    let header = wire.first_chunk::<HEADER_LEN>()?;
    (header[2] & 0x80 == 0).then(|| reply_from_header(header, ResponseCode::FormErr))
}

/// A header-only response: the query's ID, opcode, RD and CD (RFC 4035
/// §3.2.2), QR and RA set, `code` (a basic RCODE, ≤ 15), every count zero.
fn reply_from_header(header: &[u8; HEADER_LEN], code: ResponseCode) -> Vec<u8> {
    // Byte 2: QR | opcode (0x78) | AA | TC | RD (0x01). Byte 3: RA | Z | AD
    // | CD (0x10) | RCODE (0x0f).
    let opcode_and_rd = header[2] & 0x79;
    let cd = header[3] & 0x10;
    let mut reply = vec![0u8; HEADER_LEN];
    reply[0] = header[0];
    reply[1] = header[1];
    reply[2] = 0x80 | opcode_and_rd;
    reply[3] = 0x80 | cd | (code.low() & 0x0f);
    reply
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
        // The reply carries no question: echoing several would itself break
        // RFC 9619, and on UDP it would reflect a large query back in full.
        let mut reply = build_error_response(query, ResponseCode::FormErr);
        reply.queries.clear();
        return QueryPrecheck::Reply(reply);
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
        qtype => local_answer(&question.name().to_ascii(), qtype)
            .map_or(QueryPrecheck::Resolve, |local| {
                QueryPrecheck::Reply(local_response(query, question, local))
            }),
    }
}

/// RFC 6761 §6.3: TTL of the synthesized `localhost` addresses.
const LOCALHOST_TTL: u32 = 3600;

/// RFC 6303 §3: the SOA of a locally served zone (`@ 10800 IN SOA @
/// nobody.invalid. 1 3600 1200 604800 10800`), so a negative answer can be
/// cached (RFC 2308 §5).
const LOCAL_ZONE_SOA_TTL: u32 = 10_800;

/// The reply to a name answered here ([`crate::local_names`]). An answer
/// from one of our zones is authoritative and, when it has no records,
/// carries that zone's SOA; a single-label name has no zone of ours.
fn local_response(query: &Message, question: &Query, local: LocalReply) -> Message {
    let mut response = local_answer_response(query, question, local.answer);
    if let Some(labels) = local.zone_labels {
        response.metadata.authoritative = true;
        if response.answers.is_empty() {
            response
                .authorities
                .push(local_zone_soa(question.name(), labels));
        }
    }
    response
}

/// The synthetic SOA of the zone made of the last `labels` labels of `name`.
fn local_zone_soa(name: &Name, labels: u8) -> Record {
    let zone = name.trim_to(usize::from(labels));
    // A fixed valid name: the root fallback is never taken.
    let rname = Name::from_ascii("nobody.invalid.").unwrap_or_else(|_| Name::root());
    Record::from_rdata(
        zone.clone(),
        LOCAL_ZONE_SOA_TTL,
        RData::SOA(SOA::new(
            zone,
            rname,
            1,
            3600,
            1200,
            604_800,
            LOCAL_ZONE_SOA_TTL,
        )),
    )
}

fn local_answer_response(query: &Message, question: &Query, answer: LocalAnswer) -> Message {
    match answer {
        LocalAnswer::NxDomain => build_error_response(query, ResponseCode::NXDomain),
        LocalAnswer::NoData => response_shell(query),
        LocalAnswer::Loopback => {
            let mut response = response_shell(query);
            let data = match question.query_type() {
                RecordType::A => Some(RData::A(A(Ipv4Addr::LOCALHOST))),
                RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
                _ => None,
            };
            if let Some(data) = data {
                response.answers.push(Record::from_rdata(
                    question.name().clone(),
                    LOCALHOST_TTL,
                    data,
                ));
            }
            response
        }
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
    // We are a recursive service to the client (dig warns without RA).
    response.metadata.recursion_available = true;
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
    let code = upstream_response.metadata.response_code;
    // RFC 6891 §6.1.3: an extended RCODE (> 15) needs OPT to be expressed;
    // a client that sent none would read only its low 4 bits.
    response.metadata.response_code = if query.edns.is_none() && code.high() != 0 {
        ResponseCode::ServFail
    } else {
        code
    };
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

    // --- T-305 batch 3a: header-only prechecks, upstream query, RA ---

    /// A 12-byte header: `id` 0xabcd, `flags2`/`flags3`, QDCOUNT `qd`.
    fn header(flags2: u8, flags3: u8, qd: u16) -> Vec<u8> {
        let [qd_hi, qd_lo] = qd.to_be_bytes();
        vec![0xab, 0xcd, flags2, flags3, qd_hi, qd_lo, 0, 0, 0, 0, 0, 0]
    }

    fn decoded(bytes: &[u8]) -> Message {
        match decode_wire_message(bytes) {
            Ok(message) => message,
            Err(err) => panic!("header-only reply must decode: {err}"),
        }
    }

    #[test]
    fn a_single_question_query_header_goes_on_to_decoding() {
        let Ok(bytes) = encode_wire_message(&query_of_type(RecordType::A)) else {
            panic!("fixture must encode");
        };
        assert_eq!(super::precheck_raw(&bytes), super::RawPrecheck::Decode);
    }

    #[test]
    fn a_question_count_the_bytes_cannot_hold_is_formerr_without_decoding() {
        for qd in [1u16, 2, 65535] {
            // RD and CD set; no bytes after the header, so a decode would
            // fail — the reply never needs one.
            let super::RawPrecheck::Reply(bytes) = super::precheck_raw(&header(0x01, 0x10, qd))
            else {
                panic!("QDCOUNT {qd} must be answered");
            };
            let reply = decoded(&bytes);
            assert_eq!(reply.metadata.id, 0xabcd);
            assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
            assert!(reply.metadata.recursion_desired);
            assert!(reply.metadata.recursion_available);
            assert!(reply.metadata.checking_disabled);
            assert!(reply.queries.is_empty() && reply.edns.is_none());
        }
        // Boundary: one byte short of room for two minimal questions.
        let mut wire = header(0, 0, 2);
        wire.extend_from_slice(&[0; 9]);
        assert!(matches!(
            super::precheck_raw(&wire),
            super::RawPrecheck::Reply(_)
        ));
        wire.push(0);
        assert_eq!(super::precheck_raw(&wire), super::RawPrecheck::Decode);
    }

    // A count the bytes can hold decodes, so the decoded-path reply keeps
    // the client's OPT (RFC 6891 §6.1.1) — no header-only shortcut.
    #[test]
    fn a_header_only_query_without_questions_decodes() {
        assert_eq!(
            super::precheck_raw(&header(4 << 3, 0, 0)),
            super::RawPrecheck::Decode
        );
        assert_eq!(
            super::precheck_raw(&header(0, 0, 0)),
            super::RawPrecheck::Decode
        );
    }

    #[test]
    fn a_short_packet_or_a_response_header_is_dropped() {
        assert_eq!(super::precheck_raw(&[]), super::RawPrecheck::Drop);
        assert_eq!(
            super::precheck_raw(&header(0, 0, 1)[..11]),
            super::RawPrecheck::Drop
        );
        assert_eq!(
            super::precheck_raw(&header(0x80, 0, 0)),
            super::RawPrecheck::Drop
        );
        assert_eq!(super::formerr_for_undecodable(&header(0x80, 0, 1)), None);
        assert_eq!(super::formerr_for_undecodable(&[0u8; 11]), None);
    }

    #[test]
    fn an_undecodable_query_gets_formerr_from_its_header() {
        let mut garbage = header(0x01, 0, 1);
        garbage.extend_from_slice(&[0xff; 7]);
        assert!(decode_wire_message(&garbage).is_err());
        let Some(bytes) = super::formerr_for_undecodable(&garbage) else {
            panic!("a query header must get FORMERR");
        };
        let reply = decoded(&bytes);
        assert_eq!(reply.metadata.id, 0xabcd);
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
    }

    // Misuse: whatever the flag bytes say, the header-only reply is a
    // well-formed response with the same ID and no sections.
    #[test]
    fn every_header_only_reply_decodes_as_a_response() {
        for flags2 in 0..=u8::MAX {
            for flags3 in [0u8, 0x0f, 0xf0, 0xff] {
                let wire = header(flags2, flags3, 7);
                let bytes = match super::precheck_raw(&wire) {
                    super::RawPrecheck::Reply(bytes) => bytes,
                    super::RawPrecheck::Drop => continue,
                    super::RawPrecheck::Decode => panic!("7 questions never fit in 0 bytes"),
                };
                let reply = decoded(&bytes);
                assert_eq!(reply.metadata.id, 0xabcd);
                assert_eq!(reply.metadata.message_type, MessageType::Response);
                assert!(reply.queries.is_empty() && reply.answers.is_empty());
            }
        }
    }

    #[test]
    fn every_built_response_advertises_recursion() {
        let query = query_of_type(RecordType::A);
        assert!(build_servfail_response(&query).metadata.recursion_available);
        assert!(
            build_block_response(&query, 60)
                .metadata
                .recursion_available
        );
    }

    #[test]
    fn the_upstream_query_carries_the_question_and_our_own_opt_only() {
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
        let mut query = query_of_type(RecordType::A);
        query.metadata.id = 0x1234;
        query.metadata.checking_disabled = true;
        query.metadata.recursion_desired = true;
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(4096);
        edns.set_dnssec_ok(true);
        let subnet = match "198.51.100.0/24".parse::<ClientSubnet>() {
            Ok(subnet) => subnet,
            Err(err) => panic!("subnet fixture: {err:?}"),
        };
        edns.options_mut().insert(EdnsOption::Subnet(subnet));
        query.set_edns(edns);
        query.additionals.push(Record::from_rdata(
            Name::root(),
            0,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));

        let upstream = super::upstream_query(&query);
        assert_eq!(upstream.metadata.id, 0);
        assert_eq!(upstream.queries, query.queries);
        assert!(upstream.metadata.recursion_desired);
        assert!(upstream.metadata.checking_disabled);
        assert!(upstream.additionals.is_empty() && upstream.answers.is_empty());
        let Some(opt) = &upstream.edns else {
            panic!("a client OPT gets our own OPT upstream");
        };
        assert!(opt.flags().dnssec_ok);
        assert_eq!(opt.max_payload(), super::EDNS_UDP_PAYLOAD_SIZE);
        assert!(
            opt.options().as_ref().is_empty(),
            "no client option forwarded"
        );

        query.edns = None;
        assert!(super::upstream_query(&query).edns.is_none());
    }

    #[test]
    fn an_extended_rcode_reaches_a_client_without_opt_as_servfail() {
        let query = query_of_type(RecordType::A);
        let mut upstream = query_of_type(RecordType::A);
        upstream.metadata.response_code = ResponseCode::BADCOOKIE;
        assert_eq!(
            super::forward_response(&query, &upstream)
                .metadata
                .response_code,
            ResponseCode::ServFail
        );
        let mut with_opt = query.clone();
        with_opt.set_edns(hickory_proto::op::Edns::new());
        assert_eq!(
            super::forward_response(&with_opt, &upstream)
                .metadata
                .response_code,
            ResponseCode::BADCOOKIE
        );
        upstream.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(
            super::forward_response(&query, &upstream)
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
    }

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
