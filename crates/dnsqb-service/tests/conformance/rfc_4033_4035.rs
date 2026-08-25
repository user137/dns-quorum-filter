//! RFC 4033-4035 — DNSSEC (Introduction, Resource Records, Protocol): if the
//! AD bit is passed to the client at all, it must reflect the upstream's
//! actual validation result, never fabricated or blindly cleared locally
//! (SPEC.md §3.4).

use dnsqb_service::forward_response;
use hickory_proto::op::{Message, OpCode};

#[test]
fn forward_response_preserves_ad_bit_when_upstream_validated() {
    let query = Message::query();
    let mut upstream_response = Message::response(query.metadata.id, OpCode::Query);
    upstream_response.metadata.authentic_data = true;

    let response = forward_response(&query, &upstream_response);
    assert!(response.metadata.authentic_data);
}

#[test]
fn forward_response_preserves_cleared_ad_bit_when_upstream_did_not_validate() {
    let query = Message::query();
    let mut upstream_response = Message::response(query.metadata.id, OpCode::Query);
    upstream_response.metadata.authentic_data = false;

    let response = forward_response(&query, &upstream_response);
    assert!(!response.metadata.authentic_data);
}
