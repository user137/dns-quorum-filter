#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `DoH` server + quorum resolver core (SPEC.md §1, §3). Крок 0: signatures only
//! (`todo!()` bodies) — one per RFC-conformance test in `tests/conformance/`,
//! no resolver logic yet (TASKS.md "Крок 0").

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Record, RecordType};
use hickory_proto::ProtoError;

/// RFC 1035 (T-3): decode a raw wire-format `DoH` request body into a `Message`
/// without mangling it — the foundation `hickory-proto` provides (SPEC.md §1, §3).
///
/// # Errors
///
/// Returns `Err` if `bytes` is not a well-formed DNS wire-format message.
pub fn decode_wire_message(_bytes: &[u8]) -> Result<Message, ProtoError> {
    todo!("Фаза 1: T-21 — DoH server request decoding")
}

/// RFC 2181 §5.2 (T-4): minimum TTL across one `RRset` — `None` for an empty set
/// (SPEC.md §4.1, TASKS.md T-33/T-34).
///
/// T-33 is a verification task ("чи це вже валідує `hickory-dns`") — this
/// function may end up a thin passthrough to a `hickory-dns` guarantee rather
/// than new clamping logic; T-34 (TTL clamping) is the task that definitely
/// touches this code path either way.
#[must_use]
pub fn min_rrset_ttl(_records: &[Record]) -> Option<u32> {
    todo!("Фаза 1: T-33/T-34 — RRset TTL verification/clamping")
}

/// RFC 2308 (T-5): negative-caching TTL is bounded by the zone's SOA MINIMUM,
/// not an arbitrary constant (SPEC.md §3.1, §4.1, TASKS.md T-35).
#[must_use]
pub fn negative_cache_ttl(_soa: &SOA) -> u32 {
    todo!("Фаза 1: T-35 — negative caching TTL")
}

/// RFC 5891 IDNA2008 (T-6): normalize an override-list domain — lowercase,
/// punycode, trailing dot trimmed (SPEC.md §5, TASKS.md T-38).
///
/// # Errors
///
/// Returns `Err` if `input` is not a syntactically valid domain name.
pub fn normalize_domain(_input: &str) -> Result<String, ProtoError> {
    todo!("Фаза 1: T-38 — override-list domain normalization")
}

/// RFC 6891 EDNS(0) (T-7): UDP payload size advertised in outgoing queries
/// (SPEC.md §3.4).
#[must_use]
pub fn edns_udp_payload_size() -> u16 {
    todo!("Фаза 1: T-24 — quorum resolver EDNS setup")
}

/// RFC 7871 ECS (T-8): EDNS Client Subnet option to send a given upstream —
/// `None` when the upstream's variant doesn't use ECS (SPEC.md §3.4, e.g. the
/// Quad9 9.9.9.11 ECS-enabled variant vs the default 9.9.9.9).
#[must_use]
pub fn ecs_option_for_upstream(_upstream: &str) -> Option<EdnsOption> {
    todo!("Фаза 1: T-24 — per-upstream ECS handling")
}

/// RFC 8484 `DoH` (T-9): `application/dns-message` GET-request URL, base64url
/// `dns=` parameter, no padding (SPEC.md §1, §3).
#[must_use]
pub fn doh_get_url(_base: &str, _message_bytes: &[u8]) -> String {
    todo!("Фаза 1: T-24 — upstream DoH client")
}

/// RFC 8767 stale-if-error (T-10): serve a stale cache entry instead of a
/// fresh upstream error, layered on top of (not instead of) `fail-open`
/// (SPEC.md §3.3, §4.1, TASKS.md T-28).
#[must_use]
pub fn should_serve_stale(
    _fail_open: bool,
    _cache_entry_expired: bool,
    _upstream_failed: bool,
) -> bool {
    todo!("Фаза 1: T-28 — stale-if-error over fail-open")
}

/// RFC 9460 SVCB/HTTPS (T-11): these record types bypass quorum entirely and
/// proxy to a single upstream, so ECH via HTTPS RR isn't silently broken
/// (SPEC.md §3, TASKS.md T-25).
#[must_use]
pub fn requires_quorum(_qtype: RecordType) -> bool {
    todo!("Фаза 1: T-25 — quorum scope limited to A/AAAA")
}

/// RFC 4033–4035 DNSSEC (T-12): preserve the upstream's AD bit as-is, never
/// fabricate or clear it locally (SPEC.md §3.4).
#[must_use]
pub fn preserve_ad_flag(_upstream_authentic_data: bool) -> bool {
    todo!("Фаза 1: T-24 — response AD-bit passthrough")
}
