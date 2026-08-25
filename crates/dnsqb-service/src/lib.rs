#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `DoH` server + quorum resolver core (SPEC.md §1, §3). Фаза 1, перший
//! зріз (T-20–T-26): live-verified block signatures, `DoH` wire codec,
//! baseline/upstream client, OR-logic quorum. Cache, override lists, log,
//! Tauri UI, and the self-signed cert are later batches — see TASKS.md.

mod listener;
mod quorum;
mod upstream;
mod wire;

pub use listener::{bind_listener, BindError};
pub use quorum::{is_blocked, requires_quorum, resolve, QuorumVerdict};
pub use upstream::{
    doh_get_url, ecs_option_for_upstream, DohClient, Provider, ReqwestDohClient, UpstreamError,
    BASELINE_DOH_URL,
};
pub use wire::{
    attach_edns, build_block_response, decode_wire_message, encode_wire_message, forward_response,
    EDNS_UDP_PAYLOAD_SIZE,
};

use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::Record;
use hickory_proto::ProtoError;

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
