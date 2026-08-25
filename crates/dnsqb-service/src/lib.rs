#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `DoH` server + quorum resolver core (SPEC.md §1, §3). Фаза 1, другий
//! зріз (T-27–T-31): timeout-mode-aware OR-logic quorum with early
//! return/cancellation, `DoH` wire codec, baseline/upstream client with
//! HTTP/2 keep-alive. Cache, override lists, log, Tauri UI, and the
//! self-signed cert are later batches — see TASKS.md.

mod listener;
mod quorum;
mod timeout;
mod upstream;
mod wire;

pub use listener::{bind_listener, BindError};
pub use quorum::{is_blocked, requires_quorum, resolve, QuorumVerdict};
pub use timeout::{query_with_timeout, TimeoutConfig, TimeoutMode, VoterOutcome};
pub use upstream::{
    doh_get_url, ecs_option_for_upstream, DohClient, Provider, ReqwestDohClient, UpstreamError,
    BASELINE_DOH_URL,
};
pub use wire::{
    attach_edns, build_block_response, decode_wire_message, encode_wire_message, forward_response,
    EDNS_UDP_PAYLOAD_SIZE,
};

use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, Record};
use hickory_proto::ProtoError;

/// RFC 2181 §5.2 (T-33): minimum TTL across one `RRset` — `None` for an empty
/// set (SPEC.md §4.1). `hickory-proto` does not itself enforce that same-name/
/// same-type records share one TTL at decode time (verified empirically —
/// `wire::tests::hickory_proto_does_not_reconcile_rrset_ttls_on_decode`), so
/// this reconciliation is this project's own responsibility, not a passthrough
/// to an existing guarantee.
///
/// Callers must pass records already narrowed to one `(name, type)` `RRset` —
/// this function itself does no grouping. For the whole-answer-section
/// minimum (CNAME chain included), see `cache::chain_cache_ttl` (T-36)
/// instead, which is deliberately a different function with a different
/// precondition.
#[must_use]
pub fn min_rrset_ttl(records: &[Record]) -> Option<u32> {
    records.iter().map(|r| r.ttl).min()
}

/// RFC 2308 (T-35): negative-caching TTL is bounded by the zone's SOA MINIMUM,
/// not an arbitrary constant (SPEC.md §3.1, §4.1).
#[must_use]
pub fn negative_cache_ttl(soa: &SOA) -> u32 {
    soa.minimum
}

/// RFC 5891 IDNA2008 (T-38): normalize an override-list/cache-key domain —
/// lowercase, punycode, trailing dot trimmed (SPEC.md §5, §4).
///
/// Goes through `hickory_proto::rr::Name::from_utf8`/`to_ascii` — the exact
/// `idna::uts46::Uts46` path (`AsciiDenyList::STD3`, `Hyphens::Allow`,
/// `DnsLength::Ignore`) that `hickory-proto` itself uses to parse incoming
/// query names — rather than a second, directly-depended-on `idna` call.
/// Two independent IDNA code paths normalizing the same-looking domain
/// differently would mean a domain occasionally doesn't match itself between
/// override-list/cache lookups and incoming-query parsing; going through
/// `Name` makes that desync impossible by construction instead of by
/// version-pinning discipline.
///
/// # Errors
///
/// Returns `Err` if `input` is not a syntactically valid domain name.
pub fn normalize_domain(input: &str) -> Result<String, ProtoError> {
    let ascii = Name::from_utf8(input)?.to_ascii().to_ascii_lowercase();
    Ok(ascii.trim_end_matches('.').to_string())
}

/// RFC 8767 stale-if-error (T-10): serve a stale cache entry instead of a
/// fresh upstream error, layered on top of (not instead of) `fail-open` —
/// `fail-closed`/`degraded` don't get this fallback (SPEC.md §3.3, §4.1,
/// TASKS.md T-28).
#[must_use]
pub fn should_serve_stale(
    fail_open: bool,
    cache_entry_expired: bool,
    upstream_failed: bool,
) -> bool {
    fail_open && cache_entry_expired && upstream_failed
}
