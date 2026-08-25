//! RFC 9460 — Service Binding and Parameter Specification via the DNS (SVCB,
//! HTTPS RRs): these types bypass quorum entirely, proxied to a single
//! upstream, so ECH keys carried in the HTTPS RR aren't silently broken by
//! OR-logic across providers (SPEC.md §3, TASKS.md T-25).

use dnsqb_service::requires_quorum;
use hickory_proto::rr::RecordType;

#[test]
fn https_records_bypass_quorum() {
    assert!(!requires_quorum(RecordType::HTTPS));
}

#[test]
fn svcb_records_bypass_quorum() {
    assert!(!requires_quorum(RecordType::SVCB));
}

#[test]
fn a_and_aaaa_records_require_quorum() {
    assert!(requires_quorum(RecordType::A));
    assert!(requires_quorum(RecordType::AAAA));
}
