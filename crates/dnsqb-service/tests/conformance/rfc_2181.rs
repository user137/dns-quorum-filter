//! RFC 2181 §5.2 — Clarifications to the DNS Specification: TTLs within one
//! RRset should be equal; if not, the minimum is used (SPEC.md §4.1,
//! TASKS.md T-33).

use dnsqb_service::min_rrset_ttl;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record};
use std::net::Ipv4Addr;
use std::str::FromStr;

fn a_record(ttl: u32) -> Record {
    let name = Name::from_str("example.com.").expect("valid fixture name");
    Record::from_rdata(name, ttl, RData::A(A(Ipv4Addr::new(93, 184, 216, 34))))
}

#[test]
#[ignore = "Крок 0 red until T-33/T-34 (Фаза 1)"]
fn uses_minimum_ttl_when_rrset_ttls_disagree() {
    let records = vec![a_record(300), a_record(60), a_record(120)];
    assert_eq!(min_rrset_ttl(&records), Some(60));
}

#[test]
#[ignore = "Крок 0 red until T-33/T-34 (Фаза 1)"]
fn empty_rrset_has_no_ttl() {
    assert_eq!(min_rrset_ttl(&[]), None);
}
