//! RFC 2308 — Negative Caching of DNS Queries (DNS NCACHE): negative-caching
//! TTL comes from the zone's SOA MINIMUM field, not an arbitrary constant
//! (SPEC.md §3.1, §4.1, TASKS.md T-35).

use dnsqb_service::negative_cache_ttl;
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::Name;
use std::str::FromStr;

fn soa(minimum: u32) -> SOA {
    let mname = Name::from_str("ns1.example.com.").expect("valid fixture name");
    let rname = Name::from_str("hostmaster.example.com.").expect("valid fixture name");
    SOA::new(mname, rname, 2026082501, 7200, 3600, 1_209_600, minimum)
}

#[test]
fn negative_ttl_comes_from_soa_minimum() {
    assert_eq!(negative_cache_ttl(&soa(300)), 300);
}

#[test]
fn negative_ttl_is_not_a_fixed_constant() {
    assert_ne!(negative_cache_ttl(&soa(60)), negative_cache_ttl(&soa(600)));
}
