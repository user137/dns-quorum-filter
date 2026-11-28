//! RFC 7871 — Client Subnet in DNS Queries (EDNS Client Subnet): a
//! **deliberate non-target**, not an unimplemented requirement.
//!
//! T-72/T-73 removed the `ecs_option_for_upstream` `todo!()` stub this row
//! used to exercise; the re-filed **T-164** (an opt-in Quad9 9.9.9.11 voter)
//! was **rejected 2026-08-31**. A live probe (`whoami.ds.akahelp.net` TXT via
//! `dns.quad9.net` vs `dns11.quad9.net`) showed `9.9.9.11` forwards the
//! client's real public /24 to every authoritative server with no option
//! supplied by us, and a resolver on `127.0.0.1` cannot make that /24
//! coarser. ECS therefore stays a deliberate non-target. This is verified
//! by `default_upstream_gets_no_ecs_option` below: since T-305 batch 3a
//! every upstream query is `upstream_query`'s rebuild — the question, the
//! RD/CD/AD flags and our own OPT (DO only) — so neither we nor the client
//! can put a Subnet option in front of a provider.
//! Full record: SPEC.md §3.4 "Розглянуті й відхилені провайдери",
//! TASKS-DONE.md T-164.

#[test]
#[ignore = "T-164 rejected 2026-08-31 — ECS is a deliberate non-target, no surface to test"]
fn ecs_variant_upstream_gets_a_subnet_option() {
    // Intentionally empty: no ECS-enabled preset exists (T-164 rejected).
}

#[test]
fn default_upstream_gets_no_ecs_option() {
    use dnsqb_service::upstream_query;
    use hickory_proto::op::{Edns, Message, Query};
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("example.com.").expect("valid fixture name"),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    let subnet = "198.51.100.0/24"
        .parse::<ClientSubnet>()
        .expect("valid subnet fixture");
    edns.options_mut().insert(EdnsOption::Subnet(subnet));
    query.set_edns(edns);

    let upstream = upstream_query(&query);
    let opt = upstream
        .edns
        .expect("a client OPT gets our own OPT upstream");
    assert!(
        opt.options().as_ref().is_empty(),
        "a client option reached the upstream query"
    );
}
