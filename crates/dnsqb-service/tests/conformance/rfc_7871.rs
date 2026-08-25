//! RFC 7871 — Client Subnet in DNS Queries (EDNS Client Subnet): only the
//! ECS-enabled upstream variant (e.g. Quad9 9.9.9.11) gets a Subnet option;
//! the default variant does not (SPEC.md §3.4).

use dnsqb_service::ecs_option_for_upstream;
use hickory_proto::rr::rdata::opt::EdnsOption;

#[test]
#[ignore = "Крок 0 red until T-24 (Фаза 1)"]
fn ecs_variant_upstream_gets_a_subnet_option() {
    let option = ecs_option_for_upstream("quad9-ecs");
    assert!(matches!(option, Some(EdnsOption::Subnet(_))));
}

#[test]
#[ignore = "Крок 0 red until T-24 (Фаза 1)"]
fn default_upstream_gets_no_ecs_option() {
    assert_eq!(ecs_option_for_upstream("quad9-filtered"), None);
}
