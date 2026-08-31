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
//! by reading, not enforced by a test: as of 2026-08-31 no code path
//! constructs an ECS option — `quorum::resolve` forwards the client
//! `Message` to every upstream unmodified, and `attach_edns` (the only
//! OPT-writing helper) has no production caller. If `attach_edns` is ever
//! wired into the upstream path, re-check that invariant.
//! Full record: SPEC.md §3.4 "Розглянуті й відхилені провайдери",
//! TASKS-DONE.md T-164.
//!
//! These two fns stay `#[ignore]`d and assertion-free — kept only so the
//! conformance module list still names this RFC row.

#[test]
#[ignore = "T-164 rejected 2026-08-31 — ECS is a deliberate non-target, no surface to test"]
fn ecs_variant_upstream_gets_a_subnet_option() {
    // Intentionally empty: no ECS-enabled preset exists (T-164 rejected).
}

#[test]
#[ignore = "T-164 rejected 2026-08-31 — ECS is a deliberate non-target, no surface to test"]
fn default_upstream_gets_no_ecs_option() {
    // Intentionally empty: as of 2026-08-31 no code path constructs a Subnet
    // option (verified by reading quorum::resolve, not enforced here).
}
