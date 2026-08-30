//! RFC 7871 — Client Subnet in DNS Queries (EDNS Client Subnet): only the
//! ECS-enabled upstream variant (e.g. Quad9 9.9.9.11) gets a Subnet option;
//! the default variant does not (SPEC.md §3.4).
//!
//! T-72/T-73 generalized the voter set to a runtime `[[providers]]` list and
//! **removed** the `ecs_option_for_upstream` `todo!()` stub this table row
//! used to exercise — ECS-enabled upstreams (Quad9 9.9.9.11, not in §3.4's
//! table) are re-filed as **T-164**. This row stays `#[ignore]`d and
//! assertion-free until then: there is no ECS surface in the crate to test.

#[test]
#[ignore = "Крок 0 red until T-164 — ECS-enabled upstream preset (re-filed from T-73)"]
fn ecs_variant_upstream_gets_a_subnet_option() {
    // T-164: a preset that carries an ECS Subnet option, and a quorum path
    // that attaches it only for that preset.
}

#[test]
#[ignore = "Крок 0 red until T-164 — ECS-enabled upstream preset (re-filed from T-73)"]
fn default_upstream_gets_no_ecs_option() {
    // T-164: the ordinary presets must attach no Subnet option.
}
