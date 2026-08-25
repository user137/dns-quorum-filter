//! RFC-conformance test suite (Крок 0, SPEC.md §"Фазований план"). Separate
//! `cargo test` target from unit tests (TASKS.md T-13) so protocol regressions
//! are visible independently of business-logic regressions. Every test here
//! is `#[ignore]`d until the Фаза 1 task cited in its module implements the
//! behavior — run `cargo test --test conformance -- --ignored` to see the
//! current red set.

mod rfc_1035;
mod rfc_2181;
mod rfc_2308;
mod rfc_4033_4035;
mod rfc_5891;
mod rfc_6891;
mod rfc_7871;
mod rfc_8484;
mod rfc_8767;
mod rfc_9460;
