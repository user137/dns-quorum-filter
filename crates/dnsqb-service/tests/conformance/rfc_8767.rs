//! RFC 8767 — Serving Stale Data to Improve DNS Resiliency: `stale-if-error`
//! is layered on top of `fail-open`, not a replacement for the three timeout
//! modes (SPEC.md §3.3, §4.1, TASKS.md T-28).

use dnsqb_service::should_serve_stale;

#[test]
#[ignore = "Крок 0 red until T-28 (Фаза 1)"]
fn serves_stale_on_upstream_failure_when_fail_open_and_entry_expired() {
    assert!(should_serve_stale(true, true, true));
}

#[test]
#[ignore = "Крок 0 red until T-28 (Фаза 1)"]
fn does_not_serve_stale_when_upstream_succeeds() {
    assert!(!should_serve_stale(true, true, false));
}

#[test]
#[ignore = "Крок 0 red until T-28 (Фаза 1)"]
fn stale_if_error_is_gated_on_fail_open_not_a_separate_fourth_mode() {
    // fail-closed/degraded modes don't get stale-if-error (SPEC.md §3.3): it's
    // explicitly "поверх fail-open", not a standalone timeout policy.
    assert!(!should_serve_stale(false, true, true));
}
