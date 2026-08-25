//! RFC 4033-4035 — DNSSEC (Introduction, Resource Records, Protocol): if the
//! AD bit is passed to the client at all, it must reflect the upstream's
//! actual validation result, never fabricated or blindly cleared locally
//! (SPEC.md §3.4).

use dnsqb_service::preserve_ad_flag;

#[test]
#[ignore = "Крок 0 red until T-24 (Фаза 1)"]
fn preserves_ad_bit_when_upstream_validated() {
    assert!(preserve_ad_flag(true));
}

#[test]
#[ignore = "Крок 0 red until T-24 (Фаза 1)"]
fn preserves_cleared_ad_bit_when_upstream_did_not_validate() {
    assert!(!preserve_ad_flag(false));
}
