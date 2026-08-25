//! RFC 5891 — IDNA2008 protocol: override-list domains are normalized to
//! lowercase punycode with the trailing dot trimmed before storage/lookup
//! (SPEC.md §5, TASKS.md T-38).

use dnsqb_service::normalize_domain;

#[test]
#[ignore = "Крок 0 red until T-38 (Фаза 1)"]
fn lowercases_ascii_input() {
    assert_eq!(
        normalize_domain("Example.COM.").expect("valid domain"),
        "example.com"
    );
}

#[test]
#[ignore = "Крок 0 red until T-38 (Фаза 1)"]
fn trims_trailing_dot() {
    assert_eq!(
        normalize_domain("example.com.").expect("valid domain"),
        normalize_domain("example.com").expect("valid domain")
    );
}

#[test]
#[ignore = "Крок 0 red until T-38 (Фаза 1)"]
fn converts_unicode_labels_to_punycode() {
    // "приклад.укр" — IDNA2008 ASCII (punycode) form, no embedded uppercase.
    let normalized = normalize_domain("приклад.укр").expect("valid IDN");
    assert!(normalized.starts_with("xn--"));
    assert_eq!(normalized, normalized.to_ascii_lowercase());
}
