//! ccTLD block (SPEC.md §5.2, Фаза 5, T-115) — pipeline step 3: block by the
//! query domain's own suffix (a country-code TLD like `.ru`/`.cn`), not by
//! the resolved IP's country (that's `GeoIP`, §3.5, a later step). No network
//! call, no resolution — a pure string check over an already-normalized
//! domain.
//!
//! **Deliberate divergence from `blocklist_updater::BlocklistBundleState::matches_domain`:**
//! that walk structurally never tests a bare TLD candidate (T-218 Батч 7.4 —
//! a compromised *third-party* feed must never get to nuke an entire public
//! namespace via one bare-suffix line). Here a bare TLD **does** match itself
//! (`is_blocked("ru", &["ru"]) == true`) — not an oversight, a different
//! threat model: this list is a handful of codes the user typed into the
//! admin UI themselves, not fetched from an untrusted external source, and
//! "block `.ru`" naturally includes a bare `ru` query, not only its
//! subdomains.
//!
//! **Runs above the pause fast path.** `pipeline::overrides_step` (this
//! check's caller) executes before `handle_query` ever looks at
//! `filtering_paused` — the same pipeline-order precedent the manual
//! blocklist and the T-218 bundle already set. "Призупинити фільтрацію"
//! therefore does **not** exempt a ccTLD match; that's consistent with the
//! adjacent steps, not a special case decided here.

/// Whether `normalized_domain`'s own TLD (its last label) is in `blocked`.
/// `normalized_domain` must already be [`crate::normalize_domain`]'s output
/// (lowercase, no trailing dot); `blocked` entries are already-validated,
/// lowercased codes (`config::validate_cctld_codes`) — comparison is
/// case-insensitive regardless, since neither side is guaranteed by the
/// type system alone.
///
/// `rsplit('.').next()` on a `&str` is infallible (even `""` yields
/// `Some("")`) — no `None` branch exists to handle, so this doesn't
/// pattern-match on the `Option` at all.
pub(crate) fn is_blocked(normalized_domain: &str, blocked: &[String]) -> bool {
    normalized_domain
        .rsplit('.')
        .next()
        .is_some_and(|tld| blocked.iter().any(|code| code.eq_ignore_ascii_case(tld)))
}

#[cfg(test)]
mod tests {
    use super::is_blocked;

    #[test]
    fn is_blocked_matches_a_domain_under_a_blocked_tld() {
        assert!(is_blocked("example.ru", &["ru".to_string()]));
        assert!(is_blocked("sub.example.ru", &["ru".to_string()]));
    }

    #[test]
    fn is_blocked_matches_the_bare_tld_itself() {
        // Discriminating test for this module's own deliberate divergence
        // from `matches_domain` — see the module doc.
        assert!(is_blocked("ru", &["ru".to_string()]));
    }

    #[test]
    fn is_blocked_rejects_a_tld_that_only_shares_a_prefix() {
        assert!(!is_blocked("example.ruble", &["ru".to_string()]));
        assert!(!is_blocked("notru.example.com", &["ru".to_string()]));
    }

    #[test]
    fn is_blocked_is_false_for_an_empty_blocklist() {
        assert!(!is_blocked("example.ru", &[]));
    }

    #[test]
    fn is_blocked_is_case_insensitive_on_both_sides() {
        assert!(is_blocked("example.RU", &["ru".to_string()]));
        assert!(is_blocked("example.ru", &["RU".to_string()]));
    }
}
