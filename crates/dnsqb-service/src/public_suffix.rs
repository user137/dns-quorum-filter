//! Public Suffix List (PSL) parser and matcher. Moved here from
//! `examples/curate_topn.rs` (T-233 part 3) — it was already implemented and
//! tested there for CrUX-origin→registrable normalization; this makes it a
//! library type so [`crate::blocklist_download`] can reuse it for a second,
//! unrelated purpose (ingestion-time filtering of bare public-suffix entries
//! in fetched blocklist sources) instead of duplicating the parser.

use std::collections::HashSet;

/// Pinned Public Suffix List — committed next to this file, never fetched at
/// run time. Refreshing it is a one-line change to [`PSL_PINNED_COMMIT`] plus
/// a re-download from the same path.
pub const PSL_DAT: &str = include_str!("public_suffix_list.dat");
/// `publicsuffix/list` commit the bundled `public_suffix_list.dat` was taken
/// from (2026-09-08). Recorded in every curated `data/topn` file's header.
pub const PSL_PINNED_COMMIT: &str = "3955e3ec29b94c3cca7bd4509c5f14a7c0959e26";

/// Parsed Public Suffix List. `rules` holds normal and `*` wildcard rules
/// verbatim (`"com"`, `"*.ck"`) from **both** the ICANN and PRIVATE sections —
/// [`registrable`](Psl::registrable) must see both (a PRIVATE-section entry
/// like `github.io` is exactly as much a public suffix for registrable-domain
/// purposes as an ICANN one); `exceptions` holds `!` rules with the `!`
/// stripped (`"www.ck"`). `icann_rules` is the ICANN-section subset of
/// `rules`, consulted only by [`is_public_suffix`](Psl::is_public_suffix) —
/// see that method's own doc for why the split exists. Only the ASCII/`xn--`
/// form of a host is looked up, which is what `reqwest::Url::host_str`
/// yields — the bundled list's Unicode IDN entries are therefore not
/// matched, and such hosts fall to the implicit `*` rule (rare in a
/// top-1000 bucket; visible in the review diff).
pub struct Psl {
    rules: HashSet<String>,
    exceptions: HashSet<String>,
    icann_rules: HashSet<String>,
}

impl Psl {
    /// Parses a raw `public_suffix_list.dat`-format body into rule sets.
    #[must_use]
    pub fn parse(dat: &str) -> Self {
        let mut rules = HashSet::new();
        let mut exceptions = HashSet::new();
        let mut icann_rules = HashSet::new();
        let mut in_icann = false;
        for raw in dat.lines() {
            let line = raw.trim();
            if line.starts_with("//") {
                if line.contains("BEGIN ICANN DOMAINS") {
                    in_icann = true;
                } else if line.contains("END ICANN DOMAINS") {
                    in_icann = false;
                }
                continue;
            }
            if line.is_empty() {
                continue;
            }
            let Some(rule) = line.split_whitespace().next() else {
                continue;
            };
            let rule = rule.to_ascii_lowercase();
            if let Some(exc) = rule.strip_prefix('!') {
                exceptions.insert(exc.to_string());
            } else {
                if in_icann {
                    icann_rules.insert(rule.clone());
                }
                rules.insert(rule);
            }
        }
        Self {
            rules,
            exceptions,
            icann_rules,
        }
    }

    /// The registrable ("registered") domain for `host` — the public suffix
    /// plus one more label — or `None` if `host` is itself a public suffix,
    /// is empty, or has an empty label.
    #[must_use]
    pub fn registrable(&self, host: &str) -> Option<String> {
        let host = host.trim_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        let labels: Vec<&str> = host.split('.').collect();
        if labels.iter().any(|l| l.is_empty()) {
            return None;
        }

        // Exception rules win outright; the longest-matching one gives a
        // public suffix of the rule minus its leftmost label.
        for start in 0..labels.len() {
            if self.exceptions.contains(&labels[start..].join(".")) {
                let ps_len = labels.len() - (start + 1);
                return registrable_from_ps_len(&labels, ps_len);
            }
        }

        // Otherwise: longest normal / wildcard rule match. `*` matches
        // exactly one label, so a wildcard rule for suffix `labels[start..]`
        // is `"*." + labels[start+1..]`.
        let mut best_ps_len: Option<usize> = None;
        for start in 0..labels.len() {
            let span = labels.len() - start;
            let exact_match = self.rules.contains(&labels[start..].join("."));
            let wild_match = start + 1 < labels.len()
                && self
                    .rules
                    .contains(&format!("*.{}", labels[(start + 1)..].join(".")));
            if exact_match || wild_match {
                best_ps_len = Some(best_ps_len.map_or(span, |b| b.max(span)));
            }
        }

        // Implicit `*` rule: with no match, the public suffix is the single
        // rightmost label.
        registrable_from_ps_len(&labels, best_ps_len.unwrap_or(1))
    }

    /// Whether `normalized` (already run through
    /// [`crate::normalize_domain`] — lowercase, no trailing dot) is itself,
    /// in its entirety, an **ICANN-section** public suffix — `"co.uk"` is,
    /// `"evil.co.uk"` is not (a subdomain of a suffix is a normal
    /// registrable domain). Deliberately **not** `registrable(..).is_none()`:
    ///
    /// * **Cost.** `registrable` walks every prefix position of the host,
    ///   `.join(".")`-allocating at each one — built for `CrUX` curation, run
    ///   once per top-N entry. This method is called on every candidate line
    ///   of every blocklist source ingested at runtime (up to ~5.5M
    ///   lines/cycle across the eight published sources), so it does at most
    ///   one allocation (the wildcard probe) and no loop over positions —
    ///   "is the whole string exactly a suffix" doesn't need the longest-
    ///   match search `registrable` does for an arbitrary host.
    /// * **Scope.** Checks `icann_rules` only, never the PRIVATE section.
    ///   Measured against the real ~4.1M lines across all eight published
    ///   blocklist-bundle sources (2026-09-17): `hagezi-hoster`/
    ///   `hagezi-dyndns` intentionally list bare PRIVATE-section suffixes
    ///   (delegating-namespace hosts like `duckdns.org` — 468 of
    ///   `hagezi-dyndns`'s 1,547 lines, 30% of the whole source) as their
    ///   entire reason to exist; filtering those would gut both sources.
    ///   ICANN-section hits were vanishingly rare across the same corpus (4
    ///   entries total) and none belonged to either source — see
    ///   DECISIONS.md for the full measurement and the asymmetry rationale.
    ///
    /// **Known scope gap:** does not consult `exceptions` — an ICANN-section
    /// exception rule (e.g. `!city.kawasaki.jp`, carving a registrable
    /// domain out from under a wildcard suffix rule) could make this method
    /// return `true` for a string that `registrable` would actually treat as
    /// registrable. The failure direction is under-filtering-avoidance, not
    /// over-blocking (the caller drops one fewer real block-target line, on
    /// an exception-carved apex — never the reverse), so it's accepted
    /// rather than reproducing `registrable`'s full exception walk on this
    /// hot path.
    pub(crate) fn is_public_suffix(&self, normalized: &str) -> bool {
        if self.icann_rules.contains(normalized) {
            return true;
        }
        if let Some((_, rest)) = normalized.split_once('.') {
            if self.icann_rules.contains(&format!("*.{rest}")) {
                return true;
            }
        }
        false
    }
}

/// Public-suffix length (label count) → registrable domain: the public
/// suffix plus one label to its left. `None` when `host` has no label beyond
/// the public suffix.
fn registrable_from_ps_len(labels: &[&str], ps_len: usize) -> Option<String> {
    if labels.len() <= ps_len {
        return None;
    }
    Some(labels[(labels.len() - ps_len - 1)..].join("."))
}

/// Real bundled `PSL_DAT`, not a fixture — the same file that ships to
/// production, so a caller's tests exercise the real `co.uk`/`github.io`
/// rules rather than a hand-picked stand-in that could drift from it.
#[cfg(test)]
pub(crate) fn test_psl() -> Psl {
    Psl::parse(PSL_DAT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_handles_multi_label_suffixes() {
        let p = test_psl();
        assert_eq!(
            p.registrable("www.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            p.registrable("shop.foo.com.ua").as_deref(),
            Some("foo.com.ua")
        );
        assert_eq!(
            p.registrable("a.b.example.com.br").as_deref(),
            Some("example.com.br")
        );
        assert_eq!(
            p.registrable("a.b.c.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(p.registrable("gov.pl").as_deref(), None); // gov.pl is a public suffix
    }

    #[test]
    fn registrable_applies_wildcard_and_exception_rules() {
        let p = test_psl();
        // *.ck ⇒ foo.ck is a public suffix, so a.foo.ck is registrable a.foo.ck
        assert_eq!(p.registrable("a.foo.ck").as_deref(), Some("a.foo.ck"));
        // !www.ck exception ⇒ ck is the public suffix, www.ck is registrable
        assert_eq!(p.registrable("www.ck").as_deref(), Some("www.ck"));
    }

    #[test]
    fn registrable_is_none_for_a_bare_public_suffix_or_empty_input() {
        let p = test_psl();
        assert_eq!(p.registrable("co.uk"), None);
        assert_eq!(p.registrable("com"), None);
        assert_eq!(p.registrable(""), None);
        assert_eq!(p.registrable("."), None);
        assert_eq!(p.registrable("a..b"), None);
    }

    #[test]
    fn registrable_uses_the_implicit_star_rule_for_an_unknown_tld() {
        let p = test_psl();
        assert_eq!(
            p.registrable("host.example.invalidtldxyz").as_deref(),
            Some("example.invalidtldxyz")
        );
    }

    /// Discriminating test for the ICANN/PRIVATE split itself: `github.io`
    /// is a PRIVATE-section rule. If `rules` (the set `registrable` reads)
    /// were ever mistakenly narrowed to ICANN-only entries, this is the test
    /// that would catch it — none of the four tests above exercise a
    /// PRIVATE-section rule.
    #[test]
    fn registrable_still_sees_private_section_rules() {
        let p = test_psl();
        assert_eq!(
            p.registrable("foo.github.io").as_deref(),
            Some("foo.github.io")
        );
    }

    #[test]
    fn is_public_suffix_matches_an_exact_icann_rule() {
        let p = test_psl();
        assert!(p.is_public_suffix("co.uk"));
    }

    #[test]
    fn is_public_suffix_matches_an_icann_wildcard_rule() {
        let p = test_psl();
        // *.ck is an ICANN wildcard rule — any single label under ck is a suffix.
        assert!(p.is_public_suffix("something.ck"));
    }

    #[test]
    fn is_public_suffix_rejects_a_subdomain_of_a_suffix() {
        let p = test_psl();
        assert!(!p.is_public_suffix("evil.co.uk"));
    }

    #[test]
    fn is_public_suffix_ignores_private_section_rules() {
        let p = test_psl();
        assert!(
            !p.is_public_suffix("github.io"),
            "github.io is PRIVATE-section — intentionally not filtered"
        );
    }

    #[test]
    fn is_public_suffix_rejects_an_ordinary_domain() {
        let p = test_psl();
        assert!(!p.is_public_suffix("real-ads.example"));
    }
}
