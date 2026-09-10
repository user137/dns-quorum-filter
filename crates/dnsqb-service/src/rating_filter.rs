//! T-124 — the rating filter «bubble» zone-membership core (SPEC.md §5.3).
//!
//! Pipeline step 5: a domain **in** any active availability zone continues
//! through the normal pipeline unchanged; a domain **outside every** zone is
//! blocked, and quorum is never consulted. This module is the pure "is this
//! host in the zone?" decision — the impure download/refresh of the zone
//! files lives in [`crate::topn_updater`], and the pipeline wiring in
//! [`crate::pipeline`].
//!
//! **Runtime `origin → registrable` reduction without a Public Suffix
//! List.** The curation tool (`examples/curate_topn.rs`) already reduced
//! every published list to registrable domains (`example.co.uk`, never
//! `www.example.co.uk` or a bare `co.uk`). So the client does not need a PSL
//! of its own: [`ZoneLists::zone_match`] walks the query host's suffixes
//! (`www.example.co.uk` → `example.co.uk` → `co.uk` → `uk`) and a hit on any
//! of them means "in zone". A subdomain of an in-zone registrable is
//! correctly in zone; a host whose only in-set suffix is a public suffix
//! cannot happen, because the curation tool skips bare public suffixes. This
//! is the same suffix-label technique [`crate::overrides`] already uses, and
//! keeps the ~334 KB PSL out of the service binary (T-105: no new client
//! mechanism).
//!
//! **Lazy hygiene (T-108, DECISIONS.md 2026-09-09).** The `removed` set
//! passed to [`ZoneLists::zone_match`] is subtracted from the zone: a domain
//! quorum blocked at browse time is dropped from the local bubble so the
//! next lookup treats it as out-of-zone. That set is owned by
//! [`crate::dispatch::AppState`] under its own lock (not folded into the
//! zone `Arc`), because the zone `Arc` and the removed set have different
//! single writers — the refresher swaps the whole zone, the pipeline records
//! removals. In-memory only this phase; persistence is Батч 4.5's job.

use std::collections::HashSet;

/// Which curation model produced one [`ZoneSource`]. Extensible — Батч 4.2
/// adds government / sci-edu variants, Батч 4.5 the personal learned list —
/// which is why [`ZoneLists`] holds an N-ary `Vec<ZoneSource>` rather than a
/// fixed pair of fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneSourceKind {
    /// A curated per-country top-traffic list (`data/topn/<cc>.txt`); the
    /// payload is the ISO 3166-1 alpha-2 country code, lowercase.
    CountryTopN(String),
    /// The worldwide top-traffic list (`data/topn/global.txt`).
    Global,
}

impl ZoneSourceKind {
    /// The list code this source was loaded from — a country code for
    /// [`Self::CountryTopN`], the literal `"global"` for [`Self::Global`].
    /// Matches an entry of `[rating_filter] lists` and of
    /// [`crate::topn_download::AVAILABLE_TOPN_LISTS`].
    #[must_use]
    pub fn list_code(&self) -> String {
        match self {
            Self::CountryTopN(cc) => cc.clone(),
            Self::Global => "global".to_string(),
        }
    }
}

/// One loaded availability-zone list: its provenance plus the set of
/// registrable domains it contributes to the bubble.
#[derive(Debug, Clone)]
pub struct ZoneSource {
    kind: ZoneSourceKind,
    registrables: HashSet<String>,
}

impl ZoneSource {
    /// Builds a source from an already-parsed list of registrable domains
    /// (lowercase, no scheme, no `www.` — the shape `curate_topn` writes and
    /// [`crate::topn_download::parse_list`] returns).
    #[must_use]
    pub fn new(kind: ZoneSourceKind, registrables: impl IntoIterator<Item = String>) -> Self {
        Self {
            kind,
            registrables: registrables.into_iter().collect(),
        }
    }

    /// This source's provenance.
    #[must_use]
    pub fn kind(&self) -> &ZoneSourceKind {
        &self.kind
    }

    /// How many registrable domains this source contributes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.registrables.len()
    }

    /// Whether this source contributes no domains.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registrables.is_empty()
    }
}

/// The union of every active [`ZoneSource`] — the availability "bubble".
/// The lazy-hygiene `removed` set is **not** held here (see the module doc);
/// it is passed in per call so its writer stays independent of this value's.
#[derive(Debug, Clone, Default)]
pub struct ZoneLists(Vec<ZoneSource>);

impl ZoneLists {
    /// Assembles the bubble from the currently-active sources.
    #[must_use]
    pub fn new(sources: Vec<ZoneSource>) -> Self {
        Self(sources)
    }

    /// `true` when no active source contributes a single domain — the state
    /// in which an `enabled` rating filter is treated as inert (SPEC.md
    /// §5.3, "graceful, warn, don't block the whole internet from a
    /// hand-edited file / a not-yet-downloaded list").
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(ZoneSource::is_empty)
    }

    /// The active sources, for status/diagnostics.
    #[must_use]
    pub fn sources(&self) -> &[ZoneSource] {
        &self.0
    }

    /// Resolves `host` against the bubble in a single suffix walk.
    ///
    /// Returns the matched registrable (a slice of `host`) when some suffix
    /// of `host` is contributed by an active source **and** is not in
    /// `removed`; `None` when `host` is outside every zone. `host` is
    /// expected already normalized (lowercase, no trailing dot — the
    /// `pipeline::handle_query` `log_domain` form); a trailing dot is
    /// tolerated but nothing else is coerced.
    ///
    /// This is both the membership test (`.is_some()`) and, for lazy
    /// hygiene, the identity of what to remove (`Some(r)` with
    /// `host == r` ⇒ quorum blocked the registrable itself).
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsqb_service::{ZoneLists, ZoneSource, ZoneSourceKind};
    /// use std::collections::HashSet;
    ///
    /// let zones = ZoneLists::new(vec![ZoneSource::new(
    ///     ZoneSourceKind::Global,
    ///     ["example.com".to_string()],
    /// )]);
    /// let removed = HashSet::new();
    ///
    /// // A subdomain resolves to the registrable that put it in the bubble.
    /// assert_eq!(zones.zone_match("www.example.com", &removed), Some("example.com"));
    /// // Out of zone.
    /// assert_eq!(zones.zone_match("elsewhere.test", &removed), None);
    /// // Lazy-hygiene removal takes the registrable back out.
    /// let removed = HashSet::from(["example.com".to_string()]);
    /// assert_eq!(zones.zone_match("www.example.com", &removed), None);
    /// ```
    #[must_use]
    pub fn zone_match<'h>(&self, host: &'h str, removed: &HashSet<String>) -> Option<&'h str> {
        let mut candidate = host.strip_suffix('.').unwrap_or(host);
        loop {
            if !candidate.is_empty()
                && !removed.contains(candidate)
                && self.0.iter().any(|s| s.registrables.contains(candidate))
            {
                return Some(candidate);
            }
            match candidate.split_once('.') {
                Some((_, rest)) => candidate = rest,
                None => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ZoneLists, ZoneSource, ZoneSourceKind};
    use std::collections::HashSet;

    fn country(cc: &str, domains: &[&str]) -> ZoneSource {
        ZoneSource::new(
            ZoneSourceKind::CountryTopN(cc.to_string()),
            domains.iter().map(|d| (*d).to_string()),
        )
    }

    fn no_removals() -> HashSet<String> {
        HashSet::new()
    }

    // ---- Happy path ----

    #[test]
    fn a_subdomain_of_an_in_zone_registrable_is_in_zone() {
        let zone = ZoneLists::new(vec![country("ua", &["example.co.uk", "rozetka.com.ua"])]);
        assert_eq!(
            zone.zone_match("www.example.co.uk", &no_removals()),
            Some("example.co.uk")
        );
        assert_eq!(
            zone.zone_match("m.rozetka.com.ua", &no_removals()),
            Some("rozetka.com.ua")
        );
    }

    #[test]
    fn an_exact_registrable_match_returns_itself() {
        let zone = ZoneLists::new(vec![country("ua", &["diia.gov.ua"])]);
        assert_eq!(
            zone.zone_match("diia.gov.ua", &no_removals()),
            Some("diia.gov.ua")
        );
    }

    #[test]
    fn a_domain_present_in_only_one_of_several_sources_is_in_zone() {
        let zone = ZoneLists::new(vec![
            country("ua", &["rozetka.com.ua"]),
            ZoneSource::new(ZoneSourceKind::Global, ["wikipedia.org".to_string()]),
        ]);
        assert_eq!(
            zone.zone_match("en.wikipedia.org", &no_removals()),
            Some("wikipedia.org")
        );
        assert_eq!(
            zone.zone_match("rozetka.com.ua", &no_removals()),
            Some("rozetka.com.ua")
        );
    }

    // ---- Security & boundary ----

    #[test]
    fn a_sibling_of_a_multi_label_suffix_is_out_of_zone() {
        // `co.uk` is a public suffix, never itself an entry — so
        // `notexample.co.uk`, sharing only that suffix, must not match.
        let zone = ZoneLists::new(vec![country("gb", &["example.co.uk"])]);
        assert_eq!(zone.zone_match("notexample.co.uk", &no_removals()), None);
    }

    #[test]
    fn a_bare_public_suffix_query_is_out_of_zone() {
        let zone = ZoneLists::new(vec![country("gb", &["example.co.uk"])]);
        assert_eq!(zone.zone_match("co.uk", &no_removals()), None);
        assert_eq!(zone.zone_match("uk", &no_removals()), None);
    }

    #[test]
    fn a_removed_domain_is_out_of_zone_even_while_a_source_still_lists_it() {
        let zone = ZoneLists::new(vec![country("ua", &["bad.example.ua", "good.example.ua"])]);
        let removed: HashSet<String> = ["bad.example.ua".to_string()].into_iter().collect();
        assert_eq!(zone.zone_match("bad.example.ua", &removed), None);
        assert_eq!(
            zone.zone_match("www.bad.example.ua", &removed),
            None,
            "a subdomain of a removed registrable is out too"
        );
        assert_eq!(
            zone.zone_match("good.example.ua", &removed),
            Some("good.example.ua"),
            "removal is scoped to the one domain"
        );
    }

    // ---- Misuse & fool ----

    #[test]
    fn empty_single_label_and_trailing_dot_hosts_do_not_match() {
        let zone = ZoneLists::new(vec![country("ua", &["example.ua"])]);
        assert_eq!(zone.zone_match("", &no_removals()), None);
        assert_eq!(zone.zone_match("localhost", &no_removals()), None);
        // A trailing dot is tolerated: still resolves to the registrable.
        assert_eq!(
            zone.zone_match("www.example.ua.", &no_removals()),
            Some("example.ua")
        );
    }

    // ---- State / structure ----

    #[test]
    fn is_empty_is_true_only_when_every_source_contributes_nothing() {
        assert!(ZoneLists::default().is_empty());
        assert!(ZoneLists::new(vec![country("ua", &[])]).is_empty());
        assert!(!ZoneLists::new(vec![country("ua", &["example.ua"])]).is_empty());
    }
}
