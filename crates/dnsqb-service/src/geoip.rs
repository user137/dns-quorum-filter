//! `GeoIP` country lookup (T-74, Фаза 2 — SPEC.md §3.5).
//!
//! The reader: `GeoipReader::open`/`country` are a pure, standalone
//! `IpAddr → Option<country code>` lookup over a caller-supplied database
//! path. [`blocking_country`] (T-76, widened at T-79 from a bare `bool` to
//! the actual matched country) is the OR-across-multiple-IPs decision
//! `pipeline.rs` calls at both of SPEC.md §3.5's named hook points (a
//! cache-hit `Allow` replay and a fresh quorum `Allow`) — this module still
//! doesn't fetch or verify a database file itself (T-75's `geoip_updater.rs`
//! owns that).
//!
//! Deliberately reads via [`maxminddb::LookupResult::decode_path`]'s
//! `["country", "iso_code"]` path rather than the crate's typed
//! `geoip2::Country` struct — that path is the de facto standard `MaxMind`
//! `DB` layout both DB-IP Lite (the SPEC.md §3.5 default) and `MaxMind`'s
//! own `GeoLite2` (the T-80 advanced-mode alternative) use, so this reader
//! doesn't need to know or care which of the two produced the file it's
//! pointed at.
//!
//! Built with `maxminddb`'s default features only (`mmap`/`simdutf8`/
//! `unsafe-str-decode` all opt-in and left off) — this crate is
//! `#![forbid(unsafe_code)]` end to end, and the default `Reader<Vec<u8>>`
//! mode (whole file read into an owned buffer, no `unsafe`) is what keeps
//! that true without needing an exception for this dependency.

use std::net::IpAddr;
use std::path::Path;
use std::time::SystemTime;

use maxminddb::{path, Reader};

/// Failure opening or reading a `GeoIP` database file.
///
/// The wrapped path is never domain data (it's this service's own app-data
/// database file, resolved via [`crate::app_data_dir`], not anything a query
/// or override list can influence) — unlike `overrides.toml` parse errors
/// (see `overrides::OverrideError::Parse`'s own doc comment), there's no
/// "no domain names in service logs" reason to keep this payload-free, so it
/// carries the full [`maxminddb::MaxMindDbError`] for a useful diagnostic.
#[derive(Debug, thiserror::Error)]
pub enum GeoipError {
    /// The database file couldn't be opened or parsed as a valid `MaxMind`
    /// DB.
    #[error("failed to open GeoIP database: {0}")]
    Open(#[source] maxminddb::MaxMindDbError),
}

/// A loaded `GeoIP` country database, held for repeated lookups without
/// reopening/reparsing the file per query — T-75 will hold this behind an
/// `AppState` `RwLock<Arc<_>>` slice, the same shape `dispatch::CacheState`/
/// `OverridesState` already use for state that's swapped as a whole on
/// reload rather than mutated in place.
#[derive(Debug)]
pub struct GeoipReader {
    reader: Reader<Vec<u8>>,
}

impl GeoipReader {
    /// Loads a `GeoIP` database from `path` — DB-IP Lite Country-level data
    /// (T-75's downloader) or `MaxMind` `GeoLite2` Country (T-80's advanced
    /// mode); see the module doc comment for why this reader treats both
    /// the same way.
    ///
    /// # Errors
    ///
    /// Returns [`GeoipError::Open`] if `path` doesn't exist, isn't
    /// readable, or isn't a valid `MaxMind` DB file.
    pub fn open(path: &Path) -> Result<Self, GeoipError> {
        let reader = Reader::open_readfile(path).map_err(GeoipError::Open)?;
        Ok(Self { reader })
    }

    /// Parses a `GeoIP` database already held in memory, rather than reading
    /// it from a file — T-75's downloader validates a freshly-downloaded
    /// database this way *before* writing it to disk, so a corrupt/truncated
    /// download never touches the file an atomic swap would otherwise
    /// replace the last-known-good database with.
    ///
    /// # Errors
    ///
    /// Returns [`GeoipError::Open`] if `bytes` isn't a valid `MaxMind` DB.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeoipError> {
        let reader = Reader::from_source(bytes).map_err(GeoipError::Open)?;
        Ok(Self { reader })
    }

    /// The database's self-reported type string (e.g. `"DBIP-Country-Lite"`,
    /// `"GeoLite2-Country"`) — a loose sanity check T-75's downloader uses to
    /// reject a well-formed but wrong-shaped `MaxMind` DB (e.g. a City-level
    /// database) before treating it as this service's country database, not
    /// a value this crate otherwise interprets.
    #[must_use]
    pub(crate) fn database_type(&self) -> &str {
        &self.reader.metadata().database_type
    }

    /// When the database itself was built, per its own embedded metadata —
    /// **not** when this reader loaded it, and not a file's on-disk
    /// modification time. `geoip_updater.rs` (T-75) uses this for
    /// `GeoipState::updated_at` specifically because a periodic refresh
    /// polls and re-persists on a fixed schedule regardless of whether
    /// `db-ip.com` actually published anything new — the file's own mtime
    /// (or "when did the last poll run") would report a near-current date
    /// every time, honest-looking but useless for showing whether the data
    /// is actually stale (T-78's whole point). `None` only if the embedded
    /// `build_epoch` itself doesn't fit a `SystemTime` on this platform —
    /// astronomically unlikely for any real database, not treated as an
    /// error.
    #[must_use]
    pub fn build_time(&self) -> Option<SystemTime> {
        self.reader.metadata().build_time().ok()
    }

    /// The two-letter ISO 3166-1 alpha-2 country code the database
    /// associates with `ip`, or `None` if `ip` isn't found there.
    ///
    /// "Not found" is the normal, expected outcome for large swaths of
    /// address space (private/reserved ranges, gaps in DB-IP Lite's
    /// coverage) — not an error, matching SPEC.md §3.5's "порожній список
    /// країн — nop, не помилка" framing for the filter this feeds (T-76).
    /// A lookup-level error (e.g. an IPv6 address against an IPv4-only
    /// database) collapses into the same `None` rather than propagating —
    /// this is a live per-query filter, not a fallible pipeline step, and
    /// SPEC.md never asks the resolution path to fail because a `GeoIP`
    /// lookup on one address didn't apply cleanly.
    ///
    /// Returns a borrowed `&str`, not an owned `String` — T-76 will call
    /// this once per resolved IP on the busiest path in the service (every
    /// cache-hit, every fresh Quorum-Allow), and the underlying data is
    /// already a `&str` borrowed from the reader's own in-memory buffer
    /// (confirmed empirically: `decode_path::<&str>` compiles and returns
    /// real data against this reader's `'de` lifetime, not just in theory).
    /// An allocation-per-lookup on that path would be a needless cost this
    /// type can avoid for free.
    #[must_use]
    pub fn country(&self, ip: IpAddr) -> Option<&str> {
        self.reader
            .lookup(ip)
            .ok()?
            .decode_path::<&str>(&path!["country", "iso_code"])
            .ok()
            .flatten()
    }
}

/// SPEC.md §3.5's OR-across-multiple-IPs policy (T-76, widened at T-79):
/// `Some(country)` — the database's own casing, not necessarily
/// `blocked_countries`'s — for the first of `ips` (in caller-supplied order)
/// that resolves (via `reader`) to a blocked country; `None` if no `ips`
/// entry matches. SPEC.md never names an ordering beyond OR, so "first
/// matching IP wins" is the natural reading of this function's own iteration
/// order, not a documented protocol requirement — pinned by
/// `blocking_country_reports_the_first_matching_ips_country_...` below so a
/// future change to this order is a deliberate decision, not an accident.
/// The comparison against `blocked_countries` is case-insensitive
/// (`eq_ignore_ascii_case`) — **provable correct from this line alone, not by
/// trusting an upstream normalization step**: this crate's `#[deny]`-level
/// bounds/safety discipline (global CLAUDE.md) treats "correct only because a
/// caller elsewhere validated its input" as a real risk, not a formality, and
/// `blocked_countries` has more than one writer
/// ([`crate::config::ResolverConfig::load`]'s own uppercase-normalizing
/// validation is only one of them — `dispatch::AppState::update_geoip_countries`
/// takes a raw `Vec<String>` too, and T-77's future admin write route lands
/// there directly). A caller-side normalization step is a real, load-bearing
/// invariant only when the type system or this function itself enforces it;
/// here it doesn't, so the fold happens where it's actually checked, not
/// hoped for. On the handful of country codes a real deployment configures,
/// this costs nothing worth optimizing away.
///
/// An empty `blocked_countries` is always `None`, checked *before* touching
/// `reader` at all — SPEC.md's own documented default (opt-in, not a default
/// policy) and this crate's "порожній список — nop, не помилка" framing for
/// a live per-query filter, same precedent [`GeoipReader::country`]'s own doc
/// comment already states for a single lookup.
///
/// `reader: None` (no database has ever loaded — a fresh install, before
/// `geoip_updater`'s first successful check) is also always `None`, even
/// with a non-empty `blocked_countries` — Три Б: the safer failure direction
/// for a filter the user explicitly opted into by adding countries is
/// degrading to no-op, not misapplying an absent/stale database as though it
/// were current.
///
/// Returns an owned `String`, not a `&str` borrowed from `reader` — unlike
/// [`GeoipReader::country`]'s own per-lookup borrow, this value is meant to
/// outlive the call (SPEC.md §6's `geoip_country` log field, T-79). A
/// two-letter code makes the allocation cost immaterial.
#[must_use]
pub(crate) fn blocking_country(
    reader: Option<&GeoipReader>,
    blocked_countries: &[String],
    ips: &[IpAddr],
) -> Option<String> {
    if blocked_countries.is_empty() {
        return None;
    }
    let reader = reader?;
    ips.iter().find_map(|ip| {
        let code = reader.country(*ip)?;
        blocked_countries
            .iter()
            .any(|c| c.eq_ignore_ascii_case(code))
            .then(|| code.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// `maxminddb`'s own upstream test fixture (`maxmind/MaxMind-DB`,
    /// `test-data/GeoIP2-Country-Test.mmdb`, dual-licensed Apache-2.0/MIT —
    /// see `tests/fixtures/geoip/README.md`), vendored directly rather than
    /// as a git submodule (the crate's own test suite gates it behind one;
    /// this repo doesn't need the rest of that submodule's ~200 other
    /// fixture files just for this one small country-level database).
    fn fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/geoip/GeoIP2-Country-Test.mmdb")
    }

    /// Opens the fixture, panicking with a clear message on failure — this
    /// crate's `#![deny(clippy::expect_used)]` applies to inline
    /// `#[cfg(test)]` modules too (same crate), so `let-else { panic!() }`
    /// replaces `.expect()` throughout this file, not just in production
    /// code.
    fn open_fixture() -> GeoipReader {
        let Ok(reader) = GeoipReader::open(&fixture_path()) else {
            panic!("fixture must load");
        };
        reader
    }

    /// `89.160.20.112` → Sweden is the exact assertion `maxminddb`'s own
    /// `test_lookup_country` makes against this same fixture file
    /// (`reader_test.rs`, upstream) — reusing a known-good ground-truth
    /// pair rather than trusting the vendored file's contents unverified.
    #[test]
    fn country_finds_the_known_fixture_address() {
        let reader = open_fixture();
        let ip = IpAddr::V4(Ipv4Addr::new(89, 160, 20, 112));

        assert_eq!(reader.country(ip), Some("SE"));
    }

    #[test]
    fn build_time_reports_a_plausible_past_date_not_the_current_moment() {
        let reader = open_fixture();
        let Some(built) = reader.build_time() else {
            panic!("test fixture must carry a build_epoch");
        };
        // The fixture is a fixed, long-published file - its build time must
        // predate "now" by a wide margin, proving this reads the database's
        // own embedded metadata rather than reporting the moment this test
        // ran (the exact confusion this method exists to avoid, per its own
        // doc comment).
        let Ok(age) = SystemTime::now().duration_since(built) else {
            panic!("fixture build_epoch must be in the past");
        };
        assert!(age.as_secs() > 60 * 60 * 24 * 30);
    }

    #[test]
    fn country_returns_none_for_an_address_outside_the_database() {
        let reader = open_fixture();
        // TEST-NET-1 (RFC 5737) - reserved for documentation, never assigned,
        // never present in any real GeoIP database.
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        assert_eq!(reader.country(ip), None);
    }

    #[test]
    fn country_returns_none_for_an_ipv6_address_against_this_ipv4_only_fixture() {
        let reader = open_fixture();
        let Ok(ip) = "2001:db8::1".parse::<IpAddr>() else {
            panic!("valid IPv6 literal");
        };

        // Proves the lookup-error collapse documented on `country()` — an
        // IPv6 query against an IPv4-only database is a `MaxMindDbError`,
        // not a data-offset miss, and must still come back `None`, not
        // panic or propagate.
        assert_eq!(reader.country(ip), None);
    }

    #[test]
    fn open_reports_a_missing_file_as_geoip_error_not_a_panic() {
        let missing = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/geoip/does-not-exist.mmdb");

        assert!(GeoipReader::open(&missing).is_err());
    }

    fn se_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(89, 160, 20, 112))
    }

    fn unmatched_ip() -> IpAddr {
        // TEST-NET-1 (RFC 5737) - never present in any real GeoIP database,
        // same fixture address `country_returns_none_for_an_address_outside_
        // the_database` above already relies on.
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    // T-76/T-79: blocking_country's own tests. `nop_on_an_empty_blocked_list`
    // in particular asserts the real answer, not just the response code - a
    // response code alone can't distinguish "not blocked" from "blocked" in
    // this crate (`build_block_response` is also NoError for A/AAAA), the
    // same trap `pipeline.rs`'s own `label_with_a_literal_dot_does_not_
    // panic_or_false_match` test already documents.

    #[test]
    fn blocking_country_is_none_on_an_empty_blocked_list_even_for_a_matching_ip() {
        let reader = open_fixture();
        assert_eq!(blocking_country(Some(&reader), &[], &[se_ip()]), None);
    }

    #[test]
    fn blocking_country_is_none_with_no_database_loaded_even_for_a_configured_country() {
        assert_eq!(
            blocking_country(None, &["SE".to_string()], &[se_ip()]),
            None
        );
    }

    #[test]
    fn blocking_country_is_some_when_a_non_first_ip_matches_a_blocked_country() {
        let reader = open_fixture();
        // The matching IP is deliberately second - a "check only ips[0]" bug
        // would pass a first-IP-matching test but fail this one, the same
        // discipline T-40's multi-entry reload test already established for
        // this crate's other OR-across-a-collection logic.
        let ips = [unmatched_ip(), se_ip()];
        assert_eq!(
            blocking_country(Some(&reader), &["SE".to_string()], &ips),
            Some("SE".to_string())
        );
    }

    #[test]
    fn blocking_country_is_none_when_no_ip_matches_any_blocked_country() {
        let reader = open_fixture();
        assert_eq!(
            blocking_country(
                Some(&reader),
                &["DE".to_string()],
                &[se_ip(), unmatched_ip()]
            ),
            None
        );
    }

    #[test]
    fn blocking_country_reports_the_databases_own_casing_regardless_of_the_configured_entrys_case()
    {
        // Advisor-caught (T-76 closing review): the first draft's version of
        // this test locked in a plain `==` comparison as a "precondition"
        // only actually enforced at one of `blocked_countries`'s several
        // writers (`ResolverConfig::load`) - `AppState::update_geoip_countries`
        // itself takes a raw `Vec<String>` with no normalization of its own
        // (every current caller happens to pass it already-normalized data -
        // `ResolverConfig::load` for config load/`/admin/reset`,
        // `dispatch::validate_country_code` for T-77's admin add/remove
        // routes - but that's a convention every caller upholds today, not
        // a type-level guarantee this function enforces). Fixed
        // structurally (`eq_ignore_ascii_case`, not a documented-but-
        // unenforced caller contract) - this test now proves the property
        // that actually holds, as defense-in-depth against a future writer
        // that doesn't uphold the convention, not because a real gap
        // remains today. Widened at T-79: the *returned* code must be the
        // database's own casing ("SE"), not an echo of whatever case the
        // config happened to use - the one way this could pass while
        // silently sourcing the value from the wrong place.
        let reader = open_fixture();
        assert_eq!(
            blocking_country(Some(&reader), &["se".to_string()], &[se_ip()]),
            Some("SE".to_string())
        );
        assert_eq!(
            blocking_country(Some(&reader), &["Se".to_string()], &[se_ip()]),
            Some("SE".to_string())
        );
    }

    /// The known-GB fixture address used by `maxminddb`'s own upstream tests
    /// against this same `GeoIP2-Country-Test.mmdb` file (`reader_test.rs`'s
    /// `test_within` — `81.2.69.142/31` inside this address's containing
    /// `81.2.69.128/26` network resolves to London/GB) - reusing a
    /// known-good ground-truth pair rather than trusting an assumed country
    /// for a second address, same precedent `country_finds_the_known_
    /// fixture_address` above already established for the SE one.
    fn gb_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(81, 2, 69, 160))
    }

    #[test]
    fn blocking_country_reports_the_first_matching_ips_country_when_two_ips_match_different_countries(
    ) {
        let reader = open_fixture();
        // blocked_countries lists GB before SE, but the IP order is what
        // decides - proves the "first matching IP wins" semantic documented
        // on blocking_country's own doc comment isn't just alphabetical or
        // list-order coincidence.
        let blocked = ["GB".to_string(), "SE".to_string()];
        assert_eq!(
            blocking_country(Some(&reader), &blocked, &[se_ip(), gb_ip()]),
            Some("SE".to_string())
        );
        assert_eq!(
            blocking_country(Some(&reader), &blocked, &[gb_ip(), se_ip()]),
            Some("GB".to_string())
        );
    }
}
