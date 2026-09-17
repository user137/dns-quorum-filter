//! Pure helpers for the public blocklist-bundle core (T-218, Фаза 7): source
//! table, streaming parse-and-hash for the two published formats (plain
//! domain lists and the `AdGuard` adblock-syntax subset), and the final
//! sort+dedup pass. Kept separate from the network/orchestration module
//! (`blocklist_updater`, Батч 7.2 — the sole caller of everything below) —
//! same split as [`crate::topn_download`] / [`crate::topn_updater`].
//!
//! **Why hashes, not domain strings (DECISIONS.md 2026-09-13).** The eight
//! source URLs total ~111 MB — `HaGeZi` TIF/NRD/DGA alone are tens of MB each,
//! an estimated several million unique domains combined. Storing raw
//! `String`s in a `HashSet` would cost hundreds of MB resident and
//! double-allocate every domain during parse. Each domain is instead
//! reduced to a `u64` via a per-build `RandomState` (`std`, no new
//! dependency) and accumulated into a sorted, deduplicated `Vec<u64>` (Батч
//! 7.2 builds and atomically swaps this) — `O(log n)` binary-search lookups,
//! ~44 MB resident for ~5.5M entries instead of ~136 MB for an equivalent
//! `HashSet<u128>`. The hash is **never persisted** — raw text is what gets
//! written to disk and re-parsed at startup (the same pattern
//! `topn_updater`/`geoip_updater` already use for their own sources), so
//! hash-function stability across Rust versions is a non-issue; the
//! `RandomState` seed lives alongside the `Vec<u64>` it built and always
//! travels with it through the same `Arc` swap, so a lookup can never use a
//! seed mismatched to the set it's searching.

use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::hash::BuildHasher;

use crate::normalize_domain;

/// Text-body format a source publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceFormat {
    /// One domain per line, `#`-comments and blank lines skipped — the same
    /// convention [`crate::topn_download::parse_list`] reads, but streamed
    /// here instead of materialized into a `Vec<String>` first (module doc).
    PlainDomain,
    /// AdGuard/Adblock-Plus network-rule subset: `||domain^[$options]`
    /// lines only. Comments (`!`), `[Adblock ...]` header directives,
    /// exception rules (`@@...`), and anything not shaped like a plain
    /// domain-anchor rule are skipped, never treated as a block.
    AdblockNetRules,
}

/// One published blocklist-bundle source (T-218 kickoff → this batch's
/// primary-source verification, 2026-09-13 — `data/blocklists/
/// CANDIDATES.md` §3, DECISIONS.md). 7 logical sources / 8 URLs: `nrd`/`dga`
/// share `group` `"hagezi-nrd-dga"` (two URLs from the sibling `hagezi/nrd`
/// repository — GPL-3.0, verified separately from `hagezi/dns-blocklists` —
/// merged into one logical source for status/UI purposes).
///
/// `HaGeZi`'s "Most Abused TLDs" list was evaluated and deliberately excluded
/// from this table: its entries are bare TLDs, so through the same
/// suffix-walk this module feeds, one 4.4 KB source would block more of the
/// internet than the other seven combined — and it duplicates TASKS.md
/// T-115/T-116's ccTLD-block (§5.2, Фаза 5, "порожній за замовчуванням")
/// through a different, default-on door. It remains a candidate *data
/// source* for that future feature, not this one.
pub(crate) struct BlocklistSource {
    pub(crate) id: &'static str,
    pub(crate) group: &'static str,
    pub(crate) url: &'static str,
    pub(crate) format: SourceFormat,
}

pub(crate) const BLOCKLIST_SOURCES: &[BlocklistSource] = &[
    BlocklistSource {
        id: "hagezi-multi-pro",
        group: "hagezi-multi-pro",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        format: SourceFormat::PlainDomain,
    },
    BlocklistSource {
        id: "hagezi-tif",
        group: "hagezi-tif",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
        format: SourceFormat::PlainDomain,
    },
    BlocklistSource {
        id: "hagezi-nrd",
        group: "hagezi-nrd-dga",
        url: "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt",
        format: SourceFormat::PlainDomain,
    },
    BlocklistSource {
        id: "hagezi-dga",
        group: "hagezi-nrd-dga",
        url: "https://raw.githubusercontent.com/hagezi/nrd/main/domains/dga7.txt",
        format: SourceFormat::PlainDomain,
    },
    BlocklistSource {
        id: "hagezi-dyndns",
        group: "hagezi-dyndns",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
        format: SourceFormat::PlainDomain,
    },
    BlocklistSource {
        id: "hagezi-hoster",
        group: "hagezi-hoster",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/hoster-onlydomains.txt",
        format: SourceFormat::PlainDomain,
    },
    BlocklistSource {
        id: "adguard-dns-filter",
        group: "adguard-dns-filter",
        url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        format: SourceFormat::AdblockNetRules,
    },
    BlocklistSource {
        id: "1hosts-lite",
        group: "1hosts-lite",
        url: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt",
        format: SourceFormat::PlainDomain,
    },
];

/// Upper bound on one source's download (Батч 7.2 enforces this against the
/// live response, this module never fetches). `HaGeZi`'s NRD feed alone is
/// ~49 MB today and swings with daily registration volume — 128 MB is
/// headroom over that, not a measured steady-state size (same spirit as
/// `topn_download::MAX_TOPN_BYTES`, scaled up for this class of source).
pub(crate) const MAX_BLOCKLIST_BYTES: u64 = 128 * 1024 * 1024;

/// Streams a plain-domain-list body straight into hashes — no intermediate
/// `Vec<String>` (module doc: at `HaGeZi` TIF/NRD scale that would
/// double-allocate millions of `String`s per refresh). Each candidate line
/// goes through [`crate::normalize_domain`] (the same IDNA2008/
/// hickory-proto path query parsing and override-list matching already use)
/// before being hashed; a syntactically invalid line is skipped, never
/// treated as an error for the whole source. `candidates` counts every line
/// actually handed to `normalize_domain` (blank/`#`-comment lines don't
/// count — they were never candidates) — the denominator
/// [`validate_hashes`]'s parse-success-ratio check divides by (T-233).
pub(crate) fn hash_plain_domains(
    body: &str,
    seed: &RandomState,
    out: &mut Vec<u64>,
    candidates: &mut usize,
) {
    for line in body.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        push_normalized(entry, seed, out, candidates);
    }
}

/// Streams an AdGuard/Adblock-Plus-syntax body, extracting only plain
/// network domain-anchor rules (`||domain^`, optionally followed by
/// `$options`). Everything else — comments (`!`), `[Adblock ...]` headers,
/// exception rules (`@@||domain^`, which mean "never block", the opposite
/// of what this module accumulates), and any rule with a wildcard/path/
/// alternation character inside the domain slot — is skipped. Streams
/// straight to hashes for the same reason [`hash_plain_domains`] does.
/// `candidates` — see [`hash_plain_domains`]'s own doc; here it counts only
/// lines that reach the `||domain^` extraction (a comment/header/exception/
/// cosmetic line was never a domain candidate to begin with).
pub(crate) fn hash_adblock_domains(
    body: &str,
    seed: &RandomState,
    out: &mut Vec<u64>,
    candidates: &mut usize,
) {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        if line.starts_with("@@") {
            continue; // exception rule — never a block, regardless of shape
        }
        let Some(rest) = line.strip_prefix("||") else {
            continue; // not a network domain-anchor rule (cosmetic, etc.)
        };
        let Some(anchor) = rest.find('^') else {
            continue; // unanchored — not the plain-domain shape this reads
        };
        let candidate = &rest[..anchor];
        if candidate.is_empty() || candidate.contains(['/', '*', '|']) {
            continue; // path/wildcard/alternation rule, not a bare domain anchor
        }
        push_normalized(candidate, seed, out, candidates);
    }
}

/// Shared tail of both streaming parsers: normalize, hash, push. Silently
/// drops a candidate `normalize_domain` rejects — a malformed line in a
/// third-party feed must never abort the whole source (Три Б: this is
/// untrusted external input, SECURITY.md's lower-layer-safety leg). Always
/// counts the attempt in `candidates`, whether or not `normalize_domain`
/// accepted it.
fn push_normalized(
    candidate: &str,
    seed: &RandomState,
    out: &mut Vec<u64>,
    candidates: &mut usize,
) {
    *candidates += 1;
    if let Ok(domain) = normalize_domain(candidate) {
        out.push(seed.hash_one(domain));
    }
}

/// One published source failed the runtime integrity gate (T-233) — a
/// compromised or corrupted upstream feed must never silently join the
/// bundle (Три Б user-safety: over-blocking a legitimate namespace is worse
/// than no filtering at all). Carries enough detail for
/// `blocklist_updater::BlocklistRefreshError`'s matching variants (a private
/// type in another module, hence no intra-doc link here) and for a future
/// status-view field, without this pure module knowing anything about that
/// DTO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValidationFailure {
    /// Too few candidate lines actually normalized into a domain — most
    /// likely the source now serves something other than its published
    /// format (an HTML error/rate-limit page, a moved/renamed file).
    LowParseSuccessRatio { accepted: usize, candidates: usize },
    /// At least [`MIN_CANARY_HITS_TO_REJECT`] of [`BLOCKLIST_CANARY_DOMAINS`]
    /// appear as an **exact** entry in this source's freshly-hashed set —
    /// real ad/malware/NRD/DGA lists structurally don't do this (calibrated
    /// against the real 2026-09-17 download: zero exact-line hits across all
    /// eight sources for this same canary set).
    CanaryDomainsPresent { count: usize },
    /// The entry count shifted far outside [`MAX_COUNT_GROWTH_MULTIPLIER`]/
    /// [`MIN_COUNT_RETENTION_DIVISOR`] of the last successful cycle's count —
    /// catches wholesale replacement or truncation of a source. **Does not**
    /// catch injecting a small number of legitimate domains into a large
    /// list (T-233's own primary threat model) — that stays
    /// `CanaryDomainsPresent`'s job alone (a sibling variant, no intra-doc
    /// link across enum variants); see [`delta_verdict`]'s own doc for the
    /// numbers that prove this bound is too coarse for that class.
    SuspiciousCountDelta { previous: usize, current: usize },
}

/// Compiled-in, category-diverse set of globally popular domains no
/// legitimate ad/malware/tracker/NRD/DGA list should ever contain as an
/// **exact** entry (a subdomain like `ads.doubleclick.net` is a different,
/// unrelated domain under a different apex — this only ever tests the apex
/// strings below). Deliberately **not** sourced from `data/topn/global.txt`
/// — that file only exists on disk once `[rating_filter].enabled = true`
/// (default OFF; verified absent on a real install with the bubble off,
/// 2026-09-17), so a canary tied to it would be silently inert on a typical
/// install. Verified against the real ~122 MB of downloaded source text
/// (2026-09-17, `%LOCALAPPDATA%/dns-quorum-filter/blocklists/`): zero
/// exact-line matches for any of these across all eight sources.
pub(crate) const BLOCKLIST_CANARY_DOMAINS: &[&str] = &[
    "google.com",
    "cloudflare.com",
    "amazonaws.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "wikipedia.org",
    "facebook.com",
    "youtube.com",
    "letsencrypt.org",
    "fastly.net",
    "akamai.net",
];

/// At least this many [`BLOCKLIST_CANARY_DOMAINS`] must appear before a
/// source is rejected — not `1`, so a single coincidental/legitimate overlap
/// doesn't reject an otherwise-healthy source (advisor review: no canary in
/// this set has ever hit any real source, so `1` would already be safe
/// today, but `2` costs nothing and removes the single-point-of-failure).
pub(crate) const MIN_CANARY_HITS_TO_REJECT: usize = 2;

/// Below this fraction of candidate lines actually becoming a hashed domain,
/// a source is rejected as format-confused (T-233). Deliberately far below
/// the real measured floor — 0.5 leaves roughly 48 points of headroom under
/// the worst real source measured 2026-09-17 (`adguard-dns-filter.txt`,
/// adblock format, ~98.6%; every plain-domain source measured ~99.99%+) —
/// this is a "the source is clearly not what it claims to be" trip wire, not
/// a tight quality bar.
pub(crate) const MIN_PARSE_SUCCESS_RATIO: f64 = 0.5;

/// Runs both T-233 gates over one source's freshly-computed hash set.
/// `candidates == 0` (an empty body) skips the ratio check — an empty
/// source is inert, not evidence of tampering. Pure, no I/O — the caller
/// (`blocklist_updater::write_and_hash_blocking`) decides what to do with a
/// rejection (module's own doc: keep-last-known-good, never persist the
/// rejected content).
pub(crate) fn validate_hashes(
    hashes: &[u64],
    candidates: usize,
    seed: &RandomState,
) -> Result<(), ValidationFailure> {
    if candidates > 0 {
        // `candidates` is bounded by MAX_BLOCKLIST_BYTES / shortest possible
        // line (~tens of millions at most) — nowhere near f64's 2^52 exact-
        // integer ceiling, so this cast never loses precision in practice.
        #[allow(clippy::cast_precision_loss)]
        let ratio = hashes.len() as f64 / candidates as f64;
        if ratio < MIN_PARSE_SUCCESS_RATIO {
            return Err(ValidationFailure::LowParseSuccessRatio {
                accepted: hashes.len(),
                candidates,
            });
        }
    }
    let canary_hashes: HashSet<u64> = BLOCKLIST_CANARY_DOMAINS
        .iter()
        .filter_map(|d| normalize_domain(d).ok())
        .map(|d| seed.hash_one(d))
        .collect();
    let hits = hashes.iter().filter(|h| canary_hashes.contains(h)).count();
    if hits >= MIN_CANARY_HITS_TO_REJECT {
        return Err(ValidationFailure::CanaryDomainsPresent { count: hits });
    }
    Ok(())
}

/// Below this many entries in the *previous* successful cycle, the delta
/// check is skipped entirely — a source this small has no statistically
/// meaningful baseline (advisor review: the real measured sizes of the
/// eight sources span ~2500× — 1,251 for `hagezi-hoster` to 3,181,194 for
/// `hagezi-nrd`, 2026-09-17 — so one global relative threshold is honest
/// only above a floor; `hagezi-hoster`/`hagezi-dyndns` sit below it today
/// and simply never get delta protection, same as [`MIN_PARSE_SUCCESS_RATIO`]'s
/// `candidates == 0` skip).
pub(crate) const MIN_COUNT_BASELINE: usize = 5000;

/// Reject if the current count is more than this many times the previous
/// successful count — catches a source suddenly padded with a large volume
/// of new entries. Deliberately wide (module doc on [`delta_verdict`]): no
/// multi-day history exists to calibrate a tighter number against.
pub(crate) const MAX_COUNT_GROWTH_MULTIPLIER: usize = 5;

/// Reject if the current count drops below `previous / MIN_COUNT_RETENTION_DIVISOR`
/// (i.e. more than an 80% drop) — catches a source replaced with a much
/// smaller one. Expressed as a divisor, not a `f64` ratio, so the check is
/// plain integer comparison (no `usize as f64` cast — part 1 already needed
/// one `#[allow(clippy::cast_precision_loss)]`, this design avoids a second).
pub(crate) const MIN_COUNT_RETENTION_DIVISOR: usize = 5;

/// A previous successful count older than this is treated as no baseline at
/// all — a source that silently failed or was disabled for longer than this
/// and then recovers must not have its first fresh cycle read as
/// compromise (user requirement, 2026-09-17: the check must weight by
/// elapsed time since the last success, not raw magnitude alone).
// `Duration::from_days` isn't const-stable yet (unlike `from_hours`,
// already used elsewhere in this crate) — spelled out in hours instead.
pub(crate) const DELTA_CHECK_GRACE_PERIOD: std::time::Duration =
    std::time::Duration::from_hours(7 * 24);

/// T-233 part 2: verdict for the entry-count delta gate. Owns every
/// decision (floor, grace period, multiplier bounds) so it's testable with
/// no filesystem and no real clock — the impure caller
/// (`blocklist_updater::write_and_hash_blocking`) only reads `<id>.count`,
/// parses it, computes `elapsed`, and hands over `previous` as `None` when
/// any of that fails (missing file, unparseable content, or
/// `SystemTime::duration_since` returning `Err` on a clock jump / restored
/// snapshot — same "no reliable baseline" conclusion either way, the same
/// fail-open spirit as `personal_zone_stats::DayIndex`'s saturating
/// arithmetic).
///
/// **Scope, stated plainly:** this catches wholesale replacement or
/// truncation of a source, not injecting a small number of legitimate
/// domains into a large one — T-233's own primary threat model. Example:
/// 1,000 injected domains into `hagezi-nrd`'s measured 3,181,194 entries is
/// a 0.03% delta, far inside any threshold wide enough to tolerate this
/// source's own day-to-day registration volume. That class stays
/// [`ValidationFailure::CanaryDomainsPresent`]'s job alone (KNOWN-LIMITATIONS.md
/// has the full accounting).
///
/// **A second, indirect consequence of the grace period (advisor review,
/// not a separate escape hatch — the same one line of logic already
/// covers it):** `<id>.count` only advances on a *successful* cycle
/// (`blocklist_updater::write_new_count`), so a source under sustained
/// rejection (every cycle fails the ratio/canary/delta gate) leaves its
/// mtime frozen at the last real success. After [`DELTA_CHECK_GRACE_PERIOD`]
/// of that, the delta gate self-disables for this source — the next cycle
/// that clears ratio+canary is accepted unconditionally and becomes the new
/// baseline, however different it is from before. This is the same
/// time-weighting the user asked for, not a bug: a genuinely-recovering
/// source and a persistently-failing one look identical from `<id>.count`'s
/// mtime alone, and the design deliberately doesn't try to tell them apart.
pub(crate) fn delta_verdict(
    current: usize,
    previous: Option<(usize, std::time::Duration)>,
) -> Result<(), ValidationFailure> {
    let Some((previous_count, elapsed)) = previous else {
        return Ok(());
    };
    if previous_count < MIN_COUNT_BASELINE {
        return Ok(());
    }
    if elapsed > DELTA_CHECK_GRACE_PERIOD {
        return Ok(());
    }
    let grew_too_much = current > previous_count.saturating_mul(MAX_COUNT_GROWTH_MULTIPLIER);
    let shrank_too_much = current.saturating_mul(MIN_COUNT_RETENTION_DIVISOR) < previous_count;
    if grew_too_much || shrank_too_much {
        return Err(ValidationFailure::SuspiciousCountDelta {
            previous: previous_count,
            current,
        });
    }
    Ok(())
}

/// Sorts and deduplicates an accumulated hash buffer in place — the single
/// pass Батч 7.2 runs once over the combined output of every source, not
/// per-source (module doc: this is what makes cross-source domain overlap
/// collapse into one entry instead of being stored once per source).
pub(crate) fn finalize(hashes: &mut Vec<u64>) {
    hashes.sort_unstable();
    hashes.dedup();
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::RandomState;
    use std::collections::HashSet;
    use std::hash::BuildHasher;

    use super::{
        delta_verdict, finalize, hash_adblock_domains, hash_plain_domains, validate_hashes,
        ValidationFailure, BLOCKLIST_CANARY_DOMAINS, BLOCKLIST_SOURCES, DELTA_CHECK_GRACE_PERIOD,
        MAX_BLOCKLIST_BYTES, MAX_COUNT_GROWTH_MULTIPLIER, MIN_CANARY_HITS_TO_REJECT,
        MIN_COUNT_BASELINE, MIN_COUNT_RETENTION_DIVISOR, MIN_PARSE_SUCCESS_RATIO,
    };
    use crate::normalize_domain;
    use std::time::Duration;

    #[test]
    fn blocklist_sources_have_unique_https_ids() {
        assert_eq!(BLOCKLIST_SOURCES.len(), 8);
        let ids: HashSet<&str> = BLOCKLIST_SOURCES.iter().map(|s| s.id).collect();
        assert_eq!(ids.len(), BLOCKLIST_SOURCES.len(), "duplicate source id");
        for source in BLOCKLIST_SOURCES {
            assert!(
                source.url.starts_with("https://"),
                "{} url is not https",
                source.id
            );
        }
    }

    #[test]
    fn max_blocklist_bytes_covers_the_largest_known_source() {
        // HaGeZi's nrd7.txt measured ~49 MB (2026-09-13, HTTP HEAD) — the
        // cap must clear that with real headroom, not sit right at it.
        const { assert!(MAX_BLOCKLIST_BYTES > 49 * 1024 * 1024) };
    }

    #[test]
    fn hash_plain_domains_skips_comments_and_blanks() {
        let body = "# HaGeZi's Multi PRO\n\
                    \n\
                    example.com\n\
                    # trailing comment\n\
                    ads.example.net\n";
        let seed = RandomState::new();
        let mut out = Vec::new();
        let mut candidates = 0;
        hash_plain_domains(body, &seed, &mut out, &mut candidates);
        assert_eq!(out.len(), 2, "two real domain lines, two hashes");
        assert_eq!(candidates, 2, "blank/#-comment lines are never candidates");
    }

    #[test]
    fn hash_plain_domains_rejects_a_syntactically_invalid_line() {
        let seed = RandomState::new();
        let mut out = Vec::new();
        let mut candidates = 0;
        hash_plain_domains("not a domain\n", &seed, &mut out, &mut candidates);
        assert!(out.is_empty());
        assert_eq!(
            candidates, 1,
            "the line was a candidate even though it was rejected"
        );
    }

    #[test]
    fn hash_plain_domains_same_domain_and_seed_hash_identically() {
        let seed = RandomState::new();
        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut candidates = 0;
        hash_plain_domains("Example.COM.\n", &seed, &mut a, &mut candidates);
        hash_plain_domains("example.com\n", &seed, &mut b, &mut candidates);
        assert_eq!(a, b, "normalize_domain already folds case/trailing dot");
    }

    #[test]
    fn hash_plain_domains_distinct_domains_hash_differently() {
        let seed = RandomState::new();
        let mut out = Vec::new();
        let mut candidates = 0;
        hash_plain_domains(
            "example.com\nexample.net\n",
            &seed,
            &mut out,
            &mut candidates,
        );
        assert_ne!(out[0], out[1]);
    }

    #[test]
    fn hash_adblock_domains_extracts_only_plain_network_rules() {
        // Real lines captured 2026-09-13 from
        // adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt plus a
        // synthesized exception/options/cosmetic set covering the shapes
        // that file's own comments say are deliberately excluded elsewhere.
        let body = "! Title: AdGuard DNS filter\n\
                    !\n\
                    [Adblock Plus 2.0]\n\
                    ||xml.pops.gg^\n\
                    ||nyhizyjybawozi.com^\n\
                    ||doubleclick.net^$third-party\n\
                    @@||allowed.example^\n\
                    ||example.com/path*\n\
                    ||*.wildcard.example^\n\
                    example.com##.banner\n";
        let seed = RandomState::new();
        let mut out = Vec::new();
        let mut candidates = 0;
        hash_adblock_domains(body, &seed, &mut out, &mut candidates);
        assert_eq!(
            out.len(),
            3,
            "only the three ||domain^[$opt] lines are real block rules"
        );
        assert_eq!(
            candidates, 3,
            "comments/headers/exceptions/cosmetic lines were never candidates"
        );
    }

    #[test]
    fn hash_adblock_domains_and_hash_plain_domains_agree_on_the_same_domain() {
        // Same normalized domain reached through both formats must collapse
        // to one entry after finalize() — proves cross-source dedup works
        // regardless of which source's syntax carried the domain.
        let seed = RandomState::new();
        let mut out = Vec::new();
        let mut candidates = 0;
        hash_plain_domains("shared.example\n", &seed, &mut out, &mut candidates);
        hash_adblock_domains("||shared.example^\n", &seed, &mut out, &mut candidates);
        assert_eq!(out[0], out[1]);
        finalize(&mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn finalize_sorts_and_dedups() {
        let mut hashes = vec![5u64, 1, 3, 1, 5, 2];
        finalize(&mut hashes);
        assert_eq!(hashes, vec![1, 2, 3, 5]);
    }

    #[test]
    fn finalize_on_empty_stays_empty() {
        let mut hashes: Vec<u64> = Vec::new();
        finalize(&mut hashes);
        assert!(hashes.is_empty());
    }

    // --- validate_hashes (T-233) ---

    fn hash_all<'a>(entries: impl IntoIterator<Item = &'a str>, seed: &RandomState) -> Vec<u64> {
        entries
            .into_iter()
            .filter_map(|d| normalize_domain(d).ok())
            .map(|d| seed.hash_one(d))
            .collect()
    }

    #[test]
    fn validate_hashes_happy_path_accepts_a_normal_source() {
        // Real-shaped fragment: comments/blanks already excluded from
        // `candidates` upstream, every candidate here is a real domain.
        let seed = RandomState::new();
        let mut out = Vec::new();
        let mut candidates = 0;
        hash_plain_domains(
            "# HaGeZi's Multi PRO\nexample.com\nads.example.net\ntracker.example.org\n",
            &seed,
            &mut out,
            &mut candidates,
        );
        assert!(validate_hashes(&out, candidates, &seed).is_ok());
    }

    #[test]
    fn validate_hashes_rejects_below_the_ratio_floor() {
        let seed = RandomState::new();
        // 1 accepted out of 3 candidates = 1/3, below MIN_PARSE_SUCCESS_RATIO.
        let hashes = hash_all(["example.com"], &seed);
        let Err(err) = validate_hashes(&hashes, 3, &seed) else {
            panic!("1/3 candidates parsing must reject");
        };
        assert_eq!(
            err,
            ValidationFailure::LowParseSuccessRatio {
                accepted: 1,
                candidates: 3
            }
        );
    }

    #[test]
    fn validate_hashes_accepts_exactly_at_the_ratio_floor() {
        let seed = RandomState::new();
        // 1 accepted out of 2 candidates = 0.5 == MIN_PARSE_SUCCESS_RATIO —
        // the boundary itself must not reject (`<`, not `<=`, in the gate).
        assert!((MIN_PARSE_SUCCESS_RATIO - 0.5).abs() < f64::EPSILON);
        let hashes = hash_all(["example.com"], &seed);
        assert!(validate_hashes(&hashes, 2, &seed).is_ok());
    }

    #[test]
    fn validate_hashes_skips_the_ratio_check_on_zero_candidates() {
        // An empty source is inert, not evidence of tampering — must not
        // divide by zero or reject.
        let seed = RandomState::new();
        assert!(validate_hashes(&[], 0, &seed).is_ok());
    }

    #[test]
    fn validate_hashes_html_error_page_trips_the_ratio_gate() {
        // Synthetic "the feed now serves an HTML error/rate-limit page"
        // body — none of these lines are valid domains.
        let seed = RandomState::new();
        let mut out = Vec::new();
        let mut candidates = 0;
        hash_plain_domains(
            "<html>\n<body>429 Too Many Requests</body>\n</html>\n",
            &seed,
            &mut out,
            &mut candidates,
        );
        assert!(matches!(
            validate_hashes(&out, candidates, &seed),
            Err(ValidationFailure::LowParseSuccessRatio { .. })
        ));
    }

    #[test]
    fn validate_hashes_accepts_one_canary_below_the_reject_threshold() {
        assert_eq!(MIN_CANARY_HITS_TO_REJECT, 2);
        let seed = RandomState::new();
        let mut hashes = hash_all(["real-malware-domain.example"], &seed);
        hashes.extend(hash_all([BLOCKLIST_CANARY_DOMAINS[0]], &seed));
        assert!(
            validate_hashes(&hashes, hashes.len(), &seed).is_ok(),
            "a single coincidental canary hit must not reject the source"
        );
    }

    #[test]
    fn validate_hashes_rejects_at_exactly_the_canary_threshold() {
        let seed = RandomState::new();
        let mut hashes = hash_all(["real-malware-domain.example"], &seed);
        hashes.extend(hash_all(
            BLOCKLIST_CANARY_DOMAINS[..MIN_CANARY_HITS_TO_REJECT]
                .iter()
                .copied(),
            &seed,
        ));
        let Err(err) = validate_hashes(&hashes, hashes.len(), &seed) else {
            panic!("MIN_CANARY_HITS_TO_REJECT canaries must reject");
        };
        assert_eq!(
            err,
            ValidationFailure::CanaryDomainsPresent {
                count: MIN_CANARY_HITS_TO_REJECT
            }
        );
    }

    #[test]
    fn validate_hashes_a_legitimate_padded_list_with_two_canaries_is_rejected() {
        // Misuse/fool: a mostly-real list with a small injected legitimate-
        // domain payload — must not slip past on volume alone.
        let seed = RandomState::new();
        let mut out = Vec::new();
        let mut candidates = 0;
        hash_plain_domains(
            "real-ads-1.example\nreal-ads-2.example\nreal-ads-3.example\n\
             google.com\ncloudflare.com\n",
            &seed,
            &mut out,
            &mut candidates,
        );
        assert!(matches!(
            validate_hashes(&out, candidates, &seed),
            Err(ValidationFailure::CanaryDomainsPresent { count: 2 })
        ));
    }

    // --- delta_verdict (T-233 part 2) ---

    #[test]
    fn delta_verdict_accepts_a_normal_fluctuation() {
        assert!(delta_verdict(105_000, Some((100_000, Duration::from_secs(60)))).is_ok());
        assert!(delta_verdict(95_000, Some((100_000, Duration::from_secs(60)))).is_ok());
    }

    #[test]
    fn delta_verdict_has_no_previous_cycle_to_compare_against() {
        // First-ever successful fetch of a source — nothing to compare, must
        // not reject.
        assert!(delta_verdict(100_000, None).is_ok());
    }

    #[test]
    fn delta_verdict_skips_sources_below_the_baseline_floor() {
        // Real hagezi-hoster/hagezi-dyndns sizes (1,251/1,547, 2026-09-17)
        // sit below MIN_COUNT_BASELINE — a 100x jump on a source this small
        // must still pass, there is no meaningful baseline yet.
        let previous = MIN_COUNT_BASELINE - 1;
        assert!(delta_verdict(previous * 100, Some((previous, Duration::from_secs(60)))).is_ok());
    }

    #[test]
    fn delta_verdict_rejects_just_past_the_growth_multiplier() {
        let previous = MIN_COUNT_BASELINE * 2;
        let current = previous * MAX_COUNT_GROWTH_MULTIPLIER + 1;
        let Err(err) = delta_verdict(current, Some((previous, Duration::from_secs(60)))) else {
            panic!("growth just past the multiplier must reject");
        };
        assert_eq!(
            err,
            ValidationFailure::SuspiciousCountDelta { previous, current }
        );
        // One entry short of the same bound must still pass.
        assert!(delta_verdict(
            previous * MAX_COUNT_GROWTH_MULTIPLIER,
            Some((previous, Duration::from_secs(60)))
        )
        .is_ok());
    }

    #[test]
    fn delta_verdict_rejects_just_past_the_retention_divisor() {
        let previous = MIN_COUNT_BASELINE * 10;
        let current = previous / MIN_COUNT_RETENTION_DIVISOR - 1;
        let Err(err) = delta_verdict(current, Some((previous, Duration::from_secs(60)))) else {
            panic!("a drop just past the retention divisor must reject");
        };
        assert_eq!(
            err,
            ValidationFailure::SuspiciousCountDelta { previous, current }
        );
        // Exactly at the divisor must still pass.
        assert!(delta_verdict(
            previous / MIN_COUNT_RETENTION_DIVISOR,
            Some((previous, Duration::from_secs(60)))
        )
        .is_ok());
    }

    #[test]
    fn delta_verdict_skips_the_check_past_the_grace_period() {
        let previous = MIN_COUNT_BASELINE * 10;
        // A 10x jump would normally reject, but a >7-day-old baseline means
        // "no reliable comparison point" — the user's own time-weighting
        // requirement.
        let stale = DELTA_CHECK_GRACE_PERIOD + Duration::from_secs(1);
        assert!(delta_verdict(previous * 10, Some((previous, stale))).is_ok());
    }

    #[test]
    fn delta_verdict_still_applies_exactly_at_the_grace_period_boundary() {
        let previous = MIN_COUNT_BASELINE * 10;
        let current = previous * MAX_COUNT_GROWTH_MULTIPLIER + 1;
        assert!(
            matches!(
                delta_verdict(current, Some((previous, DELTA_CHECK_GRACE_PERIOD))),
                Err(ValidationFailure::SuspiciousCountDelta { .. })
            ),
            "exactly at the grace period, the check must still apply"
        );
    }
}
