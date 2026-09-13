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
/// treated as an error for the whole source.
pub(crate) fn hash_plain_domains(body: &str, seed: &RandomState, out: &mut Vec<u64>) {
    for line in body.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        push_normalized(entry, seed, out);
    }
}

/// Streams an AdGuard/Adblock-Plus-syntax body, extracting only plain
/// network domain-anchor rules (`||domain^`, optionally followed by
/// `$options`). Everything else — comments (`!`), `[Adblock ...]` headers,
/// exception rules (`@@||domain^`, which mean "never block", the opposite
/// of what this module accumulates), and any rule with a wildcard/path/
/// alternation character inside the domain slot — is skipped. Streams
/// straight to hashes for the same reason [`hash_plain_domains`] does.
pub(crate) fn hash_adblock_domains(body: &str, seed: &RandomState, out: &mut Vec<u64>) {
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
        push_normalized(candidate, seed, out);
    }
}

/// Shared tail of both streaming parsers: normalize, hash, push. Silently
/// drops a candidate `normalize_domain` rejects — a malformed line in a
/// third-party feed must never abort the whole source (Три Б: this is
/// untrusted external input, SECURITY.md's lower-layer-safety leg).
fn push_normalized(candidate: &str, seed: &RandomState, out: &mut Vec<u64>) {
    if let Ok(domain) = normalize_domain(candidate) {
        out.push(seed.hash_one(domain));
    }
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

    use super::{
        finalize, hash_adblock_domains, hash_plain_domains, BLOCKLIST_SOURCES, MAX_BLOCKLIST_BYTES,
    };

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
        hash_plain_domains(body, &seed, &mut out);
        assert_eq!(out.len(), 2, "two real domain lines, two hashes");
    }

    #[test]
    fn hash_plain_domains_rejects_a_syntactically_invalid_line() {
        let seed = RandomState::new();
        let mut out = Vec::new();
        hash_plain_domains("not a domain\n", &seed, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn hash_plain_domains_same_domain_and_seed_hash_identically() {
        let seed = RandomState::new();
        let mut a = Vec::new();
        let mut b = Vec::new();
        hash_plain_domains("Example.COM.\n", &seed, &mut a);
        hash_plain_domains("example.com\n", &seed, &mut b);
        assert_eq!(a, b, "normalize_domain already folds case/trailing dot");
    }

    #[test]
    fn hash_plain_domains_distinct_domains_hash_differently() {
        let seed = RandomState::new();
        let mut out = Vec::new();
        hash_plain_domains("example.com\nexample.net\n", &seed, &mut out);
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
        hash_adblock_domains(body, &seed, &mut out);
        assert_eq!(
            out.len(),
            3,
            "only the three ||domain^[$opt] lines are real block rules"
        );
    }

    #[test]
    fn hash_adblock_domains_and_hash_plain_domains_agree_on_the_same_domain() {
        // Same normalized domain reached through both formats must collapse
        // to one entry after finalize() — proves cross-source dedup works
        // regardless of which source's syntax carried the domain.
        let seed = RandomState::new();
        let mut out = Vec::new();
        hash_plain_domains("shared.example\n", &seed, &mut out);
        hash_adblock_domains("||shared.example^\n", &seed, &mut out);
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
}
