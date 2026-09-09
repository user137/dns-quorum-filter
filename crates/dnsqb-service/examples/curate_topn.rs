//! Фаза 4 curation tool (T-107) — **not** shipped, **not** run in CI's
//! live-gate sense. Builds the per-list availability-zone files the
//! rating-filter "bubble" (§5.3) checks a domain against: out-of-zone →
//! BLOCK, in-zone → normal pipeline. The client side (Батч 4.3) consumes
//! these files with the same TLS + `.sha256` + atomic-swap mechanism GeoIP
//! already uses (T-105).
//!
//! **This tool does no DNS.** It fetches a CrUX popularity list, normalises
//! it, and writes it out — nothing more. Hygiene (T-108) — dropping a domain
//! that a Security- or Adult-tier resolver blocks — is a **lazy, runtime**
//! job in the client, not a curation-time bulk scan: firing ~10 k DoH
//! queries at every public filtering resolver from one address, every time a
//! list is regenerated, is a good way to get that address rate-limited or
//! blocked. Instead, while the rating filter is enabled the client lets an
//! in-zone domain through the normal quorum pipeline as usual; if quorum
//! blocks it, the client removes it from its local zone set so the next
//! lookup treats it as out-of-zone too. The zone self-cleans over the ~1 k
//! sites the user actually visits, at zero extra query cost. (SPEC.md §5.3,
//! DECISIONS.md 2026-09-09.)
//!
//! **What a "list" is.** One curated file per source list:
//!
//! * a two-letter country code (`ua`, `de`, …) — the top-traffic sites of
//!   that country, from the Chrome UX Report (CrUX) per-country mirror
//!   `InternetHealthReport/crux-top-lists-country`
//!   (`data/country/<cc>/<yyyymm>.csv.gz`, columns `origin,rank`).
//! * `global` — the worldwide top sites, from `zakird/crux-top-lists`
//!   (`data/global/current.csv.gz`, same columns).
//!
//! Both are caches of the same public Google BigQuery CrUX dataset,
//! **CC BY 4.0**. `rank` is a coarse magnitude bucket (`1000` / `10000` /
//! `100000` / `1000000`), *not* an ordinal position — within a bucket the
//! order is random. So "top-N" here means "the rows in the `1000` bucket,
//! capped at N", host-only, deduplicated to the registrable domain. There is
//! no meaningful "top-100": it would be 100 arbitrary sites out of the
//! ~1000 bucket.
//!
//! **`origin` → registrable.** CrUX keys by origin (`https://www.a.co.uk`);
//! the zone matches by registrable (`a.co.uk`). Naive "last two labels"
//! fails `*.co.uk`, `*.com.ua`, `*.com.br`, so this uses a real Public
//! Suffix List: `public_suffix_list.dat` is committed next to this file,
//! pinned to `publicsuffix/list` commit
//! `3955e3ec29b94c3cca7bd4509c5f14a7c0959e26` (2026-09-08), MPL-2.0. The
//! matcher below implements the publicsuffix.org algorithm (exception rules,
//! `*` wildcards, implicit `*`); no crate is pulled in for it — the curated
//! output is a human-reviewed diff, so a wrong extraction is visible in
//! review.
//!
//! **Usage** — `cargo run --example curate_topn -- [lists=ua,de,global]
//! [n=1000] [month=YYYYMM] [out=data/topn]`. Args are prefix-tagged and
//! order-independent; a bare integer is `n`. `month` (country lists only)
//! defaults to the newest published file at or before the current system
//! month. Writes `<out>/<list>.txt` + `<out>/<list>.txt.sha256`. Fast — one
//! HTTP GET per list, no DNS.

use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

/// Pinned Public Suffix List — committed next to this file, never fetched at
/// run time. Refreshing it is a one-line change to `PSL_PINNED_COMMIT` plus a
/// re-download from the same path.
const PSL_DAT: &str = include_str!("public_suffix_list.dat");
/// `publicsuffix/list` commit the bundled `public_suffix_list.dat` was taken
/// from (2026-09-08). Recorded in every curated file's header.
const PSL_PINNED_COMMIT: &str = "3955e3ec29b94c3cca7bd4509c5f14a7c0959e26";

/// CrUX per-country mirror. `origin,rank` CSV, gzip-compressed, one file per
/// `<cc>/<yyyymm>`.
const CRUX_COUNTRY_BASE: &str =
    "https://raw.githubusercontent.com/InternetHealthReport/crux-top-lists-country/main/data/country";
/// CrUX global list. Same columns; `current.csv.gz` is always the newest
/// published month, so no month is threaded through for `global`.
const CRUX_GLOBAL_URL: &str =
    "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz";

const DEFAULT_LISTS: &[&str] = &["ua", "us", "de", "pl", "gb", "global"];
const DEFAULT_TOP_N: usize = 1000;
/// Months to walk back from the current system month looking for the newest
/// published `<yyyymm>.csv.gz` (country lists only).
const MONTH_LOOKBACK: u32 = 12;
/// Upper bound on a decompressed CrUX CSV — the global file is on the order
/// of tens of MB; this is gzip-bomb headroom, not a measured limit (same
/// discipline as `geoip_download::decompress_bounded`).
const MAX_CSV_BYTES: u64 = 256 * 1024 * 1024;
/// CrUX's coarsest (largest-traffic) rank bucket. Rows with a bucket above
/// this are the 10K / 100K / 1M buckets — outside "top sites".
const TOP_BUCKET: u64 = 1000;

struct Args {
    lists: Vec<String>,
    top_n: usize,
    month: Option<String>,
    out_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    fs::create_dir_all(&args.out_dir)?;

    let psl = Psl::parse(PSL_DAT);
    let client = reqwest::Client::new();

    let country_month = if args.lists.iter().any(|l| l != "global") {
        match &args.month {
            Some(m) => {
                println!("using caller-supplied month {m}");
                Some(m.clone())
            }
            None => Some(resolve_latest_month(&client, &args.lists).await?),
        }
    } else {
        None
    };

    let mut any_written = false;
    for list in &args.lists {
        let month_label = if list == "global" {
            "current".to_string()
        } else {
            country_month.clone().unwrap_or_default()
        };
        let url = list_url(list, &month_label);
        println!("\n=== {list} === {url}");

        let origins = match fetch_top_bucket(&client, &url, args.top_n).await {
            Ok(origins) => origins,
            Err(err) => {
                eprintln!("  {list}: skipped ({err})");
                continue;
            }
        };
        let outcome = build_list(&psl, &origins);
        let path = args.out_dir.join(format!("{list}.txt"));
        write_curated_file(&path, list, &month_label, &outcome)?;
        write_sha256_sidecar(&path)?;
        any_written = true;
        println!(
            "  {list}: {} origins -> {} registrable domains ({} skipped: no registrable) -> {}",
            outcome.origins_seen,
            outcome.unique_registrable,
            outcome.skipped_no_registrable,
            path.display(),
        );
    }

    if !any_written {
        return Err("no list could be fetched — nothing written".into());
    }
    Ok(())
}

/// Prefix-tagged, order-independent args: `lists=ua,de,global`, `n=1000`,
/// `month=202607`, `out=data/topn`; a bare integer is `n`. Anything else is
/// an error rather than a silent ignore.
fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut lists: Vec<String> = DEFAULT_LISTS.iter().map(|s| (*s).to_string()).collect();
    let mut top_n = DEFAULT_TOP_N;
    let mut month = None;
    let mut out_dir = PathBuf::from("data/topn");
    for arg in std::env::args().skip(1) {
        if let Some(rest) = arg.strip_prefix("lists=") {
            lists = rest
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_ascii_lowercase)
                .collect();
            if lists.is_empty() {
                return Err("lists= must name at least one list".into());
            }
            for l in &lists {
                if l != "global" && !(l.len() == 2 && l.chars().all(|c| c.is_ascii_alphabetic())) {
                    return Err(format!(
                        "list {l:?} is neither \"global\" nor a two-letter country code"
                    )
                    .into());
                }
            }
        } else if let Some(rest) = arg.strip_prefix("n=") {
            top_n = rest.parse()?;
        } else if let Some(rest) = arg.strip_prefix("month=") {
            if rest.len() != 6 || !rest.chars().all(|c| c.is_ascii_digit()) {
                return Err("month= must be YYYYMM".into());
            }
            month = Some(rest.to_string());
        } else if let Some(rest) = arg.strip_prefix("out=") {
            out_dir = PathBuf::from(rest);
        } else if let Ok(n) = arg.parse::<usize>() {
            top_n = n;
        } else {
            return Err(format!(
                "unrecognised arg {arg:?} (expected lists=/n=/month=/out= or a number)"
            )
            .into());
        }
    }
    if top_n == 0 {
        return Err("n must be > 0".into());
    }
    Ok(Args {
        lists,
        top_n,
        month,
        out_dir,
    })
}

fn list_url(list: &str, month: &str) -> String {
    if list == "global" {
        CRUX_GLOBAL_URL.to_string()
    } else {
        format!("{CRUX_COUNTRY_BASE}/{list}/{month}.csv.gz")
    }
}

/// Fetches one CrUX CSV, gunzips it (bounded), and returns the host part of
/// every origin whose `rank` bucket is the top (`<= TOP_BUCKET`), in file
/// order, capped at `n` rows. IP-literal and unparseable origins are
/// skipped. Deduplication to registrable happens in [`build_list`]; `n`
/// bounds *rows read from the top bucket*, matching CrUX's own "first N of
/// the 1000 bucket" granularity.
async fn fetch_top_bucket(
    client: &reqwest::Client,
    url: &str,
    n: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {} for {url}", resp.status()).into());
    }
    let gz = resp.bytes().await?;
    let mut reader = BufReader::new(GzDecoder::new(&gz[..]).take(MAX_CSV_BYTES + 1));
    let mut header = String::new();
    let mut consumed = reader.read_line(&mut header)?;

    let mut out = Vec::new();
    let mut line = String::new();
    while out.len() < n {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        consumed += read;
        if u64::try_from(consumed).unwrap_or(u64::MAX) > MAX_CSV_BYTES {
            return Err(format!("{url}: decompressed CSV exceeds the size limit").into());
        }
        let mut fields = line.trim_end().split(',');
        let origin = fields.next().unwrap_or("").trim();
        let bucket: u64 = fields
            .next()
            .unwrap_or("")
            .trim()
            .parse()
            .unwrap_or(u64::MAX);
        if bucket > TOP_BUCKET {
            break; // file is bucket-sorted ascending — nothing more is "top"
        }
        let Ok(parsed) = reqwest::Url::parse(origin) else {
            continue;
        };
        let Some(host) = parsed.host_str() else {
            continue;
        };
        let host = host.to_ascii_lowercase();
        if host.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        out.push(host);
    }
    Ok(out)
}

/// One curated list's result — the header numbers plus the sorted,
/// deduplicated registrable set.
struct ListOutcome {
    origins_seen: usize,
    unique_registrable: usize,
    skipped_no_registrable: usize,
    registrables: BTreeSet<String>,
}

/// Pure: origin hosts → sorted, deduplicated registrable domains. A host the
/// PSL yields no registrable for (it *is* a public suffix, or is malformed)
/// is counted and dropped.
fn build_list(psl: &Psl, origins: &[String]) -> ListOutcome {
    let mut registrables = BTreeSet::new();
    let mut skipped_no_registrable = 0usize;
    for host in origins {
        match psl.registrable(host) {
            Some(reg) => {
                registrables.insert(reg);
            }
            None => skipped_no_registrable += 1,
        }
    }
    ListOutcome {
        origins_seen: origins.len(),
        unique_registrable: registrables.len(),
        skipped_no_registrable,
        registrables,
    }
}

/// Walks back from the current system month, returning the first `<yyyymm>`
/// for which the first non-`global` list's file exists (a HEAD-like GET).
async fn resolve_latest_month(
    client: &reqwest::Client,
    lists: &[String],
) -> Result<String, Box<dyn Error>> {
    let probe_cc = lists
        .iter()
        .find(|l| l.as_str() != "global")
        .map_or("us", String::as_str);
    let (mut year, mut month) = current_year_month();
    for _ in 0..=MONTH_LOOKBACK {
        let ym = format!("{year:04}{month:02}");
        let url = format!("{CRUX_COUNTRY_BASE}/{probe_cc}/{ym}.csv.gz");
        if client.get(&url).send().await?.status().is_success() {
            println!("resolved newest available month: {ym} (probed via {probe_cc})");
            return Ok(ym);
        }
        if month == 1 {
            month = 12;
            year -= 1;
        } else {
            month -= 1;
        }
    }
    Err(format!(
        "no {probe_cc} CrUX file found within {MONTH_LOOKBACK} months of now — pass month=YYYYMM"
    )
    .into())
}

/// Current (year, month) from the system clock, no `chrono` dependency —
/// Howard Hinnant's `civil_from_days` on the epoch-day count.
fn current_year_month() -> (i64, i64) {
    let secs = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
    .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn write_curated_file(
    path: &std::path::Path,
    list: &str,
    month_label: &str,
    outcome: &ListOutcome,
) -> std::io::Result<()> {
    let source = if list == "global" {
        "CrUX global top bucket (Chrome UX Report, Google, CC BY 4.0) via zakird/crux-top-lists"
    } else {
        "CrUX per-country top bucket (Chrome UX Report, Google, CC BY 4.0) via InternetHealthReport/crux-top-lists-country"
    };
    let (y, m) = current_year_month();
    let mut body = format!(
        "# dns-quorum-filter — curated availability zone\n\
         # list: {list}\n\
         # source: {source}\n\
         # crux month: {month_label}   curated: {y:04}-{m:02}\n\
         # origins seen: {seen}   unique registrable: {uniq}   skipped (no registrable): {skip}\n\
         # changes: origin->registrable normalised, top (1000) bucket only. NO content\n\
         #   filtering here - the client drops a domain a Security/Adult voter blocks lazily\n\
         #   at browse time (T-108), never a bulk curation-time scan.\n\
         # PSL: publicsuffix/list @ {PSL_PINNED_COMMIT} (MPL-2.0)\n\
         #\n\
         # One registrable domain per line, sorted. Lines starting with '#' and blank lines are ignored.\n",
        seen = outcome.origins_seen,
        uniq = outcome.unique_registrable,
        skip = outcome.skipped_no_registrable,
    );
    for domain in &outcome.registrables {
        body.push_str(domain);
        body.push('\n');
    }
    fs::write(path, body)
}

fn write_sha256_sidecar(path: &std::path::Path) -> std::io::Result<()> {
    let bytes = fs::read(path)?;
    let hex: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("list.txt");
    fs::write(
        path.with_extension("txt.sha256"),
        format!("{hex}  {name}\n"),
    )
}

// ---------------------------------------------------------------------------
// Public Suffix List matcher (publicsuffix.org algorithm)
// ---------------------------------------------------------------------------

/// Parsed Public Suffix List. `rules` holds normal and `*` wildcard rules
/// verbatim (`"com"`, `"*.ck"`); `exceptions` holds `!` rules with the `!`
/// stripped (`"www.ck"`). Only the ASCII/`xn--` form of a host is looked up,
/// which is what `reqwest::Url::host_str` yields — the bundled list's Unicode
/// IDN entries are therefore not matched, and such hosts fall to the
/// implicit `*` rule (rare in a top-1000 bucket; visible in the review diff).
struct Psl {
    rules: HashSet<String>,
    exceptions: HashSet<String>,
}

impl Psl {
    fn parse(dat: &str) -> Self {
        let mut rules = HashSet::new();
        let mut exceptions = HashSet::new();
        for raw in dat.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let Some(rule) = line.split_whitespace().next() else {
                continue;
            };
            let rule = rule.to_ascii_lowercase();
            if let Some(exc) = rule.strip_prefix('!') {
                exceptions.insert(exc.to_string());
            } else {
                rules.insert(rule);
            }
        }
        Self { rules, exceptions }
    }

    /// The registrable ("registered") domain for `host` — the public suffix
    /// plus one more label — or `None` if `host` is itself a public suffix,
    /// is empty, or has an empty label.
    fn registrable(&self, host: &str) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn psl() -> Psl {
        Psl::parse(PSL_DAT)
    }

    #[test]
    fn registrable_handles_multi_label_suffixes() {
        let p = psl();
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
        let p = psl();
        // *.ck ⇒ foo.ck is a public suffix, so a.foo.ck is registrable a.foo.ck
        assert_eq!(p.registrable("a.foo.ck").as_deref(), Some("a.foo.ck"));
        // !www.ck exception ⇒ ck is the public suffix, www.ck is registrable
        assert_eq!(p.registrable("www.ck").as_deref(), Some("www.ck"));
    }

    #[test]
    fn registrable_is_none_for_a_bare_public_suffix_or_empty_input() {
        let p = psl();
        assert_eq!(p.registrable("co.uk"), None);
        assert_eq!(p.registrable("com"), None);
        assert_eq!(p.registrable(""), None);
        assert_eq!(p.registrable("."), None);
        assert_eq!(p.registrable("a..b"), None);
    }

    #[test]
    fn registrable_uses_the_implicit_star_rule_for_an_unknown_tld() {
        let p = psl();
        assert_eq!(
            p.registrable("host.example.invalidtldxyz").as_deref(),
            Some("example.invalidtldxyz")
        );
    }

    #[test]
    fn build_list_dedups_to_sorted_registrables_and_counts_skips() {
        let p = psl();
        let origins = vec![
            "www.example.com".to_string(),
            "mail.example.com".to_string(), // dup registrable
            "shop.foo.co.uk".to_string(),
            "co.uk".to_string(), // bare public suffix — skipped
            "aaa.bbb.de".to_string(),
        ];
        let out = build_list(&p, &origins);
        assert_eq!(out.origins_seen, 5);
        assert_eq!(out.skipped_no_registrable, 1);
        assert_eq!(
            out.registrables.iter().cloned().collect::<Vec<_>>(),
            ["bbb.de", "example.com", "foo.co.uk"] // sorted, deduped
        );
        assert_eq!(out.unique_registrable, 3);
    }

    #[test]
    fn list_url_routes_global_and_country_separately() {
        assert_eq!(list_url("global", "current"), CRUX_GLOBAL_URL);
        assert_eq!(
            list_url("ua", "202608"),
            format!("{CRUX_COUNTRY_BASE}/ua/202608.csv.gz")
        );
    }

    #[test]
    fn parse_args_validation_pieces() {
        assert!("13".parse::<usize>().is_ok());
        assert!("nonsense".parse::<usize>().is_err());
        let bad_month = "2026-7";
        assert!(bad_month.len() != 6 || !bad_month.chars().all(|c| c.is_ascii_digit()));
    }

    /// A curated file's header must be exactly the lines a `#`-skipping
    /// client discards, and every non-`#` line a plain registrable.
    #[test]
    fn curated_file_body_is_comments_then_bare_domains() {
        let outcome = ListOutcome {
            origins_seen: 3,
            unique_registrable: 2,
            skipped_no_registrable: 0,
            registrables: BTreeSet::from(["example.com".to_string(), "example.co.uk".to_string()]),
        };
        let dir = std::env::temp_dir().join(format!("curate_topn_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("ua.txt");
        write_curated_file(&path, "ua", "202608", &outcome).expect("write");
        write_sha256_sidecar(&path).expect("sha256");

        let text = fs::read_to_string(&path).expect("read back");
        let domains: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .collect();
        assert_eq!(domains, ["example.co.uk", "example.com"]); // sorted
        let sidecar = fs::read_to_string(path.with_extension("txt.sha256")).expect("sidecar");
        assert!(sidecar.trim_end().ends_with("  ua.txt"));
        assert_eq!(sidecar.split_whitespace().next().unwrap_or("").len(), 64);

        let _ = fs::remove_dir_all(&dir);
    }
}
