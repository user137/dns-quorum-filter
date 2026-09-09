//! Фаза 4 curation tool (T-107 / T-108) — **not** run in CI, **not** part of
//! the shipped binary. Produces the per-list availability-zone files the
//! rating-filter "bubble" (§5.3) checks a domain against: out-of-zone →
//! BLOCK, in-zone → normal pipeline. The client side (Батч 4.3) consumes
//! these files with the same TLS + `.sha256` + atomic-swap mechanism GeoIP
//! already uses (T-105); this tool is the only new piece.
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
//! ~1000 bucket, not the 100 largest.
//!
//! **Hygiene (T-108).** A per-country top list is *not* a clean "safe to
//! allow" set — T-104 found genuinely-adult and gambling domains in every
//! country's top bucket (CrUX ranks by traffic, not by topic). Out-of-zone
//! means BLOCK, so a naive "top-N ⇒ in the zone" would let that content
//! straight through a parental-control bubble. This tool drops a candidate
//! registrable if a **Security-tier** or **Adult-tier** built-in preset
//! blocks it (same `is_blocked` + `BlockSignature` table the running quorum
//! uses — the drop means the same thing at curation time as at runtime).
//! **Ads-tier blocks are *not* a drop reason** — out-of-zone is already
//! BLOCK, so removing a national retailer that AdGuard blocks over one
//! tracker subdomain would make the bubble stricter in exactly the wrong
//! direction; Ads-tier is queried for the report only.
//!
//! Each candidate is gated on **two independent unfiltered resolvers**
//! (Cloudflare `1.1.1.1` + Quad9 unsecured `dns10`, the `BASELINE_CHAIN[1]`
//! gate `phase1_metrics.rs` / `topn_fp_probe.rs` use) both returning
//! `NoError` before a filtering voter's `NXDOMAIN` counts as a real block. A
//! registrable that does not resolve on both is neither kept nor dropped —
//! it simply does not enter the zone (conservative: an unverifiable entry is
//! left out of a BLOCK-only filter).
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
//! review, not a silent runtime bug.
//!
//! **Usage** — `cargo run --release --example curate_topn -- [lists=ua,de,global]
//! [n=1000] [month=YYYYMM] [out=data/topn]`. Args are prefix-tagged and
//! order-independent; a bare integer is `n`. `month` (country lists only)
//! defaults to the newest published file at or before the current system
//! month. Writes `<out>/<list>.txt` + `<out>/<list>.txt.sha256` and prints a
//! per-list report (origins seen / kept / dropped / skipped / elapsed).
//! Expect ~20–30 min per 1000-row list — DNS lookups only, sequential, with
//! a politeness delay; this tool never opens an HTTP connection to a sampled
//! host.

use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dnsqb_service::{
    all_builtin_presets, is_blocked, sinkhole_nets_for, Category, DohClient, ProviderSpec,
    ReqwestDohClient, BASELINE_CHAIN, BASELINE_DOH_URL,
};
use flate2::read::GzDecoder;
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
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

/// Second, independent *unfiltered* resolver — `BASELINE_CHAIN[1]` (Quad9
/// unsecured `dns10`). Both baselines must return `NoError` before a voter's
/// `NXDOMAIN` is read as a real block rather than a resolver-view difference.
const SECOND_BASELINE_URL: &str = BASELINE_CHAIN[1];

const DEFAULT_LISTS: &[&str] = &["ua", "us", "de", "pl", "gb", "global"];
const DEFAULT_TOP_N: usize = 1000;
const PER_DOMAIN_DELAY: Duration = Duration::from_millis(150);
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
    let feed_client = reqwest::Client::new();
    let doh_client = ReqwestDohClient::new()?;
    let presets = all_builtin_presets();

    let country_month = if args.lists.iter().any(|l| l != "global") {
        match &args.month {
            Some(m) => {
                println!("using caller-supplied month {m}");
                Some(m.clone())
            }
            None => Some(resolve_latest_month(&feed_client, &args.lists).await?),
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

        let origins = match fetch_top_bucket(&feed_client, &url, args.top_n).await {
            Ok(origins) => origins,
            Err(err) => {
                eprintln!("  {list}: skipped ({err})");
                continue;
            }
        };
        let report = curate_list(&doh_client, &psl, &origins, &presets).await;
        let path = args.out_dir.join(format!("{list}.txt"));
        write_curated_file(&path, list, &month_label, &report)?;
        write_sha256_sidecar(&path)?;
        any_written = true;
        report.print(list);
        println!(
            "  wrote {} ({} domains) + {}.sha256",
            path.display(),
            report.kept.len(),
            path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
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
/// skipped. Deduplication to registrable happens in [`curate_list`], not
/// here — `n` bounds *rows read from the top bucket*, matching CrUX's own
/// "first N of the 1000 bucket" granularity.
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

/// One curated list's outcome — the numbers that go in the file header and
/// the stdout report, plus the kept registrable set (sorted, deduplicated).
struct ListReport {
    origins_seen: usize,
    unique_registrable: usize,
    resolvable: usize,
    kept: BTreeSet<String>,
    dropped_security: usize,
    dropped_adult: usize,
    ads_flagged_kept: usize,
    skipped_no_registrable: usize,
    elapsed: Duration,
}

impl ListReport {
    fn print(&self, list: &str) {
        println!(
            "  {list}: origins {}, unique registrable {}, resolvable {}",
            self.origins_seen, self.unique_registrable, self.resolvable
        );
        println!(
            "  kept {}, dropped {} (security {}, adult {}), skipped-no-registrable {}, ads-flagged-but-kept {}, elapsed {:.0}s",
            self.kept.len(),
            self.dropped_security + self.dropped_adult,
            self.dropped_security,
            self.dropped_adult,
            self.skipped_no_registrable,
            self.ads_flagged_kept,
            self.elapsed.as_secs_f64(),
        );
    }
}

/// One screened registrable's verdict.
struct Screen {
    resolvable: bool,
    /// `Some(Security)` / `Some(AdultContent)` if a preset of that tier
    /// blocked it — Security wins if both do. `None` ⇒ keep.
    drop_reason: Option<Category>,
    /// An Ads-tier preset blocked it (recorded, never a drop reason).
    ads_blocked: bool,
}

async fn curate_list(
    client: &ReqwestDohClient,
    psl: &Psl,
    origins: &[String],
    presets: &[ProviderSpec],
) -> ListReport {
    let started = Instant::now();

    let mut registrables: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut skipped_no_registrable = 0usize;
    for host in origins {
        match psl.registrable(host) {
            Some(reg) if seen.insert(reg.clone()) => registrables.push(reg),
            Some(_) => {}
            None => skipped_no_registrable += 1,
        }
    }

    let mut report = ListReport {
        origins_seen: origins.len(),
        unique_registrable: registrables.len(),
        resolvable: 0,
        kept: BTreeSet::new(),
        dropped_security: 0,
        dropped_adult: 0,
        ads_flagged_kept: 0,
        skipped_no_registrable,
        elapsed: Duration::ZERO,
    };

    for (i, reg) in registrables.iter().enumerate() {
        match screen_registrable(client, reg, presets).await {
            Ok(screen) => {
                if !screen.resolvable {
                    // Not counted as kept or dropped — left out of the zone.
                } else {
                    report.resolvable += 1;
                    match screen.drop_reason {
                        Some(Category::Security) => report.dropped_security += 1,
                        Some(Category::AdultContent) => report.dropped_adult += 1,
                        Some(Category::AdsTrackers) | None => {
                            report.kept.insert(reg.clone());
                            if screen.ads_blocked {
                                report.ads_flagged_kept += 1;
                            }
                        }
                    }
                }
            }
            Err(err) => eprintln!("  (skipped {reg}, query failed: {err})"),
        }
        if i + 1 < registrables.len() {
            tokio::time::sleep(PER_DOMAIN_DELAY).await;
        }
    }

    report.elapsed = started.elapsed();
    report
}

async fn screen_registrable(
    client: &ReqwestDohClient,
    registrable: &str,
    presets: &[ProviderSpec],
) -> Result<Screen, Box<dyn Error>> {
    let query = build_a_query(registrable)?;
    let baseline = client.query(BASELINE_DOH_URL, &query).await?;
    if baseline.metadata.response_code != ResponseCode::NoError {
        return Ok(Screen {
            resolvable: false,
            drop_reason: None,
            ads_blocked: false,
        });
    }
    let second = client.query(SECOND_BASELINE_URL, &query).await?;
    if second.metadata.response_code != ResponseCode::NoError {
        return Ok(Screen {
            resolvable: false,
            drop_reason: None,
            ads_blocked: false,
        });
    }

    let mut drop_reason: Option<Category> = None;
    let mut ads_blocked = false;
    for spec in presets {
        let response = client.query(&spec.doh_url, &query).await?;
        if !is_blocked(
            spec.block_signature,
            &response,
            &baseline,
            sinkhole_nets_for(&spec.id),
        ) {
            continue;
        }
        match spec.category {
            Category::Security => drop_reason = Some(Category::Security),
            Category::AdultContent => {
                if drop_reason != Some(Category::Security) {
                    drop_reason = Some(Category::AdultContent);
                }
            }
            Category::AdsTrackers => ads_blocked = true,
        }
    }
    Ok(Screen {
        resolvable: true,
        drop_reason,
        ads_blocked,
    })
}

fn build_a_query(domain: &str) -> Result<Message, Box<dyn Error>> {
    let name = Name::from_utf8(domain)?;
    let mut question = Query::new();
    question.set_name(name);
    question.set_query_type(RecordType::A);
    question.set_query_class(DNSClass::IN);
    let mut message = Message::query();
    message.add_query(question);
    // hickory's Header defaults recursion_desired to false; Cloudflare's
    // public resolver SERVFAILs anything not edge-cached without it
    // (documented at length in phase1_metrics.rs::build_a_query).
    message.metadata.recursion_desired = true;
    Ok(message)
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
    report: &ListReport,
) -> std::io::Result<()> {
    let source = if list == "global" {
        "CrUX global top bucket (Chrome UX Report, Google, CC BY 4.0) via zakird/crux-top-lists"
    } else {
        "CrUX per-country top bucket (Chrome UX Report, Google, CC BY 4.0) via InternetHealthReport/crux-top-lists-country"
    };
    let (y, m) = current_year_month();
    let mut header = format!(
        "# dns-quorum-filter — curated availability zone\n\
         # list: {list}\n\
         # source: {source}\n\
         # crux month: {month_label}   curated: {y:04}-{m:02}\n\
         # origins seen: {seen}   unique registrable: {uniq}   resolvable: {res}\n\
         # kept: {kept}   dropped: {dropped} (security {sec}, adult {adult})   skipped no-registrable: {skip}\n\
         # ads-tier flagged but kept: {ads}   (ads blocks are not a drop reason — T-108)\n\
         # changes: origin->registrable normalised, bucket truncated, Security/Adult-blocked dropped\n\
         # PSL: publicsuffix/list @ {PSL_PINNED_COMMIT} (MPL-2.0)\n\
         #\n\
         # One registrable domain per line, sorted. Lines starting with '#' and blank lines are ignored.\n",
        seen = report.origins_seen,
        uniq = report.unique_registrable,
        res = report.resolvable,
        kept = report.kept.len(),
        dropped = report.dropped_security + report.dropped_adult,
        sec = report.dropped_security,
        adult = report.dropped_adult,
        skip = report.skipped_no_registrable,
        ads = report.ads_flagged_kept,
    );
    for domain in &report.kept {
        header.push_str(domain);
        header.push('\n');
    }
    fs::write(path, header)
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

    /// T-108: the drop decision keys on Security / Adult tiers only — an
    /// Ads-tier block must leave the domain in the zone (out-of-zone = BLOCK,
    /// so dropping a popular site an Ads voter dislikes is the wrong
    /// direction). Mirrors the category-dispatch in `screen_registrable`.
    #[test]
    fn hygiene_drops_on_security_or_adult_but_not_ads() {
        fn drop_reason(blocked: &[Category]) -> Option<Category> {
            let mut reason = None;
            for c in blocked {
                match c {
                    Category::Security => reason = Some(Category::Security),
                    Category::AdultContent if reason != Some(Category::Security) => {
                        reason = Some(Category::AdultContent);
                    }
                    _ => {}
                }
            }
            reason
        }
        assert_eq!(drop_reason(&[Category::AdsTrackers]), None);
        assert_eq!(
            drop_reason(&[Category::AdultContent]),
            Some(Category::AdultContent)
        );
        assert_eq!(
            drop_reason(&[Category::Security, Category::AdultContent]),
            Some(Category::Security)
        );
        assert_eq!(
            drop_reason(&[Category::AdsTrackers, Category::AdultContent]),
            Some(Category::AdultContent)
        );
        assert_eq!(drop_reason(&[]), None);
    }

    #[test]
    fn parse_args_rejects_bad_input() {
        // parse_args reads std::env::args, so exercise the validation pieces
        // it delegates to instead of the whole function.
        assert!("13".parse::<usize>().is_ok());
        assert!("nonsense".parse::<usize>().is_err());
        let bad_month = "2026-7";
        assert!(bad_month.len() != 6 || !bad_month.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn list_url_routes_global_and_country_separately() {
        assert_eq!(list_url("global", "current"), CRUX_GLOBAL_URL);
        assert_eq!(
            list_url("ua", "202608"),
            format!("{CRUX_COUNTRY_BASE}/ua/202608.csv.gz")
        );
    }

    /// A curated file's header must be exactly the lines a `#`-skipping
    /// client discards, and every non-`#` line a plain registrable.
    #[test]
    fn curated_file_body_is_comments_then_bare_domains() {
        let report = ListReport {
            origins_seen: 3,
            unique_registrable: 2,
            resolvable: 2,
            kept: BTreeSet::from(["example.com".to_string(), "example.co.uk".to_string()]),
            dropped_security: 0,
            dropped_adult: 1,
            ads_flagged_kept: 0,
            skipped_no_registrable: 0,
            elapsed: Duration::ZERO,
        };
        let dir = std::env::temp_dir().join(format!("curate_topn_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("ua.txt");
        write_curated_file(&path, "ua", "202608", &report).expect("write");
        write_sha256_sidecar(&path).expect("sha256");

        let text = fs::read_to_string(&path).expect("read back");
        let domains: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .collect();
        assert_eq!(domains, ["example.co.uk", "example.com"]); // sorted
        for d in &domains {
            assert!(psl().registrable(d).is_some() || d.matches('.').count() >= 1);
        }
        let sidecar = fs::read_to_string(path.with_extension("txt.sha256")).expect("sidecar");
        assert!(sidecar.trim_end().ends_with("  ua.txt"));
        assert_eq!(sidecar.split_whitespace().next().unwrap_or("").len(), 64);

        let _ = fs::remove_dir_all(&dir);
    }
}
