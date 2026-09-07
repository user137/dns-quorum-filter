//! Manual Фаза 4 metric probe (T-104) — **not** run in CI, **not** part of the
//! shipped binary. One question:
//!
//! > How often do the Ads/Adult-category voters block a domain that sits in
//! > the **top-N of a country's traffic**?
//!
//! **History.** This began as the gate for SPEC.md §5.1 (top-N domains exempt
//! from the Ads/Adult voters). §5.1 was removed on 2026-09-07 (T-179,
//! DECISIONS.md) — the top-sites mechanism is now a single opt-in "bubble"
//! (the rating filter, §5.3): out-of-zone → BLOCK, in-zone → normal pipeline.
//! The run still matters, but as **input to the bubble's zone design**, not as
//! a voter-scope gate. Its central finding: a per-country top-N list is *not*
//! a clean "legitimate traffic" set — every country's top-75 here contained
//! multiple genuinely-adult and gambling domains (CrUX ranks by traffic, not
//! by topic). So a naive "top-N ⇒ allowed zone" would let adult/gambling
//! content straight through a parental-control bubble; the curated zone needs
//! its own hygiene pass (T-108). See `scratchpad/t104_verdict_2026-09-07.md`.
//!
//! **Corpus** — real per-country top-sites lists from the Chrome UX Report
//! (CrUX), via the `InternetHealthReport/crux-top-lists-country` GitHub
//! mirror (`data/country/<cc>/<yyyymm>.csv.gz`, columns `origin,rank`). CrUX
//! data is CC BY 4.0 (Google); this mirror is a cache of the public BigQuery
//! dataset. It is fetched here only for a **one-off private measurement** —
//! nothing derived from it is redistributed by this repo, so the licence of
//! the eventual rating-filter zone source (open decision after T-106 — CrUX
//! CC BY 4.0 is the leading candidate) does not gate this run. A hard-coded
//! "top sites" list was rejected for the same
//! reason `phase1_metrics.rs` rejects a hard-coded malware list: this project
//! has no independent, current knowledge of what a country's real top traffic
//! is, and a guessed list would produce a meaningless rate.
//!
//! CrUX identifies sites by **origin** (`https://www.example.com`), and its
//! `rank` column is a coarse magnitude bucket (`1000` / `10K` / `100K` /
//! `1M`), not an ordinal position — so "top-N" here means "the first N rows
//! of the top-1000 bucket", host-only, deduplicated. The granularity gap (no
//! ordinal top-50 available, only a ≥1000 bucket) was one of the reasons the
//! centralized §5.1 model did not hold up (T-106).
//!
//! **Method** — for each sampled domain: gate on two independent *unfiltered*
//! resolvers both returning `NoError` (Cloudflare `1.1.1.1` primary + Quad9
//! unsecured `dns10` second — the same `BASELINE_CHAIN[1]` gate
//! `phase1_metrics.rs` uses, so a filtering voter's `NXDOMAIN` is a real
//! block, not a resolver-view difference); then query every built-in preset
//! with its own block signature and record which ones block. A block by an
//! **Ads-tier** or **Adult-tier** preset on a presumed-legit top site is a
//! candidate false positive. Security-tier presets are queried too, for
//! context only. DNS lookups only: this tool never opens an HTTP connection
//! to a sampled host.
//!
//! **Reading the two headline rates.** An Ads-tier block on a top national
//! site is a clean false positive — `adguard` is the shipped default voter
//! (`DEFAULT_PROVIDER_IDS`), and it has no business blocking, say, a national
//! retailer. An Adult-tier block is softer evidence: a genuinely-adult site
//! can also be nationally popular (CrUX ranks by traffic, not by topic), so
//! an Adult-tier "false positive" here is an **upper bound** — some of it is
//! the Adult filter working correctly.
//!
//! **Usage** — `cargo run --example topn_fp_probe [countries=us,de,ua,jp,br]
//! [n=75] [month=YYYYMM]`. Args are prefix-tagged and order-independent; a
//! bare integer is taken as `n`. `month` defaults to the newest published
//! file at or before the current system month (the mirror's cron can lag a
//! month or two — this walks back up to a year). Output is a report to
//! stdout; exit 0 on a completed run. Sampled domains are public popularity
//! data, so the per-country "blocked" trace prints them verbatim — that list
//! *is* the finding.

use dnsqb_service::{
    all_builtin_presets, is_blocked, sinkhole_nets_for, Category, DohClient, ProviderSpec,
    ReqwestDohClient, BASELINE_CHAIN, BASELINE_DOH_URL,
};
use flate2::read::GzDecoder;
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use std::collections::HashSet;
use std::error::Error;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Second, independent *unfiltered* resolver — `BASELINE_CHAIN[1]` (Quad9
/// unsecured `dns10`). See the module doc and `phase1_metrics.rs`'s
/// `SECOND_BASELINE_URL` for why both must agree before a voter's `NXDOMAIN`
/// counts as a block.
const SECOND_BASELINE_URL: &str = BASELINE_CHAIN[1];

/// CrUX per-country mirror. `origin,rank` CSV, gzip-compressed, one file per
/// `<cc>/<yyyymm>`.
const CRUX_COUNTRY_BASE: &str =
    "https://raw.githubusercontent.com/InternetHealthReport/crux-top-lists-country/main/data/country";

const DEFAULT_COUNTRIES: &[&str] = &["us", "de", "ua", "jp", "br"];
const DEFAULT_TOP_N: usize = 75;
const PER_DOMAIN_DELAY: Duration = Duration::from_millis(150);
/// Months to walk back from the current system month looking for the newest
/// published `<yyyymm>.csv.gz`.
const MONTH_LOOKBACK: u32 = 12;
/// Below this per-country sample size the number is indicative, not measured.
const SMALL_SAMPLE_WARNING: usize = 30;

/// One sampled domain's per-preset outcome. `voter_blocked` is parallel to
/// `all_builtin_presets()` order — index `i` belongs to `presets[i]`.
struct DomainResult {
    domain: String,
    country: String,
    voter_blocked: Vec<bool>,
}

/// Outcome of sampling one domain — kept, or dropped with a tallied reason.
enum Sampled {
    Kept(Box<DomainResult>),
    /// Primary baseline (Cloudflare) did not return `NoError` — a domain that
    /// does not resolve on an unfiltered resolver cannot be a false positive.
    SkippedPrimaryBaseline,
    /// Primary said `NoError`, the second unfiltered resolver did not — the
    /// two disagree, so a voter's `NXDOMAIN` here is not distinguishable from
    /// a resolver-view difference.
    SkippedBaselineDisagree,
}

struct Args {
    countries: Vec<String>,
    top_n: usize,
    month: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;

    let feed_client = reqwest::Client::new();
    let month = match &args.month {
        Some(m) => {
            println!("using caller-supplied month {m}");
            m.clone()
        }
        None => resolve_latest_month(&feed_client, &args.countries).await?,
    };

    let mut sample: Vec<(String, String)> = Vec::new();
    let mut per_country_sampled: Vec<(String, usize)> = Vec::new();
    for cc in &args.countries {
        match fetch_country_top_n(&feed_client, cc, &month, args.top_n).await {
            Ok(domains) => {
                println!("{cc}: {} domains from {month}.csv.gz", domains.len());
                per_country_sampled.push((cc.clone(), domains.len()));
                sample.extend(domains.into_iter().map(|d| (d, cc.clone())));
            }
            Err(err) => eprintln!("{cc}: skipped ({err})"),
        }
    }
    if sample.is_empty() {
        return Err("no per-country lists could be fetched — nothing to measure".into());
    }

    let presets = all_builtin_presets();
    println!(
        "\nmeasuring {} built-in presets against {} domains across {} countries (month {month})",
        presets.len(),
        sample.len(),
        per_country_sampled.len()
    );

    let doh_client = ReqwestDohClient::new()?;
    let mut results: Vec<DomainResult> = Vec::new();
    let mut skipped_primary = 0usize;
    let mut skipped_disagree = 0usize;
    for (domain, country) in &sample {
        match resolve_all_voters(&doh_client, domain, country, &presets).await {
            Ok(Sampled::Kept(result)) => results.push(*result),
            Ok(Sampled::SkippedPrimaryBaseline) => skipped_primary += 1,
            Ok(Sampled::SkippedBaselineDisagree) => skipped_disagree += 1,
            Err(err) => eprintln!("  (skipped {domain}, query failed: {err})"),
        }
        tokio::time::sleep(PER_DOMAIN_DELAY).await;
    }

    println!(
        "\nbaseline gating: {skipped_primary} dropped (primary baseline not NoError), \
         {skipped_disagree} dropped (unfiltered resolvers disagree)"
    );

    report(&results, &presets, &per_country_sampled);
    Ok(())
}

/// Prefix-tagged, order-independent args: `countries=us,de`, `n=120`,
/// `month=202607`; a bare integer is `n`. Anything else is an error rather
/// than a silent ignore.
fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut countries: Vec<String> = DEFAULT_COUNTRIES.iter().map(|s| (*s).to_string()).collect();
    let mut top_n = DEFAULT_TOP_N;
    let mut month = None;
    for arg in std::env::args().skip(1) {
        if let Some(rest) = arg.strip_prefix("countries=") {
            countries = rest
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_ascii_lowercase)
                .collect();
            if countries.is_empty() {
                return Err("countries= must list at least one code".into());
            }
        } else if let Some(rest) = arg.strip_prefix("n=") {
            top_n = rest.parse()?;
        } else if let Some(rest) = arg.strip_prefix("month=") {
            if rest.len() != 6 || !rest.chars().all(|c| c.is_ascii_digit()) {
                return Err("month= must be YYYYMM".into());
            }
            month = Some(rest.to_string());
        } else if let Ok(n) = arg.parse::<usize>() {
            top_n = n;
        } else {
            return Err(format!(
                "unrecognised arg {arg:?} (expected countries=/n=/month= or a number)"
            )
            .into());
        }
    }
    if top_n == 0 {
        return Err("n must be > 0".into());
    }
    Ok(Args {
        countries,
        top_n,
        month,
    })
}

/// Walks back from the current system month, returning the first `<yyyymm>`
/// for which the **first** requested country's file exists (a HEAD-like GET).
async fn resolve_latest_month(
    client: &reqwest::Client,
    countries: &[String],
) -> Result<String, Box<dyn Error>> {
    let probe_cc = countries.first().map_or("us", String::as_str);
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
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
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

/// Fetches one `<cc>/<month>.csv.gz`, gunzips it, and returns the host part
/// of the first `n` unique origins (top-1000 bucket, in file order).
async fn fetch_country_top_n(
    client: &reqwest::Client,
    cc: &str,
    month: &str,
    n: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    let url = format!("{CRUX_COUNTRY_BASE}/{cc}/{month}.csv.gz");
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {} for {url}", resp.status()).into());
    }
    let gz = resp.bytes().await?;
    let mut csv = String::new();
    GzDecoder::new(&gz[..]).read_to_string(&mut csv)?;

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in csv.lines().skip(1) {
        if out.len() >= n {
            break;
        }
        let origin = line.split(',').next().unwrap_or("").trim();
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
        if seen.insert(host.clone()) {
            out.push(host);
        }
    }
    Ok(out)
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
    // public resolver honours that literally and SERVFAILs anything not
    // edge-cached (documented at length in phase1_metrics.rs::build_a_query).
    message.metadata.recursion_desired = true;
    Ok(message)
}

async fn resolve_all_voters(
    client: &ReqwestDohClient,
    domain: &str,
    country: &str,
    presets: &[ProviderSpec],
) -> Result<Sampled, Box<dyn Error>> {
    let query = build_a_query(domain)?;
    let baseline = client.query(BASELINE_DOH_URL, &query).await?;
    if baseline.metadata.response_code != ResponseCode::NoError {
        return Ok(Sampled::SkippedPrimaryBaseline);
    }
    let second = client.query(SECOND_BASELINE_URL, &query).await?;
    if second.metadata.response_code != ResponseCode::NoError {
        return Ok(Sampled::SkippedBaselineDisagree);
    }
    let mut voter_blocked = Vec::with_capacity(presets.len());
    for spec in presets {
        let response = client.query(&spec.doh_url, &query).await?;
        voter_blocked.push(is_blocked(
            spec.block_signature,
            &response,
            &baseline,
            sinkhole_nets_for(&spec.id),
        ));
    }
    Ok(Sampled::Kept(Box::new(DomainResult {
        domain: domain.to_string(),
        country: country.to_string(),
        voter_blocked,
    })))
}

fn report(
    results: &[DomainResult],
    presets: &[ProviderSpec],
    per_country_sampled: &[(String, usize)],
) {
    if results.is_empty() {
        println!("\nno resolvable domains — nothing to report");
        return;
    }

    let ads_idx: Vec<usize> = tier_indices(presets, Category::AdsTrackers);
    let adult_idx: Vec<usize> = tier_indices(presets, Category::AdultContent);

    let mut ads_fp_total = 0usize;
    let mut adult_fp_total = 0usize;
    let mut n_total = 0usize;

    for (cc, sampled) in per_country_sampled {
        let rows: Vec<&DomainResult> = results.iter().filter(|r| &r.country == cc).collect();
        let n = rows.len();
        n_total += n;
        println!("\n=== {cc} (n = {n} resolvable of {sampled} sampled) ===");
        if n == 0 {
            println!("  (nothing resolvable)");
            continue;
        }
        if n < SMALL_SAMPLE_WARNING {
            println!("  (n < {SMALL_SAMPLE_WARNING} — indicative, not measured)");
        }

        let ads_fp = rows.iter().filter(|r| any_blocked(r, &ads_idx)).count();
        let adult_fp = rows.iter().filter(|r| any_blocked(r, &adult_idx)).count();
        ads_fp_total += ads_fp;
        adult_fp_total += adult_fp;
        println!(
            "  Ads-tier blocked   {ads_fp:>3}/{n} ({:>5.1}%)   Adult-tier blocked {adult_fp:>3}/{n} ({:>5.1}%)",
            pct(ads_fp, n),
            pct(adult_fp, n)
        );

        for (i, spec) in presets.iter().enumerate() {
            if spec.category == Category::Security {
                continue;
            }
            let blocked = rows.iter().filter(|r| r.voter_blocked[i]).count();
            println!(
                "    {:<22} [{:>12}]  {blocked:>3}/{n} ({:>5.1}%)",
                spec.id,
                category_label(spec.category),
                pct(blocked, n)
            );
        }

        let flagged: Vec<String> = rows
            .iter()
            .filter(|r| any_blocked(r, &ads_idx) || any_blocked(r, &adult_idx))
            .map(|r| {
                let ids: Vec<&str> = presets
                    .iter()
                    .zip(&r.voter_blocked)
                    .filter(|(spec, &b)| b && spec.category != Category::Security)
                    .map(|(spec, _)| spec.id.as_str())
                    .collect();
                format!("{} -> [{}]", r.domain, ids.join(", "))
            })
            .collect();
        if flagged.is_empty() {
            println!("  blocked top sites: none");
        } else {
            println!("  blocked top sites:");
            for line in flagged {
                println!("    {line}");
            }
        }
    }

    println!(
        "\n=== Overall (n = {n_total} across {} countries) ===",
        per_country_sampled.len()
    );
    println!(
        "  Ads-tier false-positive rate:   {ads_fp_total}/{n_total} ({:.1}%)",
        pct(ads_fp_total, n_total)
    );
    println!(
        "  Adult-tier false-positive rate: {adult_fp_total}/{n_total} ({:.1}%)  [upper bound — a \
         genuinely-adult site can also be nationally popular]",
        pct(adult_fp_total, n_total)
    );
    println!("  Security tier is not counted here (queried for context only).");
}

fn tier_indices(presets: &[ProviderSpec], category: Category) -> Vec<usize> {
    presets
        .iter()
        .enumerate()
        .filter(|(_, s)| s.category == category)
        .map(|(i, _)| i)
        .collect()
}

fn any_blocked(row: &DomainResult, idx: &[usize]) -> bool {
    idx.iter().any(|&i| row.voter_blocked[i])
}

fn category_label(category: Category) -> &'static str {
    match category {
        Category::Security => "SECURITY",
        Category::AdsTrackers => "ADS_TRACKERS",
        Category::AdultContent => "ADULT",
    }
}

fn pct(count: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (count as f64 / total as f64) * 100.0
}
