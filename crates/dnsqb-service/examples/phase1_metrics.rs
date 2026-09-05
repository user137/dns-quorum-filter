//! Manual Фаза 1 benchmark (T-66) — **not** run in CI, **not** part of the
//! shipped binary. Two measurements:
//!
//! 1. Local cache-miss vs cache-hit latency against a running
//!    `dnsqb-service` instance (SPEC.md §4 — the cache's own contribution,
//!    not upstream latency).
//! 2. Quorum detection rate vs each individual provider, measured over
//!    **every built-in preset** (`all_builtin_presets()` — the 10 §3.4
//!    entries across Security / AdsTrackers / AdultContent) against three
//!    corpora: `malware` (a live abuse.ch URLhaus sample — the
//!    quorum-hypothesis question T-66/T-171 asked), `ads` (a small fixed
//!    list of well-known ad/tracker infrastructure hostnames, which a
//!    malware feed never exercises), and `adult` (a small fixed list of the
//!    highest-traffic adult sites). The ads/adult lists are hardcoded on
//!    purpose: unlike churning malware domains they are stable, and there is
//!    no clean public "ad domain" / "adult domain" feed to pull the way
//!    URLhaus is pulled. This tool only ever does a DNS lookup for any host
//!    — it never opens an HTTP connection to one. The per-corpus breakdown
//!    doubles as a block-signature check (T-174): a preset whose declared
//!    signature cannot see the rcode it actually returns shows up as
//!    `0 blocked` with a high raw-NXDOMAIN count. T-66 measured 2 providers
//!    on n=38; T-171 the 3 shipped defaults on n=122; this runs all 10.
//!
//! **Preconditions** (run with `cargo run --example phase1_metrics [port]`,
//! default port 8443 — a plain HTTP client, it does not manage the service's
//! lifecycle):
//! - Measurement 2 (detection rate) needs no local service — it talks to the
//!   public upstreams directly, and its results print before measurement 1
//!   runs.
//! - Measurement 1 (latency) needs `cargo run --bin dnsqb-service` already
//!   running against the **default** app-data directory (not a scratch
//!   `LOCALAPPDATA` override): the client pins TLS to `app_data_dir()/cert.pem`
//!   the way `admin::AdminClient` does (T-165 — no `danger_accept_invalid_certs`).
//!   A missing `cert.pem` fails this half only, after measurement 2 has printed.
//!
//! **Malicious-domain source**: the live abuse.ch URLhaus recent-URLs CSV
//! feed (`https://urlhaus.abuse.ch/downloads/csv_recent/`, no Auth-Key
//! required — confirmed 2026-08-26; URLhaus's newer bulk-export API does
//! require one, this older recent-URLs dump does not). Deliberately not a
//! hardcoded domain list — this project has no reliable, current knowledge
//! of what's actually on Quad9's/AdGuard's live blocklists, and a
//! fabricated "known-malicious" list would produce a meaningless detection
//! rate. Chosen with the user during T-66 planning, not invented silently.
//! Fetching this feed only ever resolves DNS for the listed hosts — this
//! tool never makes an HTTP connection to a malicious URL itself.
//!
//! **Latency sample reuses the detection-rate sample** (not a fixed
//! well-known-domain list) — `example.com`-style domains are themselves so
//! heavily cached upstream that a "cold" query against them would still
//! land in ~10ms regardless of this service's own cache state, making a
//! cold/warm comparison uninterpretable (caught by advisor review of the
//! plan). The URLhaus-derived sample is genuinely uncached anywhere and
//! differs each run.
//!
//! **Quad9's block signal (NXDOMAIN) is ambiguous with genuine
//! non-existence** — `quorum::evaluate` resolves that ambiguity via
//! `Signal::NeedsBaseline` (`is_blocked`'s own logic: "baseline resolved
//! fine, Quad9 didn't" *is* the block signal). Since this benchmark already
//! filters to baseline-`NoError` domains, essentially every Quad9-detected
//! block below goes through that fallback path, not an unambiguous explicit
//! signal — unlike AdGuard, whose block signal is an explicit `0.0.0.0`/`::`
//! answer. This is `is_blocked`'s actual shipped semantic, not a bug in this
//! tool, but any single NXDOMAIN-signature voter's rate is an upper bound
//! under that semantic. **T-174 closing-advisor mitigation**: a domain is
//! kept only if the primary baseline (Cloudflare) *and* a second
//! independent unfiltered resolver (Quad9 unsecured `dns10`, `SECOND_BASELINE_URL`)
//! both return `NoError` — so an NXDOMAIN-signature voter's block is against
//! a domain two unfiltered resolvers agree resolves, not a
//! propagation/view difference. The count dropped by that second gate is
//! reported ("baseline gating: … dropped").
//!
//! **An AdGuard 0% rate is ambiguous by rcode alone and was separately
//! checked, not assumed** — advisor review of a real run pointed out that
//! AdGuard's own block signal is an explicit `0.0.0.0`/`::` *answer*, which
//! is still rcode `NoError` — so "AdGuard blocked nothing" and "AdGuard
//! blocked everything but `is_blocked` failed to recognize it" look
//! identical in an rcode-only trace. A one-off run with the raw answer
//! records logged confirmed every AdGuard response carried genuine,
//! routable IPs (real hosting/CDN addresses) across the full sample — no
//! `0.0.0.0`/`::` anywhere — so a 0% rate is a real finding about this
//! sample, not a masked detection bug.
//!
//! **T-175 — sinkhole-IP detection**: each preset's block check now passes
//! `sinkhole_nets_for(&spec.id)` (not `&[]`), so a preset that blocks by
//! substituting a provider-specific block-page IP (`adguard`,
//! `adguard-family`, `opendns-familyshield`, `dns4eu-*`) is finally counted.
//! Rates for those presets rise relative to T-174; the quorum-hypothesis
//! verdict is *strengthened*, not changed.
//!
//! **Optional `oisd:<n>` corpus** (`cargo run --example phase1_metrics
//! [port] oisd:2000`): a random-stride sample of `n` domains from the oisd
//! "big" aggregated community blocklist. Deeper coverage for ads/trackers,
//! but it is **agreement with a big list, not detection of known-bad** — a
//! large fraction of oisd resolves fine and a Security-tier resolver
//! correctly leaves it alone. Printed as its own labelled section and
//! **never folded into the quorum-hypothesis verdict** (that stays the
//! malware corpus only). There is a circularity caveat too: some providers
//! share upstream list sources with oisd.
//!
//! Output is a report to stdout only. Per-domain lines are indexed, not
//! labeled with the raw domain text — the fetched malicious-domain list
//! itself is never persisted anywhere in this repo (someone else's live
//! threat feed, churns constantly, no reason to keep it here).

use dnsqb_service::{
    all_builtin_presets, app_data_dir, decode_wire_message, doh_get_url, encode_wire_message,
    is_blocked, sinkhole_nets_for, BlockSignature, Category, DohClient, ProviderSpec,
    ReqwestDohClient, BASELINE_CHAIN, BASELINE_DOH_URL,
};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use std::collections::HashSet;
use std::error::Error;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A second, independent *unfiltered* resolver (`BASELINE_CHAIN[1]` — Quad9
/// unsecured `dns10`). T-174 closing-advisor: for an `NxdomainVsBaseline` /
/// `NullIpOrNxdomain` voter, `is_blocked` counts a block whenever the
/// primary baseline resolved and the voter said `NXDOMAIN` — but on a live
/// URLhaus feed a fresh domain can be `NoError` on one recursive resolver
/// and `NXDOMAIN` on another purely from propagation/view differences, not a
/// filter decision. A domain is kept only if **both** unfiltered resolvers
/// return `NoError`, so a filtering voter's `NXDOMAIN` is a real block, not
/// a resolver-view artifact.
const SECOND_BASELINE_URL: &str = BASELINE_CHAIN[1];

const URLHAUS_RECENT_CSV: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";
/// oisd "big" list, plain-hostname format (~200k lines, `#`/`!` comments).
/// Only fetched when `oisd:<n>` is passed; a random-stride sample of `n` is
/// taken (T-133 ToS — never all 200k against public resolvers).
const OISD_BIG_URL: &str = "https://big.oisd.nl/";
// T-171 widened this from 40 to a ~100-200 target (T-133 ToS: moderate
// volume, no bulk abuse). The feed's `csv_recent` dump holds a few thousand
// rows; the cap plus the baseline-NoError filter decides the final n.
const SAMPLE_CAP: usize = 150;
const PER_DOMAIN_DELAY: Duration = Duration::from_millis(150);
const DEFAULT_LOCAL_PORT: u16 = 8443;
const SMALL_SAMPLE_WARNING_THRESHOLD: usize = 20;

/// Well-known ad / tracker infrastructure hostnames — the kind of entry that
/// appears in every published ad-blocking DNS filter list. Fixed, not
/// fetched: these are stable (unlike churning malware domains) and there is
/// no clean public "ad domain" feed. Used only for DNS resolution.
const ADS_DOMAINS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "adnxs.com",
    "criteo.com",
    "scorecardresearch.com",
    "taboola.com",
    "outbrain.com",
    "pubmatic.com",
    "rubiconproject.com",
    "casalemedia.com",
    "moatads.com",
    "adsafeprotected.com",
    "serving-sys.com",
    "amazon-adsystem.com",
    "adform.net",
];

/// Highest-traffic adult sites — the standard reference set for checking
/// that an AdultContent DNS filter actually blocks (these appear as examples
/// in CleanBrowsing / OpenDNS / AdGuard filter documentation). Fixed for the
/// same reason as [`ADS_DOMAINS`]. Used only for DNS resolution — this tool
/// never opens an HTTP connection to any host.
const ADULT_DOMAINS: &[&str] = &[
    "pornhub.com",
    "xvideos.com",
    "xnxx.com",
    "xhamster.com",
    "redtube.com",
    "youporn.com",
    "onlyfans.com",
    "chaturbate.com",
    "stripchat.com",
    "brazzers.com",
];

/// Which fixed list (or the live feed) a sampled domain came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Corpus {
    Malware,
    Ads,
    Adult,
    /// A random-stride sample of the oisd "big" aggregated community blocklist
    /// (opt-in, `oisd:<n>` CLI arg — T-175). **Not ground truth**: oisd is an
    /// aggregate of ads/trackers/malware/phishing lists, and a large share of
    /// its entries are ad/tracker hosts that resolve fine and that a
    /// Security-tier resolver correctly does *not* block — so a "detection
    /// rate" against it measures *agreement with a big list*, not filtering
    /// accuracy, and it never feeds the quorum-hypothesis verdict (that stays
    /// [`Corpus::Malware`]-only).
    Oisd,
}

impl Corpus {
    fn label(self) -> &'static str {
        match self {
            Corpus::Malware => "malware",
            Corpus::Ads => "ads",
            Corpus::Adult => "adult",
            Corpus::Oisd => "oisd-biglist",
        }
    }
}

/// One sampled domain's per-voter outcome. `voter_rcode` / `voter_blocked`
/// are parallel to `presets` (`all_builtin_presets()` order), so index `i`
/// in either belongs to `presets[i]`.
struct DomainResult {
    domain: String,
    corpus: Corpus,
    baseline_rcode: ResponseCode,
    second_baseline_rcode: ResponseCode,
    voter_rcode: Vec<ResponseCode>,
    voter_blocked: Vec<bool>,
}

/// Outcome of sampling one domain — kept, or dropped with the reason (so the
/// reasons can be tallied rather than silently swallowed).
enum Sampled {
    Kept(Box<DomainResult>),
    /// Primary baseline (Cloudflare) did not return `NoError`.
    SkippedPrimaryBaseline,
    /// Primary baseline said `NoError` but the second unfiltered resolver
    /// (Quad9 unsecured) did not — the two disagree, so any filtering
    /// voter's `NXDOMAIN` here is not distinguishable from a resolver-view
    /// difference. Dropped. (T-174 closing-advisor.)
    SkippedBaselineDisagree,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let port = args.port;

    let feed_client = reqwest::Client::new();
    let malware = fetch_urlhaus_domains(&feed_client, SAMPLE_CAP).await?;
    println!(
        "fetched {} candidate malware domains from URLhaus",
        malware.len()
    );

    let mut sample: Vec<(String, Corpus)> = Vec::new();
    sample.extend(malware.into_iter().map(|d| (d, Corpus::Malware)));
    sample.extend(ADS_DOMAINS.iter().map(|d| ((*d).to_string(), Corpus::Ads)));
    sample.extend(
        ADULT_DOMAINS
            .iter()
            .map(|d| ((*d).to_string(), Corpus::Adult)),
    );

    let mut oisd_count = 0usize;
    if let Some(n) = args.oisd_sample {
        let oisd = fetch_oisd_domains(&feed_client, n).await?;
        oisd_count = oisd.len();
        println!(
            "fetched {oisd_count} oisd domains (random-stride sample of {n}) - \
             agreement-with-a-big-list, NOT part of the quorum verdict"
        );
        sample.extend(oisd.into_iter().map(|d| (d, Corpus::Oisd)));
    }
    println!(
        "corpora: {} malware + {} ads + {} adult + {oisd_count} oisd",
        sample.iter().filter(|(_, c)| *c == Corpus::Malware).count(),
        ADS_DOMAINS.len(),
        ADULT_DOMAINS.len()
    );

    let presets = all_builtin_presets();
    println!(
        "measuring {} built-in presets: {}",
        presets.len(),
        presets
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let doh_client = ReqwestDohClient::new()?;
    let mut results = Vec::new();
    let mut skipped_primary = 0usize;
    let mut skipped_disagree = 0usize;
    for (domain, corpus) in &sample {
        match resolve_all_voters(&doh_client, domain, *corpus, &presets).await {
            Ok(Sampled::Kept(result)) => results.push(*result),
            Ok(Sampled::SkippedPrimaryBaseline) => skipped_primary += 1,
            Ok(Sampled::SkippedBaselineDisagree) => skipped_disagree += 1,
            Err(err) => eprintln!("  (skipped one domain, query failed: {err})"),
        }
        tokio::time::sleep(PER_DOMAIN_DELAY).await;
    }

    println!(
        "\nbaseline gating: {skipped_primary} dropped (primary baseline not NoError), \
         {skipped_disagree} dropped (unfiltered resolvers disagree - Cloudflare NoError but \
         Quad9-unsecured did not; an NXDOMAIN-signature voter's block on these would be \
         indistinguishable from a resolver-view difference)"
    );

    report_detection_rate(&results, &presets);

    // Pinned to this instance's own self-signed leaf, same construction as
    // `admin::AdminClient::new` — never `danger_accept_invalid_certs` (CLAUDE.md,
    // SPEC.md §7.1 #10). Assumes the manually-started service in this example's
    // precondition used the default app-data dir, not a scratch `LOCALAPPDATA`.
    let cert_pem = std::fs::read(app_data_dir()?.join("cert.pem"))?;
    let cert = reqwest::Certificate::from_pem(&cert_pem)?;
    let local_client = reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()?;
    let local_base = format!("https://127.0.0.1:{port}/dns-query");
    let mut cache_miss = Vec::new();
    let mut cache_hit = Vec::new();
    // Latency reuses only the malware sample — well-known ad/adult domains
    // are heavily cached upstream, exactly the "uninterpretable cold/warm"
    // problem the module doc warns about.
    for result in results.iter().filter(|r| r.corpus == Corpus::Malware) {
        match measure_local_latency(&local_client, &local_base, &result.domain).await {
            Ok((miss, hit)) => {
                cache_miss.push(miss);
                cache_hit.push(hit);
            }
            Err(err) => eprintln!("  (skipped one domain, local query failed: {err})"),
        }
    }
    report_latency("local cache miss", &cache_miss);
    report_latency("local cache hit", &cache_hit);

    Ok(())
}

/// CLI args, order-independent: a bare number is the local service port
/// (default [`DEFAULT_LOCAL_PORT`]); `oisd:<n>` opts a random-stride sample of
/// `n` oisd domains into the run as a separate [`Corpus::Oisd`] section.
/// Anything else is an error rather than a silent ignore.
struct Args {
    port: u16,
    oisd_sample: Option<usize>,
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut port = DEFAULT_LOCAL_PORT;
    let mut oisd_sample = None;
    for arg in std::env::args().skip(1) {
        if let Some(rest) = arg.strip_prefix("oisd:") {
            let n: usize = rest.parse()?;
            if n == 0 {
                return Err("oisd:<n> must be > 0".into());
            }
            oisd_sample = Some(n);
        } else if let Ok(p) = arg.parse::<u16>() {
            port = p;
        } else {
            return Err(format!("unrecognised arg {arg:?} (expected a port or oisd:<n>)").into());
        }
    }
    Ok(Args { port, oisd_sample })
}

/// Fetches the oisd "big" list and takes a deterministic even-stride sample of
/// `n` hostnames — deterministic (not `rand`) so a number that lands in
/// `PERFORMANCE.md` is re-runnable to the same result, and `rand` is a
/// dev-only dep in this tree. Comment lines (`#`, `!`) and bare IPs are
/// dropped. If the list has `<= n` usable lines, all of them are returned.
async fn fetch_oisd_domains(
    client: &reqwest::Client,
    n: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    let text = client
        .get(OISD_BIG_URL)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let all: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('!'))
        .filter(|line| line.parse::<IpAddr>().is_err())
        .map(str::to_ascii_lowercase)
        .collect();
    if all.len() <= n {
        return Ok(all);
    }
    let stride = all.len() / n;
    Ok(all.into_iter().step_by(stride).take(n).collect())
}

/// Fetches the URLhaus recent-URLs CSV and extracts up to `cap` unique
/// domain-name hosts (bare-IP hosts are dropped — meaningless for a
/// DNS-filtering test). Quoted-CSV fields are split on `","`, which is
/// exact for this feed's format: every field is quoted, and none of the
/// fields this tool reads contain that literal three-character sequence.
async fn fetch_urlhaus_domains(
    client: &reqwest::Client,
    cap: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    let text = client
        .get(URLHAUS_RECENT_CSV)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let mut seen = HashSet::new();
    let mut domains = Vec::new();
    for line in text.lines() {
        if domains.len() >= cap {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let trimmed = line.trim_matches('"');
        let fields: Vec<&str> = trimmed.split("\",\"").collect();
        let Some(url_field) = fields.get(2) else {
            continue;
        };
        let Ok(parsed) = reqwest::Url::parse(url_field) else {
            continue;
        };
        let Some(host) = parsed.host_str() else {
            continue;
        };
        if host.parse::<IpAddr>().is_ok() {
            continue;
        }
        let host = host.to_ascii_lowercase();
        if seen.insert(host.clone()) {
            domains.push(host);
        }
    }
    Ok(domains)
}

fn build_a_query(domain: &str) -> Result<Message, Box<dyn Error>> {
    let name = Name::from_utf8(domain)?;
    let mut question = Query::new();
    question.set_name(name);
    question.set_query_type(RecordType::A);
    question.set_query_class(DNSClass::IN);
    let mut message = Message::query();
    message.add_query(question);
    // hickory_proto::op::Header::new defaults recursion_desired to false.
    // Cloudflare's public resolver (BASELINE_DOH_URL) honors that literally
    // - a non-recursive lookup against anything not already edge-cached
    // comes back SERVFAIL, which looked at first like near-universal dead
    // domains (39/40 SERVFAIL on a real run) until a debug trace showed
    // well-known, definitely-live domains (res.cloudinary.com, filedn.com)
    // failing the same way. Confirmed empirically, not assumed.
    message.metadata.recursion_desired = true;
    Ok(message)
}

/// A domain is kept only if **both** unfiltered resolvers (Cloudflare
/// `1.1.1.1` primary + Quad9 unsecured `dns10` second) return `NoError` —
/// see [`SECOND_BASELINE_URL`]. Otherwise it's dropped with a reason
/// ([`Sampled::SkippedPrimaryBaseline`] / [`Sampled::SkippedBaselineDisagree`]).
///
/// Queries every preset in `presets` (`all_builtin_presets()`), each with
/// its own block signature, against the **primary** baseline (the shipped
/// `is_blocked` contract). A single query failure to any one preset
/// propagates as `Err` (the whole domain is skipped) — a partial per-voter
/// record would silently understate that voter's rate.
async fn resolve_all_voters(
    client: &ReqwestDohClient,
    domain: &str,
    corpus: Corpus,
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
    let mut voter_rcode = Vec::with_capacity(presets.len());
    let mut voter_blocked = Vec::with_capacity(presets.len());
    for spec in presets {
        let response = client.query(&spec.doh_url, &query).await?;
        // T-175: every preset gets its own sinkhole prefixes — `&[]` here
        // would silently re-create the undercount this measurement exists to
        // expose (presets that block via a provider-specific block-page IP).
        voter_blocked.push(is_blocked(
            spec.block_signature,
            &response,
            &baseline,
            sinkhole_nets_for(&spec.id),
        ));
        voter_rcode.push(response.metadata.response_code);
    }
    Ok(Sampled::Kept(Box::new(DomainResult {
        domain: domain.to_string(),
        corpus,
        baseline_rcode: baseline.metadata.response_code,
        second_baseline_rcode: second.metadata.response_code,
        voter_rcode,
        voter_blocked,
    })))
}

fn report_detection_rate(results: &[DomainResult], presets: &[ProviderSpec]) {
    if results.is_empty() {
        println!("\nno resolvable domains in any corpus - nothing to report");
        return;
    }

    for corpus in [Corpus::Malware, Corpus::Ads, Corpus::Adult] {
        report_corpus(results, presets, corpus);
    }
    if results.iter().any(|r| r.corpus == Corpus::Oisd) {
        report_corpus(results, presets, Corpus::Oisd);
        println!(
            "  ^ oisd is an aggregated community blocklist, not known-bad ground truth: \
             a low rate here (esp. Quad9) can mean the resolver is correctly NOT blocking \
             ad/tracker hosts. Reported separately; never folded into the quorum verdict."
        );
    }

    report_quorum_hypothesis(results, presets);

    println!(
        "\nper-domain trace, malware corpus only \
         (index: cloudflare/quad9-unsec baseline rcodes -> ids that blocked):"
    );
    for (i, r) in results
        .iter()
        .filter(|r| r.corpus == Corpus::Malware)
        .enumerate()
    {
        let blocked_ids: Vec<&str> = presets
            .iter()
            .zip(&r.voter_blocked)
            .filter_map(|(spec, &b)| b.then_some(spec.id.as_str()))
            .collect();
        let rcodes: Vec<String> = r.voter_rcode.iter().map(|rc| format!("{rc:?}")).collect();
        println!(
            "  #{i}: {:?}/{:?} -> [{}]   (rcodes: {})",
            r.baseline_rcode,
            r.second_baseline_rcode,
            blocked_ids.join(", "),
            rcodes.join("/")
        );
    }
}

/// Per-preset block rate and raw-NXDOMAIN count for one corpus. The NXDOMAIN
/// column is the T-174 signature check: a preset whose declared signature is
/// `NullIp` (blind to NXDOMAIN) but which returns NXDOMAIN for a large slice
/// of a corpus it is meant to filter is almost certainly blocking via
/// NXDOMAIN, and every one of those blocks is invisible to `quorum::resolve`.
fn report_corpus(results: &[DomainResult], presets: &[ProviderSpec], corpus: Corpus) {
    let rows: Vec<&DomainResult> = results.iter().filter(|r| r.corpus == corpus).collect();
    let n = rows.len();
    println!(
        "\n=== {} corpus (n = {n} resolvable, baseline NoError) ===",
        corpus.label()
    );
    if n == 0 {
        println!("  (no resolvable domains)");
        return;
    }
    if n < SMALL_SAMPLE_WARNING_THRESHOLD {
        println!("  (n < {SMALL_SAMPLE_WARNING_THRESHOLD} - indicative, not measured)");
    }
    for (i, spec) in presets.iter().enumerate() {
        let blocked = rows.iter().filter(|r| r.voter_blocked[i]).count();
        let nx = rows
            .iter()
            .filter(|r| r.voter_rcode[i] == ResponseCode::NXDomain)
            .count();
        let suspect = spec.block_signature == BlockSignature::NullIp && nx * 10 > n;
        println!(
            "  {:<24} [{:>12}] blocked {blocked:>3}/{n} ({:>5.1}%)  NXDOMAIN {nx:>3}/{n}{}",
            spec.id,
            category_label(spec.category),
            pct(blocked, n),
            if suspect {
                "   [!] signature=NullIp cannot see these NXDOMAIN blocks - likely wrong"
            } else {
                ""
            }
        );
    }
}

/// The T-66/T-171 question, on the malware corpus only: does the OR-quorum
/// catch domains no single provider does?
fn report_quorum_hypothesis(results: &[DomainResult], presets: &[ProviderSpec]) {
    let rows: Vec<&DomainResult> = results
        .iter()
        .filter(|r| r.corpus == Corpus::Malware)
        .collect();
    let n = rows.len();
    println!("\n=== Quorum hypothesis (malware corpus, n = {n}) ===");
    if n == 0 {
        return;
    }
    let per_provider: Vec<usize> = (0..presets.len())
        .map(|i| rows.iter().filter(|r| r.voter_blocked[i]).count())
        .collect();
    let security_idx: Vec<usize> = (0..presets.len())
        .filter(|&i| presets[i].category == Category::Security)
        .collect();
    let quorum_all = rows
        .iter()
        .filter(|r| r.voter_blocked.iter().any(|&b| b))
        .count();
    let quorum_security = rows
        .iter()
        .filter(|r| security_idx.iter().any(|&i| r.voter_blocked[i]))
        .count();
    let best_single = per_provider.iter().copied().max().unwrap_or(0);
    let best_single_security = security_idx
        .iter()
        .map(|&i| per_provider[i])
        .max()
        .unwrap_or(0);

    println!(
        "  Quorum (OR of all {} presets):     {quorum_all}/{n} ({:.1}%)  |  delta over best single: \
         +{}/{n} ({:+.1} pp)",
        presets.len(),
        pct(quorum_all, n),
        quorum_all - best_single,
        pct(quorum_all, n) - pct(best_single, n)
    );
    println!(
        "  Quorum (OR of Security tier, {}):    {quorum_security}/{n} ({:.1}%)  |  delta over best \
         single Security: +{}/{n} ({:+.1} pp)",
        security_idx.len(),
        pct(quorum_security, n),
        quorum_security - best_single_security,
        pct(quorum_security, n) - pct(best_single_security, n)
    );
    println!(
        "  A delta >0 means OR-logic caught domains no single provider did. Quad9's rate is an \
         upper bound (NeedsBaseline path - module doc). A preset flagged [!] above is not \
         contributing its real blocks here."
    );
}

fn category_label(category: Category) -> &'static str {
    match category {
        Category::Security => "SECURITY",
        Category::AdsTrackers => "ADS_TRACKERS",
        Category::AdultContent => "ADULT",
    }
}

fn pct(count: usize, total: usize) -> f64 {
    (count as f64 / total as f64) * 100.0
}

async fn measure_local_latency(
    client: &reqwest::Client,
    base_url: &str,
    domain: &str,
) -> Result<(Duration, Duration), Box<dyn Error>> {
    let query = build_a_query(domain)?;
    let bytes = encode_wire_message(&query)?;
    let url = doh_get_url(base_url, &bytes);

    let miss = timed_local_query(client, &url).await?;
    let hit = timed_local_query(client, &url).await?;
    Ok((miss, hit))
}

async fn timed_local_query(
    client: &reqwest::Client,
    url: &str,
) -> Result<Duration, Box<dyn Error>> {
    let start = Instant::now();
    let body = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let elapsed = start.elapsed();
    decode_wire_message(&body)?;
    Ok(elapsed)
}

fn report_latency(label: &str, samples: &[Duration]) {
    println!("\n=== {label} (n = {}) ===", samples.len());
    if samples.is_empty() {
        println!("no samples");
        return;
    }
    let mut sorted = samples.to_vec();
    sorted.sort();
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let median = sorted[sorted.len() / 2];
    let sum: Duration = sorted.iter().sum();
    let mean = sum / u32::try_from(sorted.len()).unwrap_or(1);
    println!("min={min:?} median={median:?} mean={mean:?} max={max:?}");
}
