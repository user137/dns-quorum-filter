//! Manual Фаза 1 benchmark (T-66) — **not** run in CI, **not** part of the
//! shipped binary. Two measurements:
//!
//! 1. Local cache-miss vs cache-hit latency against a running
//!    `dnsqb-service` instance (SPEC.md §4 — the cache's own contribution,
//!    not upstream latency).
//! 2. Quorum detection rate vs each individual provider, against a live
//!    URLhaus malicious-domain sample — validates or refutes the "OR-logic
//!    across providers beats a single provider" hypothesis this whole
//!    project rests on. Re-run for T-171 with the T-170 shipped default set
//!    (`quad9` + `cloudflare-malware` + `adguard`) on a larger sample.
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
//! tool, but Quad9's rate here is an upper bound under that semantic, not an
//! unconditional measurement — the per-domain rcode trace this tool prints
//! makes that checkable rather than just asserted.
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
//! Output is a report to stdout only. Per-domain lines are indexed, not
//! labeled with the raw domain text — the fetched malicious-domain list
//! itself is never persisted anywhere in this repo (someone else's live
//! threat feed, churns constantly, no reason to keep it here).

use dnsqb_service::{
    app_data_dir, builtin_preset, decode_wire_message, doh_get_url, encode_wire_message,
    is_blocked, BlockSignature, DohClient, ReqwestDohClient, BASELINE_DOH_URL,
};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use std::collections::HashSet;
use std::error::Error;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const URLHAUS_RECENT_CSV: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";
// T-171 widened this from 40 to a ~100-200 target (T-133 ToS: moderate
// volume, no bulk abuse). The feed's `csv_recent` dump holds a few thousand
// rows; the cap plus the baseline-NoError filter decides the final n.
const SAMPLE_CAP: usize = 150;
const PER_DOMAIN_DELAY: Duration = Duration::from_millis(150);
const DEFAULT_LOCAL_PORT: u16 = 8443;
const SMALL_SAMPLE_WARNING_THRESHOLD: usize = 20;

struct DomainResult {
    domain: String,
    baseline_rcode: ResponseCode,
    quad9_rcode: ResponseCode,
    cloudflare_rcode: ResponseCode,
    adguard_rcode: ResponseCode,
    quad9_blocked: bool,
    cloudflare_blocked: bool,
    adguard_blocked: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let port = local_port_from_args()?;

    let feed_client = reqwest::Client::new();
    let sample = fetch_urlhaus_domains(&feed_client, SAMPLE_CAP).await?;
    println!("fetched {} candidate domains from URLhaus", sample.len());

    let doh_client = ReqwestDohClient::new()?;
    let mut results = Vec::new();
    for domain in &sample {
        match resolve_all_voters(&doh_client, domain).await {
            Ok(Some(result)) => results.push(result),
            Ok(None) => {}
            Err(err) => eprintln!("  (skipped one domain, query failed: {err})"),
        }
        tokio::time::sleep(PER_DOMAIN_DELAY).await;
    }

    report_detection_rate(&results);

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
    for result in &results {
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

fn local_port_from_args() -> Result<u16, Box<dyn Error>> {
    match std::env::args().nth(1) {
        Some(arg) => Ok(arg.parse()?),
        None => Ok(DEFAULT_LOCAL_PORT),
    }
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

/// `Ok(None)` means the domain's baseline query didn't come back `NoError`
/// (dead/sinkholed/NXDOMAIN) — excluded from the detection-rate denominator,
/// URLhaus churn rather than a provider miss.
///
/// Queries the T-170 shipped default voter set — `quad9`
/// (`NxdomainVsBaseline`), `cloudflare-malware` (`NullIp`) and `adguard`
/// (`NullIp`) — each with its preset's own block signature.
async fn resolve_all_voters(
    client: &ReqwestDohClient,
    domain: &str,
) -> Result<Option<DomainResult>, Box<dyn Error>> {
    let query = build_a_query(domain)?;
    let baseline = client.query(BASELINE_DOH_URL, &query).await?;
    if baseline.metadata.response_code != ResponseCode::NoError {
        return Ok(None);
    }
    let quad9_spec = builtin_preset("quad9").ok_or("quad9 preset must exist")?;
    let cloudflare_spec =
        builtin_preset("cloudflare-malware").ok_or("cloudflare-malware preset must exist")?;
    let adguard_spec = builtin_preset("adguard").ok_or("adguard preset must exist")?;
    let quad9 = client.query(&quad9_spec.doh_url, &query).await?;
    let cloudflare = client.query(&cloudflare_spec.doh_url, &query).await?;
    let adguard = client.query(&adguard_spec.doh_url, &query).await?;
    let quad9_blocked = is_blocked(BlockSignature::NxdomainVsBaseline, &quad9, &baseline);
    let cloudflare_blocked = is_blocked(BlockSignature::NullIp, &cloudflare, &baseline);
    let adguard_blocked = is_blocked(BlockSignature::NullIp, &adguard, &baseline);
    Ok(Some(DomainResult {
        domain: domain.to_string(),
        baseline_rcode: baseline.metadata.response_code,
        quad9_rcode: quad9.metadata.response_code,
        cloudflare_rcode: cloudflare.metadata.response_code,
        adguard_rcode: adguard.metadata.response_code,
        quad9_blocked,
        cloudflare_blocked,
        adguard_blocked,
    }))
}

fn report_detection_rate(results: &[DomainResult]) {
    let n = results.len();
    println!("\n=== Detection rate (n = {n} resolvable, baseline NoError) ===");
    if n == 0 {
        println!("no resolvable domains in this sample - nothing to report");
        return;
    }
    if n < SMALL_SAMPLE_WARNING_THRESHOLD {
        println!(
            "(sample under {SMALL_SAMPLE_WARNING_THRESHOLD} - treat as indicative, not measured)"
        );
    }

    let quad9_blocked = results.iter().filter(|r| r.quad9_blocked).count();
    let cloudflare_blocked = results.iter().filter(|r| r.cloudflare_blocked).count();
    let adguard_blocked = results.iter().filter(|r| r.adguard_blocked).count();
    let quorum_blocked = results
        .iter()
        .filter(|r| r.quad9_blocked || r.cloudflare_blocked || r.adguard_blocked)
        .count();
    let best_single = quad9_blocked.max(cloudflare_blocked).max(adguard_blocked);
    let quorum_over_best_single = quorum_blocked - best_single;

    println!(
        "Quad9 alone:              {quad9_blocked}/{n} ({:.1}%) - via NXDOMAIN+baseline-NoError \
         (NeedsBaseline path, an upper bound under that semantic - see module doc)",
        pct(quad9_blocked, n)
    );
    println!(
        "Cloudflare Malware alone: {cloudflare_blocked}/{n} ({:.1}%) - explicit 0.0.0.0/:: signal",
        pct(cloudflare_blocked, n)
    );
    println!(
        "AdGuard alone:            {adguard_blocked}/{n} ({:.1}%) - explicit 0.0.0.0/:: signal \
         (T-66: a run discriminating raw answer IPs confirmed a 0/38 AdGuard rate meant genuine \
         routable IPs for every domain, not an unrecognized null-IP - see module doc)",
        pct(adguard_blocked, n)
    );
    println!(
        "Quorum (OR of all three): {quorum_blocked}/{n} ({:.1}%)",
        pct(quorum_blocked, n)
    );
    println!(
        "Quorum delta over the best single provider (the hypothesis: >0 means OR-logic \
         caught domains no single provider did on this sample; 0 means it added nothing): \
         +{quorum_over_best_single}/{n} ({:.1} pp)",
        pct(quorum_blocked, n) - pct(best_single, n)
    );

    println!("\nper-domain trace (index: baseline/quad9/cloudflare/adguard rcode -> verdict):");
    for (i, r) in results.iter().enumerate() {
        println!(
            "  #{i}: {:?}/{:?}/{:?}/{:?} -> quad9={} cloudflare={} adguard={}",
            r.baseline_rcode,
            r.quad9_rcode,
            r.cloudflare_rcode,
            r.adguard_rcode,
            r.quad9_blocked,
            r.cloudflare_blocked,
            r.adguard_blocked
        );
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
