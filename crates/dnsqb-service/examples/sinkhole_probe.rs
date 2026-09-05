//! T-175 sinkhole-prefix recalibrator — **not** CI, run manually (like
//! `phase1_metrics`).
//!
//! Five built-in presets block by substituting a stable provider-specific
//! sinkhole / block-page IP instead of `0.0.0.0` or NXDOMAIN:
//! `adguard`, `adguard-family` (AdGuard `94.140.14.0/24`),
//! `opendns-familyshield` (Cisco `146.112.61.104/29`),
//! `dns4eu-protective`, `dns4eu-child` (Scaleway `51.15.69.11/32`).
//! `quorum::evaluate` detects those via the `SINKHOLE_NETS` prefix table in
//! `upstream.rs`. That table is hard-coded, so if a provider moves its block
//! IP **out of its declared prefix**, detection silently stops counting that
//! voter's blocks (a false negative — never a wrong block of user traffic).
//!
//! This tool re-checks the table against live behaviour: for each preset it
//! resolves a domain that preset is known to block (a canary) plus the
//! provider's own site as a control, and prints whether the answer landed
//! `IN` or `OUT` of the declared prefix. Run it before a release, or whenever
//! coverage for one of these presets looks wrong in `phase1_metrics`. An
//! `OUT` result means: re-probe, then update `SINKHOLE_NETS`.
//!
//! DNS resolution only — never an HTTP connection to any listed host.

use dnsqb_service::{
    sinkhole_nets_for, DohClient, ReqwestDohClient, SinkholeNet, BASELINE_DOH_URL,
};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use std::error::Error;
use std::net::IpAddr;
use std::time::Duration;

const PER_DOMAIN_DELAY: Duration = Duration::from_millis(150);
const URLHAUS_RECENT_CSV: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";

/// One preset to recalibrate: its `id`, a canary domain it is expected to
/// block, and the provider's own domain as a "must NOT be seen as a sinkhole"
/// control.
struct Target {
    id: &'static str,
    /// Known-blocked canary. For the pure-malware presets there is no stable
    /// canary — `""` means "use a fresh URLhaus host at run time instead".
    canary: &'static str,
    control: &'static str,
}

const TARGETS: &[Target] = &[
    Target {
        id: "opendns-familyshield",
        // Cisco/OpenDNS's own permanent phishing test domain — stable for years.
        canary: "internetbadguys.com",
        control: "opendns.com",
    },
    Target {
        id: "adguard-family",
        canary: "pornhub.com",
        control: "adguard.com",
    },
    Target {
        id: "dns4eu-child",
        canary: "pornhub.com",
        control: "joindns4.eu",
    },
    Target {
        id: "adguard",
        // No stable malware canary — filled from URLhaus at run time.
        canary: "",
        control: "adguard.com",
    },
    Target {
        id: "dns4eu-protective",
        canary: "",
        control: "joindns4.eu",
    },
];

const PRESET_URL: &[(&str, &str)] = &[
    ("adguard", "https://dns.adguard-dns.com/dns-query"),
    ("adguard-family", "https://family.adguard-dns.com/dns-query"),
    (
        "opendns-familyshield",
        "https://doh.familyshield.opendns.com/dns-query",
    ),
    (
        "dns4eu-protective",
        "https://protective.joindns4.eu/dns-query",
    ),
    ("dns4eu-child", "https://child.joindns4.eu/dns-query"),
];

fn preset_url(id: &str) -> &'static str {
    PRESET_URL
        .iter()
        .find(|(preset, _)| *preset == id)
        .map_or("", |(_, url)| url)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = ReqwestDohClient::new()?;
    let malware_canaries = fetch_urlhaus_domains(&client, 12).await.unwrap_or_default();

    let mut stale = 0usize;
    for target in TARGETS {
        let url = preset_url(target.id);
        let nets = sinkhole_nets_for(target.id);
        println!("\n===== {} ({}) =====", target.id, describe_nets(nets));

        // Control: the provider's own domain must resolve OUTSIDE its prefix.
        match observe(&client, url, target.control).await {
            Ok(ips) => {
                let inside = ips.iter().any(|ip| in_any(*ip, nets));
                println!(
                    "  control {:<22} ips={ips:?}  {}",
                    target.control,
                    if inside {
                        "[!] control resolves INSIDE the prefix - prefix too wide"
                    } else {
                        "ok (outside prefix)"
                    }
                );
                if inside {
                    stale += 1;
                }
            }
            Err(err) => println!("  control {:<22} ERR {err}", target.control),
        }
        tokio::time::sleep(PER_DOMAIN_DELAY).await;

        // Canary: a known-blocked domain must resolve INSIDE the prefix.
        let canaries: Vec<String> = if target.canary.is_empty() {
            malware_canaries.clone()
        } else {
            vec![target.canary.to_string()]
        };
        let mut seen_in = false;
        for canary in &canaries {
            match observe(&client, url, canary).await {
                Ok(ips) => {
                    let inside = ips.iter().any(|ip| in_any(*ip, nets));
                    if inside {
                        seen_in = true;
                    }
                    println!(
                        "  canary  {canary:<22} ips={ips:?}  {}",
                        if inside { "IN prefix" } else { "not in prefix" }
                    );
                }
                Err(err) => println!("  canary  {canary:<22} ERR {err}"),
            }
            tokio::time::sleep(PER_DOMAIN_DELAY).await;
            if seen_in && target.canary.is_empty() {
                break; // one confirmed malware hit is enough for the pure-malware presets
            }
        }
        if !seen_in {
            println!("  [!] no canary landed inside {}'s prefix - it may have rotated; re-probe and update SINKHOLE_NETS", target.id);
            stale += 1;
        }
    }

    if stale == 0 {
        println!("\nOK - every sinkhole prefix still matches live behaviour.");
        Ok(())
    } else {
        Err(format!("{stale} sinkhole prefix(es) look stale - see [!] lines above").into())
    }
}

fn describe_nets(nets: &[SinkholeNet]) -> String {
    if nets.is_empty() {
        return "no sinkhole prefix".to_string();
    }
    nets.iter()
        .map(|net| format!("{net:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn in_any(ip: IpAddr, nets: &[SinkholeNet]) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    nets.iter().any(|net| net.contains(ip))
}

/// Resolve `domain`'s A **and** AAAA records via `url` (or the baseline if
/// `url` is empty), returning every answer IP. A non-`NoError` rcode
/// contributes nothing — the caller reads "no IP inside the prefix" from
/// that, which is the point.
async fn observe(
    client: &ReqwestDohClient,
    url: &str,
    domain: &str,
) -> Result<Vec<IpAddr>, Box<dyn Error>> {
    let endpoint = if url.is_empty() {
        BASELINE_DOH_URL
    } else {
        url
    };
    let mut ips = Vec::new();
    for qtype in [RecordType::A, RecordType::AAAA] {
        let response = client.query(endpoint, &build_query(domain, qtype)?).await?;
        if response.metadata.response_code != ResponseCode::NoError {
            continue;
        }
        for record in &response.answers {
            match &record.data {
                RData::A(A(ip)) => ips.push(IpAddr::V4(*ip)),
                RData::AAAA(AAAA(ip)) => ips.push(IpAddr::V6(*ip)),
                _ => {}
            }
        }
    }
    Ok(ips)
}

fn build_query(domain: &str, qtype: RecordType) -> Result<Message, Box<dyn Error>> {
    let mut question = Query::new();
    question.set_name(Name::from_utf8(domain)?);
    question.set_query_type(qtype);
    question.set_query_class(DNSClass::IN);
    let mut message = Message::query();
    message.add_query(question);
    message.metadata.recursion_desired = true;
    Ok(message)
}

/// A handful of fresh URLhaus domain hosts (bare IPs dropped) for the
/// pure-malware presets that have no stable canary.
async fn fetch_urlhaus_domains(
    client: &ReqwestDohClient,
    cap: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    let text = reqwest::Client::new()
        .get(URLHAUS_RECENT_CSV)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let mut out = Vec::new();
    for line in text.lines() {
        if out.len() >= cap {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.trim_matches('"').split("\",\"").collect();
        let Some(url_field) = fields.get(2) else {
            continue;
        };
        let Ok(parsed) = reqwest::Url::parse(url_field) else {
            continue;
        };
        let Some(host) = parsed.host_str() else {
            continue;
        };
        if host.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        // Keep only hosts the baseline resolves (so "not in prefix" means the
        // preset didn't sinkhole it, not that the domain is dead).
        let host = host.to_ascii_lowercase();
        let Ok(query) = build_query(&host, RecordType::A) else {
            continue;
        };
        let Ok(base) = client.query(BASELINE_DOH_URL, &query).await else {
            continue;
        };
        if base.metadata.response_code == ResponseCode::NoError {
            out.push(host);
        }
    }
    Ok(out)
}
