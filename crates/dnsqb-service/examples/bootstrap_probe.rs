//! T-305 bootstrap recalibrator — **not** CI, run before a release (like
//! `sinkhole_probe`).
//!
//! With the plain-DNS listener on, the service never asks the OS resolver:
//! the baseline hosts come from the hard-coded `PINNED_BASELINE` table and
//! every other outbound host is looked up over `DoH` through those pinned
//! addresses. If a provider retires one of them, the bootstrap path quietly
//! loses that address (or the whole baseline).
//!
//! Two checks:
//! 1. every pinned address answers `DoH` for its host name over TLS (the
//!    certificate must match the host, so a reassigned address fails);
//!    the OS resolver's answer for the host is printed alongside, for
//!    information only — anycast hosts often resolve elsewhere;
//! 2. in bootstrap mode, every built-in preset URL answers a query — this
//!    exercises the `DoH` lookup of each preset host through the baselines.
//!
//! Non-zero exit if an IPv4 pinned address fails, an IPv6 one fails while
//! another IPv6 one works (IPv6 reachable here), or a preset fails. One query
//! per address/preset — a few dozen requests in total.

use dnsqb_service::{
    all_builtin_presets, doh_get_url, DohClient, ReqwestDohClient, ResolverMode, PINNED_BASELINE,
};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const PROBE_NAME: &str = "example.com.";
const TIMEOUT: Duration = Duration::from_secs(5);

fn probe_query() -> Result<Message, Box<dyn Error>> {
    let mut message = Message::query();
    message.add_query(Query::query(Name::from_ascii(PROBE_NAME)?, RecordType::A));
    message.metadata.recursion_desired = true;
    Ok(message)
}

/// One `DoH` GET to `https://<host>/dns-query`, connecting to `ip` only.
async fn doh_via(host: &str, ip: IpAddr, wire: &[u8]) -> Result<ResponseCode, Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .resolve(host, SocketAddr::new(ip, 443))
        .build()?;
    let url = doh_get_url(&format!("https://{host}/dns-query"), wire);
    let response = client
        .get(url)
        .header("accept", "application/dns-message")
        .send()
        .await?
        .error_for_status()?;
    let body = response.bytes().await?;
    Ok(Message::from_vec(&body)?.metadata.response_code)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let query = probe_query()?;
    let wire = query.to_vec()?;
    let mut failures = 0usize;

    println!("1. pinned baseline addresses");
    for (host, ips) in PINNED_BASELINE {
        let system: Vec<IpAddr> = match tokio::net::lookup_host((host, 443)).await {
            Ok(addrs) => addrs.map(|a| a.ip()).collect(),
            Err(err) => {
                println!("  {host}: OS lookup failed ({err})");
                Vec::new()
            }
        };
        println!("  {host}: OS resolver says {system:?}");
        let mut v6_ok = false;
        let mut v6_failed = 0usize;
        for ip in ips {
            let result = doh_via(host, ip, &wire).await;
            let ok = matches!(result, Ok(ResponseCode::NoError));
            let listed = if system.contains(&ip) {
                " (also from OS)"
            } else {
                ""
            };
            match &result {
                Ok(code) => println!("    {ip}: {code}{listed}"),
                Err(err) => println!("    {ip}: FAIL {err}{listed}"),
            }
            match (ip, ok) {
                (IpAddr::V4(_), false) => failures += 1,
                (IpAddr::V6(_), true) => v6_ok = true,
                (IpAddr::V6(_), false) => v6_failed += 1,
                (IpAddr::V4(_), true) => {}
            }
        }
        if v6_ok {
            failures += v6_failed;
        } else if v6_failed > 0 {
            println!("    (no IPv6 address answered — no IPv6 route here? not counted)");
        }
    }

    println!("2. built-in presets in bootstrap mode");
    let mode = ResolverMode::default();
    mode.set_bootstrap(true);
    let client = ReqwestDohClient::with_mode(&mode)?;
    for preset in all_builtin_presets() {
        match client.query(&preset.doh_url, &query).await {
            Ok(response) => println!("  {}: {}", preset.id, response.metadata.response_code),
            Err(err) => {
                failures += 1;
                println!("  {}: FAIL {err} {:?}", preset.id, err.http_detail());
            }
        }
    }

    if failures > 0 {
        return Err(format!("{failures} check(s) failed").into());
    }
    println!("all checks passed");
    Ok(())
}
