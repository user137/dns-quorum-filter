//! Manual T-168 load-test harness — **not** run in CI, **not** part of the
//! shipped binary. Same category as `examples/phase1_metrics.rs`.
//!
//! Measures how `dnsqb-service`'s connection/request layer behaves under
//! concurrency, with **zero real upstream calls** — every query in this file
//! resolves against a synthetic blocklist entry (`blocklist_response_with_meta`,
//! `pipeline.rs` — no `client` parameter at all, confirmed by reading the
//! code, not assumed). This deliberately isolates the accept-loop/TLS/hyper/
//! `overrides::decision` layer from quorum fan-out, so it needs no live-
//! upstream ToS review (TASKS.md T-133) and produces deterministic numbers.
//!
//! **The allowlist path was considered and rejected for this purpose**:
//! `pipeline.rs`'s `Allowlist` branch calls `baseline_passthrough_with_meta`,
//! which makes a real network call to the baseline resolver — not a local
//! path. **A cache-hit curve was considered and rejected too**: the cache is
//! only ever populated from the real quorum `Allow` path (`handle_allow`,
//! `pipeline.rs`) — `baseline_passthrough_with_meta` never calls
//! `cache.insert` — so there is no way to warm the cache without at least one
//! live upstream round-trip. `moka`'s O(1) lookup is already a well-
//! documented property of the crate (CLAUDE.md's gotchas) and doesn't need a
//! live measurement the way `overrides::decision`'s O(n) scan does.
//!
//! **Two curves**, both against the same synthetic target domain, blocklisted
//! either way:
//! 1. `n=1` — exactly one blocklist entry (the target). Isolates the
//!    connection/TLS/hyper ceiling with the override scan effectively free.
//! 2. `n≈10_000` — the target plus ~10k padding entries. Compared against
//!    curve 1 at one fixed concurrency level, this is the measured cost of
//!    `overrides::decision`'s linear scan at a realistic-to-generous list
//!    size, not an assumption from reading the code.
//!
//! **Two concurrency shapes** at each curve (they measure different things):
//! - *Many connections, one request each* — a fresh `reqwest::Client` per
//!   request (no connection reuse), modeling N independent local DoH clients.
//! - *One shared client, many concurrent requests* — one `reqwest::Client`
//!   reused across all concurrent requests, relying on `reqwest`/`hyper`'s own
//!   HTTP/2 connection reuse, modeling one client multiplexing many queries
//!   (a browser or stub resolver's typical shape). The exact number of TCP
//!   connections `reqwest`'s pool opens is **not** observed from the client
//!   side — past the 200-streams-per-connection cap (`hyper` 1.11.0's own
//!   server h2 default, see PERFORMANCE.md) it may open more connections
//!   rather than queue, and this harness can't tell which. So this shape
//!   measures a shared-client path, not "one connection" specifically.
//!
//! Every result is bucketed into success / connect-error (the client
//! couldn't even establish the connection — `reqwest::Error::is_connect`) /
//! other request error, specifically so a client-side ceiling (e.g. running
//! out of ephemeral ports on this single Windows dev box) isn't
//! misread as a server-side one — advisor review of the plan flagged this as
//! the harness's most likely self-inflicted failure mode at high concurrency.
//!
//! **Preconditions**: run against a **scratch** `dnsqb-service` instance, not
//! the default app-data directory — this tool overwrites `overrides.toml`
//! directly (faster and safer than thousands of individual
//! `/admin/overrides/add` calls, which would also each pay a full
//! file-rewrite cost). Start the service with a scratch `LOCALAPPDATA`:
//!
//! ```text
//! $env:LOCALAPPDATA = "C:\temp\dnsqb-loadtest"
//! cargo run --bin dnsqb-service
//! ```
//!
//! then run this tool with the **same** `$env:LOCALAPPDATA` set in its own
//! shell (so `app_data_dir()` resolves to the same `cert.pem`/`overrides.toml`):
//!
//! ```text
//! $env:LOCALAPPDATA = "C:\temp\dnsqb-loadtest"
//! cargo run --example load_test [port]
//! ```
//!
//! Also samples the target process's memory (RSS) via `sysinfo` during each
//! run, reading `service.pid` (`watchdog::instance`, T-92) to find the PID —
//! reported as a Windows working-set number, not "file descriptors" (that
//! framing doesn't apply on this platform).
//!
//! Before the ramps, one response is decoded and checked to be an actual
//! `0.0.0.0` NULL-block — a bare HTTP 200 is not enough (a DoH SERVFAIL is
//! also 200, rcode inside), and the whole point is that these numbers belong
//! to the blocklist path, not a failing quorum or an offline fast-path.
//!
//! The scratch instance mints its own Windows Credential Manager TLS-key
//! entry (`doh-tls-private-key:<hash>` for the scratch app-data dir) — benign
//! and per convention, but it stays after the run; remove it with a
//! `keyring` probe or `cmdkey` if you care.
//!
//! Output is a report to stdout only.

use dnsqb_service::{
    app_data_dir, decode_wire_message, doh_get_url, encode_wire_message, read_pid_file,
    InstanceRole,
};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use reqwest::Certificate;
use serde::Serialize;
use std::error::Error;
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};
use tokio::task::JoinSet;

const DEFAULT_LOCAL_PORT: u16 = 8443;
const TARGET_DOMAIN: &str = "loadtest-target.example";
const OVERRIDE_SCALE_COUNT: usize = 10_000;
const MANY_CONNECTIONS_LEVELS: &[usize] = &[50, 200, 1000, 3000];
const MANY_STREAMS_LEVELS: &[usize] = &[50, 200, 500, 2000];
const FIXED_COMPARISON_LEVEL: usize = 200;
const RSS_SAMPLE_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Success,
    ConnectError,
    RequestError,
}

#[derive(Serialize)]
struct OverridesFile {
    allowlist: Vec<String>,
    blocklist: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let port = local_port_from_args()?;
    let base_url = format!("https://127.0.0.1:{port}/dns-query");
    let admin_base = format!("https://127.0.0.1:{port}");
    let app_data = app_data_dir()?;
    let cert_pem = std::fs::read(app_data.join("cert.pem"))?;
    let query_bytes = build_query_bytes(TARGET_DOMAIN)?;
    let url = doh_get_url(&base_url, &query_bytes);

    println!("=== curve 1: n=1 override entry ===");
    write_overrides_blocklist(&app_data, vec![TARGET_DOMAIN.to_string()])?;
    reset_service(&cert_pem, &admin_base).await?;
    verify_block_response(&cert_pem, &url).await?;
    run_ramp(
        "many connections x 1 request",
        &cert_pem,
        &url,
        MANY_CONNECTIONS_LEVELS,
        true,
    )
    .await?;
    run_ramp(
        "one shared client x many requests",
        &cert_pem,
        &url,
        MANY_STREAMS_LEVELS,
        false,
    )
    .await?;

    println!("\n=== curve 2: n~{OVERRIDE_SCALE_COUNT} override entries (fixed concurrency {FIXED_COMPARISON_LEVEL}, compare against curve 1) ===");
    let mut padded: Vec<String> = (0..OVERRIDE_SCALE_COUNT)
        .map(|i| format!("loadtest-pad-{i:07}.example"))
        .collect();
    padded.push(TARGET_DOMAIN.to_string());
    write_overrides_blocklist(&app_data, padded)?;
    reset_service(&cert_pem, &admin_base).await?;
    run_ramp(
        "many connections x 1 request",
        &cert_pem,
        &url,
        &[FIXED_COMPARISON_LEVEL],
        true,
    )
    .await?;
    run_ramp(
        "one shared client x many requests",
        &cert_pem,
        &url,
        &[FIXED_COMPARISON_LEVEL],
        false,
    )
    .await?;

    // Leave the scratch instance's overrides.toml empty rather than full of
    // synthetic padding entries.
    write_overrides_blocklist(&app_data, Vec::new())?;
    reset_service(&cert_pem, &admin_base).await?;

    Ok(())
}

fn local_port_from_args() -> Result<u16, Box<dyn Error>> {
    match std::env::args().nth(1) {
        Some(arg) => Ok(arg.parse()?),
        None => Ok(DEFAULT_LOCAL_PORT),
    }
}

fn build_query_bytes(domain: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let name = Name::from_utf8(domain)?;
    let mut question = Query::new();
    question.set_name(name);
    question.set_query_type(RecordType::A);
    question.set_query_class(DNSClass::IN);
    let mut message = Message::query();
    message.add_query(question);
    message.metadata.recursion_desired = true;
    Ok(encode_wire_message(&message)?)
}

/// Overwrites `overrides.toml` directly — see the module doc comment for why
/// this needs a scratch app-data directory, never the default one.
fn write_overrides_blocklist(
    app_data: &std::path::Path,
    blocklist: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let file = OverridesFile {
        allowlist: Vec::new(),
        blocklist,
    };
    let toml = toml::to_string(&file)?;
    std::fs::write(app_data.join("overrides.toml"), toml)?;
    Ok(())
}

fn build_pinned_client_builder(cert_pem: &[u8]) -> Result<reqwest::ClientBuilder, Box<dyn Error>> {
    let cert = Certificate::from_pem(cert_pem)?;
    Ok(reqwest::Client::builder().add_root_certificate(cert))
}

async fn reset_service(cert_pem: &[u8], admin_base: &str) -> Result<(), Box<dyn Error>> {
    let client = build_pinned_client_builder(cert_pem)?.build()?;
    client
        .post(format!("{admin_base}/admin/reset"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Decodes one response and asserts it is an actual `0.0.0.0` NULL-block, not
/// just an HTTP 200 (a DoH SERVFAIL — from a failed quorum or T-152's offline
/// fast path — is also 200, with the rcode inside). Bails loudly: every
/// number the ramps produce is meaningless if the path under load isn't the
/// blocklist path.
async fn verify_block_response(cert_pem: &[u8], url: &str) -> Result<(), Box<dyn Error>> {
    let client = build_pinned_client_builder(cert_pem)?.build()?;
    let body = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let message = decode_wire_message(&body)?;
    let is_null_block =
        !message.answers.is_empty() && format!("{:?}", message.answers).contains("0.0.0.0");
    if !is_null_block {
        return Err(format!(
            "target domain did not return a 0.0.0.0 NULL-block — the ramp would measure the \
             wrong path. Decoded response: {message:?}"
        )
        .into());
    }
    println!("(verified: target resolves to a 0.0.0.0 NULL-block — blocklist path confirmed)");
    Ok(())
}

async fn run_ramp(
    label: &str,
    cert_pem: &[u8],
    url: &str,
    levels: &[usize],
    fresh_client_per_request: bool,
) -> Result<(), Box<dyn Error>> {
    println!("\n--- {label} ---");
    let pid = read_pid_file(&app_data_dir()?, InstanceRole::Service)
        .ok()
        .map(|f| f.pid);

    let shared_client = if fresh_client_per_request {
        None
    } else {
        Some(build_pinned_client_builder(cert_pem)?.build()?)
    };

    for &level in levels {
        let rss_before = pid.and_then(sample_rss_bytes);
        let started = Instant::now();
        let mut set = JoinSet::new();
        for _ in 0..level {
            let url = url.to_string();
            let cert_pem = cert_pem.to_vec();
            let shared = shared_client.clone();
            set.spawn(async move {
                let client = match shared {
                    Some(c) => c,
                    None => match build_pinned_client_builder(&cert_pem) {
                        Ok(builder) => match builder.pool_max_idle_per_host(0).build() {
                            Ok(c) => c,
                            Err(_) => return (Outcome::ConnectError, Duration::ZERO),
                        },
                        Err(_) => return (Outcome::ConnectError, Duration::ZERO),
                    },
                };
                let req_start = Instant::now();
                match client
                    .get(url)
                    .header(reqwest::header::ACCEPT, "application/dns-message")
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        (Outcome::Success, req_start.elapsed())
                    }
                    Ok(_) => (Outcome::RequestError, req_start.elapsed()),
                    Err(err) if err.is_connect() => (Outcome::ConnectError, req_start.elapsed()),
                    Err(_) => (Outcome::RequestError, req_start.elapsed()),
                }
            });
        }

        let mut successes = Vec::new();
        let mut connect_errors = 0usize;
        let mut request_errors = 0usize;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((Outcome::Success, elapsed)) => successes.push(elapsed),
                Ok((Outcome::ConnectError, _)) => connect_errors += 1,
                Ok((Outcome::RequestError, _)) => request_errors += 1,
                Err(_) => request_errors += 1,
            }
        }
        let wall = started.elapsed();
        let rss_after = pid.and_then(sample_rss_bytes);

        report_level(
            level,
            &successes,
            connect_errors,
            request_errors,
            wall,
            rss_before,
            rss_after,
        );
        tokio::time::sleep(RSS_SAMPLE_INTERVAL).await;
    }
    Ok(())
}

/// Resident-set size in bytes (`sysinfo::Process::memory` — bytes, not KB,
/// on this crate's pinned 0.39.6, confirmed by reading its doc comment).
fn sample_rss_bytes(pid: u32) -> Option<u64> {
    let mut system = System::new();
    let sys_pid = Pid::from_u32(pid);
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sys_pid]), true);
    system.process(sys_pid).map(sysinfo::Process::memory)
}

fn report_level(
    level: usize,
    successes: &[Duration],
    connect_errors: usize,
    request_errors: usize,
    wall: Duration,
    rss_before_bytes: Option<u64>,
    rss_after_bytes: Option<u64>,
) {
    let mut sorted = successes.to_vec();
    sorted.sort();
    let (p50, p99) = if sorted.is_empty() {
        (Duration::ZERO, Duration::ZERO)
    } else {
        let p50_idx = sorted.len() / 2;
        let p99_idx = ((sorted.len() * 99) / 100).min(sorted.len() - 1);
        (sorted[p50_idx], sorted[p99_idx])
    };
    let rss_delta = match (rss_before_bytes, rss_after_bytes) {
        (Some(before), Some(after)) => format!(
            "{} bytes",
            i64::try_from(after).unwrap_or(i64::MAX) - i64::try_from(before).unwrap_or(0)
        ),
        _ => "n/a (service.pid not found)".to_string(),
    };
    let success = sorted.len();
    println!(
        "level={level:>5}  success={success:>5}  connect_err={connect_errors:>5}  \
         request_err={request_errors:>5}  wall={wall:>8.2?}  p50={p50:>8.2?}  p99={p99:>8.2?}  \
         rss_delta={rss_delta}"
    );
}
