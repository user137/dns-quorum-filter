//! Name resolution for this service's own outbound HTTPS clients (T-305
//! batch 3a): the `DoH` upstream client and [`crate::http_client`].
//!
//! While the plain-DNS listener is on, Windows may be pointed at our own
//! port 53, so asking the OS resolver would loop back into this service. In
//! that mode nothing here calls the OS resolver: the baseline hosts come from
//! [`PINNED_BASELINE`], every other host from a `DoH` A/AAAA lookup sent to a
//! pinned baseline. With the listener off, the OS resolver is used as before.
//! Bootstrap answers are cached and looked up in a detached task: `reqwest`'s
//! 500 ms connect timeout also covers name resolution, so a lookup that ran
//! inside it would be cut short on a slow or blackholed first baseline and
//! never finish. Local-only names (`localhost`, `.local`, …) are answered
//! here in that mode, never sent to a public resolver.
//! For the `DoH` client, a non-built-in host is then left with its public
//! addresses only (the T-72 SSRF check, applied after resolution) — except
//! a proxy host named in the environment, which the operator chose. The
//! other outbound clients reach only hosts this code names, so they take
//! addresses as resolved ([`Destinations::Any`]): a network whose DNS maps
//! a reachability marker to an internal proxy must not read as offline.

use crate::baseline_selector::BASELINE_CHAIN;
use crate::upstream::{
    is_builtin_host, public_addrs, DohClient, NoPublicAddress, ReqwestDohClient,
};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Addresses of the [`BASELINE_CHAIN`] hosts, from the providers' own
/// documentation (2026-11-28): Cloudflare `developers.cloudflare.com/1.1.1.1/
/// ip-addresses`, Quad9 `quad9.net/service/service-addresses-and-features`
/// (Unsecured), Google `developers.google.com/speed/public-dns/docs/using`.
/// `examples/bootstrap_probe` checks each one still serves `DoH` under its
/// host name; run it before a release.
pub const PINNED_BASELINE: [(&str, [IpAddr; 4]); 3] = [
    (
        "cloudflare-dns.com",
        [
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
        ],
    ),
    (
        "dns10.quad9.net",
        [
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 10)),
            IpAddr::V4(Ipv4Addr::new(149, 112, 112, 10)),
            IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x10)),
            IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0xfe, 0x10)),
        ],
    ),
    (
        "dns.google",
        [
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
        ],
    ),
];

/// The pinned addresses of `host`, if it is a baseline host.
pub(crate) fn pinned_addrs(host: &str) -> Option<Vec<SocketAddr>> {
    let host = host.trim_end_matches('.');
    PINNED_BASELINE
        .iter()
        .find(|(pinned, _)| pinned.eq_ignore_ascii_case(host))
        .map(|(_, ips)| ips.iter().map(|ip| SocketAddr::new(*ip, 0)).collect())
}

/// Whether the outbound clients must avoid the OS resolver — `true` while the
/// plain-DNS listener is on. One shared handle: the admin route flips it, every
/// client built from it reads it at each lookup.
#[derive(Debug, Clone, Default)]
pub struct ResolverMode(Arc<AtomicBool>);

impl ResolverMode {
    /// Switch between the OS resolver (`false`) and the bootstrap path (`true`).
    pub fn set_bootstrap(&self, on: bool) {
        self.0.store(on, Ordering::Relaxed);
    }

    /// Whether lookups currently take the bootstrap path.
    #[must_use]
    pub fn is_bootstrap(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// No baseline answered the bootstrap lookup. Names no host.
#[derive(Debug)]
struct BootstrapUnavailable;

impl std::fmt::Display for BootstrapUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no pinned baseline answered the bootstrap lookup")
    }
}

impl std::error::Error for BootstrapUnavailable {}

/// A host outside [`PINNED_BASELINE`] asked of the bootstrap client. Names no
/// host.
#[derive(Debug)]
struct NotPinned;

impl std::fmt::Display for NotPinned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the bootstrap client only reaches pinned baseline hosts")
    }
}

impl std::error::Error for NotPinned {}

/// A host the bootstrap lookup cannot put in a DNS query. Names no host
/// (hickory's own parse error may quote it).
#[derive(Debug)]
struct InvalidHostName;

impl std::fmt::Display for InvalidHostName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a valid DNS host name")
    }
}

impl std::error::Error for InvalidHostName {}

/// A local-only name (RFC 6761 and friends, [`crate::local_names`]) asked
/// for in bootstrap mode; it never goes to a public resolver.
#[derive(Debug)]
struct LocalOnlyName;

impl std::fmt::Display for LocalOnlyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a local-only name is not looked up through a public resolver")
    }
}

impl std::error::Error for LocalOnlyName {}

/// The proxy host `reqwest` uses for an `https://` request — the only kind
/// our clients send — as hyper-util 0.1.20 (`Matcher::from_env`) picks it:
/// the first set of `HTTPS_PROXY`/`https_proxy`, or if that does not parse,
/// the first set of `ALL_PROXY`/`all_proxy`; none at all under CGI
/// (`REQUEST_METHOD` set). Lowercased, without the root dot; `None` also for
/// an IP literal, which never reaches a resolver. `HTTP_PROXY` is not read:
/// it applies to `http://` requests only.
fn env_proxy_host(is_cgi: bool, var: impl Fn(&str) -> Option<String>) -> Option<String> {
    if is_cgi {
        return None;
    }
    let first = |names: [&str; 2]| names.into_iter().find_map(&var);
    let used = first(["HTTPS_PROXY", "https_proxy"])
        .and_then(|value| proxy_uri_host(&value))
        .or_else(|| first(["ALL_PROXY", "all_proxy"]).and_then(|value| proxy_uri_host(&value)));
    match used? {
        ProxyHost::Name(host) => Some(host),
        ProxyHost::IpLiteral => None,
    }
}

/// The host of a proxy URI hyper-util accepts.
enum ProxyHost {
    Name(String),
    IpLiteral,
}

/// `None` when hyper-util would not use `value` as a proxy.
fn proxy_uri_host(value: &str) -> Option<ProxyHost> {
    let uri = value.parse::<http::Uri>().ok()?;
    if let Some(scheme) = uri.scheme_str() {
        let known = ["http", "https", "socks4", "socks4a", "socks5", "socks5h"];
        if !known.iter().any(|k| k.eq_ignore_ascii_case(scheme)) {
            return None;
        }
    }
    let host = uri.authority()?.host();
    if host.starts_with('[') || host.parse::<IpAddr>().is_ok() {
        return Some(ProxyHost::IpLiteral);
    }
    Some(ProxyHost::Name(
        host.trim_end_matches('.').to_ascii_lowercase(),
    ))
}

/// The bootstrap client's resolver: [`PINNED_BASELINE`] and nothing else, so
/// a bootstrap lookup can never recurse into another lookup.
#[derive(Debug)]
struct PinnedOnlyResolver;

impl reqwest::dns::Resolve for PinnedOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let found = pinned_addrs(name.as_str());
        Box::pin(async move {
            match found {
                Some(addrs) => Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs),
                None => Err(Box::new(NotPinned) as BoxError),
            }
        })
    }
}

/// A recursion-desired query for `name`/`qtype`.
fn lookup_query(name: Name, qtype: RecordType) -> Message {
    let mut message = Message::query();
    message.add_query(Query::query(name, qtype));
    message.metadata.recursion_desired = true;
    message
}

/// The A/AAAA addresses in a usable answer; `None` for SERVFAIL/REFUSED and
/// the like, so the next baseline is tried.
fn answer_ips(response: &Message) -> Option<Vec<IpAddr>> {
    match response.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => Some(
            response
                .answers
                .iter()
                .filter_map(|record| match &record.data {
                    RData::A(a) => Some(IpAddr::V4(a.0)),
                    RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

/// How long one baseline gets for its A+AAAA pair before the next is tried:
/// the bootstrap client has only a connect timeout, so a baseline that
/// accepts TCP and then stalls would otherwise hold the whole lookup.
const BASELINE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

/// A and AAAA for `host` through the baselines in [`BASELINE_CHAIN`] order;
/// the first baseline that answers either query wins.
async fn lookup_via_baseline<C: DohClient>(
    client: &C,
    host: &str,
) -> Result<Vec<SocketAddr>, BoxError> {
    let name = Name::from_ascii(host).map_err(|_| Box::new(InvalidHostName) as BoxError)?;
    let a = lookup_query(name.clone(), RecordType::A);
    let aaaa = lookup_query(name, RecordType::AAAA);
    for url in BASELINE_CHAIN {
        let attempt = tokio::time::timeout(BASELINE_ATTEMPT_TIMEOUT, async {
            tokio::join!(client.query(url, &a), client.query(url, &aaaa))
        });
        let Ok((v4, v6)) = attempt.await else {
            continue;
        };
        let v4 = v4.ok().as_ref().and_then(answer_ips);
        let v6 = v6.ok().as_ref().and_then(answer_ips);
        if v4.is_none() && v6.is_none() {
            continue;
        }
        return Ok(v4
            .into_iter()
            .chain(v6)
            .flatten()
            .map(|ip| SocketAddr::new(ip, 0))
            .collect());
    }
    Err(Box::new(BootstrapUnavailable))
}

/// Which resolved addresses a client may connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Destinations {
    /// Public addresses only, unless the host is built-in, pinned or an
    /// environment proxy — the `DoH` client, whose custom hosts the user
    /// typed.
    PublicOnly,
    /// Every address — clients whose hosts are constants in this code.
    Any,
}

/// How long a bootstrap answer is used without asking again.
const BOOTSTRAP_FRESH_FOR: Duration = Duration::from_secs(300);
/// How long a stale answer is still served while a refresh runs.
const BOOTSTRAP_STALE_FOR: Duration = Duration::from_hours(24);
/// Deadline of one detached lookup (every baseline in turn).
const BOOTSTRAP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Hosts cached, and lookups in flight, each at most this many: the hosts
/// are the presets, the custom providers and our own constant hosts.
const BOOTSTRAP_CACHE_CAP: usize = 64;

/// A lookup in flight: `None` until it finishes; the error carries no detail
/// (it is never shown — waiters report [`BootstrapUnavailable`]).
type Pending = tokio::sync::watch::Receiver<Option<Result<Vec<SocketAddr>, ()>>>;

struct Cached {
    addrs: Vec<SocketAddr>,
    at: Instant,
}

/// Bootstrap answers and the lookups in flight, keyed by lowercase host.
#[derive(Default)]
struct BootstrapCache {
    entries: HashMap<String, Cached>,
    pending: HashMap<String, Pending>,
}

impl BootstrapCache {
    fn store(&mut self, host: String, addrs: Vec<SocketAddr>, at: Instant) {
        if self.entries.len() >= BOOTSTRAP_CACHE_CAP && !self.entries.contains_key(&host) {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, cached)| cached.at)
                .map(|(host, _)| host.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(host, Cached { addrs, at });
    }
}

/// The resolver of every outbound client (see the module doc). `C` is the
/// bootstrap `DoH` client; only tests replace it.
pub(crate) struct OutboundResolver<C = ReqwestDohClient> {
    mode: ResolverMode,
    destinations: Destinations,
    bootstrap: Arc<C>,
    /// The environment's proxy host at construction, resolved unfiltered:
    /// the operator chose it, and a proxy on this machine or the LAN is the
    /// usual case.
    proxy_hosts: Vec<String>,
    cache: Arc<parking_lot::Mutex<BootstrapCache>>,
}

impl OutboundResolver {
    /// # Errors
    ///
    /// The bootstrap client's TLS backend failed to initialise.
    pub(crate) fn new(
        mode: ResolverMode,
        destinations: Destinations,
    ) -> Result<Self, reqwest::Error> {
        let bootstrap = ReqwestDohClient::bootstrap(Arc::new(PinnedOnlyResolver))?;
        let is_cgi = std::env::var_os("REQUEST_METHOD").is_some();
        // A variable that is unset or not Unicode is no proxy for `reqwest`
        // either.
        let proxy = env_proxy_host(is_cgi, |var| std::env::var(var).ok());
        Ok(Self::with_bootstrap(
            mode,
            destinations,
            Arc::new(bootstrap),
            proxy.into_iter().collect(),
        ))
    }
}

impl<C> OutboundResolver<C> {
    pub(crate) fn with_bootstrap(
        mode: ResolverMode,
        destinations: Destinations,
        bootstrap: Arc<C>,
        proxy_hosts: Vec<String>,
    ) -> Self {
        Self {
            mode,
            destinations,
            bootstrap,
            proxy_hosts,
            cache: Arc::default(),
        }
    }

    /// Hosts whose addresses are used as resolved: built-in presets, the
    /// pinned baselines and the environment's proxy.
    fn is_trusted(&self, host: &str) -> bool {
        let bare = host.trim_end_matches('.');
        is_builtin_host(host)
            || pinned_addrs(host).is_some()
            || self
                .proxy_hosts
                .iter()
                .any(|proxy| proxy.eq_ignore_ascii_case(bare))
    }
}

/// Bootstrap mode, a host that is not pinned: a local-only name is answered
/// here, anything else from the cache or a detached lookup.
async fn bootstrap_lookup<C: DohClient + Send + Sync + 'static>(
    bootstrap: Arc<C>,
    cache: Arc<parking_lot::Mutex<BootstrapCache>>,
    host: String,
) -> Result<Vec<SocketAddr>, BoxError> {
    match crate::local_names::local_answer(&host, RecordType::A).map(|reply| reply.answer) {
        Some(crate::local_names::LocalAnswer::Loopback) => {
            return Ok(vec![
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
                SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0),
            ]);
        }
        Some(
            crate::local_names::LocalAnswer::NxDomain | crate::local_names::LocalAnswer::NoData,
        ) => {
            return Err(Box::new(LocalOnlyName));
        }
        None => {}
    }
    let key = host.trim_end_matches('.').to_ascii_lowercase();
    let mut pending = {
        let mut guard = cache.lock();
        let now = Instant::now();
        let cached = guard.entries.get(&key).map(|cached| {
            (
                cached.addrs.clone(),
                now.saturating_duration_since(cached.at),
            )
        });
        match cached {
            Some((addrs, age)) if age < BOOTSTRAP_FRESH_FOR => return Ok(addrs),
            Some((addrs, age)) if age < BOOTSTRAP_STALE_FOR => {
                // A refresh that can't start (cap reached) is retried by the
                // next caller; the stale answer serves meanwhile.
                let _ = start_lookup(&mut guard, &cache, &bootstrap, key);
                return Ok(addrs);
            }
            _ => match start_lookup(&mut guard, &cache, &bootstrap, key) {
                Some(pending) => pending,
                None => return Err(Box::new(BootstrapUnavailable)),
            },
        }
    };
    let done = pending
        .wait_for(Option::is_some)
        .await
        .map_err(|_| Box::new(BootstrapUnavailable) as BoxError)?;
    match done.as_ref() {
        Some(Ok(addrs)) => Ok(addrs.clone()),
        Some(Err(())) | None => Err(Box::new(BootstrapUnavailable)),
    }
}

/// Joins the lookup of `key` in flight, or starts one in a detached task that
/// outlives a caller cut short by a connect timeout and fills the cache.
/// `None` when [`BOOTSTRAP_CACHE_CAP`] lookups are already in flight.
fn start_lookup<C: DohClient + Send + Sync + 'static>(
    guard: &mut BootstrapCache,
    cache: &Arc<parking_lot::Mutex<BootstrapCache>>,
    bootstrap: &Arc<C>,
    key: String,
) -> Option<Pending> {
    if let Some(pending) = guard.pending.get(&key) {
        return Some(pending.clone());
    }
    if guard.pending.len() >= BOOTSTRAP_CACHE_CAP {
        return None;
    }
    let (done, pending) = tokio::sync::watch::channel(None);
    guard.pending.insert(key.clone(), pending.clone());
    let cache = Arc::clone(cache);
    let bootstrap = Arc::clone(bootstrap);
    tokio::spawn(async move {
        let found = tokio::time::timeout(
            BOOTSTRAP_LOOKUP_TIMEOUT,
            lookup_via_baseline(bootstrap.as_ref(), &key),
        )
        .await;
        let result = match found {
            Ok(Ok(addrs)) => Ok(addrs),
            Ok(Err(_)) | Err(_) => Err(()),
        };
        {
            let mut guard = cache.lock();
            guard.pending.remove(&key);
            if let Ok(addrs) = &result {
                if !addrs.is_empty() {
                    guard.store(key, addrs.clone(), Instant::now());
                }
            }
        }
        // `send_replace` never fails: a lookup every caller gave up on still
        // lands in the cache above.
        done.send_replace(Some(result));
    });
    Some(pending)
}

impl<C: DohClient + Send + Sync + 'static> reqwest::dns::Resolve for OutboundResolver<C> {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let bootstrap_mode = self.mode.is_bootstrap();
        let trusted = self.destinations == Destinations::Any || self.is_trusted(&host);
        let bootstrap = Arc::clone(&self.bootstrap);
        let cache = Arc::clone(&self.cache);
        Box::pin(async move {
            let found: Vec<SocketAddr> = match (bootstrap_mode, pinned_addrs(&host)) {
                (true, Some(addrs)) => addrs,
                (true, None) => bootstrap_lookup(bootstrap, cache, host).await?,
                (false, _) => tokio::net::lookup_host((host.as_str(), 0)).await?.collect(),
            };
            let addrs = if trusted {
                found
            } else {
                let public = public_addrs(found);
                if public.is_empty() {
                    return Err(Box::new(NoPublicAddress) as BoxError);
                }
                public
            };
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Every [`BASELINE_CHAIN`] host has pinned addresses (checked by a test).
#[cfg(test)]
fn baseline_hosts() -> impl Iterator<Item = &'static str> {
    BASELINE_CHAIN
        .into_iter()
        .filter_map(crate::upstream::https_url_host)
}

#[cfg(test)]
mod tests {
    use super::{
        answer_ips, baseline_hosts, env_proxy_host, lookup_via_baseline, pinned_addrs,
        Destinations, OutboundResolver, ResolverMode, BOOTSTRAP_FRESH_FOR, PINNED_BASELINE,
    };
    use crate::upstream::{DohClient, UpstreamError};
    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use reqwest::dns::Resolve;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::Mutex;

    #[test]
    fn every_baseline_host_is_pinned_and_only_to_public_addresses() {
        for host in baseline_hosts() {
            let Some(addrs) = pinned_addrs(host) else {
                panic!("baseline host {host} has no pinned addresses");
            };
            assert!(!addrs.is_empty());
            assert_eq!(
                crate::upstream::public_addrs(addrs.clone()),
                addrs,
                "{host}: a pinned address is not public"
            );
        }
        assert_eq!(PINNED_BASELINE.len(), baseline_hosts().count());
    }

    #[test]
    fn pinned_lookup_ignores_case_and_the_root_dot() {
        assert!(pinned_addrs("DNS.Google.").is_some());
        assert!(pinned_addrs("dns.google.example.com").is_none());
        assert!(pinned_addrs("").is_none());
    }

    #[test]
    fn the_mode_handle_is_shared_by_every_clone() {
        let mode = ResolverMode::default();
        let seen_by_client = mode.clone();
        assert!(!seen_by_client.is_bootstrap());
        mode.set_bootstrap(true);
        assert!(seen_by_client.is_bootstrap());
        mode.set_bootstrap(false);
        assert!(!seen_by_client.is_bootstrap());
    }

    fn answer(code: ResponseCode, rdata: Vec<RData>) -> Message {
        let mut message = Message::query();
        message.metadata.response_code = code;
        for data in rdata {
            message
                .answers
                .push(Record::from_rdata(Name::root(), 60, data));
        }
        message
    }

    #[test]
    fn answer_ips_reads_a_and_aaaa_and_rejects_a_failed_answer() {
        let ok = answer(
            ResponseCode::NoError,
            vec![
                RData::A(A(Ipv4Addr::new(9, 9, 9, 9))),
                RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
            ],
        );
        assert_eq!(
            answer_ips(&ok),
            Some(vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ])
        );
        assert_eq!(
            answer_ips(&answer(ResponseCode::NXDomain, vec![])),
            Some(vec![])
        );
        assert_eq!(answer_ips(&answer(ResponseCode::ServFail, vec![])), None);
        assert_eq!(answer_ips(&answer(ResponseCode::Refused, vec![])), None);
    }

    /// Answers per baseline URL; records every URL asked. `v4` is the A
    /// answer of every baseline that does not fail.
    struct ScriptedBaselines {
        failing: Vec<&'static str>,
        asked: Mutex<Vec<String>>,
        v4: Ipv4Addr,
        /// How long each answer takes (paused-time tests).
        delay: std::time::Duration,
        /// Baselines that accept the query and never answer.
        hanging: Vec<&'static str>,
    }

    impl ScriptedBaselines {
        fn answering(v4: Ipv4Addr) -> Self {
            Self {
                failing: vec![],
                asked: Mutex::new(Vec::new()),
                v4,
                delay: std::time::Duration::ZERO,
                hanging: vec![],
            }
        }

        fn slow(delay: std::time::Duration) -> Self {
            Self {
                delay,
                ..Self::answering(PUBLIC)
            }
        }

        fn failing(failing: Vec<&'static str>) -> Self {
            Self {
                failing,
                ..Self::answering(Ipv4Addr::new(192, 0, 2, 1))
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().map(|a| a.clone()).unwrap_or_default()
        }
    }

    impl DohClient for ScriptedBaselines {
        fn query(
            &self,
            url: &str,
            query: &Message,
        ) -> impl std::future::Future<Output = Result<Message, UpstreamError>> + Send {
            let answer = self.answer_for(url, query);
            let delay = self.delay;
            let hangs = self.hanging.contains(&url);
            async move {
                if hangs {
                    std::future::pending::<()>().await;
                }
                tokio::time::sleep(delay).await;
                Ok(answer)
            }
        }
    }

    impl ScriptedBaselines {
        fn answer_for(&self, url: &str, query: &Message) -> Message {
            if let Ok(mut asked) = self.asked.lock() {
                asked.push(url.to_owned());
            }
            if self.failing.contains(&url) {
                return answer(ResponseCode::ServFail, vec![]);
            }
            let qtype = query
                .queries
                .first()
                .map(hickory_proto::op::Query::query_type);
            if qtype == Some(RecordType::AAAA) {
                return answer(ResponseCode::NoError, vec![]);
            }
            answer(ResponseCode::NoError, vec![RData::A(A(self.v4))])
        }
    }

    #[tokio::test]
    async fn a_failing_baseline_falls_through_to_the_next() {
        let client = ScriptedBaselines::failing(vec![crate::baseline_selector::BASELINE_CHAIN[0]]);
        let addrs = match lookup_via_baseline(&client, "example.org").await {
            Ok(addrs) => addrs,
            Err(err) => panic!("lookup: {err}"),
        };
        assert_eq!(addrs.len(), 1);
        let asked = client.asked();
        assert!(asked.contains(&crate::baseline_selector::BASELINE_CHAIN[1].to_owned()));
        assert!(!asked.contains(&crate::baseline_selector::BASELINE_CHAIN[2].to_owned()));
    }

    // A first baseline that takes the query and stalls (TLS or HTTP held
    // open) gets its own deadline; the next one answers.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_baseline_falls_through_to_the_next() {
        let client = ScriptedBaselines {
            hanging: vec![crate::baseline_selector::BASELINE_CHAIN[0]],
            ..ScriptedBaselines::answering(PUBLIC)
        };
        let found = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            lookup_via_baseline(&client, "example.org"),
        )
        .await;
        assert!(
            matches!(found, Ok(Ok(ref addrs)) if addrs.len() == 1),
            "{found:?}"
        );
        assert!(client
            .asked()
            .contains(&crate::baseline_selector::BASELINE_CHAIN[1].to_owned()));
    }

    #[tokio::test]
    async fn every_baseline_failing_is_an_error_naming_no_host() {
        let client = ScriptedBaselines::failing(crate::baseline_selector::BASELINE_CHAIN.to_vec());
        let Err(err) = lookup_via_baseline(&client, "secret-host.example").await else {
            panic!("no baseline answered, the lookup must fail");
        };
        assert!(!err.to_string().contains("secret-host"), "{err}");
    }

    #[tokio::test]
    async fn a_malformed_host_name_is_an_error_not_a_query() {
        let client = ScriptedBaselines::failing(vec![]);
        let Err(err) = lookup_via_baseline(&client, "bad..name").await else {
            panic!("a malformed name must not resolve");
        };
        assert!(!err.to_string().contains("bad"), "{err}");
        assert!(client.asked().is_empty());
    }

    // Bootstrap mode, pinned host: the answer is the table, no lookup at all
    // (offline-safe).
    #[tokio::test]
    async fn bootstrap_mode_answers_a_baseline_host_from_the_table() {
        let mode = ResolverMode::default();
        let resolver = match OutboundResolver::new(mode.clone(), Destinations::PublicOnly) {
            Ok(resolver) => resolver,
            Err(err) => panic!("resolver: {err}"),
        };
        mode.set_bootstrap(true);
        let name = match "dns.google".parse::<reqwest::dns::Name>() {
            Ok(name) => name,
            Err(err) => panic!("valid name: {err}"),
        };
        let addrs: Vec<_> = match resolver.resolve(name).await {
            Ok(addrs) => addrs.collect(),
            Err(err) => panic!("pinned lookup: {err}"),
        };
        assert_eq!(Some(addrs), pinned_addrs("dns.google"));
    }

    fn name(host: &str) -> reqwest::dns::Name {
        match host.parse::<reqwest::dns::Name>() {
            Ok(name) => name,
            Err(err) => panic!("valid name {host}: {err}"),
        }
    }

    fn scripted(
        mode: &ResolverMode,
        v4: Ipv4Addr,
        proxies: &[&str],
    ) -> (OutboundResolver<ScriptedBaselines>, Arc<ScriptedBaselines>) {
        let baselines = Arc::new(ScriptedBaselines::answering(v4));
        let proxies = proxies.iter().map(|p| (*p).to_owned()).collect();
        let resolver = OutboundResolver::with_bootstrap(
            mode.clone(),
            Destinations::PublicOnly,
            Arc::clone(&baselines),
            proxies,
        );
        (resolver, baselines)
    }

    const PUBLIC: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

    // RFC 6761: `localhost` resolves to loopback through every OS resolver,
    // offline too — so an OS answer and a bootstrap answer are told apart.
    #[tokio::test]
    async fn off_the_os_resolver_answers_and_a_loopback_only_custom_host_is_refused() {
        let mode = ResolverMode::default();
        let (resolver, baselines) = scripted(&mode, PUBLIC, &[]);
        let Err(err) = resolver.resolve(name("localhost")).await else {
            panic!("a loopback-only custom host must not resolve");
        };
        assert!(
            err.downcast_ref::<crate::upstream::NoPublicAddress>()
                .is_some(),
            "{err}"
        );
        assert!(!err.to_string().contains("localhost"), "{err}");
        assert!(
            baselines.asked().is_empty(),
            "off must not use the bootstrap"
        );
    }

    #[tokio::test]
    async fn on_a_custom_host_is_looked_up_through_a_pinned_baseline() {
        let mode = ResolverMode::default();
        mode.set_bootstrap(true);
        let (resolver, baselines) = scripted(&mode, PUBLIC, &[]);
        let addrs: Vec<_> = match resolver.resolve(name("custom.example")).await {
            Ok(addrs) => addrs.collect(),
            Err(err) => panic!("bootstrap lookup: {err}"),
        };
        assert_eq!(addrs, vec![std::net::SocketAddr::new(PUBLIC.into(), 0)]);
        assert_eq!(
            baselines.asked().first().map(String::as_str),
            Some(crate::baseline_selector::BASELINE_CHAIN[0])
        );
    }

    #[tokio::test]
    async fn on_a_baseline_answer_with_only_private_addresses_is_refused() {
        let mode = ResolverMode::default();
        mode.set_bootstrap(true);
        let (resolver, _) = scripted(&mode, Ipv4Addr::new(10, 0, 0, 1), &[]);
        let Err(err) = resolver.resolve(name("rebind.example")).await else {
            panic!("a private-only answer must not resolve");
        };
        assert!(
            err.downcast_ref::<crate::upstream::NoPublicAddress>()
                .is_some(),
            "{err}"
        );
    }

    #[tokio::test]
    async fn the_lookup_path_follows_the_mode_live() {
        let mode = ResolverMode::default();
        let (resolver, baselines) = scripted(&mode, PUBLIC, &[]);
        assert!(resolver.resolve(name("custom.example")).await.is_err());
        assert!(baselines.asked().is_empty());
        mode.set_bootstrap(true);
        assert!(resolver.resolve(name("custom.example")).await.is_ok());
        assert!(!baselines.asked().is_empty());
    }

    // In bootstrap mode `localhost` is answered here and the other local-only
    // names are refused — none of them reaches a public resolver.
    #[tokio::test]
    async fn on_local_only_names_never_reach_a_baseline() {
        let mode = ResolverMode::default();
        mode.set_bootstrap(true);
        let baselines = Arc::new(ScriptedBaselines::answering(PUBLIC));
        let resolver = OutboundResolver::with_bootstrap(
            mode,
            Destinations::Any,
            Arc::clone(&baselines),
            Vec::new(),
        );
        let addrs: Vec<_> = match resolver.resolve(name("localhost")).await {
            Ok(addrs) => addrs.collect(),
            Err(err) => panic!("localhost: {err}"),
        };
        assert!(!addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback()));
        for host in ["printer.local", "router.home.arpa", "intranet"] {
            assert!(resolver.resolve(name(host)).await.is_err(), "{host}");
        }
        assert!(baselines.asked().is_empty());
    }

    // reqwest's connect timeout (500 ms) also covers resolution: a caller cut
    // short must not cancel the lookup — it finishes and fills the cache.
    #[tokio::test(start_paused = true)]
    async fn a_lookup_outlives_a_caller_cut_short_and_is_cached() {
        let mode = ResolverMode::default();
        mode.set_bootstrap(true);
        let baselines = Arc::new(ScriptedBaselines::slow(std::time::Duration::from_secs(2)));
        let resolver = OutboundResolver::with_bootstrap(
            mode,
            Destinations::PublicOnly,
            Arc::clone(&baselines),
            Vec::new(),
        );
        let cut_short = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            resolver.resolve(name("slow.example")),
        )
        .await;
        assert!(cut_short.is_err(), "the first caller times out");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let asked = baselines.asked().len();
        let again = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            resolver.resolve(name("slow.example")),
        )
        .await;
        assert!(matches!(again, Ok(Ok(_))), "served from the cache");
        assert_eq!(baselines.asked().len(), asked, "no second lookup");
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_share_one_lookup() {
        let mode = ResolverMode::default();
        mode.set_bootstrap(true);
        let baselines = Arc::new(ScriptedBaselines::slow(std::time::Duration::from_secs(1)));
        let resolver = OutboundResolver::with_bootstrap(
            mode,
            Destinations::PublicOnly,
            Arc::clone(&baselines),
            Vec::new(),
        );
        let (a, b) = tokio::join!(
            resolver.resolve(name("shared.example")),
            resolver.resolve(name("shared.example"))
        );
        assert!(a.is_ok() && b.is_ok());
        // One A and one AAAA query to the first baseline.
        assert_eq!(baselines.asked().len(), 2);
    }

    // A stale answer is served at once while a refresh runs behind it.
    #[tokio::test(start_paused = true)]
    async fn a_stale_answer_is_served_while_it_refreshes() {
        let mode = ResolverMode::default();
        mode.set_bootstrap(true);
        let baselines = Arc::new(ScriptedBaselines::slow(std::time::Duration::from_secs(1)));
        let resolver = OutboundResolver::with_bootstrap(
            mode,
            Destinations::PublicOnly,
            Arc::clone(&baselines),
            Vec::new(),
        );
        assert!(resolver.resolve(name("stale.example")).await.is_ok());
        tokio::time::advance(BOOTSTRAP_FRESH_FOR + std::time::Duration::from_secs(1)).await;
        let stale = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            resolver.resolve(name("stale.example")),
        )
        .await;
        assert!(matches!(stale, Ok(Ok(_))), "stale served without waiting");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert_eq!(baselines.asked().len(), 4, "one refresh ran");
    }

    // A proxy on this machine (`localhost:8888`) is the operator's choice,
    // so its loopback address is kept.
    #[tokio::test]
    async fn an_environment_proxy_host_is_resolved_unfiltered() {
        let mode = ResolverMode::default();
        let (resolver, _) = scripted(&mode, PUBLIC, &["localhost"]);
        let addrs: Vec<_> = match resolver.resolve(name("LOCALHOST.")).await {
            Ok(addrs) => addrs.collect(),
            Err(err) => panic!("proxy host: {err}"),
        };
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
        assert!(!addrs.is_empty());
    }

    // Bootstrap mode, the trusted proxy `localhost`: answered locally and
    // kept although the `DoH` client keeps public addresses only.
    #[tokio::test]
    async fn on_a_trusted_localhost_proxy_keeps_its_loopback_address() {
        let mode = ResolverMode::default();
        mode.set_bootstrap(true);
        let (resolver, baselines) = scripted(&mode, PUBLIC, &["localhost"]);
        let addrs: Vec<_> = match resolver.resolve(name("localhost")).await {
            Ok(addrs) => addrs.collect(),
            Err(err) => panic!("proxy host: {err}"),
        };
        assert!(!addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback()));
        assert!(baselines.asked().is_empty());
    }

    // The non-`DoH` clients reach only our own constant hosts: an internal
    // answer (a proxy, a captive portal) is used, not refused.
    #[tokio::test]
    async fn any_destinations_keep_a_private_answer() {
        let mode = ResolverMode::default();
        let resolver = OutboundResolver::with_bootstrap(
            mode.clone(),
            Destinations::Any,
            Arc::new(ScriptedBaselines::answering(Ipv4Addr::new(10, 0, 0, 1))),
            Vec::new(),
        );
        let addrs: Vec<_> = match resolver.resolve(name("localhost")).await {
            Ok(addrs) => addrs.collect(),
            Err(err) => panic!("OS answer kept: {err}"),
        };
        assert!(!addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback()));
        mode.set_bootstrap(true);
        let addrs: Vec<_> = match resolver.resolve(name("marker.example")).await {
            Ok(addrs) => addrs.collect(),
            Err(err) => panic!("bootstrap answer kept: {err}"),
        };
        assert_eq!(
            addrs,
            vec![std::net::SocketAddr::new(
                Ipv4Addr::new(10, 0, 0, 1).into(),
                0
            )]
        );
    }

    fn proxy_of(vars: &[(&str, &str)]) -> Option<String> {
        env_proxy_host(false, |name| {
            vars.iter()
                .find(|(var, _)| *var == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn the_proxy_host_is_the_one_reqwest_uses_for_https() {
        assert_eq!(
            proxy_of(&[("HTTPS_PROXY", "http://Proxy.Corp.:3128")]).as_deref(),
            Some("proxy.corp")
        );
        assert_eq!(
            proxy_of(&[("ALL_PROXY", "socks5://user:pw@socks.lan:1080")]).as_deref(),
            Some("socks.lan")
        );
        // No scheme: hyper-util assumes http.
        assert_eq!(
            proxy_of(&[("HTTPS_PROXY", "localhost:8888")]).as_deref(),
            Some("localhost")
        );
        // HTTPS wins over ALL; the upper-case name wins over the lower-case.
        assert_eq!(
            proxy_of(&[
                ("ALL_PROXY", "http://all.lan"),
                ("https_proxy", "http://https.lan")
            ])
            .as_deref(),
            Some("https.lan")
        );
        assert_eq!(
            proxy_of(&[
                ("HTTPS_PROXY", "http://upper.lan"),
                ("https_proxy", "http://lower.lan")
            ])
            .as_deref(),
            Some("upper.lan")
        );
        // An unusable HTTPS value falls back to ALL, as hyper-util does.
        assert_eq!(
            proxy_of(&[("HTTPS_PROXY", ""), ("ALL_PROXY", "http://all.lan")]).as_deref(),
            Some("all.lan")
        );
        assert_eq!(
            proxy_of(&[
                ("HTTPS_PROXY", "ftp://x.lan"),
                ("ALL_PROXY", "http://all.lan")
            ])
            .as_deref(),
            Some("all.lan")
        );
    }

    // Misuse: variables reqwest ignores for https never make a host trusted.
    #[test]
    fn hosts_reqwest_would_not_use_are_not_trusted() {
        assert_eq!(proxy_of(&[("HTTP_PROXY", "http://gw.corp:3128")]), None);
        assert_eq!(proxy_of(&[("HTTPS_PROXY", "http://127.0.0.1:8080")]), None);
        assert_eq!(proxy_of(&[("HTTPS_PROXY", "http://[::1]:8080")]), None);
        // An IP literal in HTTPS is used by reqwest, so ALL is not.
        assert_eq!(
            proxy_of(&[
                ("HTTPS_PROXY", "http://10.0.0.1:3128"),
                ("ALL_PROXY", "http://all.lan")
            ]),
            None
        );
        assert_eq!(
            env_proxy_host(true, |_| Some("http://proxy.corp".to_owned())),
            None,
            "CGI: reqwest ignores the variables"
        );
    }
}
