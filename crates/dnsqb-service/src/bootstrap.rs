//! Name resolution for this service's own outbound HTTPS clients (T-305
//! batch 3a): the `DoH` upstream client and [`crate::http_client`].
//!
//! While the plain-DNS listener is on, Windows may be pointed at our own
//! port 53, so asking the OS resolver would loop back into this service. In
//! that mode nothing here calls the OS resolver: the baseline hosts come from
//! [`PINNED_BASELINE`], every other host from a `DoH` A/AAAA lookup sent to a
//! pinned baseline. With the listener off, the OS resolver is used as before.
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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

/// The proxy variables `reqwest` reads (its system-proxy default).
const PROXY_VARS: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// The host names of the proxies in `values`, lowercased, without the root
/// dot. A value that does not parse as a URL is skipped: `reqwest` cannot use
/// it either, so no request goes there.
fn proxy_hosts_from(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|value| {
            let value = value.trim();
            let url = url::Url::parse(value)
                .ok()
                .filter(url::Url::has_host)
                // `host:port` with no scheme, as `reqwest` also accepts.
                .or_else(|| {
                    (!value.contains("://"))
                        .then(|| url::Url::parse(&format!("http://{value}")).ok())
                        .flatten()
                })?;
            match url.host()? {
                url::Host::Domain(host) => Some(host.trim_end_matches('.').to_ascii_lowercase()),
                // An IP literal never reaches a resolver.
                url::Host::Ipv4(_) | url::Host::Ipv6(_) => None,
            }
        })
        .collect()
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
        let (v4, v6) = tokio::join!(client.query(url, &a), client.query(url, &aaaa));
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

/// The resolver of every outbound client (see the module doc). `C` is the
/// bootstrap `DoH` client; only tests replace it.
pub(crate) struct OutboundResolver<C = ReqwestDohClient> {
    mode: ResolverMode,
    destinations: Destinations,
    bootstrap: Arc<C>,
    /// Proxy hosts from the environment at construction, resolved
    /// unfiltered: the operator chose them, and a proxy on this machine or
    /// the LAN is the usual case.
    proxy_hosts: Vec<String>,
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
        // A variable that is unset or not Unicode is no proxy for `reqwest`
        // either.
        let proxies = PROXY_VARS.iter().filter_map(|var| std::env::var(var).ok());
        Ok(Self::with_bootstrap(
            mode,
            destinations,
            Arc::new(bootstrap),
            proxy_hosts_from(proxies),
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
        }
    }

    /// Hosts whose addresses are used as resolved: built-in presets, the
    /// pinned baselines and the environment's proxies.
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

impl<C: DohClient + Send + Sync + 'static> reqwest::dns::Resolve for OutboundResolver<C> {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let bootstrap_mode = self.mode.is_bootstrap();
        let trusted = self.destinations == Destinations::Any || self.is_trusted(&host);
        let bootstrap = Arc::clone(&self.bootstrap);
        Box::pin(async move {
            let found: Vec<SocketAddr> = match (bootstrap_mode, pinned_addrs(&host)) {
                (true, Some(addrs)) => addrs,
                (true, None) => lookup_via_baseline(bootstrap.as_ref(), &host).await?,
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
        answer_ips, baseline_hosts, lookup_via_baseline, pinned_addrs, proxy_hosts_from,
        Destinations, OutboundResolver, ResolverMode, PINNED_BASELINE,
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
    }

    impl ScriptedBaselines {
        fn answering(v4: Ipv4Addr) -> Self {
            Self {
                failing: vec![],
                asked: Mutex::new(Vec::new()),
                v4,
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
            std::future::ready(Ok(self.answer_for(url, query)))
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
        let addrs: Vec<_> = match resolver.resolve(name("localhost")).await {
            Ok(addrs) => addrs.collect(),
            Err(err) => panic!("bootstrap lookup: {err}"),
        };
        // The baseline's answer, not the OS's loopback one.
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
        let (resolver, _) = scripted(&mode, PUBLIC, &[]);
        assert!(resolver.resolve(name("localhost")).await.is_err());
        mode.set_bootstrap(true);
        assert!(resolver.resolve(name("localhost")).await.is_ok());
        mode.set_bootstrap(false);
        assert!(resolver.resolve(name("localhost")).await.is_err());
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

    #[test]
    fn proxy_hosts_are_read_from_urls_and_bare_host_ports() {
        let hosts = proxy_hosts_from(
            [
                "http://Proxy.Corp.:3128",
                "socks5://user:pw@socks.lan:1080",
                "localhost:8888",
                " http://127.0.0.1:8080 ",
                "http://[::1]:8080",
                "",
                "http://",
                "::not a url::",
            ]
            .map(String::from),
        );
        assert_eq!(hosts, vec!["proxy.corp", "socks.lan", "localhost"]);
    }
}
