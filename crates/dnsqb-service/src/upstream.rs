//! `DoH` transport to a single upstream (RFC 8484 GET, T-9/T-21; T-22
//! baseline client; T-24 upstream client). Since T-72/T-73 the voter set is a
//! runtime-configured list of [`ProviderSpec`]s (built-in §3.4 presets or a
//! user-added custom `https` endpoint), not a fixed 2-variant enum.

use crate::wire::{decode_wire_message, encode_wire_message};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_proto::op::Message;
use hickory_proto::ProtoError;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// SPEC.md §3.6 (T-31): idle HTTP/2 connections to an upstream are dropped
/// after this long. Short relative to `reqwest`'s 90s default — a `DoH`
/// resolver is bursty (a page load fires many lookups, then goes quiet for
/// a while), so holding idle connections open past a browsing pause just
/// wastes upstream-side resources without saving a meaningful number of
/// handshakes.
const UPSTREAM_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Interval between HTTP/2 keepalive pings on idle upstream connections, and
/// how long to wait for a pong before treating the connection as dead
/// (SPEC.md §3.6, T-31) — keeps NAT/firewall state alive between bursts of
/// queries without waiting for a full new TLS handshake on the next one.
const UPSTREAM_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const UPSTREAM_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-connection-attempt timeout (T-154). Without it, `reqwest`/`hyper`
/// tries a `DoH` hostname's resolved addresses sequentially but only
/// advances past one that fails *fast* (RST); a blackholed first address
/// (packets dropped, no reply) instead holds the whole per-query budget, so
/// a provider's second IP is never tried on the outage shape that matters
/// most. Set well below the per-query timeout (`TimeoutConfig::default()`'s
/// 2s) so a second-address attempt still fits inside one query —
/// empirically confirmed to restore multi-address failover for the
/// blackhole shape (`CLAUDE.md` gotcha, kickoff `resolve_to_addrs` probe).
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// RFC 8484 §4.1.1 (T-9): `application/dns-message` GET-request URL —
/// unpadded base64url `dns=` parameter (SPEC.md §1, §3).
#[must_use]
pub fn doh_get_url(base: &str, message_bytes: &[u8]) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(message_bytes);
    format!("{base}?dns={encoded}")
}

/// Filtering category a preset belongs to (SPEC.md §3.4) — drives the
/// `/admin/ui` grouping and the first-run default (Security only, see
/// `config::ResolverConfig`). Baseline-resolver alternatives from §3.4 are a
/// separate concern (the baseline endpoint is not admin-selectable yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    /// Malware / phishing (Quad9 Filtered, `Cloudflare` Malware, ...).
    Security,
    /// Ads + trackers + malware (`AdGuard` Default).
    AdsTrackers,
    /// Adds adult-content blocking (`Cloudflare` Family, `OpenDNS`
    /// `FamilyShield`, ...).
    AdultContent,
}

/// How [`crate::quorum`] decides a given upstream's response means "blocked"
/// (T-72/T-73). Only Quad9 and `AdGuard` were live-verified (DECISIONS.md
/// 2026-08-25, n=1); every other preset's value is derived from that
/// provider's published behaviour and carries a `#[ignore]`d live-verify
/// test until confirmed. A user-added custom provider defaults to the
/// permissive [`BlockSignature::NullIpOrNxdomain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockSignature {
    /// An `A`/`AAAA` answer containing `0.0.0.0` / `::` (`AdGuard`,
    /// `Cloudflare` Malware/Family).
    NullIp,
    /// `NXDOMAIN`, undecidable on its own — needs the baseline resolver to
    /// tell a filter block from genuine non-existence (Quad9, `OpenDNS`
    /// `FamilyShield`). SPEC.md §3.1.
    NxdomainVsBaseline,
    /// Either of the above — the permissive default for a custom endpoint
    /// whose block shape isn't known ahead of time, and (T-174) the
    /// `CleanBrowsing` presets, whose published `0.0.0.0` behaviour was
    /// observed to actually be `NXDOMAIN`.
    NullIpOrNxdomain,
}

/// One upstream filtering resolver in the quorum's voter set (T-72/T-73).
/// Built either from a built-in §3.4 preset ([`builtin_preset`]) or from a
/// user-added custom entry in `resolver_config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSpec {
    /// Lowercase wire identifier, unique within the active set — the value
    /// the `GET /admin/log?voter=` facet and `VoterRecord::provider_id`
    /// carry.
    pub id: String,
    /// Human-readable name for the `/admin/ui` list.
    pub display_name: String,
    /// The `DoH` endpoint — always `https://` (enforced on config load and
    /// on `POST /admin/providers/add`).
    pub doh_url: String,
    /// Which `/admin/ui` group this provider sits in.
    pub category: Category,
    /// How the quorum reads this provider's block responses.
    pub block_signature: BlockSignature,
}

/// A configured voter: its [`ProviderSpec`] plus whether it is currently
/// enabled (T-72/T-73). `resolve` is handed the whole list — a disabled
/// entry still produces a [`crate::quorum::VoterRecord`] with
/// [`crate::quorum::VoterVerdict::Disabled`], so the query log stays honest
/// about who was configured but silent (T-148's invariant, generalized).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEntry {
    /// The provider definition.
    pub spec: ProviderSpec,
    /// Whether it is queried this round.
    pub enabled: bool,
}

impl ProviderEntry {
    /// The fresh-install default voter set — [`DEFAULT_PROVIDER_IDS`]
    /// (`quad9` + `cloudflare-malware` + `adguard`), all enabled — used when
    /// `resolver_config.toml` has no `[[providers]]`.
    #[must_use]
    pub fn default_active_set() -> Vec<Self> {
        DEFAULT_PROVIDER_IDS
            .iter()
            .filter_map(|id| builtin_preset(id))
            .map(|spec| Self {
                spec,
                enabled: true,
            })
            .collect()
    }

    /// Whether at least one configured provider is enabled. `false` is
    /// SPEC.md §3/§8.1's explicit pass-through case — resolution goes through
    /// the unfiltered baseline resolver instead of calling `quorum::resolve`.
    #[must_use]
    pub fn any_enabled(entries: &[Self]) -> bool {
        entries.iter().any(|entry| entry.enabled)
    }
}

/// The built-in §3.4 presets, in display order. `IPv4` bootstrap addresses
/// from that table are omitted deliberately — `ReqwestDohClient` resolves
/// each URL's host via the system resolver; a bootstrap-IP field would imply
/// a custom-bootstrap feature this project doesn't have.
const BUILTIN_PRESETS: &[(&str, &str, &str, Category, BlockSignature)] = &[
    (
        "quad9",
        "Quad9 Filtered",
        "https://dns.quad9.net/dns-query",
        Category::Security,
        BlockSignature::NxdomainVsBaseline,
    ),
    (
        "cloudflare-malware",
        "Cloudflare Malware (1.1.1.2)",
        "https://security.cloudflare-dns.com/dns-query",
        Category::Security,
        BlockSignature::NullIp,
    ),
    (
        "cleanbrowsing-security",
        "CleanBrowsing Security",
        "https://doh.cleanbrowsing.org/doh/security-filter/",
        Category::Security,
        // T-174 (2026-09-05): CleanBrowsing's published behaviour is
        // `0.0.0.0`, but `examples/phase1_metrics.rs` observed it return
        // NXDOMAIN for every domain it blocks (66/126 malware, 10/10 adult;
        // baseline resolved all of them). `NullIpOrNxdomain` accepts both so
        // a region/qtype that does answer `0.0.0.0` is still covered.
        BlockSignature::NullIpOrNxdomain,
    ),
    (
        "dns4eu-protective",
        "DNS4EU Protective",
        "https://protective.joindns4.eu/dns-query",
        Category::Security,
        BlockSignature::NullIpOrNxdomain,
    ),
    (
        "adguard",
        "AdGuard Default",
        "https://dns.adguard-dns.com/dns-query",
        Category::AdsTrackers,
        BlockSignature::NullIp,
    ),
    (
        "cloudflare-family",
        "Cloudflare Family (1.1.1.3)",
        "https://family.cloudflare-dns.com/dns-query",
        Category::AdultContent,
        BlockSignature::NullIp,
    ),
    (
        "adguard-family",
        "AdGuard Family",
        "https://family.adguard-dns.com/dns-query",
        Category::AdultContent,
        BlockSignature::NullIp,
    ),
    (
        "cleanbrowsing-adult",
        "CleanBrowsing Adult",
        "https://doh.cleanbrowsing.org/doh/adult-filter/",
        Category::AdultContent,
        // T-174: same as `cleanbrowsing-security` — observed NXDOMAIN, not
        // `0.0.0.0` (10/10 adult sample blocked via NXDOMAIN).
        BlockSignature::NullIpOrNxdomain,
    ),
    (
        "opendns-familyshield",
        "OpenDNS FamilyShield",
        "https://doh.familyshield.opendns.com/dns-query",
        Category::AdultContent,
        BlockSignature::NxdomainVsBaseline,
    ),
    (
        "dns4eu-child",
        "DNS4EU Child",
        "https://child.joindns4.eu/dns-query",
        Category::AdultContent,
        BlockSignature::NullIpOrNxdomain,
    ),
];

/// The `id`s of the presets enabled on a fresh install with no
/// `[[providers]]` in `resolver_config.toml`: two Security-tier voters
/// (`quad9` + `cloudflare-malware`, matching SPEC.md §3.4/§3.5's "Security
/// category only" first-run default) **plus** `adguard` for ads/trackers —
/// a deliberate divergence from the SPEC default, decided 2026-09-05
/// (T-170, `DECISIONS.md`): `adguard` filters ads out of the box rather
/// than as an opt-in category. Was `quad9` + `adguard` (the Phase-1
/// voters) up to that decision.
pub const DEFAULT_PROVIDER_IDS: &[&str] = &["quad9", "cloudflare-malware", "adguard"];

/// Resolve a built-in preset `id` to its full [`ProviderSpec`], or `None` if
/// `id` names no preset (i.e. it must be a custom entry carrying its own
/// `url`/`category`).
#[must_use]
pub fn builtin_preset(id: &str) -> Option<ProviderSpec> {
    BUILTIN_PRESETS
        .iter()
        .find(|(preset_id, ..)| *preset_id == id)
        .map(
            |&(id, display_name, doh_url, category, block_signature)| ProviderSpec {
                id: id.to_string(),
                display_name: display_name.to_string(),
                doh_url: doh_url.to_string(),
                category,
                block_signature,
            },
        )
}

/// Every built-in preset as a [`ProviderSpec`], display order — for the
/// `GET /admin/providers` "available presets" list.
#[must_use]
pub fn all_builtin_presets() -> Vec<ProviderSpec> {
    BUILTIN_PRESETS
        .iter()
        .map(
            |&(id, display_name, doh_url, category, block_signature)| ProviderSpec {
                id: id.to_string(),
                display_name: display_name.to_string(),
                doh_url: doh_url.to_string(),
                category,
                block_signature,
            },
        )
        .collect()
}

/// A network prefix that a built-in provider substitutes into DNS answers as
/// its "blocked" response — a sinkhole / block-page address, not `0.0.0.0` /
/// `::` and not NXDOMAIN (T-175, SPEC.md §3.4). `quorum::evaluate` matches an
/// A or AAAA answer against this **by network prefix**, not by exact address,
/// so a provider rotating the host bits of its block IP inside its own
/// netblock (which one might do specifically to defeat third parties keying
/// off a fixed `/32`) does not silently break detection — the failure mode is
/// a false *negative* (a real block goes uncounted), never a wrong block of
/// the user's traffic. An IPv4-mapped AAAA answer (`::ffff:a.b.c.d`, e.g.
/// `OpenDNS` `FamilyShield`) is matched against the v4 prefixes. Builtin-only:
/// a custom provider has no known sinkhole, so [`sinkhole_nets_for`] returns
/// `&[]` for it.
#[derive(Debug, Clone, Copy)]
pub struct SinkholeNet {
    /// The network address (host bits within `prefix` are zero for every
    /// entry in [`SINKHOLE_NETS`] — a test enforces it).
    addr: IpAddr,
    /// Prefix length — `1..=32` for a v4 `addr`, `1..=128` for v6. The
    /// max value matches one exact address; a `0` prefix (match everything)
    /// is deliberately unrepresentable — the table test rejects it, so
    /// `SinkholeNet` intentionally derives no `Default`.
    prefix: u8,
}

impl SinkholeNet {
    const fn v4(addr: Ipv4Addr, prefix: u8) -> Self {
        Self {
            addr: IpAddr::V4(addr),
            prefix,
        }
    }

    const fn v6(addr: Ipv6Addr, prefix: u8) -> Self {
        Self {
            addr: IpAddr::V6(addr),
            prefix,
        }
    }

    /// Whether `ip` falls inside this prefix (only same-family addresses can
    /// match). XOR then count leading equal bits — no shift, so there is no
    /// `<< 32` / `<< 128` overflow path and nothing about `WIDTH - prefix` to
    /// prove safe from the line (a panic on the query-serving path would be a
    /// watchdog restart loop). Max `prefix` ⇒ exact-address match only.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                (ip.to_bits() ^ net.to_bits()).leading_zeros() >= u32::from(self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                (ip.to_bits() ^ net.to_bits()).leading_zeros() >= u32::from(self.prefix)
            }
            _ => false,
        }
    }
}

/// Per-preset sinkhole prefixes (T-175). Keyed by the same `id` as
/// [`BUILTIN_PRESETS`]; a preset absent here has no sinkhole detection (its
/// `BlockSignature` alone decides). Prefixes are chosen from the **network
/// owner** (`RDAP`, verified 2026-09-06), not a vendor "block page IP" doc:
///
/// - `94.140.14.0/24` — inside `AdGuard` Software Limited's registered
///   `94.140.14.0/23` (`CY-ADGUARD-20081128`); their public resolvers
///   `94.140.14.14` / `94.140.14.15` sit in it. Filtering infrastructure, not
///   hosting, so a `/24` (absorbing host-bit rotation) carries ~no
///   legitimate-host risk. Observed block IPs 2026-09-05: `94.140.14.33`,
///   `94.140.14.35`.
/// - `146.112.61.104/29` — inside Cisco `OpenDNS` LLC's `146.112.0.0/16`
///   (`OpenDNS-RIPE`); the historically documented block-page range is
///   `146.112.61.104` to `146.112.61.110`. Far tighter than the allocation, so
///   safe. Observed 2026-09-05: `146.112.61.106`, `146.112.61.108`.
/// - `51.15.69.11/32` — `DNS4EU`'s block IP sits in `Scaleway`'s
///   `51.15.0.0/17` (`SCALEWAY-AMS`), a general cloud-hosting range, so
///   **no** prefix widening here — an exact address only; rotation resilience
///   for `DNS4EU` rests on the `sinkhole_probe` recalibrator (SPEC.md §3.4).
/// - `dns4eu-protective` and `dns4eu-child` also sinkhole **AAAA** to the same
///   native v6 address `2001:bc8:1640:3ffd:dc00:ff:fe4a:3ec9` (`Scaleway`
///   `2001:bc8::/29` general hosting) — pinned `/128`, same "no widening"
///   reasoning as the v4. Stable across ≥3 blocked domains for each preset,
///   `joindns4.eu` / `example.com` controls clean (2026-09-06).
///   `opendns-familyshield` sinkholes AAAA to `::ffff:146.112.61.108`, an
///   IPv4-mapped form of its v4 block IP — [`SinkholeNet::contains`]'s caller
///   unwraps that, so no separate v6 entry is needed. `adguard` /
///   `adguard-family` returned NODATA on AAAA for their canaries (2026-09-06)
///   — no v6 sinkhole observed; if one appears, add it here (see the
///   recalibrator).
///
/// **Widen a provider's prefix only on registry/`RDAP` evidence of
/// ownership**, never by "completing" a documented block-page range.
const SINKHOLE_NETS: &[(&str, &[SinkholeNet])] = &[
    (
        "adguard",
        &[SinkholeNet::v4(Ipv4Addr::new(94, 140, 14, 0), 24)],
    ),
    (
        "adguard-family",
        &[SinkholeNet::v4(Ipv4Addr::new(94, 140, 14, 0), 24)],
    ),
    (
        "opendns-familyshield",
        &[SinkholeNet::v4(Ipv4Addr::new(146, 112, 61, 104), 29)],
    ),
    ("dns4eu-protective", DNS4EU_SINKHOLE_NETS),
    ("dns4eu-child", DNS4EU_SINKHOLE_NETS),
];

/// Both DNS4EU presets substitute the same v4 and v6 block addresses.
const DNS4EU_SINKHOLE_NETS: &[SinkholeNet] = &[
    SinkholeNet::v4(Ipv4Addr::new(51, 15, 69, 11), 32),
    SinkholeNet::v6(
        Ipv6Addr::new(
            0x2001, 0x0bc8, 0x1640, 0x3ffd, 0xdc00, 0x00ff, 0xfe4a, 0x3ec9,
        ),
        128,
    ),
];

/// The sinkhole prefixes for a preset `id`, or `&[]` for a preset with no
/// known sinkhole and for every custom (non-builtin) provider (T-175). A free
/// function rather than a [`ProviderSpec`] field: `ProviderSpec` is
/// `Serialize + Deserialize` and a `&'static [SinkholeNet]` would not
/// round-trip through TOML, and this keeps the mechanism builtin-only by
/// construction.
#[must_use]
pub fn sinkhole_nets_for(id: &str) -> &'static [SinkholeNet] {
    SINKHOLE_NETS
        .iter()
        .find(|(preset_id, _)| *preset_id == id)
        .map_or(&[], |(_, nets)| *nets)
}

/// A custom provider's `id` must fit the same lowercase wire shape the
/// built-in ids use — the value flows into `VoterRecord::provider_id`, the
/// `?voter=` log facet, and the on-disk `[[providers]]` key.
#[must_use]
pub fn is_valid_provider_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Why a custom `DoH` provider URL was rejected (T-72). Payload-free — the
/// URL can embed a per-account NextDNS/ControlD profile id, so the reason
/// never carries the URL text itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProviderUrlError {
    /// Not a parseable absolute URL.
    #[error("provider URL is not a valid absolute URL")]
    Unparseable,
    /// Scheme is not `https`.
    #[error("provider URL must use https")]
    NotHttps,
    /// No host component.
    #[error("provider URL has no host")]
    NoHost,
    /// The host is a literal loopback / private / link-local IP address — a
    /// custom provider URL must point at a public resolver, never back at
    /// this machine or an internal service (SSRF). **Stated gap:** a
    /// *hostname* that later resolves to such an address is not caught here.
    #[error("provider URL host is a loopback, private, or link-local address")]
    NonPublicHost,
}

/// Validates a candidate custom `DoH` provider URL (T-72). Reused by
/// `config::ResolverConfig::load` and `POST /admin/providers/add` so both
/// reject the same shapes. See [`ProviderUrlError`] for what "public" means
/// and the gap that leaves.
///
/// # Errors
///
/// A [`ProviderUrlError`] variant for each rejected shape.
pub fn validate_provider_url(url: &str) -> Result<(), ProviderUrlError> {
    let parsed = url::Url::parse(url).map_err(|_| ProviderUrlError::Unparseable)?;
    if parsed.scheme() != "https" {
        return Err(ProviderUrlError::NotHttps);
    }
    match parsed.host() {
        None => Err(ProviderUrlError::NoHost),
        Some(url::Host::Domain(_)) => Ok(()),
        Some(url::Host::Ipv4(ip)) => {
            if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() {
                Err(ProviderUrlError::NonPublicHost)
            } else {
                Ok(())
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            // `Ipv6Addr::is_unique_local`/`is_unicast_link_local` are unstable;
            // check the documented prefixes directly. fc00::/7 (ULA),
            // fe80::/10 (link-local).
            let seg = ip.segments();
            let ula = (seg[0] & 0xfe00) == 0xfc00;
            let link_local = (seg[0] & 0xffc0) == 0xfe80;
            if ip.is_loopback() || ip.is_unspecified() || ula || link_local {
                Err(ProviderUrlError::NonPublicHost)
            } else {
                Ok(())
            }
        }
    }
}

/// The baseline (non-filtering) resolver's `DoH` endpoint (SPEC.md §3.4) —
/// used to disambiguate Quad9's NXDOMAIN from genuine non-existence (T-23)
/// and, later, for allowlist resolution (T-22's other half, wired at
/// T-37–T-41).
pub const BASELINE_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";

/// A `DoH` transport to a single upstream — a trait so quorum logic (T-24)
/// can be tested against mocked upstreams (T-61/T-62) instead of live
/// network calls.
pub trait DohClient {
    /// Send `query` to `url` and return the decoded response.
    fn query(
        &self,
        url: &str,
        query: &Message,
    ) -> impl Future<Output = Result<Message, UpstreamError>> + Send;
}

/// Errors from a single upstream `DoH` round-trip.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The outgoing query could not be wire-encoded.
    #[error("encoding outgoing query failed: {0}")]
    Encode(#[source] ProtoError),
    /// The HTTP request itself failed (network, TLS, non-2xx status).
    #[error("HTTP request to upstream failed: {0}")]
    Http(#[source] reqwest::Error),
    /// The response body was not a well-formed DNS wire-format message —
    /// e.g. `dns.quad9.net`'s HTML error page when HTTP/2 isn't negotiated
    /// (DECISIONS.md 2026-08-25, T-20).
    #[error("decoding upstream response failed: {0}")]
    Decode(#[source] ProtoError),
}

/// [`DohClient`] backed by a real `reqwest::Client` (T-24).
pub struct ReqwestDohClient {
    http: reqwest::Client,
}

impl ReqwestDohClient {
    /// Build a client with the `rustls`/HTTP-2 backend (SPEC.md "Технічний
    /// стек" — TLS only via `rustls`) and per-upstream HTTP/2 keep-alive
    /// (SPEC.md §3.6, T-31). Callers must reuse a single instance across
    /// queries — reconstructing one per query defeats the connection
    /// pooling configured here.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying TLS backend fails to initialize.
    pub fn new() -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .pool_idle_timeout(UPSTREAM_POOL_IDLE_TIMEOUT)
            .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
            .http2_keep_alive_interval(UPSTREAM_KEEP_ALIVE_INTERVAL)
            .http2_keep_alive_timeout(UPSTREAM_KEEP_ALIVE_TIMEOUT)
            .http2_keep_alive_while_idle(true)
            .build()?;
        Ok(Self { http })
    }
}

impl DohClient for ReqwestDohClient {
    async fn query(&self, url: &str, query: &Message) -> Result<Message, UpstreamError> {
        let bytes = encode_wire_message(query).map_err(UpstreamError::Encode)?;
        let request_url = doh_get_url(url, &bytes);
        let response = self
            .http
            .get(&request_url)
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .send()
            .await
            .map_err(UpstreamError::Http)?
            .error_for_status()
            .map_err(UpstreamError::Http)?
            .bytes()
            .await
            .map_err(UpstreamError::Http)?;
        decode_wire_message(&response).map_err(UpstreamError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        all_builtin_presets, builtin_preset, is_valid_provider_id, validate_provider_url,
        BlockSignature, Category, DohClient, ProviderEntry, ProviderSpec, ProviderUrlError,
        ReqwestDohClient, SinkholeNet, DEFAULT_PROVIDER_IDS,
    };
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    // T-72/T-73: the two live-verified Phase-1 signatures must survive the
    // move into the preset table unchanged (DECISIONS.md 2026-08-25).
    #[test]
    fn builtin_preset_resolves_the_two_phase1_voters_with_their_verified_signatures() {
        let (Some(quad9), Some(adguard)) = (builtin_preset("quad9"), builtin_preset("adguard"))
        else {
            panic!("quad9 and adguard are builtin presets");
        };
        assert_eq!(quad9.doh_url, "https://dns.quad9.net/dns-query");
        assert_eq!(quad9.category, Category::Security);
        assert_eq!(quad9.block_signature, BlockSignature::NxdomainVsBaseline);
        assert_eq!(adguard.doh_url, "https://dns.adguard-dns.com/dns-query");
        assert_eq!(adguard.category, Category::AdsTrackers);
        assert_eq!(adguard.block_signature, BlockSignature::NullIp);
    }

    // `default_active_set` builds via `filter_map(builtin_preset)`, which
    // silently drops an id that names no preset — a typo in
    // `DEFAULT_PROVIDER_IDS` would quietly shrink (or empty) the fresh-install
    // voter set, i.e. ship with filtering off. Pin the count.
    #[test]
    fn every_default_provider_id_resolves_to_a_preset() {
        let set = ProviderEntry::default_active_set();
        assert_eq!(set.len(), DEFAULT_PROVIDER_IDS.len());
        assert!(!set.is_empty(), "a fresh install must have voters");
        assert!(set.iter().all(|entry| entry.enabled));
    }

    // T-170 (DECISIONS.md 2026-09-05): the shipped first-run default is
    // pinned deliberately — two Security-tier voters plus AdGuard for ads.
    // A silent edit of `DEFAULT_PROVIDER_IDS` that drops the malware feed or
    // the ads feed changes what a fresh install blocks; make it loud.
    #[test]
    fn the_fresh_install_default_is_two_security_voters_plus_adguard() {
        let set = ProviderEntry::default_active_set();
        let ids: Vec<&str> = set.iter().map(|entry| entry.spec.id.as_str()).collect();
        assert_eq!(ids, ["quad9", "cloudflare-malware", "adguard"]);
        let security = set
            .iter()
            .filter(|entry| entry.spec.category == Category::Security)
            .count();
        assert_eq!(security, 2, "SPEC §3.4/§3.5 Security-tier core");
        assert!(
            set.iter()
                .any(|entry| entry.spec.category == Category::AdsTrackers),
            "T-170: AdGuard ships for ads out of the box"
        );
    }

    #[test]
    fn builtin_preset_returns_none_for_an_unknown_id() {
        assert_eq!(builtin_preset("Quad9"), None, "ids are lowercase, exact");
        assert_eq!(builtin_preset(""), None);
        assert_eq!(builtin_preset("my-custom-nextdns"), None);
    }

    #[test]
    fn every_builtin_preset_has_a_unique_lowercase_id_and_https_url() {
        let presets = all_builtin_presets();
        let mut ids: Vec<&str> = presets
            .iter()
            .map(|p: &ProviderSpec| p.id.as_str())
            .collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "preset ids must be unique");
        for preset in &presets {
            assert_eq!(preset.id, preset.id.to_lowercase(), "ids are lowercase");
            assert!(
                preset.doh_url.starts_with("https://"),
                "{} must be https",
                preset.id
            );
        }
    }

    #[test]
    fn validate_provider_url_accepts_a_public_https_endpoint() {
        assert_eq!(
            validate_provider_url("https://abcd1234.dns.nextdns.io/dns-query"),
            Ok(())
        );
        assert_eq!(validate_provider_url("https://8.8.8.8/dns-query"), Ok(()));
    }

    #[test]
    fn validate_provider_url_rejects_non_https_and_ssrf_hosts() {
        assert_eq!(
            validate_provider_url("http://dns.example.com/dns-query"),
            Err(ProviderUrlError::NotHttps)
        );
        assert_eq!(
            validate_provider_url("not a url"),
            Err(ProviderUrlError::Unparseable)
        );
        for ssrf in [
            "https://127.0.0.1/dns-query",
            "https://localhost.localdomain@127.0.0.1/dns-query",
            "https://10.0.0.5/dns-query",
            "https://192.168.1.1/dns-query",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/dns-query",
            "https://[fe80::1]/dns-query",
            "https://[fd00::1]/dns-query",
        ] {
            assert_eq!(
                validate_provider_url(ssrf),
                Err(ProviderUrlError::NonPublicHost),
                "{ssrf} must be rejected"
            );
        }
    }

    #[test]
    fn is_valid_provider_id_matches_the_wire_shape() {
        assert!(is_valid_provider_id("my-nextdns-1"));
        assert!(is_valid_provider_id("quad9"));
        assert!(!is_valid_provider_id(""));
        assert!(!is_valid_provider_id("MyNextDNS"));
        assert!(!is_valid_provider_id("has space"));
        assert!(!is_valid_provider_id("under_score"));
        assert!(!is_valid_provider_id(&"x".repeat(65)));
    }

    // T-31: proves the keep-alive/pool builder options are accepted by the
    // `rustls`/HTTP-2 backend. Doesn't prove connection reuse actually
    // happens across queries - that needs a live network test, out of scope
    // for unit coverage (TASKS.md T-31 notes this as partial coverage).
    #[test]
    fn client_with_keep_alive_settings_builds() {
        if let Err(err) = ReqwestDohClient::new() {
            panic!("client construction with keep-alive settings must not fail: {err}");
        }
    }

    // T-154(a): `reqwest`/`hyper` only advances to a DoH hostname's second
    // resolved address after the first when the first fails *fast* (RST) or
    // hits `connect_timeout`; a blackholed first address otherwise consumes
    // the whole per-query budget and the second IP is never tried
    // (empirically confirmed — see the CLAUDE.md gotcha). So the connect
    // timeout must sit safely below the per-query timeout, leaving room for
    // the second-address attempt within one query.
    #[test]
    fn connect_timeout_is_shorter_than_the_default_per_query_timeout() {
        assert!(
            super::UPSTREAM_CONNECT_TIMEOUT < crate::timeout::TimeoutConfig::default().duration,
            "connect timeout must leave room for a second-address attempt within one query"
        );
    }

    // --- T-175: sinkhole prefixes ---

    #[test]
    fn sinkhole_nets_for_known_preset_is_non_empty_and_custom_is_empty() {
        assert!(!super::sinkhole_nets_for("adguard").is_empty());
        assert!(!super::sinkhole_nets_for("opendns-familyshield").is_empty());
        assert!(!super::sinkhole_nets_for("dns4eu-child").is_empty());
        // A preset with no sinkhole, and a custom id, both resolve to nothing.
        assert!(super::sinkhole_nets_for("quad9").is_empty());
        assert!(super::sinkhole_nets_for("my-custom-resolver").is_empty());
        assert!(super::sinkhole_nets_for("").is_empty());
    }

    #[test]
    fn every_sinkhole_net_is_a_well_formed_prefix() {
        for (id, nets) in super::SINKHOLE_NETS {
            for net in *nets {
                let (max, host_bits, is_network_addr) = match net.addr {
                    IpAddr::V4(a) => {
                        let hb = 32 - u32::from(net.prefix);
                        let mask = if hb == 32 { 0 } else { u32::MAX << hb };
                        (32u8, hb, a.to_bits() & mask == a.to_bits())
                    }
                    IpAddr::V6(a) => {
                        let hb = 128 - u32::from(net.prefix);
                        let mask = if hb == 128 { 0 } else { u128::MAX << hb };
                        (128u8, hb, a.to_bits() & mask == a.to_bits())
                    }
                };
                assert!(
                    (1..=max).contains(&net.prefix),
                    "{id}: prefix /{} outside 1..={max}",
                    net.prefix
                );
                assert!(
                    net.contains(net.addr),
                    "{id}: net does not contain its own addr"
                );
                assert!(
                    is_network_addr,
                    "{id}: addr {} has host bits set for /{} ({host_bits} host bits)",
                    net.addr, net.prefix
                );
            }
        }
    }

    #[test]
    fn observed_block_ips_lie_inside_their_declared_prefix() {
        // The addresses `examples/sinkhole_probe.rs` actually saw — the
        // invariant that keeps the table honest.
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        let dns4eu_v6 = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0bc8, 0x1640, 0x3ffd, 0xdc00, 0x00ff, 0xfe4a, 0x3ec9,
        ));
        let cases: &[(&str, IpAddr)] = &[
            ("adguard", v4(94, 140, 14, 33)),
            ("adguard", v4(94, 140, 14, 35)),
            ("adguard-family", v4(94, 140, 14, 33)),
            ("opendns-familyshield", v4(146, 112, 61, 106)),
            ("opendns-familyshield", v4(146, 112, 61, 108)),
            ("dns4eu-protective", v4(51, 15, 69, 11)),
            ("dns4eu-protective", dns4eu_v6),
            ("dns4eu-child", v4(51, 15, 69, 11)),
            ("dns4eu-child", dns4eu_v6),
        ];
        for (id, ip) in cases {
            assert!(
                super::sinkhole_nets_for(id)
                    .iter()
                    .any(|net| net.contains(*ip)),
                "{id}: observed block IP {ip} not covered by its prefix"
            );
        }
    }

    #[test]
    fn contains_matches_by_prefix_family_and_rejects_neighbours() {
        let ag = SinkholeNet::v4(Ipv4Addr::new(94, 140, 14, 0), 24);
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        // Host-bit rotation inside the /24 still matches (the whole point).
        assert!(ag.contains(v4(94, 140, 14, 200)));
        assert!(ag.contains(v4(94, 140, 14, 33)));
        // One octet outside → no match.
        assert!(!ag.contains(v4(94, 140, 15, 1)));
        assert!(!ag.contains(v4(94, 141, 14, 33)));
        // adguard.com (Cloudflare) is a legitimate host outside the /24.
        assert!(!ag.contains(v4(104, 18, 188, 9)));
        // A v6 address never matches a v4 prefix.
        assert!(!ag.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        let dns4eu = SinkholeNet::v4(Ipv4Addr::new(51, 15, 69, 11), 32);
        assert!(dns4eu.contains(v4(51, 15, 69, 11)));
        assert!(!dns4eu.contains(v4(51, 15, 69, 12)));

        let cisco = SinkholeNet::v4(Ipv4Addr::new(146, 112, 61, 104), 29);
        assert!(cisco.contains(v4(146, 112, 61, 110)));
        assert!(!cisco.contains(v4(146, 112, 61, 112))); // just past the /29
        assert!(!cisco.contains(v4(146, 112, 62, 105))); // opendns.com

        // dns4eu-child's native-v6 /128 — exact match only.
        let child6 = SinkholeNet::v6(
            Ipv6Addr::new(
                0x2001, 0x0bc8, 0x1640, 0x3ffd, 0xdc00, 0x00ff, 0xfe4a, 0x3ec9,
            ),
            128,
        );
        assert!(child6.contains(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0bc8, 0x1640, 0x3ffd, 0xdc00, 0x00ff, 0xfe4a, 0x3ec9
        ))));
        assert!(!child6.contains(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0bc8, 0x1640, 0x3ffd, 0xdc00, 0x00ff, 0xfe4a, 0x3eca
        ))));
        assert!(!child6.contains(v4(51, 15, 69, 11)));
    }

    // Live network check - not run in CI (Відкрите питання п.2, ToS on
    // automated upstream queries is still unverified; see DECISIONS.md
    // 2026-08-25 T-20). Confirms the hard precondition recorded this
    // session: dns.quad9.net requires HTTP/2 and returns an HTML error body
    // instead of a wire-format response otherwise - this proves
    // ReqwestDohClient's default client actually negotiates it, rather than
    // assuming ALPN handles it.
    #[tokio::test]
    #[ignore = "live network call to dns.quad9.net - run manually, not in CI"]
    async fn reqwest_client_negotiates_http2_against_quad9() {
        let client = match ReqwestDohClient::new() {
            Ok(client) => client,
            Err(err) => panic!("client construction must not fail: {err}"),
        };
        let name = match Name::from_str("example.com.") {
            Ok(name) => name,
            Err(err) => panic!("valid fixture name: {err}"),
        };
        let mut question = Query::new();
        question.set_name(name);
        question.set_query_type(RecordType::A);
        question.set_query_class(DNSClass::IN);
        let mut query = Message::query();
        query.add_query(question);

        let result = client
            .query("https://dns.quad9.net/dns-query", &query)
            .await;
        if let Err(err) = result {
            panic!("expected a decoded DNS response, got: {err}");
        }
    }
}
