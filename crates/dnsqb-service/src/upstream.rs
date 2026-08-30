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
    /// `Cloudflare` Malware/Family, `CleanBrowsing`).
    NullIp,
    /// `NXDOMAIN`, undecidable on its own — needs the baseline resolver to
    /// tell a filter block from genuine non-existence (Quad9, `OpenDNS`
    /// `FamilyShield`). SPEC.md §3.1.
    NxdomainVsBaseline,
    /// Either of the above — the permissive default for a custom endpoint
    /// whose block shape isn't known ahead of time.
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
    /// The two Phase-1 voters, both enabled — the fresh-install default when
    /// `resolver_config.toml` has no `[[providers]]` (unchanged behaviour).
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
        BlockSignature::NullIp,
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
        BlockSignature::NullIp,
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
/// `[[providers]]` in `resolver_config.toml` — the two Phase-1 voters,
/// unchanged. SPEC.md §3.4/§3.5's "Security category only" first-run default
/// is a separate, still-open decision (see `TASKS.md`).
pub const DEFAULT_PROVIDER_IDS: &[&str] = &["quad9", "adguard"];

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
        BlockSignature, Category, DohClient, ProviderSpec, ProviderUrlError, ReqwestDohClient,
    };
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
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
