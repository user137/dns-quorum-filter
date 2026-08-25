//! `DoH` transport to a single upstream (RFC 8484 GET, T-9/T-21; T-22
//! baseline client; T-24 upstream client). Fixed to the two Phase-1 presets
//! (Quad9 Filtered, `AdGuard` Default) — more presets are Фаза 2 (T-73), not
//! this batch.

use crate::wire::{decode_wire_message, encode_wire_message};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::ProtoError;
use std::future::Future;

/// RFC 8484 §4.1.1 (T-9): `application/dns-message` GET-request URL —
/// unpadded base64url `dns=` parameter (SPEC.md §1, §3).
#[must_use]
pub fn doh_get_url(base: &str, message_bytes: &[u8]) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(message_bytes);
    format!("{base}?dns={encoded}")
}

/// RFC 7871 (T-8): EDNS Client Subnet option for a named upstream variant —
/// `None` unless the identifier names an ECS-enabled variant. Neither
/// Phase-1 preset ([`Provider::Quad9`]'s `dns.quad9.net`, 9.9.9.9, nor
/// `AdGuard` Default) uses ECS; Quad9's ECS-enabled 9.9.9.11 variant isn't a
/// wired preset yet (SPEC.md §3.4, TASKS.md T-73, Фаза 2). Kept as a stub
/// pending that preset — implementing it now against a string identifier
/// nothing in this batch actually produces would guard nothing.
#[must_use]
pub fn ecs_option_for_upstream(_upstream: &str) -> Option<EdnsOption> {
    todo!("Фаза 2: T-73 — ECS-enabled upstream preset")
}

/// The Phase-1 upstream `DoH` providers (SPEC.md "Фазований план", Фаза 1:
/// Quad9 + `AdGuard` DNS, literally). Adding more presets is T-73 (Фаза 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// Quad9 Filtered (Security category) — malware/phishing blocking.
    Quad9,
    /// `AdGuard` Default — ads/trackers/malware blocking.
    AdGuard,
}

impl Provider {
    /// The provider's Phase-1 `DoH` endpoint (SPEC.md §3.4).
    #[must_use]
    pub fn doh_url(self) -> &'static str {
        match self {
            Self::Quad9 => "https://dns.quad9.net/dns-query",
            Self::AdGuard => "https://dns.adguard-dns.com/dns-query",
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
    /// стек" — TLS only via `rustls`).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying TLS backend fails to initialize.
    pub fn new() -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder().build()?;
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
    use super::{DohClient, Provider, ReqwestDohClient};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::str::FromStr;

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

        let result = client.query(Provider::Quad9.doh_url(), &query).await;
        if let Err(err) = result {
            panic!("expected a decoded DNS response, got: {err}");
        }
    }
}
