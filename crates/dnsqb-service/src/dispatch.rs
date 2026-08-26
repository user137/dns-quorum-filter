//! `DoH` GET/POST → `pipeline::handle_query` request dispatch (T-143) — RFC 8484
//! (SPEC.md §1, §3). `main.rs`'s TCP accept loop and TLS handshake hand each
//! connection off to [`serve`], the only piece of this module `main.rs`
//! (a separate crate — the `[[bin]]` target) actually calls; everything else
//! here is `pub(crate)` and independently unit-tested with a mock
//! [`DohClient`] and a hand-built [`Request`], no live TCP/TLS needed.
//! [`serve`] itself is generic over the request body type (not hardcoded to
//! `hyper::body::Incoming`, which can't be constructed outside a real
//! connection) for exactly that reason — `main.rs` calls it with `Incoming`,
//! tests call it with `http_body_util::Full`.
//!
//! Endpoint is fixed to `/dns-query` (SPEC.md §1 line 84) — any other path is
//! a 404, deliberately leaving `/health` (T-86, Фаза 3: "розширення наявного
//! порту, не новий слухач") free to add on this same listener later without
//! colliding.

use crate::cache::{Cache, CacheConfig};
use crate::overrides::OverrideLists;
use crate::pipeline::{handle_query, proxy_to_single_upstream, PipelineOutcome, Voters};
use crate::query_log::{LogEntry, QueryLog};
use crate::timeout::TimeoutConfig;
use crate::upstream::DohClient;
use crate::wire::{decode_wire_message, encode_wire_message};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use hickory_proto::ProtoError;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Body;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

/// The largest a DNS wire message is allowed to be, GET or POST alike — the
/// classic DNS-over-TCP 2-byte length prefix this project doesn't use still
/// names the right upper bound (a real DNS message can't legally exceed it),
/// and rejecting anything larger here is what actually bounds allocation
/// (SPEC.md §8.1: "ліміт розміру, не необмежена алокація").
pub(crate) const MAX_MESSAGE_SIZE: usize = 65_535;

const DNS_QUERY_PATH: &str = "/dns-query";
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// A malformed `DoH` HTTP request — never carries the request's own bytes or
/// the decoded message, only a closed, coarse reason (same discipline as
/// `overrides::InvalidReason`/`upstream::UpstreamError::error_kind()`: no
/// domain names, and here, no arbitrary client-supplied bytes, in
/// logs/diagnostics).
#[derive(Debug, thiserror::Error)]
pub(crate) enum DohRequestError {
    /// GET request had no `dns=` query parameter (RFC 8484 §4.1.1).
    #[error("missing dns query parameter")]
    MissingDnsParam,
    /// The `dns=` parameter wasn't valid unpadded base64url.
    #[error("dns query parameter is not valid unpadded base64url")]
    InvalidBase64,
    /// Decoded/POSTed message exceeds [`MAX_MESSAGE_SIZE`].
    #[error("dns message exceeds the maximum allowed size")]
    MessageTooLarge,
    /// POST request's `Content-Type` wasn't `application/dns-message` (RFC
    /// 8484 §6).
    #[error("unsupported content-type for a DoH POST request")]
    UnsupportedContentType,
    /// Reading the POST body itself failed for a reason other than
    /// exceeding [`MAX_MESSAGE_SIZE`] (e.g. the client disconnected
    /// mid-body) — kept distinct from `MessageTooLarge` so a 413 always
    /// means what it says.
    #[error("failed to read the request body")]
    BodyReadError,
}

/// RFC 8484 §4.1.1: extract the wire message from a GET request's raw query
/// string. No percent-decoding — base64url's alphabet (`A-Za-z0-9-_`) is
/// already URL-safe, matching `upstream::doh_get_url`'s own encoder; a
/// client that percent-encodes anyway fails to decode safely rather than
/// being silently mishandled.
pub(crate) fn wire_bytes_from_get(query_string: &str) -> Result<Vec<u8>, DohRequestError> {
    let encoded = query_string
        .split('&')
        .find_map(|pair| pair.strip_prefix("dns="))
        .ok_or(DohRequestError::MissingDnsParam)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DohRequestError::InvalidBase64)?;
    if decoded.len() > MAX_MESSAGE_SIZE {
        return Err(DohRequestError::MessageTooLarge);
    }
    Ok(decoded)
}

/// RFC 7231: media-type comparison is ASCII-case-insensitive and may carry
/// parameters (`application/dns-message; charset=utf-8` is still
/// `application/dns-message`) — a byte-equality check would reject a
/// conforming client whose `Content-Type` isn't byte-identical to Chrome's.
pub(crate) fn content_type_is_dns_message(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case(DNS_MESSAGE_CONTENT_TYPE)
        })
}

/// Decode `wire_bytes`, run it through the pipeline, and encode whatever
/// comes back. `PipelineOutcome::ProxyToSingleUpstream` (T-25 — non-A/AAAA
/// types) is handled here, not left to the caller: this is the one place
/// that actually has an upstream `client` to proxy through.
///
/// Takes `&AppState<C>` rather than its seven fields as separate parameters
/// (T-147 added the seventh, `query_log`, tripping `clippy::too_many_arguments`)
/// — every one of those fields already lives in `state`, and this function
/// only ever runs against the shared per-service state `serve` already holds.
///
/// # Errors
///
/// Returns `Err` if `wire_bytes` doesn't decode as a DNS message, or if
/// (practically unreachable) the resolved response somehow fails to
/// re-encode.
pub(crate) async fn resolve_doh_request<C: DohClient + Sync>(
    wire_bytes: &[u8],
    state: &AppState<C>,
) -> Result<Vec<u8>, ProtoError> {
    let query = decode_wire_message(wire_bytes)?;
    let started = Instant::now();
    let response = match handle_query(
        &query,
        &state.client,
        &state.overrides,
        state.voters,
        &state.cache,
        &state.cache_config,
        &state.timeout_config,
    )
    .await
    {
        (PipelineOutcome::Response(message), meta) => {
            // T-147: the one place both the Response and proxy paths are
            // visible, and the natural point to bracket total latency - see
            // `pipeline::QueryLogMeta`'s own doc comment for why the push
            // isn't inside `handle_query` itself.
            if let Some(meta) = meta {
                let latency_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                state.query_log.push(LogEntry {
                    timestamp: SystemTime::now(),
                    domain: meta.domain,
                    qtype: meta.qtype,
                    decision: meta.decision,
                    decision_source: meta.decision_source,
                    voters: meta.voters,
                    latency_ms,
                });
            }
            message
        }
        // Non-A/AAAA proxy path: not logged this slice - handle_query never
        // sees the actual proxied response, and none of the four Ф1
        // decision_source values describe a proxy pass-through (T-147, named
        // gap, not silently dropped).
        (PipelineOutcome::ProxyToSingleUpstream, _) => {
            proxy_to_single_upstream(&state.client, &query, &state.timeout_config).await
        }
    };
    encode_wire_message(&response)
}

/// Everything one connection's worth of [`serve`] calls need — one instance
/// built at startup and shared (via `Arc`) across every accepted connection.
/// Generic over the same `C: DohClient` bound `pipeline::handle_query` uses,
/// so tests can substitute a mock client instead of a real
/// `upstream::ReqwestDohClient`.
pub struct AppState<C: DohClient + Sync> {
    client: C,
    overrides: OverrideLists,
    voters: Voters,
    cache: Cache,
    cache_config: CacheConfig,
    timeout_config: TimeoutConfig,
    query_log: QueryLog,
}

impl<C: DohClient + Sync> AppState<C> {
    /// Builds the shared per-service state `serve` reads from on every
    /// request.
    #[must_use]
    pub fn new(
        client: C,
        overrides: OverrideLists,
        voters: Voters,
        cache: Cache,
        cache_config: CacheConfig,
        timeout_config: TimeoutConfig,
        query_log: QueryLog,
    ) -> Self {
        Self {
            client,
            overrides,
            voters,
            cache,
            cache_config,
            timeout_config,
            query_log,
        }
    }
}

/// A fixed-`status`, empty-body response — used for every non-2xx outcome
/// below (`serve` never has a meaningful body to return alongside an error
/// status: RFC 8484 doesn't define one, and the request may not have parsed
/// far enough to have a query ID worth answering). Built via `Response::new`
/// and `status_mut`, not `Response::builder()...body(...)` — the builder
/// path returns a `Result` only because it also handles header/URI
/// validation this function never exercises, so unlike the
/// `resolved`-response builder below (a real `Content-Type` header, worth
/// double-checking), there is no failure mode here to handle at all.
fn status_response(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

/// The `hyper` request handler `main.rs` hands every accepted, TLS-terminated
/// connection to. Routes only `GET`/`POST /dns-query` (SPEC.md §1 line 84) to
/// [`resolve_doh_request`] — everything else is a 404/405/400/413 with no
/// pipeline involvement at all.
///
/// Generic over the request body type `B` rather than hardcoded to
/// `hyper::body::Incoming` — `Incoming` can only be produced by a real
/// `hyper` connection, so a generic bound is what lets this function be unit
/// tested with a plain `http_body_util::Full` request instead of needing a
/// live socket. `main.rs` calls this with `Incoming`; the type is inferred
/// from context there, never spelled out.
///
/// # Errors
///
/// Never returns `Err` — every failure mode maps to an HTTP status instead,
/// which is what lets this be a `hyper` `Service` (`Infallible` is the
/// required error type for a connection that must never itself fail).
pub async fn serve<C, B>(
    req: Request<B>,
    state: Arc<AppState<C>>,
) -> Result<Response<Full<Bytes>>, Infallible>
where
    C: DohClient + Sync,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.uri().path() != DNS_QUERY_PATH {
        return Ok(status_response(StatusCode::NOT_FOUND));
    }

    let wire_bytes = match *req.method() {
        Method::GET => wire_bytes_from_get(req.uri().query().unwrap_or_default()),
        Method::POST => {
            let content_type = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok());
            if content_type_is_dns_message(content_type) {
                let limited = Limited::new(req.into_body(), MAX_MESSAGE_SIZE);
                match limited.collect().await {
                    Ok(collected) => Ok(collected.to_bytes().to_vec()),
                    // `Limited<B>::Error` is `Box<dyn Error + Send + Sync>` and
                    // carries either a `LengthLimitError` or `B`'s own
                    // underlying error (e.g. the client disconnected
                    // mid-body) - only the former is genuinely "too large".
                    Err(err) if err.downcast_ref::<LengthLimitError>().is_some() => {
                        Err(DohRequestError::MessageTooLarge)
                    }
                    Err(_) => Err(DohRequestError::BodyReadError),
                }
            } else {
                Err(DohRequestError::UnsupportedContentType)
            }
        }
        _ => return Ok(status_response(StatusCode::METHOD_NOT_ALLOWED)),
    };

    let wire_bytes = match wire_bytes {
        Ok(bytes) => bytes,
        Err(DohRequestError::MessageTooLarge) => {
            return Ok(status_response(StatusCode::PAYLOAD_TOO_LARGE))
        }
        Err(_) => return Ok(status_response(StatusCode::BAD_REQUEST)),
    };

    let resolved = resolve_doh_request(&wire_bytes, &state).await;

    match resolved {
        Ok(bytes) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
            .body(Full::new(Bytes::from(bytes)))
            .unwrap_or_else(|_| status_response(StatusCode::INTERNAL_SERVER_ERROR))),
        Err(_) => Ok(status_response(StatusCode::BAD_REQUEST)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        content_type_is_dns_message, resolve_doh_request, serve, wire_bytes_from_get, AppState,
        DohRequestError, MAX_MESSAGE_SIZE,
    };
    use crate::cache::{Cache, CacheConfig};
    use crate::overrides::OverrideLists;
    use crate::pipeline::Voters;
    use crate::query_log::QueryLog;
    use crate::timeout::TimeoutConfig;
    use crate::upstream::{doh_get_url, DohClient, UpstreamError};
    use bytes::Bytes;
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use http::{header, Method, Request, StatusCode};
    use http_body_util::Full;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn query_bytes(domain: &str, qtype: RecordType) -> Vec<u8> {
        let Ok(name) = Name::from_str(domain) else {
            panic!("valid fixture domain");
        };
        let mut question = Query::new();
        question.set_name(name);
        question.set_query_type(qtype);
        let mut message = Message::query();
        message.add_query(question);
        let Ok(bytes) = crate::wire::encode_wire_message(&message) else {
            panic!("fixture message must encode");
        };
        bytes
    }

    #[test]
    fn wire_bytes_from_get_round_trips_doh_get_urls_own_encoder() {
        let message_bytes = query_bytes("example.com.", RecordType::A);
        let url = doh_get_url("https://example.test/dns-query", &message_bytes);
        let Some(query_string) = url.split('?').nth(1) else {
            panic!("fixture URL must have a query string");
        };
        let decoded = match wire_bytes_from_get(query_string) {
            Ok(bytes) => bytes,
            Err(err) => panic!("a doh_get_url-encoded query string must decode: {err}"),
        };
        assert_eq!(decoded, message_bytes);
    }

    #[test]
    fn wire_bytes_from_get_rejects_a_missing_dns_param() {
        assert!(matches!(
            wire_bytes_from_get("other=1"),
            Err(DohRequestError::MissingDnsParam)
        ));
    }

    #[test]
    fn wire_bytes_from_get_rejects_invalid_base64() {
        assert!(matches!(
            wire_bytes_from_get("dns=not!valid!base64"),
            Err(DohRequestError::InvalidBase64)
        ));
    }

    #[test]
    fn wire_bytes_from_get_rejects_an_oversized_message() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let query_string = format!("dns={}", URL_SAFE_NO_PAD.encode(oversized));
        assert!(matches!(
            wire_bytes_from_get(&query_string),
            Err(DohRequestError::MessageTooLarge)
        ));
    }

    #[test]
    fn content_type_accepts_the_exact_media_type() {
        assert!(content_type_is_dns_message(Some("application/dns-message")));
    }

    #[test]
    fn content_type_accepts_different_case() {
        assert!(content_type_is_dns_message(Some("Application/DNS-Message")));
    }

    #[test]
    fn content_type_accepts_a_charset_parameter() {
        assert!(content_type_is_dns_message(Some(
            "application/dns-message; charset=utf-8"
        )));
    }

    #[test]
    fn content_type_rejects_the_wrong_type() {
        assert!(!content_type_is_dns_message(Some("application/json")));
    }

    #[test]
    fn content_type_rejects_a_missing_header() {
        assert!(!content_type_is_dns_message(None));
    }

    #[derive(Clone)]
    enum MockResponse {
        Instant(Message),
        Panic,
    }

    struct MockClient {
        baseline: MockResponse,
        quorum: MockResponse,
        calls: AtomicU32,
    }

    impl DohClient for MockClient {
        fn query(
            &self,
            url: &str,
            _query: &Message,
        ) -> impl std::future::Future<Output = Result<Message, UpstreamError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let response = if url == crate::upstream::BASELINE_DOH_URL {
                &self.baseline
            } else {
                &self.quorum
            };
            let result = match response {
                MockResponse::Instant(message) => Ok(message.clone()),
                MockResponse::Panic => panic!("unexpected upstream call to {url}"),
            };
            std::future::ready(result)
        }
    }

    fn allow_message_with_ip(ip: Ipv4Addr) -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NoError;
        message
            .answers
            .push(Record::from_rdata(Name::root(), 300, RData::A(A(ip))));
        message
    }

    #[tokio::test]
    async fn resolve_doh_request_answers_an_a_query_via_quorum() {
        // An A/AAAA Allow verdict queries baseline too, not just the two
        // filtering voters (quorum::resolve's own representative-answer
        // logic) - same three-way fixture pipeline.rs's own
        // cache_miss_allow_with_records_is_cached_and_reused test uses.
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let state = state_with(client);

        let response_bytes = match resolve_doh_request(&wire_bytes, &state).await {
            Ok(bytes) => bytes,
            Err(err) => panic!("must resolve: {err}"),
        };
        let Ok(decoded) = crate::wire::decode_wire_message(&response_bytes) else {
            panic!("response must decode");
        };
        assert_eq!(decoded.metadata.response_code, ResponseCode::NoError);
    }

    // T-147: resolve_doh_request is the one place that pushes a LogEntry -
    // a test at pipeline.rs's level can prove the metadata is computed
    // correctly, but only this layer can prove it actually reaches the log.
    #[tokio::test]
    async fn resolve_doh_request_pushes_a_log_entry_for_a_resolved_a_query() {
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let state = state_with(client);

        if let Err(err) = resolve_doh_request(&wire_bytes, &state).await {
            panic!("must resolve: {err}");
        }

        let entries = state.query_log.snapshot(std::time::SystemTime::now());
        assert_eq!(entries.len(), 1, "exactly one query must have been logged");
        assert_eq!(entries[0].domain, "example.com");
        assert_eq!(entries[0].decision, crate::query_log::Decision::Allowed);
        assert_eq!(
            entries[0].decision_source,
            crate::query_log::DecisionSource::Quorum
        );
    }

    // T-147: the proxy path is a named, still-open gap - not logged yet.
    #[tokio::test]
    async fn resolve_doh_request_does_not_log_a_proxied_non_a_aaaa_query() {
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(9, 9, 9, 9))),
            quorum: MockResponse::Panic,
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::TXT);
        let state = state_with(client);

        if let Err(err) = resolve_doh_request(&wire_bytes, &state).await {
            panic!("must resolve: {err}");
        }

        assert!(state
            .query_log
            .snapshot(std::time::SystemTime::now())
            .is_empty());
    }

    #[tokio::test]
    async fn resolve_doh_request_proxies_a_non_a_aaaa_query_to_a_single_upstream() {
        // T-25: TXT never consults quorum - proving the baseline mock was
        // called (not the quorum branch, which panics on any call) is what
        // distinguishes "proxied" from "coincidentally also NOERROR".
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(9, 9, 9, 9))),
            quorum: MockResponse::Panic,
            calls: AtomicU32::new(0),
        };
        let wire_bytes = query_bytes("example.com.", RecordType::TXT);
        let state = state_with(client);

        if let Err(err) = resolve_doh_request(&wire_bytes, &state).await {
            panic!("must resolve: {err}");
        }
        assert_eq!(state.client.calls.load(Ordering::SeqCst), 1);
    }

    fn state_with(client: MockClient) -> Arc<AppState<MockClient>> {
        Arc::new(AppState::new(
            client,
            OverrideLists::empty(),
            Voters::Enabled,
            Cache::new(&CacheConfig::default()),
            CacheConfig::default(),
            TimeoutConfig::default(),
            QueryLog::default(),
        ))
    }

    fn no_op_client() -> MockClient {
        MockClient {
            baseline: MockResponse::Panic,
            quorum: MockResponse::Panic,
            calls: AtomicU32::new(0),
        }
    }

    #[tokio::test]
    async fn serve_returns_404_for_a_path_other_than_dns_query() {
        let req = match Request::builder()
            .method(Method::GET)
            .uri("/other")
            .body(Full::new(Bytes::new()))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serve_returns_405_for_an_unsupported_method_on_dns_query() {
        let req = match Request::builder()
            .method(Method::DELETE)
            .uri("/dns-query")
            .body(Full::new(Bytes::new()))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn serve_returns_400_for_a_malformed_get_query_string() {
        let req = match Request::builder()
            .method(Method::GET)
            .uri("/dns-query?other=1")
            .body(Full::new(Bytes::new()))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serve_returns_400_for_a_post_with_the_wrong_content_type() {
        let req = match Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"irrelevant")))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serve_returns_413_for_an_oversized_post_body() {
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let req = match Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header(header::CONTENT_TYPE, "application/dns-message")
            .body(Full::new(Bytes::from(oversized)))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let response = match serve(req, state_with(no_op_client())).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn serve_answers_a_valid_get_request_with_200_and_the_encoded_response() {
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let url = doh_get_url("/dns-query", &wire_bytes);
        let req = match Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Full::new(Bytes::new()))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let response = match serve(req, state_with(client)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/dns-message"))
        );
    }

    #[tokio::test]
    async fn serve_answers_a_valid_post_request_with_200() {
        let wire_bytes = query_bytes("example.com.", RecordType::A);
        let req = match Request::builder()
            .method(Method::POST)
            .uri("/dns-query")
            .header(header::CONTENT_TYPE, "application/dns-message")
            .body(Full::new(Bytes::from(wire_bytes)))
        {
            Ok(req) => req,
            Err(err) => panic!("fixture request must build: {err}"),
        };
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockClient {
            baseline: MockResponse::Instant(allow_message_with_ip(ip)),
            quorum: MockResponse::Instant(allow_message_with_ip(ip)),
            calls: AtomicU32::new(0),
        };
        let response = match serve(req, state_with(client)).await {
            Ok(response) => response,
            Err(err) => match err {},
        };
        assert_eq!(response.status(), StatusCode::OK);
    }
}
