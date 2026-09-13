//! T-201 (1.2-B): integration coverage for the `AdminClient` ↔ `serve()`
//! contract. `AdminClient` is consumed by **both** `dnsqb-tray` and
//! `dnsqb-watcher`; before this there was no test anywhere exercising the
//! client against a real running server — only `serve()` unit tests with
//! hand-built `Request`s, and `AdminClient` with nothing at all.
//!
//! Each test stands up an ephemeral `serve()` over real TLS with a freshly
//! generated self-signed cert (the same `cert::generate_self_signed_cert`
//! path production uses), pins `AdminClient` to that cert, and drives real
//! HTTPS round-trips. This proves URL/method/DTO agreement (the JSON is
//! produced by the real handler and decoded by the real client) and the
//! `AdminClientError` mapping.
//!
//! Not covered: a `200` response carrying non-JSON — no admin route produces
//! that shape, and `reqwest::Response::error_for_status` collapses a non-2xx
//! and a decode failure into the same `AdminClientError::Request` anyway, so
//! the honest assertion for both is `matches!(err, Request(_))`.
//!
//! Also noted while writing this: the pieces needed to build a `ServerConfig`
//! from a generated cert *without* the OS key store
//! (`tls::server_config_from_certified_key`) are `pub(crate)`, so this
//! harness re-derives the ~10-line `rustls` assembly. That gap belongs with
//! the "oversized public API, missing the useful bits" item (review 4-B /
//! T-210), not with this task.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use dnsqb_service::{
    generate_self_signed_cert, serve, AdminClient, AdminClientError, AppState, Cache, CacheConfig,
    CacheState, DohClient, GeoipInit, GeoipSource, GeoipState, LimitsConfig, OverrideLists,
    OverridesState, PersistTarget, QueryLog, RatingFilterConfig, RuntimeInit, UpstreamError,
    ZoneLists,
};
use hickory_proto::op::Message;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// A `DohClient` that is never invoked — no `/admin/*` handler touches
/// `state.client`, and the tests here never hit `/dns-query`.
struct UnusedClient;

impl DohClient for UnusedClient {
    fn query(
        &self,
        _url: &str,
        _query: &Message,
    ) -> impl Future<Output = Result<Message, UpstreamError>> + Send {
        std::future::ready(Err(UpstreamError::Decode("unused".to_string().into())))
    }
}

fn test_state() -> Arc<AppState<UnusedClient>> {
    Arc::new(AppState::new(
        UnusedClient,
        OverridesState {
            lists: OverrideLists::empty(),
            invalid: Vec::new(),
        },
        RuntimeInit::default(),
        CacheState {
            cache: Cache::new(&CacheConfig::default()),
            config: CacheConfig::default(),
        },
        GeoipInit {
            database: GeoipState::default(),
            blocked_countries: Vec::new(),
            source: GeoipSource::DbIpLite,
            rating_filter_config: RatingFilterConfig::default(),
            rating_filter_zone: ZoneLists::default(),
            system_region: None,
        },
        QueryLog::default(),
        PersistTarget {
            port: 0,
            persist_query_log: false,
            persist_cache: false,
            rating_filter: RatingFilterConfig::default(),
            limits: LimitsConfig::default(),
            paths: None,
        },
    ))
}

/// A live `serve()` instance: a real TLS listener on an ephemeral loopback
/// port, plus the temp directory holding the `cert.pem` `AdminClient::new`
/// pins to.
struct TestServer {
    dir: tempfile::TempDir,
    port: u16,
}

impl TestServer {
    fn cert_dir(&self) -> &Path {
        self.dir.path()
    }

    fn client(&self) -> AdminClient {
        match AdminClient::new(self.cert_dir(), self.port) {
            Ok(client) => client,
            Err(err) => panic!("AdminClient::new against the test cert must succeed: {err}"),
        }
    }
}

/// Mirrors `tls::server_config_from_certified_key` + `build_server_config`
/// (both `pub(crate)`) — kept minimal, no handshake/idle timeouts (this is a
/// trusted local peer that always completes promptly).
fn spawn_test_server() -> TestServer {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => panic!("temp dir: {err}"),
    };
    let certified_key = match generate_self_signed_cert() {
        Ok(certified_key) => certified_key,
        Err(err) => panic!("cert generation: {err}"),
    };
    if let Err(err) = std::fs::write(dir.path().join("cert.pem"), certified_key.cert.pem()) {
        panic!("write cert.pem: {err}");
    }

    let cert_der = certified_key.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified_key.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_config =
        match ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions() {
            Ok(builder) => match builder
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
            {
                Ok(config) => config,
                Err(err) => panic!("ServerConfig::with_single_cert: {err}"),
            },
            Err(err) => panic!("ServerConfig protocol versions: {err}"),
        };
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => panic!("bind: {err}"),
    };
    if let Err(err) = listener.set_nonblocking(true) {
        panic!("set_nonblocking: {err}");
    }
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(err) => panic!("local_addr: {err}"),
    };
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(err) => panic!("TcpListener::from_std: {err}"),
    };

    let state = test_state();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let io = TokioIo::new(tls);
                let service = service_fn(move |req| serve(req, Arc::clone(&state)));
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    TestServer { dir, port }
}

/// An ephemeral port that nothing listens on — bind, read the port, drop.
async fn dead_port() -> u16 {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => panic!("bind: {err}"),
    };
    match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(err) => panic!("local_addr: {err}"),
    }
}

#[tokio::test]
async fn status_round_trips_and_decodes_the_real_status_dto() {
    let server = spawn_test_server();
    let client = server.client();

    let status = match client.status().await {
        Ok(status) => status,
        Err(err) => panic!("GET /admin/status must succeed against a live server: {err}"),
    };

    // Fields the real handler fills that a fixture couldn't fake into
    // agreement: a fresh in-memory log means zero totals, nothing is paused,
    // and `RuntimeInit::default()` brings up the default voter set.
    assert_eq!(status.stats.total, 0);
    assert_eq!(status.stats.blocked, 0);
    assert!(!status.paused);
    assert!(
        !status.active_providers.is_empty(),
        "the default runtime config should expose at least one voter"
    );
}

#[tokio::test]
async fn health_round_trips_against_the_real_endpoint() {
    let server = spawn_test_server();
    let client = server.client();

    if let Err(err) = client.health().await {
        panic!("GET /health must succeed against a live server: {err}");
    }
}

#[tokio::test]
async fn apply_then_status_reflect_the_same_timeout_mode() {
    use dnsqb_service::{AdminConfigUpdate, TimeoutMode};

    let server = spawn_test_server();
    let client = server.client();

    let applied = match client
        .apply(AdminConfigUpdate {
            timeout_mode: TimeoutMode::FailClosed,
            serve_baseline_when_filters_unreachable: false,
        })
        .await
    {
        Ok(status) => status,
        Err(err) => panic!("POST /admin/config must round-trip: {err}"),
    };
    assert_eq!(applied.timeout_mode, TimeoutMode::FailClosed);

    let status = match client.status().await {
        Ok(status) => status,
        Err(err) => panic!("GET /admin/status after apply: {err}"),
    };
    assert_eq!(status.timeout_mode, TimeoutMode::FailClosed);
}

#[tokio::test]
async fn missing_cert_pem_maps_to_cert_read_error() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => panic!("temp dir: {err}"),
    };
    let Err(err) = AdminClient::new(dir.path(), 1) else {
        panic!("AdminClient::new must fail when cert.pem is absent");
    };
    assert!(
        matches!(err, AdminClientError::CertRead(_)),
        "expected CertRead, got {err:?}"
    );
}

#[tokio::test]
async fn unparseable_cert_pem_maps_to_client_build_error() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(err) => panic!("temp dir: {err}"),
    };
    // A well-formed PEM envelope whose body is not valid base64 / DER — a
    // bare "not a pem" string is silently tolerated by `Certificate::from_pem`
    // (it just parses zero certs), so the envelope is needed to reach the
    // actual decode-failure path.
    let malformed_pem =
        b"-----BEGIN CERTIFICATE-----\nnot valid base64 !!!\n-----END CERTIFICATE-----\n";
    if let Err(err) = std::fs::write(dir.path().join("cert.pem"), malformed_pem) {
        panic!("write cert.pem: {err}");
    }
    let Err(err) = AdminClient::new(dir.path(), 1) else {
        panic!("AdminClient::new must fail on a non-PEM cert.pem");
    };
    assert!(
        matches!(err, AdminClientError::ClientBuild(_)),
        "expected ClientBuild, got {err:?}"
    );
}

#[tokio::test]
async fn service_unreachable_maps_to_request_error() {
    // A valid pinned cert, but nothing listening on the target port.
    let server = spawn_test_server();
    let client = match AdminClient::new(server.cert_dir(), dead_port().await) {
        Ok(client) => client,
        Err(err) => panic!("AdminClient::new: {err}"),
    };
    let Err(err) = client.status().await else {
        panic!("status() against a dead port must fail");
    };
    assert!(
        matches!(err, AdminClientError::Request(_)),
        "expected Request, got {err:?}"
    );
}

#[tokio::test]
async fn a_non_2xx_response_maps_to_request_error() {
    let server = spawn_test_server();
    let client = server.client();

    // `POST /admin/providers/remove` with an id that isn't configured is a
    // `400` (dispatch.rs) — a real non-2xx through the real client.
    let Err(err) = client.remove_provider("no-such-provider-xyz").await else {
        panic!("removing an unknown provider must fail");
    };
    assert!(
        matches!(err, AdminClientError::Request(_)),
        "expected Request, got {err:?}"
    );
}
