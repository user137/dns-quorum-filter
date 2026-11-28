//! The one place outbound `reqwest` clients are built (T-305 batch 2), apart
//! from [`crate::upstream::ReqwestDohClient`] (`DoH` upstreams) and
//! [`crate::admin::AdminClient`] (loopback admin channel, pinned cert). A
//! test keeps every other production `reqwest::Client` construction out.

use crate::bootstrap::{OutboundResolver, ResolverMode};

/// Client for the fixed public HTTPS endpoints: `GeoIP`, top-N and
/// blocklist downloads, reachability markers and the `MaxMind` key check.
/// HTTPS only; redirects stay on (release downloads redirect to a CDN).
/// Lookups follow `mode` (T-305 batch 3a): with the plain-DNS listener on,
/// the OS resolver may point back at this service, so the bootstrap path is
/// used instead — or a reachability marker would be answered by our own
/// offline SERVFAIL and never recover.
///
/// # Errors
///
/// The TLS backend failed to initialise.
pub(crate) fn public_https_client(mode: &ResolverMode) -> Result<reqwest::Client, reqwest::Error> {
    let resolver = OutboundResolver::new(mode.clone())?;
    reqwest::Client::builder()
        .https_only(true)
        .dns_resolver(std::sync::Arc::new(resolver))
        .build()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// Files allowed to build a `reqwest` client in production code.
    const ALLOWED: [&str; 3] = ["http_client.rs", "upstream.rs", "admin.rs"];
    const CONSTRUCTORS: [&str; 5] = [
        "Client::builder(",
        "Client::new(",
        "Client::default(",
        "ClientBuilder::new(",
        "ClientBuilder::default(",
    ];

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) => panic!("read {}: {err}", dir.display()),
        };
        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(err) => panic!("dir entry: {err}"),
            };
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// `pattern` occurs not as the tail of a longer name
    /// (`ReqwestDohClient::new(` is not a `Client::new(`). Whitespace is
    /// ignored, so `Client :: builder ()` counts too.
    fn builds_client(text: &str, pattern: &str) -> bool {
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        text.match_indices(pattern).any(|(at, _)| {
            !text[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    }

    // `localhost` is a host name, so the lookup goes through the resolver;
    // it resolves to loopback only and is refused before any connection.
    // Without `dns_resolver` the listener would see the TLS handshake.
    #[tokio::test]
    async fn the_public_client_never_connects_to_a_host_resolving_to_loopback() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) => panic!("bind loopback: {err}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("local_addr: {err}"),
        };
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let client = match super::public_https_client(&super::ResolverMode::default()) {
            Ok(client) => client,
            Err(err) => panic!("client: {err}"),
        };
        let Err(err) = client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
        else {
            panic!("the request must fail");
        };
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        let mut refused = false;
        while let Some(current) = cause {
            refused |= current.is::<crate::upstream::NoPublicAddress>();
            cause = current.source();
        }
        assert!(refused, "{err:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "connected to loopback");
    }

    #[test]
    fn the_scan_tells_a_client_constructor_from_a_longer_name() {
        assert!(builds_client(
            "let c = reqwest::Client::new();",
            "Client::new("
        ));
        assert!(builds_client("Client::builder()", "Client::builder("));
        assert!(!builds_client("ReqwestDohClient::new()", "Client::new("));
        assert!(builds_client(
            "reqwest::Client\n    ::builder ()",
            "Client::builder("
        ));
        assert!(builds_client(
            "let c: reqwest::Client = reqwest::Client::default();",
            "Client::default("
        ));
        assert!(!builds_client("AdminClient::default()", "Client::default("));
        assert!(!builds_client(
            "AdminClient::new(dir, port)",
            "Client::new("
        ));
    }

    #[test]
    fn no_other_production_code_builds_a_reqwest_client() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        assert!(files.len() > 20, "scanned too few files: {}", files.len());
        let mut offenders = Vec::new();
        for file in files {
            let name = file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if ALLOWED.contains(&name) {
                continue;
            }
            let text = match std::fs::read_to_string(&file) {
                Ok(text) => text,
                Err(err) => panic!("read {}: {err}", file.display()),
            };
            // Unit tests build their own clients against loopback servers.
            let production = text.split("\nmod tests {").next().unwrap_or_default();
            if CONSTRUCTORS.iter().any(|c| builds_client(production, c)) {
                offenders.push(file.display().to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "use http_client::public_https_client: {offenders:?}"
        );
    }
}
