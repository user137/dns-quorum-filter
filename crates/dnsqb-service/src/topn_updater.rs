//! T-124 — the availability-zone list refresher (SPEC.md §5.3). Downloads
//! each curated `data/topn/<list>.txt` the operator selected in
//! `[rating_filter] lists`, verifies its SHA-256 sidecar, atomic-swaps it
//! into `<app-data>/topn/`, and publishes the assembled [`ZoneLists`] to
//! [`AppState`]. One fetch-verify-swap per list per cycle; no DNS.
//!
//! Mirrors [`crate::geoip_updater`] structure: [`run_topn_updater`] is a
//! thin `loop { refresh_all_lists; park_until_due }` shell over the pure
//! helpers in [`crate::topn_download`]. A failed list keeps its
//! last-known-good file (the same "never regress on a transient error"
//! posture the `GeoIP` updater has).
//!
//! **Network politeness.** One sidecar GET per selected list per 24 h; the
//! list body only when the sidecar no longer matches the file on disk, and
//! no check at all on a restart while the files are younger than 24 h
//! (ARCH-10) — a handful of requests a day to a CDN, well within one
//! ordinary user's footprint (see the project's network-politeness
//! principle).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;

use crate::config::RatingFilterConfig;
use crate::dispatch::AppState;
use crate::paths::write_atomic;
use crate::rating_filter::{ZoneLists, ZoneSource, ZoneSourceKind};
use crate::refresh_schedule::{first_cycle_delay, oldest_mtime};
use crate::topn_download::{
    list_url, parse_list, sha256_sidecar_url, verify_sha256, MAX_TOPN_BYTES,
};
use crate::upstream::ReqwestDohClient;

/// How often to re-check the curated lists for a new revision. They are
/// republished at most monthly (the upstream popularity data is monthly, and
/// a human PR gates each change), so a daily poll is generous headroom — the
/// same 24-hour cadence as [`crate::geoip_updater::GEOIP_CHECK_INTERVAL`].
pub const TOPN_CHECK_INTERVAL: Duration = Duration::from_hours(24);

/// Upper bound on one list's whole fetch-verify-swap attempt (both the
/// `.txt` and its sidecar). Generous relative to a <64 KiB download; a hung
/// attempt must not stall the loop past this (same hazard as
/// `geoip_updater`'s `GEOIP_FETCH_TIMEOUT`).
const TOPN_FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// Subdirectory of the app-data directory the list files live in.
const TOPN_DIR: &str = "topn";

/// Failure modes of one list refresh. Payload-free / list-code-only — a list
/// code is this service's own config, never a domain name.
#[derive(Debug, thiserror::Error)]
enum TopnRefreshError {
    #[error("list download failed")]
    Http(#[source] reqwest::Error),
    #[error("list download exceeds the {MAX_TOPN_BYTES}-byte size limit")]
    TooLarge,
    #[error("no SHA-256 sidecar available for the list")]
    NoSidecar,
    #[error("downloaded list does not match its published SHA-256 checksum")]
    ChecksumMismatch,
    #[error("writing the verified list to disk failed")]
    Io(#[source] std::io::Error),
    #[error("the whole fetch-verify-swap attempt exceeded {TOPN_FETCH_TIMEOUT:?}")]
    Timeout,
}

/// Builds the initial [`ZoneLists`] from whatever `<app-data>/topn/*.txt`
/// files are already present (T-124) — called once by `main.rs` at startup.
/// Missing files just contribute nothing, exactly like `load_geoip_state`
/// with no `geoip.mmdb` yet; the first [`run_topn_updater`] cycle fills them
/// in. Returns an empty bubble when the filter is disabled, no lists are
/// selected, or no app-data directory exists.
#[must_use]
pub fn load_zone_from_disk(app_data: Option<&Path>, config: &RatingFilterConfig) -> ZoneLists {
    let Some(dir) = app_data else {
        return ZoneLists::default();
    };
    if !config.enabled || config.lists.is_empty() {
        return ZoneLists::default();
    }
    let topn_dir = dir.join(TOPN_DIR);
    let sources = config
        .lists
        .iter()
        .filter_map(|list| {
            let body = std::fs::read_to_string(topn_dir.join(format!("{list}.txt"))).ok()?;
            Some(ZoneSource::new(zone_source_kind(list), parse_list(&body)))
        })
        .collect();
    ZoneLists::new(sources)
}

/// Runs one refresh — right away, or once the files on disk reach
/// [`TOPN_CHECK_INTERVAL`] of age (ARCH-10: a restart doesn't refetch lists
/// `load_zone_from_disk` just loaded) — then every [`TOPN_CHECK_INTERVAL`] (or sooner
/// if `apply_admin_reset` / `apply_rating_filter_change` wakes it). Spawned
/// by `main.rs` whenever an app-data directory exists — [`refresh_all_lists`]
/// re-reads the config snapshot each cycle and returns immediately while the
/// filter is disabled, so an always-running idle task is the price of letting
/// `POST /admin/rating-filter` enable the bubble with no restart.
pub async fn run_topn_updater(
    client: reqwest::Client,
    app_data: PathBuf,
    state: Arc<AppState<ReqwestDohClient>>,
) {
    let wake = state.rating_filter_refresh_wake_handle();
    let first = first_cycle_delay(
        SystemTime::now(),
        selected_lists_last_success(&app_data, &state.rating_filter_config_snapshot()),
        TOPN_CHECK_INTERVAL,
    );
    if !first.is_zero() {
        tracing::info!("top-N lists on disk are fresh, first check deferred");
        park_until_due(&wake, first).await;
    }
    loop {
        refresh_all_lists(&client, &app_data, &state).await;
        park_until_due(&wake, TOPN_CHECK_INTERVAL).await;
    }
}

/// The oldest mtime among the selected lists' files, or `None` (refresh now)
/// when the filter is off, nothing is selected, or any file is missing.
fn selected_lists_last_success(app_data: &Path, config: &RatingFilterConfig) -> Option<SystemTime> {
    if !config.enabled {
        return None;
    }
    let topn_dir = app_data.join(TOPN_DIR);
    oldest_mtime(
        config
            .lists
            .iter()
            .map(|list| topn_dir.join(format!("{list}.txt"))),
    )
}

/// Park between refresh cycles: return when the periodic timer elapses **or**
/// a `wake_rating_filter_refresh()` signal fires. A `notify_one` left before
/// this is entered is remembered (one permit), so a config reload during an
/// in-flight refresh still resolves the next park immediately.
async fn park_until_due(wake: &tokio::sync::Notify, after: Duration) {
    tokio::select! {
        () = tokio::time::sleep(after) => {}
        () = wake.notified() => tracing::info!("top-N list refresh woken by a config reload"),
    }
}

/// One cycle: snapshot the config, refresh every selected list, publish the
/// assembled bubble. A list that fails this cycle keeps whatever file it had
/// on disk (possibly none) — its error is logged, not fatal.
async fn refresh_all_lists(
    client: &reqwest::Client,
    app_data: &Path,
    state: &AppState<ReqwestDohClient>,
) {
    let config = state.rating_filter_config_snapshot();
    if !config.enabled || config.lists.is_empty() {
        return;
    }
    let topn_dir = app_data.join(TOPN_DIR);
    if let Err(err) = std::fs::create_dir_all(&topn_dir) {
        tracing::warn!("could not create the top-N list directory, skipping refresh: {err}");
        return;
    }

    let mut sources = Vec::with_capacity(config.lists.len());
    let mut any_updated = false;
    for list in &config.lists {
        match refresh_one_list_bounded(client, list, &topn_dir).await {
            Ok((source, fetch)) => {
                any_updated |= fetch == ListFetch::Updated;
                sources.push(source);
            }
            Err(err) => {
                tracing::warn!(
                    "top-N list refresh failed, keeping the last-known-good file: {err}"
                );
                // Fall back to whatever is already on disk for this list.
                if let Ok(body) = std::fs::read_to_string(topn_dir.join(format!("{list}.txt"))) {
                    sources.push(ZoneSource::new(zone_source_kind(list), parse_list(&body)));
                }
            }
        }
    }
    state.update_rating_filter_zone(ZoneLists::new(sources));
    if any_updated {
        tracing::info!("top-N availability-zone lists refreshed");
    } else {
        tracing::info!("top-N availability-zone lists checked, unchanged upstream");
    }
}

/// Whether one list's cycle actually downloaded a new body (ARCH-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListFetch {
    Updated,
    /// The sidecar matched the file already on disk — the body was not
    /// downloaded and the local copy was reused.
    Unchanged,
}

async fn refresh_one_list_bounded(
    client: &reqwest::Client,
    list: &str,
    topn_dir: &Path,
) -> Result<(ZoneSource, ListFetch), TopnRefreshError> {
    let (body_url, sidecar_url) = (list_url(list), sha256_sidecar_url(list));
    let attempt = refresh_one_list_at(client, list, &body_url, &sidecar_url, topn_dir);
    match tokio::time::timeout(TOPN_FETCH_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_elapsed) => Err(TopnRefreshError::Timeout),
    }
}

/// Sidecar first (ARCH-10): when it matches the file already on disk, the
/// body is not downloaded and the local copy is reused — the zone must still
/// get this list back, since the caller replaces the whole zone each cycle.
/// URLs are parameters only so a test can point them at a loopback server.
async fn refresh_one_list_at(
    client: &reqwest::Client,
    list: &str,
    body_url: &str,
    sidecar_url: &str,
    topn_dir: &Path,
) -> Result<(ZoneSource, ListFetch), TopnRefreshError> {
    let sidecar = fetch_sidecar(client, sidecar_url)
        .await
        .ok_or(TopnRefreshError::NoSidecar)?;
    let path = topn_dir.join(format!("{list}.txt"));
    if let Ok(local) = std::fs::read(&path) {
        if verify_sha256(&local, &sidecar) {
            let text = String::from_utf8_lossy(&local);
            let source = ZoneSource::new(zone_source_kind(list), parse_list(&text));
            return Ok((source, ListFetch::Unchanged));
        }
    }
    let body = fetch_bounded(client, body_url).await?;
    if !verify_sha256(&body, &sidecar) {
        return Err(TopnRefreshError::ChecksumMismatch);
    }
    write_atomic(&path, &body).map_err(TopnRefreshError::Io)?;
    // `body` is a verified curated file — UTF-8 by construction (ASCII/
    // punycode domains + `#` header). `from_utf8_lossy` keeps a stray byte
    // from aborting the whole refresh; `parse_list` then drops it as a
    // non-conforming line.
    let text = String::from_utf8_lossy(&body);
    let source = ZoneSource::new(zone_source_kind(list), parse_list(&text));
    Ok((source, ListFetch::Updated))
}

fn zone_source_kind(list: &str) -> ZoneSourceKind {
    if list == "global" {
        ZoneSourceKind::Global
    } else if list == "edu" {
        ZoneSourceKind::SciEdu
    } else if let Some(cc) = list.strip_prefix("gov-") {
        ZoneSourceKind::GovernmentTopN(cc.to_string())
    } else {
        ZoneSourceKind::CountryTopN(list.to_string())
    }
}

/// Streams `url` into memory, rejecting anything past [`MAX_TOPN_BYTES`] as
/// the bytes arrive (not trusting `Content-Length`). Same shape as
/// `geoip_updater::fetch_bounded`.
async fn fetch_bounded(client: &reqwest::Client, url: &str) -> Result<Bytes, TopnRefreshError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(TopnRefreshError::Http)?
        .error_for_status()
        .map_err(TopnRefreshError::Http)?;
    let mut body = BytesMut::new();
    let mut stream = std::pin::pin!(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(TopnRefreshError::Http)?;
        let total = u64::try_from(body.len() + chunk.len()).unwrap_or(u64::MAX);
        if total > MAX_TOPN_BYTES {
            return Err(TopnRefreshError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// Fetches a list's `.txt.sha256` sidecar text, or `None` if it 404s / can't
/// be fetched / is oversized. Unlike `GeoIP`'s opportunistic sidecar, a
/// missing one here is a hard failure for that list (the caller maps `None`
/// to [`TopnRefreshError::NoSidecar`]) — every published list ships one.
async fn fetch_sidecar(client: &reqwest::Client, url: &str) -> Option<String> {
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let bytes = fetch_body_capped(response).await?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

async fn fetch_body_capped(response: reqwest::Response) -> Option<Bytes> {
    let mut body = BytesMut::new();
    let mut stream = std::pin::pin!(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if u64::try_from(body.len() + chunk.len()).unwrap_or(u64::MAX) > MAX_TOPN_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body.freeze())
}

#[cfg(test)]
mod tests {
    use super::{
        load_zone_from_disk, refresh_one_list_at, selected_lists_last_success, zone_source_kind,
        ListFetch, TOPN_CHECK_INTERVAL,
    };
    use crate::config::RatingFilterConfig;
    use crate::rating_filter::{ZoneLists, ZoneSourceKind};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn zone_source_kind_routes_global_and_country_lists() {
        assert_eq!(zone_source_kind("global"), ZoneSourceKind::Global);
        assert_eq!(
            zone_source_kind("ua"),
            ZoneSourceKind::CountryTopN("ua".to_string())
        );
    }

    // T-122/T-123 (Батч 4.2)
    #[test]
    fn zone_source_kind_routes_gov_and_edu_lists() {
        assert_eq!(
            zone_source_kind("gov-ua"),
            ZoneSourceKind::GovernmentTopN("ua".to_string())
        );
        assert_eq!(zone_source_kind("edu"), ZoneSourceKind::SciEdu);
    }

    #[test]
    fn load_zone_from_disk_reads_a_gov_list() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        let topn = dir.path().join("topn");
        if let Err(err) = std::fs::create_dir_all(&topn) {
            panic!("mkdir: {err}");
        }
        if let Err(err) = std::fs::write(topn.join("gov-ua.txt"), "# header\ngov.ua\n") {
            panic!("write: {err}");
        }
        let config = RatingFilterConfig {
            enabled: true,
            lists: vec!["gov-ua".to_string()],
        };
        let zone = load_zone_from_disk(Some(dir.path()), &config);
        let no_removals = HashSet::new();
        assert_eq!(
            zone.zone_match("diia.gov.ua", &no_removals),
            Some("gov.ua"),
            "the blanket suffix entry loads and covers a subdomain nobody listed"
        );
    }

    /// ARCH-10: a loopback HTTP/1.1 server with a fixed body and sidecar,
    /// counting how many times the body itself was requested.
    async fn counting_list_server(
        body: &'static str,
        sidecar: String,
    ) -> (String, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            panic!("bind loopback");
        };
        let Ok(addr) = listener.local_addr() else {
            panic!("local_addr");
        };
        let body_hits = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&body_hits);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let Ok(n) = stream.read(&mut buf).await else {
                    continue;
                };
                let request = String::from_utf8_lossy(&buf[..n]);
                let payload = if request.starts_with("GET /ua.txt.sha256 ") {
                    sidecar.clone()
                } else {
                    hits.fetch_add(1, Ordering::SeqCst);
                    body.to_string()
                };
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                // Best effort: the client observes whatever arrives.
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (format!("http://{addr}/"), body_hits)
    }

    fn sha256_line(body: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(body.as_bytes());
        let hex = digest.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            // Writing into a String cannot fail.
            let _ = write!(acc, "{b:02x}");
            acc
        });
        format!("{hex}  ua.txt\n")
    }

    #[tokio::test]
    async fn an_unchanged_sidecar_skips_the_body_and_reuses_the_local_file() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        let local = "# header\nrozetka.com.ua\n";
        if let Err(err) = std::fs::write(dir.path().join("ua.txt"), local) {
            panic!("write: {err}");
        }
        let (base, body_hits) =
            counting_list_server("# other\nexample.ua\n", sha256_line(local)).await;
        let client = reqwest::Client::new();
        let result = refresh_one_list_at(
            &client,
            "ua",
            &format!("{base}ua.txt"),
            &format!("{base}ua.txt.sha256"),
            dir.path(),
        )
        .await;
        let Ok((source, fetch)) = result else {
            panic!("refresh must succeed");
        };
        assert_eq!(fetch, ListFetch::Unchanged);
        assert_eq!(
            body_hits.load(Ordering::SeqCst),
            0,
            "body must not be downloaded"
        );
        let zone = ZoneLists::new(vec![source]);
        let no_removals = HashSet::new();
        assert_eq!(
            zone.zone_match("rozetka.com.ua", &no_removals),
            Some("rozetka.com.ua"),
            "the zone keeps the local list, never drops it"
        );
        assert!(zone.zone_match("example.ua", &no_removals).is_none());
    }

    #[tokio::test]
    async fn a_changed_sidecar_downloads_verifies_and_replaces_the_body() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        if let Err(err) = std::fs::write(dir.path().join("ua.txt"), "# old\nold.ua\n") {
            panic!("write: {err}");
        }
        let fresh = "# new\nexample.ua\n";
        let (base, body_hits) = counting_list_server(fresh, sha256_line(fresh)).await;
        let client = reqwest::Client::new();
        let result = refresh_one_list_at(
            &client,
            "ua",
            &format!("{base}ua.txt"),
            &format!("{base}ua.txt.sha256"),
            dir.path(),
        )
        .await;
        let Ok((_source, fetch)) = result else {
            panic!("refresh must succeed");
        };
        assert_eq!(fetch, ListFetch::Updated);
        assert_eq!(body_hits.load(Ordering::SeqCst), 1);
        let Ok(on_disk) = std::fs::read_to_string(dir.path().join("ua.txt")) else {
            panic!("read back");
        };
        assert_eq!(on_disk, fresh);
    }

    #[test]
    fn last_success_needs_every_selected_list_on_disk() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        let topn = dir.path().join("topn");
        if let Err(err) = std::fs::create_dir_all(&topn) {
            panic!("mkdir: {err}");
        }
        if let Err(err) = std::fs::write(topn.join("ua.txt"), "x.ua\n") {
            panic!("write: {err}");
        }
        let only_ua = RatingFilterConfig {
            enabled: true,
            lists: vec!["ua".to_string()],
        };
        assert!(selected_lists_last_success(dir.path(), &only_ua).is_some());
        let with_missing = RatingFilterConfig {
            enabled: true,
            lists: vec!["ua".to_string(), "global".to_string()],
        };
        assert!(
            selected_lists_last_success(dir.path(), &with_missing).is_none(),
            "a newly selected list with no file must be fetched at once"
        );
        let disabled = RatingFilterConfig {
            enabled: false,
            lists: vec!["ua".to_string()],
        };
        assert!(selected_lists_last_success(dir.path(), &disabled).is_none());
    }

    #[test]
    fn check_interval_is_a_day() {
        assert_eq!(TOPN_CHECK_INTERVAL, Duration::from_hours(24));
    }

    #[test]
    fn load_zone_from_disk_is_empty_without_app_data_or_when_disabled() {
        let enabled = RatingFilterConfig {
            enabled: true,
            lists: vec!["ua".to_string()],
        };
        assert!(load_zone_from_disk(None, &enabled).is_empty());

        let dir = std::env::temp_dir();
        let disabled = RatingFilterConfig::default();
        assert!(load_zone_from_disk(Some(&dir), &disabled).is_empty());
    }

    #[test]
    fn load_zone_from_disk_reads_present_files_and_skips_missing_ones() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        let topn = dir.path().join("topn");
        if let Err(err) = std::fs::create_dir_all(&topn) {
            panic!("mkdir: {err}");
        }
        if let Err(err) = std::fs::write(
            topn.join("ua.txt"),
            "# header\nexample.ua\nrozetka.com.ua\n",
        ) {
            panic!("write: {err}");
        }

        let config = RatingFilterConfig {
            enabled: true,
            lists: vec!["ua".to_string(), "global".to_string()],
        };
        let zone = load_zone_from_disk(Some(dir.path()), &config);
        let no_removals = HashSet::new();
        assert_eq!(
            zone.zone_match("www.rozetka.com.ua", &no_removals),
            Some("rozetka.com.ua"),
            "the present ua.txt is loaded"
        );
        // global.txt was absent — it simply contributed nothing, no error.
        assert!(zone.zone_match("wikipedia.org", &no_removals).is_none());
    }
}
