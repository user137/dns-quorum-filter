//! T-218 Фаза 7, Батч 7.2 — the network/orchestration half of the public
//! blocklist-bundle core: fetch each [`crate::blocklist_download::BLOCKLIST_SOURCES`]
//! entry, write its raw text atomically to `<app-data>/blocklists/<id>.txt`,
//! hash it via [`crate::blocklist_download`]'s streaming parsers, and
//! atomically swap the combined, deduplicated set into [`BlocklistBundleState`].
//! Mirrors [`crate::topn_updater`]'s split from [`crate::topn_download`] — the
//! pure per-line parsing stays in `blocklist_download`, everything that
//! touches the network or the filesystem lives here.
//!
//! **Батч 7.3** wires this up end to end: [`run_blocklist_updater`] is spawned
//! by `orchestrate::spawn_public_http_tasks` (same shape as
//! `topn_updater::run_topn_updater`) and [`refresh_all_sources`] reads the
//! live `[blocklist_bundles]` config every cycle — `enabled = false` or an
//! empty `sources` selection makes it a no-op **before** any filesystem or
//! network call, same order `topn_updater::refresh_all_lists` checks in.
//! Startup itself does **not** warm-load `<app-data>/blocklists/*.txt`
//! this batch (advisor review, Батч 7.3 — see [`load_blocklist_bundles_from_disk`]'s
//! own doc for why that call stays deferred): `blocklist_bundles` on
//! `AppState` starts empty and [`run_blocklist_updater`]'s first cycle (which
//! runs immediately, before any park) populates it.
//!
//! **No `.sha256` sidecar for any of the 7 sources** (`data/blocklists/
//! CANDIDATES.md` §3, verified 2026-09-13) — unlike `topn_updater`, there is
//! no checksum to verify; a failed fetch (`Http`/`TooLarge`/`Io`/`Timeout`)
//! just falls back to whatever `<id>.txt` is already on disk, the same
//! "keep last-known-good" posture `topn_updater`/`geoip_updater` already use.
//!
//! **`BlocklistSourceStatus.sources`'s shape differs by path** — worth
//! knowing before a future batch builds a status view over it:
//! [`refresh_all_sources`] pushes one entry per *currently-selected* source
//! (per `[blocklist_bundles] sources` — `config.rs`'s own doc on
//! `BlocklistBundlesConfig` has the `None`-means-"every source" semantics),
//! even a freshly-failed one, while [`load_blocklist_bundles_from_disk`]
//! pushes one only for each file actually present on disk — a fresh install
//! with no files yet yields an **empty** `sources`, not one row per source.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use tokio::sync::Notify;

use crate::blocklist_download::{
    finalize, hash_adblock_domains, hash_plain_domains, BlocklistSource, SourceFormat,
    BLOCKLIST_SOURCES, MAX_BLOCKLIST_BYTES,
};
use crate::dispatch::AppState;
use crate::normalize_domain;
use crate::paths::write_atomic;
use crate::upstream::ReqwestDohClient;

/// Subdirectory of the app-data directory the raw per-source text files live
/// in — sibling of `topn_updater::TOPN_DIR`/`geoip_updater`'s own directory.
const BLOCKLIST_DIR: &str = "blocklists";

/// Upper bound on one source's whole fetch-write-hash attempt. Deliberately
/// generous relative to `topn_updater::TOPN_FETCH_TIMEOUT` (60s, calibrated
/// to a <64 KB curated file): [`MAX_BLOCKLIST_BYTES`] is 128 MB, and 180s
/// (a first draft of this constant) would make that cap unreachable on an
/// ordinary connection — 49 MB (the measured `nrd7.txt` size) in 180s alone
/// needs ~2.2 Mbit/s sustained, and 128 MB in 180s needs ~5.7 Mbit/s. Sources
/// that size would hit `Timeout` most cycles and sit on last-known-good
/// forever — a silent *permanent* staleness bug, not the transient one this
/// design is supposed to tolerate. 600s clears 128 MB even at ~1.7 Mbit/s.
const BLOCKLIST_FETCH_TIMEOUT: Duration = Duration::from_secs(600);

/// How often to re-check the selected sources for a fresh revision. Several
/// (`HaGeZi` Multi PRO/TIF/DynDNS/Hoster) update every few hours upstream,
/// but a daily poll is the same "generous headroom, not a race to be first"
/// cadence [`crate::topn_updater::TOPN_CHECK_INTERVAL`] already settled on
/// (module doc's network-politeness principle).
const BLOCKLIST_CHECK_INTERVAL: Duration = Duration::from_hours(24);

/// Per-source refresh failure. Mirrors `topn_updater::TopnRefreshError` minus
/// the sidecar/checksum variants (module doc — no source publishes one).
#[derive(Debug, thiserror::Error)]
enum BlocklistRefreshError {
    #[error("source download failed")]
    Http(#[source] reqwest::Error),
    #[error("source download exceeds the {MAX_BLOCKLIST_BYTES}-byte size limit")]
    TooLarge,
    #[error("writing the fetched source to disk failed")]
    Io(#[source] std::io::Error),
    #[error("the fetch-write-hash attempt exceeded {BLOCKLIST_FETCH_TIMEOUT:?}")]
    Timeout,
}

impl BlocklistRefreshError {
    /// Payload-free label for [`BlocklistSourceStatus::last_error`] — the
    /// same closed-set-of-`&'static str` pattern `persist_dto`'s
    /// `error_kind` and the watchdog's `WatchdogErrorLabel` already use,
    /// rather than storing this error type itself (not `Clone`/`Eq`, and a
    /// status snapshot must outlive the `reqwest`/`io` error it came from).
    fn label(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::TooLarge => "too_large",
            Self::Io(_) => "io",
            Self::Timeout => "timeout",
        }
    }
}

/// Per-source metadata for the eventual admin status view (Батч 7.4+, not
/// built this batch — hence the struct-level `#[allow(dead_code)]` below:
/// `entry_count`/`last_error` are written this batch but have no reader
/// until that view exists).
#[allow(dead_code)]
pub(crate) struct BlocklistSourceStatus {
    pub(crate) id: &'static str,
    pub(crate) group: &'static str,
    /// Count *before* the cross-source dedup pass — summing every source's
    /// `entry_count` does not equal the final deduplicated set's size.
    pub(crate) entry_count: usize,
    /// `None` = this source has never been fetched successfully. Carried
    /// forward from the previous [`BlocklistBundleState`] on a fallback
    /// (`refresh_all_sources`), so a transient failure doesn't read as
    /// "never updated".
    pub(crate) last_updated: Option<SystemTime>,
    /// Set whenever this cycle's fetch failed, **even if the last-known-good
    /// fallback succeeded** — the source still didn't refresh this cycle,
    /// and a future status view must say so rather than reading clean.
    pub(crate) last_error: Option<&'static str>,
}

/// The atomically-swapped bundle: every published source's domains, reduced
/// to hashes and merged into one sorted, deduplicated set (module doc of
/// `blocklist_download.rs` has the full memory/hash-stability rationale).
/// `seed` is the exact [`RandomState`] instance that built `domains` — always
/// travels with it through the same `Arc` swap, so [`contains_domain`] can
/// never look a hash up against a seed that didn't build the set it's
/// searching (structural version of 7.1's closing-review finding #1).
///
/// [`contains_domain`]: BlocklistBundleState::contains_domain
#[derive(Default)]
pub(crate) struct BlocklistBundleState {
    seed: RandomState,
    domains: Vec<u64>,
    pub(crate) sources: Vec<BlocklistSourceStatus>,
}

impl BlocklistBundleState {
    /// Exact-match membership test — normalizes `domain` the same way every
    /// hashed entry was normalized, then a binary search over the sorted
    /// set. **Not** a suffix walk: whether a hit on `example.com` should also
    /// cover `sub.example.com` depends on whether that source's own semantics
    /// are wildcard (`wildcard/*-onlydomains.txt`, `||domain^`) or exact
    /// (`domains/*.txt`) — 7.1's closing-review finding #2 left this open,
    /// and this method deliberately doesn't prejudge it; the suffix-walk
    /// pipeline wiring is Батч 7.4's job.
    #[allow(dead_code)] // no caller until 7.4 wires pipeline step 2 to this
    pub(crate) fn contains_domain(&self, domain: &str) -> bool {
        let Ok(domain) = normalize_domain(domain) else {
            return false;
        };
        self.domains
            .binary_search(&self.seed.hash_one(domain))
            .is_ok()
    }
}

/// Streams `body` into hashes via the parser matching `format` — shared tail
/// of both the network path ([`refresh_one_source`]) and the disk path
/// ([`load_blocklist_bundles_from_disk`]), so the format dispatch isn't
/// duplicated between them. Pure (no I/O) — unit-tested directly.
fn hash_source_body(format: SourceFormat, body: &str, seed: &RandomState) -> Vec<u64> {
    let mut out = Vec::new();
    match format {
        SourceFormat::PlainDomain => hash_plain_domains(body, seed, &mut out),
        SourceFormat::AdblockNetRules => hash_adblock_domains(body, seed, &mut out),
    }
    out
}

/// Builds the initial [`BlocklistBundleState`] from whatever
/// `<app-data>/blocklists/<id>.txt` files are already present — mirrors
/// `topn_updater::load_zone_from_disk`. Missing files contribute nothing; a
/// fresh install (no files yet) returns an empty bundle. Mints its own fresh
/// [`RandomState`] (there is no previous one to reuse at startup, same as
/// the first `refresh_all_sources` cycle would do anyway).
///
/// **Deliberately still no caller as of Батч 7.3** (advisor review): calling
/// this synchronously at startup — before the listener accepts traffic, the
/// same point `load_zone_from_disk`/`restore_cache` run at — reads and hashes
/// up to `MAX_BLOCKLIST_BYTES` × 8 sources; `load_zone_from_disk`'s own files
/// are three orders of magnitude smaller, so its "warm-load at startup"
/// precedent doesn't carry over without measuring the real cost first. A
/// future batch that wants a warm start without waiting for
/// `run_blocklist_updater`'s first cycle can wire this in then, with that
/// measurement done. Until then `AppState.blocklist_bundles` simply starts
/// empty and that first cycle (runs immediately, no park before it) fills it.
#[allow(dead_code)]
pub(crate) fn load_blocklist_bundles_from_disk(app_data: Option<&Path>) -> BlocklistBundleState {
    let Some(dir) = app_data else {
        return BlocklistBundleState::default();
    };
    let blocklist_dir = dir.join(BLOCKLIST_DIR);
    let seed = RandomState::new();
    let mut domains = Vec::new();
    let mut sources = Vec::with_capacity(BLOCKLIST_SOURCES.len());
    for source in BLOCKLIST_SOURCES {
        let path = blocklist_dir.join(format!("{}.txt", source.id));
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        // A present file proves a past successful fetch — its mtime (written
        // by `write_atomic` at fetch time) is the honest `last_updated`, not
        // `None`; `BlocklistSourceStatus::last_updated`'s own doc says `None`
        // means "never fetched successfully", which a present file disproves.
        let last_updated = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        let hashes = hash_source_body(source.format, &body, &seed);
        sources.push(BlocklistSourceStatus {
            id: source.id,
            group: source.group,
            entry_count: hashes.len(),
            last_updated,
            last_error: None,
        });
        domains.extend(hashes);
    }
    finalize(&mut domains);
    BlocklistBundleState {
        seed,
        domains,
        sources,
    }
}

/// Streams `url` into memory, rejecting anything past [`MAX_BLOCKLIST_BYTES`]
/// as the bytes arrive (not trusting `Content-Length`) — same shape as
/// `topn_updater::fetch_bounded`/`geoip_updater::fetch_bounded`.
async fn fetch_bounded(
    client: &reqwest::Client,
    url: &str,
) -> Result<Bytes, BlocklistRefreshError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(BlocklistRefreshError::Http)?
        .error_for_status()
        .map_err(BlocklistRefreshError::Http)?;
    let mut body = BytesMut::new();
    let mut stream = std::pin::pin!(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BlocklistRefreshError::Http)?;
        let total = u64::try_from(body.len() + chunk.len()).unwrap_or(u64::MAX);
        if total > MAX_BLOCKLIST_BYTES {
            return Err(BlocklistRefreshError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// Fetches, atomically writes the raw text to `<dir>/<id>.txt`, then hashes
/// it. Returns the hashes for this source alone (not yet merged into the
/// combined set — the caller does that once over every source's output).
async fn refresh_one_source(
    client: &reqwest::Client,
    source: &BlocklistSource,
    dir: &Path,
    seed: &RandomState,
) -> Result<Vec<u64>, BlocklistRefreshError> {
    let body = fetch_bounded(client, source.url).await?;
    write_atomic(&dir.join(format!("{}.txt", source.id)), &body)
        .map_err(BlocklistRefreshError::Io)?;
    // A third-party feed is UTF-8 by construction (ASCII/punycode domains,
    // `#`/`!` comments) — `from_utf8_lossy` keeps one stray byte from
    // aborting the whole source; the per-line parsers drop any resulting
    // non-conforming line, same tolerance `topn_updater::refresh_one_list`
    // already applies to its own curated download.
    let text = String::from_utf8_lossy(&body);
    Ok(hash_source_body(source.format, &text, seed))
}

async fn refresh_one_source_bounded(
    client: &reqwest::Client,
    source: &BlocklistSource,
    dir: &Path,
    seed: &RandomState,
) -> Result<Vec<u64>, BlocklistRefreshError> {
    match tokio::time::timeout(
        BLOCKLIST_FETCH_TIMEOUT,
        refresh_one_source(client, source, dir, seed),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(BlocklistRefreshError::Timeout),
    }
}

/// Runs one refresh right away, then every [`BLOCKLIST_CHECK_INTERVAL`] (or
/// sooner if `apply_admin_reset` wakes it) — exact shape of
/// `topn_updater::run_topn_updater`. Spawned by
/// `orchestrate::spawn_public_http_tasks` whenever an app-data directory
/// exists; [`refresh_all_sources`] itself re-reads the config snapshot each
/// cycle and returns immediately while disabled, so an always-running idle
/// task is the price of letting a hand-edit + `/admin/reset` enable the
/// bundles with no restart.
pub async fn run_blocklist_updater(
    client: reqwest::Client,
    app_data: PathBuf,
    state: Arc<AppState<ReqwestDohClient>>,
) {
    let wake = state.blocklist_bundles_refresh_wake_handle();
    loop {
        refresh_all_sources(&client, &app_data, &state).await;
        park_until_due(&wake).await;
    }
}

/// Park between refresh cycles: return when the periodic timer elapses **or**
/// a `wake_blocklist_bundles_refresh()` signal fires. Identical shape to
/// `topn_updater::park_until_due` (a `notify_one` left before this is entered
/// is remembered — one permit — so a config reload during an in-flight
/// refresh still resolves the next park immediately).
async fn park_until_due(wake: &Notify) {
    tokio::select! {
        () = tokio::time::sleep(BLOCKLIST_CHECK_INTERVAL) => {}
        () = wake.notified() => tracing::info!("blocklist-bundle refresh woken by a config reload"),
    }
}

/// One full refresh cycle: fetch every currently-selected
/// [`BLOCKLIST_SOURCES`] entry sequentially (not `FuturesUnordered` — this is
/// a background bulk refetch, not the latency-sensitive quorum fan-out), fall
/// back to last-known-good on a per-source failure, and atomically swap the
/// combined result into `state`. Reads `state.blocklist_bundles_config_snapshot()`
/// fresh every call (so `POST /admin/reset` can flip `enabled`/`sources`
/// without a restart, same as `topn_updater::refresh_all_lists`) and is a
/// no-op — before any filesystem or network access — when disabled or no
/// source is selected. Called by [`run_blocklist_updater`]'s loop.
pub(crate) async fn refresh_all_sources(
    client: &reqwest::Client,
    app_data: &Path,
    state: &AppState<ReqwestDohClient>,
) {
    let config = state.blocklist_bundles_config_snapshot();
    if !config.enabled {
        return;
    }
    // `None` = every current `BLOCKLIST_SOURCES` id (config.rs's
    // `BlocklistBundlesConfig` doc); `Some(ids)` = an explicit subset,
    // `Some(vec![])` explicitly inert.
    if matches!(&config.sources, Some(ids) if ids.is_empty()) {
        return;
    }
    let dir = app_data.join(BLOCKLIST_DIR);
    if let Err(err) = std::fs::create_dir_all(&dir) {
        tracing::warn!("could not create the blocklist-bundle directory, skipping refresh: {err}");
        return;
    }
    let previous = state.blocklist_bundles_snapshot();
    let seed = RandomState::new();
    let mut domains = Vec::new();
    let is_selected = |id: &str| {
        config
            .sources
            .as_ref()
            .is_none_or(|ids| ids.iter().any(|sel| sel == id))
    };
    let mut sources = Vec::with_capacity(
        config
            .sources
            .as_ref()
            .map_or(BLOCKLIST_SOURCES.len(), Vec::len),
    );
    for source in BLOCKLIST_SOURCES.iter().filter(|s| is_selected(s.id)) {
        match refresh_one_source_bounded(client, source, &dir, &seed).await {
            Ok(hashes) => {
                sources.push(BlocklistSourceStatus {
                    id: source.id,
                    group: source.group,
                    entry_count: hashes.len(),
                    last_updated: Some(SystemTime::now()),
                    last_error: None,
                });
                domains.extend(hashes);
            }
            Err(err) => {
                tracing::warn!(
                    "blocklist source {} refresh failed, falling back to last-known-good: {err}",
                    source.id
                );
                let previous_status = previous.sources.iter().find(|s| s.id == source.id);
                let last_updated = previous_status.and_then(|s| s.last_updated);
                let body = std::fs::read_to_string(dir.join(format!("{}.txt", source.id))).ok();
                let hashes = body
                    .map(|body| hash_source_body(source.format, &body, &seed))
                    .unwrap_or_default();
                sources.push(BlocklistSourceStatus {
                    id: source.id,
                    group: source.group,
                    entry_count: hashes.len(),
                    last_updated,
                    // The last-known-good fallback may have succeeded, but
                    // this source still didn't refresh this cycle — the
                    // error is recorded either way (module doc).
                    last_error: Some(err.label()),
                });
                domains.extend(hashes);
            }
        }
    }
    finalize(&mut domains);
    state.update_blocklist_bundles(BlocklistBundleState {
        seed,
        domains,
        sources,
    });
    tracing::info!("blocklist bundles refreshed");
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::RandomState;

    use super::{
        hash_source_body, load_blocklist_bundles_from_disk, BlocklistRefreshError,
        BLOCKLIST_CHECK_INTERVAL, BLOCKLIST_FETCH_TIMEOUT,
    };
    use crate::blocklist_download::SourceFormat;

    #[test]
    fn check_interval_is_a_day() {
        assert_eq!(
            BLOCKLIST_CHECK_INTERVAL,
            std::time::Duration::from_hours(24)
        );
    }

    #[test]
    fn hash_source_body_dispatches_plain_domain_format() {
        let seed = RandomState::new();
        let out = hash_source_body(SourceFormat::PlainDomain, "example.com\n# comment\n", &seed);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn hash_source_body_dispatches_adblock_net_rules_format() {
        let seed = RandomState::new();
        let out = hash_source_body(
            SourceFormat::AdblockNetRules,
            "! comment\n||example.com^\n@@||allowed.example^\n",
            &seed,
        );
        assert_eq!(out.len(), 1, "only the one real ||domain^ rule counts");
    }

    #[test]
    fn blocklist_refresh_error_labels_are_stable() {
        // `Http` isn't constructible outside a real `reqwest` call (no public
        // constructor) — the other three cover the closed-set mapping itself.
        assert_eq!(BlocklistRefreshError::TooLarge.label(), "too_large");
        assert_eq!(BlocklistRefreshError::Timeout.label(), "timeout");
        let io_err = std::io::Error::other("disk full");
        assert_eq!(BlocklistRefreshError::Io(io_err).label(), "io");
    }

    #[test]
    fn fetch_timeout_clears_the_max_size_at_a_realistic_bitrate() {
        // 128 MB at 600s is ~1.7 Mbit/s sustained -- the regression this
        // guards is the original 180s draft, which needed ~5.7 Mbit/s and
        // would have made the cap practically unreachable.
        let seconds = BLOCKLIST_FETCH_TIMEOUT.as_secs();
        let min_mbit_per_sec =
            (crate::blocklist_download::MAX_BLOCKLIST_BYTES * 8) / seconds / 1_000_000;
        assert!(
            min_mbit_per_sec <= 2,
            "timeout too tight for an ordinary connection"
        );
    }

    #[test]
    fn load_blocklist_bundles_from_disk_is_empty_without_app_data() {
        assert!(load_blocklist_bundles_from_disk(None).sources.is_empty());
    }

    #[test]
    fn load_blocklist_bundles_from_disk_reads_present_files_and_skips_missing() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        let blocklists = dir.path().join("blocklists");
        if let Err(err) = std::fs::create_dir_all(&blocklists) {
            panic!("mkdir: {err}");
        }
        if let Err(err) = std::fs::write(
            blocklists.join("hagezi-multi-pro.txt"),
            "# header\nexample.com\nads.example.net\n",
        ) {
            panic!("write: {err}");
        }

        let bundle = load_blocklist_bundles_from_disk(Some(dir.path()));
        assert_eq!(
            bundle.sources.len(),
            1,
            "only the present file contributes a status entry"
        );
        assert_eq!(bundle.sources[0].id, "hagezi-multi-pro");
        assert_eq!(bundle.sources[0].entry_count, 2);
        assert!(
            bundle.sources[0].last_updated.is_some(),
            "a present file proves a past successful fetch"
        );
        // Raw, un-normalized input -- `contains_domain` must normalize it
        // itself (the same case/trailing-dot folding `push_normalized`
        // already applied when this entry was hashed). Pre-normalizing in
        // the test would pass even if `contains_domain` dropped its own
        // `normalize_domain` call.
        assert!(
            bundle.contains_domain("Example.COM."),
            "lookup normalization must match the normalization entries were hashed with"
        );
        assert!(!bundle.contains_domain("not-in-any-list.example"));
    }

    #[test]
    fn load_blocklist_bundles_from_disk_dedups_the_same_domain_across_two_sources() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        let blocklists = dir.path().join("blocklists");
        if let Err(err) = std::fs::create_dir_all(&blocklists) {
            panic!("mkdir: {err}");
        }
        if let Err(err) =
            std::fs::write(blocklists.join("hagezi-multi-pro.txt"), "shared.example\n")
        {
            panic!("write: {err}");
        }
        if let Err(err) = std::fs::write(blocklists.join("1hosts-lite.txt"), "shared.example\n") {
            panic!("write: {err}");
        }

        let bundle = load_blocklist_bundles_from_disk(Some(dir.path()));
        let total_entry_count: usize = bundle.sources.iter().map(|s| s.entry_count).sum();
        assert_eq!(
            total_entry_count, 2,
            "each source reports its own pre-dedup count"
        );
        assert!(
            bundle.contains_domain("shared.example"),
            "the shared domain is still found post-dedup"
        );
        assert_eq!(
            bundle.domains.len(),
            1,
            "finalize() must collapse the two sources' identical hash into one entry"
        );
    }
}
