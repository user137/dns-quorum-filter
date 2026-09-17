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
    finalize, hash_adblock_domains, hash_plain_domains, validate_hashes, BlocklistSource,
    SourceFormat, ValidationFailure, BLOCKLIST_SOURCES, MAX_BLOCKLIST_BYTES,
};
use crate::dispatch::AppState;
use crate::normalize_domain;
use crate::paths::write_atomic;
use crate::upstream::ReqwestDohClient;

/// Subdirectory of the app-data directory the raw per-source text files live
/// in — sibling of `topn_updater::TOPN_DIR`/`geoip_updater`'s own directory.
const BLOCKLIST_DIR: &str = "blocklists";

/// Upper bound on one source's fetch, and on *initiating* its write+hash —
/// **not** a bound on write+hash actually finishing (T-232, 2026-09-17):
/// write+hash now runs on `tokio::task::spawn_blocking`'s pool, which
/// `tokio::time::timeout` cannot cancel. A timeout firing mid-hash returns
/// [`BlocklistRefreshError::Timeout`] to the caller while the detached
/// blocking thread keeps hashing to completion in the background, its
/// result simply dropped — not a correctness bug (the fallback path already
/// treats `Timeout` like any other failure), just a reason this constant no
/// longer bounds the *whole* attempt's wall-clock cost the way its name
/// suggests. Deliberately generous relative to `topn_updater::TOPN_FETCH_TIMEOUT`
/// (60s, calibrated to a <64 KB curated file): [`MAX_BLOCKLIST_BYTES`] is
/// 128 MB, and 180s (a first draft of this constant) would make that cap
/// unreachable on an ordinary connection — 49 MB (the measured `nrd7.txt`
/// size) in 180s alone needs ~2.2 Mbit/s sustained, and 128 MB in 180s needs
/// ~5.7 Mbit/s. Sources that size would hit `Timeout` most cycles and sit on
/// last-known-good forever — a silent *permanent* staleness bug, not the
/// transient one this design is supposed to tolerate. 600s clears 128 MB
/// even at ~1.7 Mbit/s.
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
    /// T-232: the `spawn_blocking` write+hash task panicked, or (far more
    /// rarely) the runtime shut down mid-task — **not** "cancelled": dropping
    /// a `spawn_blocking` `JoinHandle` doesn't cancel it, so this variant is
    /// only ever constructed from a real `Err(JoinError)`.
    #[error("the blocking write+hash task panicked (or the runtime shut down)")]
    Join(#[source] tokio::task::JoinError),
    /// T-233: too few candidate lines normalized into a real domain — the
    /// source most likely no longer serves its published format. The bad
    /// body is **never** written to disk (`write_and_hash_blocking` gates
    /// before `write_atomic`), so the existing last-known-good fallback
    /// below stays genuinely last-*good*.
    #[error("only {accepted}/{candidates} candidate lines parsed as a domain")]
    LowParseSuccessRatio { accepted: usize, candidates: usize },
    /// T-233: at least `MIN_CANARY_HITS_TO_REJECT` well-known legitimate
    /// domains appear as an exact entry — same never-written-to-disk
    /// guarantee as above.
    #[error("{count} known-legitimate canary domains present in the source")]
    CanaryDomainsPresent { count: usize },
}

impl From<ValidationFailure> for BlocklistRefreshError {
    fn from(failure: ValidationFailure) -> Self {
        match failure {
            ValidationFailure::LowParseSuccessRatio {
                accepted,
                candidates,
            } => Self::LowParseSuccessRatio {
                accepted,
                candidates,
            },
            ValidationFailure::CanaryDomainsPresent { count } => {
                Self::CanaryDomainsPresent { count }
            }
        }
    }
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
            Self::Join(_) => "join",
            Self::LowParseSuccessRatio { .. } => "low_parse_ratio",
            Self::CanaryDomainsPresent { .. } => "canary_hit",
        }
    }
}

/// Per-source metadata for the admin status view (T-218 Батч 7.4 частина 2 —
/// [`crate::admin::BlocklistSourceStatusView`] is the read side, built by
/// `crate::dispatch::blocklist_bundles_status_view`).
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
/// `seed` travels with `domains` through the same `Arc` swap, so
/// [`matches_domain`] never looks a hash up against a seed unrelated to the
/// one that built the set it's searching (structural version of 7.1's
/// closing-review finding #1). **Since T-232, this isn't always the exact
/// same `RandomState` *instance*** — `refresh_one_source`/`refresh_all_sources`'s
/// fallback arm each `.clone()` this seed to move it into a `spawn_blocking`
/// closure and hash with the clone, while the original (unmoved) instance is
/// what ends up in this struct. That's sound only because `RandomState::clone`
/// copies its two internal keys rather than reseeding — a clone and its
/// original `hash_one` identically for the same input, pinned by
/// `blocklist_updater::tests::a_cloned_random_state_hashes_identically_to_its_original`
/// below, not just known from `std`'s docs.
///
/// [`matches_domain`]: BlocklistBundleState::matches_domain
#[derive(Default)]
pub(crate) struct BlocklistBundleState {
    seed: RandomState,
    domains: Vec<u64>,
    pub(crate) sources: Vec<BlocklistSourceStatus>,
}

impl BlocklistBundleState {
    /// Suffix-walk membership test (T-218 Батч 7.4 — resolves 7.1's
    /// closing-review finding #2). Every currently published source is
    /// subdomain-inclusive by intent even where the URL path alone doesn't
    /// say so: `hagezi-multi-pro`/`tif`/`dyndns`/`hoster` fetch `HaGeZi`'s own
    /// `wildcard/` variant (`HaGeZi` publishes both `wildcard/` and `domains/`
    /// specifically to mark this); `hagezi-nrd`/`hagezi-dga` list whole fresh
    /// registrations, where the point of NRD/DGA detection is the
    /// registration itself, not one hostname under it; `1hosts-lite` is
    /// already registrable-level by construction (hosts-style ad/tracker
    /// blocking); and `adguard-dns-filter`'s `||domain^` is an adblock
    /// anchor rule, which matches a domain **and every subdomain** by the
    /// filter-syntax spec regardless of file naming (DECISIONS.md
    /// 2026-09-13). SPEC.md §5 already states step 2 doesn't distinguish a
    /// bundle entry's origin from a manual one — same wildcard-suffix
    /// contract as the manual blocklist.
    ///
    /// Normalizes `domain` once (self-normalizing, not reliant on the
    /// caller — same invariant the exact-match predecessor of this method
    /// already had, still proven by this module's own `Example.COM.` test),
    /// then walks each suffix candidate from the full normalized domain
    /// down. **Deliberately stricter than [`crate::rating_filter::ZoneLists::zone_match`]**,
    /// which does test the bare final label: the `while let Some(_) =
    /// candidate.split_once('.')` loop condition below only ever tests a
    /// candidate with at least one dot (≥2 labels) — a bare TLD can never
    /// reach `binary_search`, provable from the loop condition itself, not
    /// from remembering that Батч 7.1 already excluded `HaGeZi`'s "Most
    /// Abused TLDs" source. The apex domain itself still matches (the first
    /// iteration's candidate is the full normalized input).
    pub(crate) fn matches_domain(&self, domain: &str) -> bool {
        let Ok(normalized) = normalize_domain(domain) else {
            return false;
        };
        let mut candidate = normalized.as_str();
        while let Some((_, rest)) = candidate.split_once('.') {
            if self
                .domains
                .binary_search(&self.seed.hash_one(candidate))
                .is_ok()
            {
                return true;
            }
            candidate = rest;
        }
        false
    }

    /// Whether the bundle currently holds any entry — the non-empty half of
    /// `dispatch::blocklist_bundles_is_active`'s `enabled && !is_empty()`
    /// gate, mirroring `rating_filter_is_active`'s own zone-emptiness check.
    pub(crate) fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Builds a bundle straight from a list of domain strings — mints a
    /// fresh [`RandomState`], normalizes and hashes each entry the same way
    /// the real ingestion path does, and finalizes the set. `sources` is
    /// left empty (no status metadata to fabricate). `#[cfg(test)]`, unlike
    /// `rating_filter::ZoneLists::new` (which a real caller,
    /// `topn_updater::refresh_all_lists`, also uses) — nothing outside
    /// `pipeline`/`dispatch`'s own test modules needs this; the real bundle
    /// only ever comes from [`refresh_all_sources`]/
    /// [`load_blocklist_bundles_from_disk`].
    #[cfg(test)]
    pub(crate) fn from_domains<'a>(entries: impl IntoIterator<Item = &'a str>) -> Self {
        let seed = RandomState::new();
        let mut domains = Vec::new();
        for entry in entries {
            if let Ok(domain) = normalize_domain(entry) {
                domains.push(seed.hash_one(domain));
            }
        }
        finalize(&mut domains);
        Self {
            seed,
            domains,
            sources: Vec::new(),
        }
    }
}

/// Streams `body` into hashes via the parser matching `format` — shared tail
/// of both the network path ([`refresh_one_source`]) and the disk path
/// ([`load_blocklist_bundles_from_disk`]), so the format dispatch isn't
/// duplicated between them. Pure (no I/O) — unit-tested directly. Returns
/// the candidate-line count alongside the hashes (T-233 — the denominator
/// `blocklist_download::validate_hashes`'s parse-success-ratio check needs).
fn hash_source_body(format: SourceFormat, body: &str, seed: &RandomState) -> (Vec<u64>, usize) {
    let mut out = Vec::new();
    let mut candidates = 0;
    match format {
        SourceFormat::PlainDomain => hash_plain_domains(body, seed, &mut out, &mut candidates),
        SourceFormat::AdblockNetRules => {
            hash_adblock_domains(body, seed, &mut out, &mut candidates);
        }
    }
    (out, candidates)
}

/// T-232/T-233: the synchronous hash-validate-then-write tail of
/// [`refresh_one_source`], extracted so it's directly unit-testable (a
/// tempfile, no tokio) and so the `spawn_blocking` call site around it stays
/// a thin, untested-by-design shell — same split as
/// `log_persist::persist_snapshot` vs `run_query_log_persister`. Called only
/// from inside `spawn_blocking`.
///
/// **Order matters (T-233 advisor review): hash+validate happen entirely in
/// memory over `body` before any disk write.** `write_atomic(path, ...)`
/// only runs once [`validate_hashes`] returns `Ok` — a source that fails the
/// gate never touches `<id>.txt`, so the existing last-known-good file
/// [`read_and_hash_blocking`] falls back to on the *next* failure is never
/// overwritten by this cycle's rejected content. Getting this order backward
/// (write first, validate after — T-232's original shape) would let a single
/// gate-failing cycle poison the very last-known-good fallback the gate
/// exists to protect.
fn write_and_hash_blocking(
    path: &Path,
    body: &[u8],
    format: SourceFormat,
    seed: &RandomState,
) -> Result<Vec<u64>, BlocklistRefreshError> {
    // A third-party feed is UTF-8 by construction (ASCII/punycode domains,
    // `#`/`!` comments) — `from_utf8_lossy` keeps one stray byte from
    // aborting the whole source; the per-line parsers drop any resulting
    // non-conforming line, same tolerance `topn_updater::refresh_one_list`
    // already applies to its own curated download.
    let text = String::from_utf8_lossy(body);
    let (hashes, candidates) = hash_source_body(format, &text, seed);
    validate_hashes(&hashes, candidates, seed)?;
    write_atomic(path, body).map_err(BlocklistRefreshError::Io)?;
    Ok(hashes)
}

/// T-232: the synchronous read-then-hash tail of `refresh_all_sources`'s
/// last-known-good fallback, extracted for the same reason as
/// [`write_and_hash_blocking`]. A missing/unreadable file yields an empty
/// set — same "silently skip, never abort the cycle" tolerance the caller
/// already had for this path before this extraction. No gate here — any file
/// written **since T-233** already passed [`validate_hashes`] the cycle it
/// was written (module doc on [`write_and_hash_blocking`]); the eight files
/// already on disk from before this gate existed are grandfathered in
/// unvalidated on the first post-upgrade read, same as any other
/// last-known-good content this module trusts without re-checking.
fn read_and_hash_blocking(path: &Path, format: SourceFormat, seed: &RandomState) -> Vec<u64> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    hash_source_body(format, &body, seed).0
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
        let (hashes, _candidates) = hash_source_body(source.format, &body, &seed);
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

/// Fetches (async), then writes+hashes the body entirely inside one
/// `tokio::task::spawn_blocking` hop (T-232: [`write_and_hash_blocking`] —
/// write, UTF-8 conversion and hash are all synchronous CPU/IO work, and
/// bundling them in one blocking hop avoids an extra runtime round-trip
/// versus splitting the write from the hash). Returns the hashes for this
/// source alone (not yet merged into the combined set — the caller does
/// that once over every source's output).
async fn refresh_one_source(
    client: &reqwest::Client,
    source: &BlocklistSource,
    dir: &Path,
    seed: &RandomState,
) -> Result<Vec<u64>, BlocklistRefreshError> {
    let body = fetch_bounded(client, source.url).await?;
    let path = dir.join(format!("{}.txt", source.id));
    let format = source.format;
    let seed = seed.clone();
    tokio::task::spawn_blocking(move || write_and_hash_blocking(&path, &body, format, &seed))
        .await
        .map_err(BlocklistRefreshError::Join)?
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
                let path = dir.join(format!("{}.txt", source.id));
                let format = source.format;
                let seed_for_fallback = seed.clone();
                // T-232: read+hash moved off the async worker via
                // `spawn_blocking`, same as the primary path. A `JoinError`
                // here collapses to the same empty `Vec` as a missing file
                // (`read_and_hash_blocking`'s own `Ok`/`Err` already do that)
                // — not new data loss: a first-ever failed fetch already has
                // no file on disk, so "nothing to fall back to" is an
                // already-reachable, already-handled outcome this just
                // extends to one more cause of the same result.
                let hashes = tokio::task::spawn_blocking(move || {
                    read_and_hash_blocking(&path, format, &seed_for_fallback)
                })
                .await
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
    // T-232: `finalize` (sort_unstable+dedup over the combined set) is its
    // own synchronous CPU-bound step, separate from any one source's hash —
    // moved off the async worker the same way. On a `JoinError` here (should
    // never happen in practice: `finalize` is a pure sort/dedup over
    // already-computed hashes, nothing user-controlled to panic on) this
    // cycle's result is discarded entirely rather than ever swapping in an
    // unsorted/undeduped `Vec` — `matches_domain`'s `binary_search`
    // correctness depends on `finalize` having actually run, so the
    // previous, still-valid bundle staying in place is strictly safer than
    // applying a partial result.
    let domains = match tokio::task::spawn_blocking(move || {
        finalize(&mut domains);
        domains
    })
    .await
    {
        Ok(domains) => domains,
        Err(join_err) => {
            tracing::error!(
                "blocklist-bundle finalize task failed, keeping the previous bundle: {join_err}"
            );
            return;
        }
    };
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
    use std::hash::BuildHasher;

    use super::{
        hash_source_body, load_blocklist_bundles_from_disk, read_and_hash_blocking,
        write_and_hash_blocking, BlocklistBundleState, BlocklistRefreshError,
        BLOCKLIST_CHECK_INTERVAL, BLOCKLIST_FETCH_TIMEOUT,
    };
    use crate::blocklist_download::{SourceFormat, BLOCKLIST_CANARY_DOMAINS};

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
        let (out, candidates) =
            hash_source_body(SourceFormat::PlainDomain, "example.com\n# comment\n", &seed);
        assert_eq!(out.len(), 1);
        assert_eq!(candidates, 1);
    }

    #[test]
    fn hash_source_body_dispatches_adblock_net_rules_format() {
        let seed = RandomState::new();
        let (out, candidates) = hash_source_body(
            SourceFormat::AdblockNetRules,
            "! comment\n||example.com^\n@@||allowed.example^\n",
            &seed,
        );
        assert_eq!(out.len(), 1, "only the one real ||domain^ rule counts");
        assert_eq!(candidates, 1);
    }

    #[test]
    fn a_cloned_random_state_hashes_identically_to_its_original() {
        // T-232: `refresh_one_source`/`refresh_all_sources`'s fallback arm
        // each `.clone()` `BlocklistBundleState.seed` to move it into a
        // `spawn_blocking` closure, then hash with the clone while the
        // *original* instance is what lands back in the struct. This test
        // pins the invariant that makes that sound (`BlocklistBundleState`'s
        // own doc comment above references it by name) — if
        // `RandomState::clone` ever stopped copying its keys and started
        // reseeding instead, every `matches_domain` lookup would silently
        // return `false` for the whole bundle: a total, unannounced filter
        // bypass, not a panic or a test failure anywhere else.
        let original = RandomState::new();
        let clone = original.clone();
        let (built_with_clone, _candidates) =
            hash_source_body(SourceFormat::PlainDomain, "example.com\n", &clone);
        let looked_up_with_original = original.hash_one("example.com");
        assert_eq!(built_with_clone, vec![looked_up_with_original]);
    }

    #[test]
    fn blocklist_refresh_error_labels_are_stable() {
        // `Http` isn't constructible outside a real `reqwest` call (no public
        // constructor) — the other three cover the closed-set mapping itself.
        assert_eq!(BlocklistRefreshError::TooLarge.label(), "too_large");
        assert_eq!(BlocklistRefreshError::Timeout.label(), "timeout");
        let io_err = std::io::Error::other("disk full");
        assert_eq!(BlocklistRefreshError::Io(io_err).label(), "io");
        assert_eq!(
            BlocklistRefreshError::LowParseSuccessRatio {
                accepted: 1,
                candidates: 10
            }
            .label(),
            "low_parse_ratio"
        );
        assert_eq!(
            BlocklistRefreshError::CanaryDomainsPresent { count: 2 }.label(),
            "canary_hit"
        );
    }

    #[tokio::test]
    async fn blocklist_refresh_error_join_label_is_stable() {
        // `JoinError` (like `Http`) has no public constructor either — the
        // one way to build a real one is to let a spawned task actually
        // panic and await its handle; tokio catches the panic inside the
        // task, it doesn't propagate to this test's own thread.
        let Err(join_err) = tokio::spawn(async { panic!("boom") }).await else {
            panic!("the spawned task must have panicked");
        };
        assert_eq!(BlocklistRefreshError::Join(join_err).label(), "join");
    }

    #[test]
    fn write_and_hash_blocking_writes_the_file_and_hashes_it() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("source.txt");
        let seed = RandomState::new();
        let Ok(hashes) = write_and_hash_blocking(
            &path,
            b"example.com\n# comment\n",
            SourceFormat::PlainDomain,
            &seed,
        ) else {
            panic!("write_and_hash_blocking must succeed against a writable temp dir");
        };
        assert_eq!(hashes.len(), 1);
        let Ok(written) = std::fs::read_to_string(&path) else {
            panic!("the file must have been written");
        };
        assert_eq!(written, "example.com\n# comment\n");
    }

    #[test]
    fn write_and_hash_blocking_tolerates_invalid_utf8_via_lossy_conversion() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("source.txt");
        let seed = RandomState::new();
        // Two valid lines plus the invalid tail keeps the ratio (2/3) well
        // clear of MIN_PARSE_SUCCESS_RATIO (0.5) — this test is about UTF-8
        // tolerance, not the ratio boundary (that's
        // `validate_hashes_accepts_exactly_at_the_ratio_floor`'s job; a
        // single-valid-line fixture here would pass at exactly the
        // threshold and silently start asserting the wrong thing).
        let mut body = b"example.com\nexample.net\n".to_vec();
        body.extend_from_slice(&[0xff, 0xfe]);
        let Ok(hashes) = write_and_hash_blocking(&path, &body, SourceFormat::PlainDomain, &seed)
        else {
            panic!("invalid UTF-8 must not abort the whole source");
        };
        assert_eq!(
            hashes.len(),
            2,
            "the two valid lines before the bad tail still count"
        );
    }

    #[test]
    fn write_and_hash_blocking_rejects_a_low_parse_ratio_and_never_writes_the_file() {
        // T-233 discriminating test: a source that trips the gate must never
        // touch disk — a regression back to "write, then validate" (T-232's
        // original order) would leave the bad body on disk despite the
        // caller-visible `Err`.
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("source.txt");
        let seed = RandomState::new();
        let body = b"<html>\n<body>429 Too Many Requests</body>\n</html>\n";
        let Err(err) = write_and_hash_blocking(&path, body, SourceFormat::PlainDomain, &seed)
        else {
            panic!("an HTML error page must trip the parse-ratio gate");
        };
        assert!(matches!(
            err,
            BlocklistRefreshError::LowParseSuccessRatio { .. }
        ));
        assert!(
            !path.exists(),
            "a gate-rejected body must never be written to disk"
        );
    }

    #[test]
    fn write_and_hash_blocking_rejects_canary_domains_and_never_writes_the_file() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("source.txt");
        let seed = RandomState::new();
        let body = format!(
            "real-ads-1.example\nreal-ads-2.example\n{}\n{}\n",
            BLOCKLIST_CANARY_DOMAINS[0], BLOCKLIST_CANARY_DOMAINS[1]
        );
        let Err(err) =
            write_and_hash_blocking(&path, body.as_bytes(), SourceFormat::PlainDomain, &seed)
        else {
            panic!("two canary domains must trip the gate");
        };
        assert!(matches!(
            err,
            BlocklistRefreshError::CanaryDomainsPresent { count: 2 }
        ));
        assert!(
            !path.exists(),
            "a gate-rejected body must never be written to disk"
        );
    }

    #[test]
    fn write_and_hash_blocking_does_not_poison_an_existing_last_known_good_file() {
        // The scenario the reordering fix protects: a healthy cycle writes a
        // good file, then a later gate-rejected cycle must leave it exactly
        // as it was, so `read_and_hash_blocking`'s fallback still reads the
        // real last-known-good, not the rejected content.
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("source.txt");
        let seed = RandomState::new();
        let good_body = b"real-ads-1.example\nreal-ads-2.example\n";
        assert!(
            write_and_hash_blocking(&path, good_body, SourceFormat::PlainDomain, &seed).is_ok(),
            "a healthy first cycle must succeed"
        );
        let bad_body = b"<html>\n<body>429 Too Many Requests</body>\n</html>\n";
        assert!(
            write_and_hash_blocking(&path, bad_body, SourceFormat::PlainDomain, &seed).is_err()
        );
        let Ok(on_disk) = std::fs::read(&path) else {
            panic!("the good file must still be on disk");
        };
        assert_eq!(
            on_disk, good_body,
            "a rejected later cycle must not overwrite the earlier good file"
        );
    }

    #[test]
    fn read_and_hash_blocking_returns_empty_for_a_missing_file() {
        let seed = RandomState::new();
        let missing = std::path::Path::new("this/path/does/not/exist.txt");
        assert!(read_and_hash_blocking(missing, SourceFormat::PlainDomain, &seed).is_empty());
    }

    #[test]
    fn read_and_hash_blocking_reads_and_hashes_an_existing_file() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let path = dir.path().join("source.txt");
        let Ok(()) = std::fs::write(&path, "example.com\nexample.org\n") else {
            panic!("must be able to write the fixture file");
        };
        let seed = RandomState::new();
        let hashes = read_and_hash_blocking(&path, SourceFormat::PlainDomain, &seed);
        assert_eq!(hashes.len(), 2);
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
        // Raw, un-normalized input -- `matches_domain` must normalize it
        // itself (the same case/trailing-dot folding `push_normalized`
        // already applied when this entry was hashed). Pre-normalizing in
        // the test would pass even if `matches_domain` dropped its own
        // `normalize_domain` call.
        assert!(
            bundle.matches_domain("Example.COM."),
            "lookup normalization must match the normalization entries were hashed with"
        );
        assert!(!bundle.matches_domain("not-in-any-list.example"));
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
            bundle.matches_domain("shared.example"),
            "the shared domain is still found post-dedup"
        );
        assert_eq!(
            bundle.domains.len(),
            1,
            "finalize() must collapse the two sources' identical hash into one entry"
        );
    }

    #[test]
    fn matches_domain_covers_a_subdomain_of_a_hashed_entry() {
        let bundle = BlocklistBundleState::from_domains(["blocked.example"]);
        assert!(
            bundle.matches_domain("sub.blocked.example"),
            "a subdomain of a hashed entry must match (wildcard/subdomain-inclusive \
             semantics — module doc on matches_domain)"
        );
        assert!(
            bundle.matches_domain("blocked.example"),
            "the apex entry itself still matches"
        );
        assert!(!bundle.matches_domain("not-blocked.example"));
    }

    #[test]
    fn matches_domain_never_tests_a_bare_tld() {
        // Discriminating test (not just an empty-candidate check, which
        // would pass under either walk): a bare TLD hashed into the set
        // must never make an unrelated domain under it match. Proves the
        // loop's `while let Some(_) = candidate.split_once('.')` condition
        // really excludes the final single-label candidate, not just that
        // the walk doesn't panic on one.
        let bundle = BlocklistBundleState::from_domains(["com"]);
        assert!(
            !bundle.matches_domain("example.com"),
            "a bare TLD in the hashed set must never suffix-match every domain under it"
        );
    }
}
