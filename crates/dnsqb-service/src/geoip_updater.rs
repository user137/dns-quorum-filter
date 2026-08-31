//! T-75: the background task that keeps the local `GeoIP` country database
//! (`geoip.rs`) up to date — fetches DB-IP Lite's monthly `.mmdb.gz` release
//! over TLS, verifies it, and atomically swaps it into both [`AppState`]
//! (live) and the on-disk file `main.rs` will reload from on the next
//! restart.
//!
//! **Integrity verification, and why it isn't a single mechanism (T-75
//! plan, user-decided 2026-08-29).** `download.db-ip.com` is unreachable
//! from this project's dev environment (a DNS-blocked sandbox — confirmed
//! via both `curl` and `WebFetch`, both fail to resolve the host at all,
//! while an unrelated domain resolves fine), so whether `db-ip.com`
//! publishes a machine-readable checksum sidecar next to the `.mmdb.gz`
//! file could not be confirmed before writing this module — only that their
//! download *page* shows an MD5/SHA1 as plain HTML text, which is not the
//! same thing as a fetchable sidecar file. SPEC.md §3.5 calls integrity
//! verification "не опційна" (not optional), so rather than silently
//! reinterpret that requirement on this module's own security analysis,
//! the choice below was put to the user directly and this is what they
//! chose: try a `.sha1` sidecar at the same URL opportunistically
//! ([`crate::geoip_download::checksum_sidecar_url`]) and verify against it
//! when present (a mismatch is a hard failure, not a warning); when absent
//! (a 404, or any other failure fetching it), fall back to a still-real
//! integrity gate that doesn't depend on `db-ip.com` publishing anything
//! extra: TLS (transport integrity + CA-validated origin identity), the
//! gzip trailer's own CRC32/ISIZE (validated automatically by `flate2`
//! reading the stream to its real EOF —
//! [`crate::geoip_download::decompress_bounded`]), a structural `MaxMind`-DB
//! parse via [`GeoipReader::from_bytes`], and a loose `database_type` sanity
//! check below (catches a well-formed but wrong-shaped DB, e.g. a City-level
//! one, rather than a country one).
//!
//! **Whoever first runs this against real `db-ip.com` connectivity** (CI,
//! or a developer machine with normal internet access) should check which
//! integrity path actually fires — see
//! `tests::fetch_and_verify_against_live_db_ip` (`#[ignore]`d, same
//! "manual, not CI-gated" precedent as `upstream.rs`'s live-Quad9 test) —
//! and fold that confirmation back into this doc comment.
//!
//! **`MaxMind GeoLite2` advanced mode (T-80).** When the operator drops a
//! complete `geoip_maxmind.toml` in the app-data dir
//! ([`crate::geoip_credentials`]), [`GeoipSource::Maxmind`] replaces DB-IP
//! Lite: a single download of `MaxMind`'s modern permalink,
//! `https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz`,
//! authenticated with an HTTP `Authorization: Basic` header (account id :
//! license key), never a URL query parameter. **Verified this session** (not
//! reconstructed from docs): that path answers `401 WWW-Authenticate: Basic
//! realm="geoip-download"` — a real endpoint, where a bogus sibling answers
//! `404` — and `reqwest` 0.13 strips `Authorization` on the cross-host
//! redirect to Cloudflare R2 (`reqwest/src/redirect.rs::remove_sensitive_headers`),
//! so the credential never leaves `MaxMind`'s origin. **Not verified without
//! real credentials**: whether the `?suffix=tar.gz.sha256` sidecar returns a
//! usable digest per release (the path exists — `401`, not `404`), so it's
//! fetched opportunistically and a *present* mismatch hard-fails, while its
//! absence falls back to the same TLS + gzip-CRC + structural-parse gate as
//! DB-IP (the resolution the user already chose at T-75). The `GeoLite2`
//! download is a `.tar.gz` carrying `GeoLite2-Country.mmdb` alongside
//! `LICENSE.txt`/`COPYRIGHT.txt`;
//! [`crate::geoip_download::extract_mmdb_from_tar_gz`] pulls the single
//! `.mmdb` member, bounded. A `MaxMind` `reqwest::Error` is **never** logged
//! via `Display` — mapped to a coarse [`GeoipUpdateError`] label instead
//! ([`GeoipUpdateError::MaxmindDownloadFailed`] /
//! [`GeoipUpdateError::MaxmindAuthRejected`]), the same `quorum::error_kind`
//! discipline applied to a Basic-auth secret rather than a domain.
//! `GEOIP_CHECK_INTERVAL` stays 24h — a daily poll catches `GeoLite2`'s
//! twice-weekly (Tue/Fri) release well within a day, and polling `MaxMind`
//! harder risks their documented rate-limiting.
//!
//! **Whoever first runs this against real `MaxMind` credentials** should note
//! in this doc comment whether the `.tar.gz.sha256` sidecar fired — see
//! `tests::fetch_and_verify_against_live_maxmind` (`#[ignore]`d, reads
//! `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY` from the environment).
//!
//! A failed refresh (network error, checksum mismatch, corrupt download,
//! wrong database type) never clears an already-loaded database — SPEC.md's
//! own user-safety framing: a stale country list is far better than
//! silently losing `GeoIP` filtering because one refresh attempt hit a
//! transient error. It's logged (`tracing::warn!`) and retried on the next
//! periodic check.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::dispatch::{AppState, GeoipState};
use crate::geoip::{GeoipError, GeoipReader};
use crate::geoip_credentials::MaxmindCredentials;
use crate::geoip_download::{
    candidate_download_urls, checksum_sidecar_url, decompress_bounded, extract_mmdb_from_tar_gz,
    maxmind_download_url, MAXMIND_EDITION, MAX_GEOIP_COMPRESSED_BYTES,
    MAX_GEOIP_DECOMPRESSED_BYTES,
};
use crate::upstream::ReqwestDohClient;

/// Which upstream a [`run_geoip_updater`] instance pulls its database from
/// (T-80). Seeded at startup by `main.rs` from
/// [`crate::geoip_credentials::load`] — DB-IP Lite (SPEC.md §3.5's
/// registration-free default) unless the operator has stored `MaxMind`
/// credentials, in which case `MaxMind GeoLite2` (twice-weekly updates, the
/// operator's own key). Since T-163 it lives on
/// [`crate::dispatch::AppState`] and `run_geoip_updater` re-snapshots it every
/// cycle, so a `/admin/geoip/maxmind[/clear]` or `/admin/reset` change is
/// picked up with no restart.
///
/// `Debug` is derived but safe to log: the key inside [`MaxmindCredentials`]
/// is a [`crate::geoip_credentials::LicenseKey`], whose own `Debug` redacts.
#[derive(Debug, Clone)]
pub enum GeoipSource {
    /// DB-IP Lite Country — monthly, no credentials (SPEC.md §3.5 default).
    DbIpLite,
    /// `MaxMind GeoLite2` Country — twice-weekly, operator-supplied credentials.
    Maxmind(MaxmindCredentials),
}

/// How often to check for a new `GeoIP` database release — both sources
/// (T-80). DB-IP Lite updates monthly (SPEC.md §3.5); `MaxMind GeoLite2`
/// twice weekly. A daily check is generous headroom for either — it catches
/// a twice-weekly release well within a day — and not tuned to a published
/// release-day guarantee (neither source's exact within-window schedule is
/// confirmed from this dev environment; polling `MaxMind` harder also risks
/// their documented rate-limiting). See this module's own doc comment.
pub const GEOIP_CHECK_INTERVAL: Duration = Duration::from_hours(24);

/// Upper bound on one candidate release's whole fetch-verify-swap attempt
/// (network fetch(es) + decompress + validate + disk write). Without this,
/// a stalled connection would park [`run_geoip_updater`]'s loop
/// indefinitely — it never reaches its own `sleep`, so the feature goes
/// silently dead until the process restarts, the exact "no timeout on a
/// path that's now load-bearing" gotcha already recorded in this crate for
/// `pipeline::resolve_via_baseline` (advisor-caught before implementing,
/// same lesson applied here to a brand-new outbound path rather than
/// rediscovered the hard way). Generous relative to an ~8 MB download (per
/// a live web search — this dev sandbox can't measure the real file
/// directly), not tuned to a measured connection speed.
const GEOIP_FETCH_TIMEOUT: Duration = Duration::from_secs(120);

/// Timeout for [`check_maxmind_credentials`]'s single status probe — an order
/// of magnitude below [`GEOIP_FETCH_TIMEOUT`] because it runs *inline* in an
/// interactive `POST /admin/geoip/maxmind` (T-162) and only needs a status
/// code back, never a download. A timeout collapses to
/// [`GeoipUpdateError::Timeout`] → `MaxmindCredentialCheck::Unverified`, never
/// a `5xx` to the operator.
const MAXMIND_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// A `GeoIP` database refresh attempt failed — see this module's own doc
/// comment for what happens next (the last-known-good database, if any,
/// stays in place).
#[derive(Debug, thiserror::Error)]
pub enum GeoipUpdateError {
    /// Neither the current nor the previous calendar month's release URL
    /// produced a usable database.
    #[error("no candidate DB-IP Lite release succeeded: {0}")]
    NoReleaseFound(#[source] Box<GeoipUpdateError>),
    /// The HTTP request itself failed (network error, non-2xx status).
    #[error("download failed: {0}")]
    Http(#[source] reqwest::Error),
    /// The download exceeded [`MAX_GEOIP_COMPRESSED_BYTES`] before
    /// completing — rejected mid-stream, not after a full allocation.
    #[error("download exceeds the {MAX_GEOIP_COMPRESSED_BYTES}-byte size limit")]
    CompressedTooLarge,
    /// A checksum sidecar was found and fetched, but didn't match the
    /// downloaded bytes.
    #[error("downloaded database doesn't match its published checksum")]
    ChecksumMismatch,
    /// Decompression failed (malformed gzip, a CRC32/ISIZE trailer
    /// mismatch, or oversized output) — a flat `String`, not the crate-
    /// private `DecompressError` itself: a `pub` error enum can't wrap a
    /// `pub(crate)` type via `#[from]` (`private_interfaces`; same fix as
    /// `cert::CertError::MissingLocalAppData`'s own precedent).
    #[error("failed to decompress the downloaded database: {0}")]
    Decompress(String),
    /// The decompressed bytes aren't a valid `MaxMind`-format database.
    #[error("downloaded data isn't a valid GeoIP database: {0}")]
    InvalidDatabase(#[source] GeoipError),
    /// The database parsed fine but its self-reported type doesn't look
    /// like a country-level database.
    #[error("downloaded database has unexpected type {0:?}, expected a country-level database")]
    UnexpectedDatabaseType(String),
    /// Writing the validated database to disk (the atomic-swap step)
    /// failed.
    #[error("failed to persist the database to disk: {0}")]
    Io(#[source] std::io::Error),
    /// The whole fetch-verify-swap attempt didn't finish within
    /// [`GEOIP_FETCH_TIMEOUT`] — a stalled connection, not a clean HTTP-level
    /// failure.
    #[error("timed out after {GEOIP_FETCH_TIMEOUT:?}")]
    Timeout,
    /// `MaxMind` advanced mode (T-80): the download request failed (network
    /// error, or a non-2xx status other than an auth rejection).
    /// **Deliberately carries no `reqwest::Error`** — its `Display` can echo
    /// the request URL and, on some error paths, header material, and this
    /// request carries an HTTP Basic credential; a coarse label only, the
    /// same discipline as `quorum::error_kind` applied to a secret rather
    /// than a domain name.
    #[error("MaxMind database download failed")]
    MaxmindDownloadFailed,
    /// `MaxMind` advanced mode: the server returned `401`/`403` — the account
    /// id / license key in `geoip_maxmind.toml` is wrong, expired, or lacks
    /// `GeoLite2` access.
    #[error("MaxMind rejected the supplied account id / license key")]
    MaxmindAuthRejected,
    /// `MaxMind` advanced mode: a `.tar.gz.sha256` sidecar was fetched but
    /// didn't match the downloaded archive.
    #[error("downloaded MaxMind database doesn't match its published SHA-256 checksum")]
    MaxmindChecksumMismatch,
    /// `MaxMind` advanced mode: the downloaded `.tar.gz` couldn't be
    /// decompressed, had no `.mmdb` member, or the member was oversized — a
    /// flat `String` for the same `private_interfaces` reason as
    /// [`GeoipUpdateError::Decompress`].
    #[error("downloaded MaxMind archive is invalid: {0}")]
    MaxmindArchiveInvalid(String),
}

/// Runs [`refresh_once`] immediately (so a fresh install gets a database
/// right away rather than waiting a full [`GEOIP_CHECK_INTERVAL`]), then
/// repeats every `GEOIP_CHECK_INTERVAL` for as long as the service runs.
/// Never returns — spawned once from `main.rs` via `tokio::spawn` and left
/// to run for the process's lifetime, the same "spawn and forget, the
/// service's own shutdown handles cleanup" pattern already used for
/// per-connection tasks.
pub async fn run_geoip_updater(
    client: reqwest::Client,
    target_path: PathBuf,
    state: Arc<AppState<ReqwestDohClient>>,
) {
    // T-163: the source is no longer a spawn-time argument — it lives on
    // `AppState`, re-snapshotted every cycle, so a runtime credentials change
    // (`/admin/geoip/maxmind[/clear]`, `/admin/reset`) is picked up with no
    // restart. Those routes also `notify_one` this handle, so the change acts
    // within seconds instead of at the next 24h check.
    let wake = state.geoip_refresh_wake_handle();
    loop {
        let source = state.geoip_source_snapshot();
        match refresh_once(&client, &target_path, &state, &source).await {
            Ok(()) => tracing::info!("GeoIP database refreshed"),
            Err(err) => tracing::warn!(
                "GeoIP database refresh failed, keeping the last-known-good database: {err}"
            ),
        }
        tokio::select! {
            () = tokio::time::sleep(GEOIP_CHECK_INTERVAL) => {}
            () = wake.notified() => {
                tracing::info!("GeoIP refresh woken by a source change");
            }
        }
    }
}

/// One fetch-verify-swap cycle, dispatched on the configured [`GeoipSource`]
/// (T-80). DB-IP Lite is the unchanged default path; `MaxMind GeoLite2` is the
/// opt-in advanced mode — see this module's doc comment.
///
/// # Errors
///
/// Propagates whichever source-specific path failed — see
/// [`refresh_db_ip_lite`] and [`try_one_maxmind_release_bounded`].
pub(crate) async fn refresh_once(
    client: &reqwest::Client,
    target_path: &Path,
    state: &AppState<ReqwestDohClient>,
    source: &GeoipSource,
) -> Result<(), GeoipUpdateError> {
    match source {
        GeoipSource::DbIpLite => refresh_db_ip_lite(client, target_path, state).await,
        GeoipSource::Maxmind(creds) => {
            try_one_maxmind_release_bounded(client, creds, target_path, state).await
        }
    }
}

/// The DB-IP Lite fetch-verify-swap cycle (T-75). Tries
/// [`candidate_download_urls`]'s two candidates in order (current calendar
/// month, then the previous one); the first that both downloads and passes
/// verification wins.
///
/// # Errors
///
/// Returns [`GeoipUpdateError::NoReleaseFound`] (wrapping the previous
/// month's own error - the current month's is logged, not discarded) if
/// both candidates failed.
async fn refresh_db_ip_lite(
    client: &reqwest::Client,
    target_path: &Path,
    state: &AppState<ReqwestDohClient>,
) -> Result<(), GeoipUpdateError> {
    // Destructured, not looped - `candidate_download_urls` always returns
    // exactly two URLs, so this stays total by construction with no
    // "unreachable, but the compiler doesn't know that" fallback needed.
    let [current, previous] = candidate_download_urls(SystemTime::now());
    match try_one_release_bounded(client, &current, target_path, state).await {
        Ok(()) => Ok(()),
        Err(current_err) => {
            match try_one_release_bounded(client, &previous, target_path, state).await {
                Ok(()) => Ok(()),
                Err(previous_err) => {
                    tracing::debug!(
                        "current calendar month's GeoIP release also failed: {current_err}"
                    );
                    Err(GeoipUpdateError::NoReleaseFound(Box::new(previous_err)))
                }
            }
        }
    }
}

/// [`try_one_release`], bounded to [`GEOIP_FETCH_TIMEOUT`] — see that
/// constant's own doc comment for why an unbounded attempt would be a real
/// hazard, not just untidy.
async fn try_one_release_bounded(
    client: &reqwest::Client,
    mmdb_url: &str,
    target_path: &Path,
    state: &AppState<ReqwestDohClient>,
) -> Result<(), GeoipUpdateError> {
    match tokio::time::timeout(
        GEOIP_FETCH_TIMEOUT,
        try_one_release(client, mmdb_url, target_path, state),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(GeoipUpdateError::Timeout),
    }
}

async fn try_one_release(
    client: &reqwest::Client,
    mmdb_url: &str,
    target_path: &Path,
    state: &AppState<ReqwestDohClient>,
) -> Result<(), GeoipUpdateError> {
    let gz_bytes = fetch_bounded(client, mmdb_url).await?;

    if let Some(expected) = fetch_checksum_sidecar(client, mmdb_url).await {
        if !checksum_matches(&expected, &gz_bytes) {
            return Err(GeoipUpdateError::ChecksumMismatch);
        }
    }

    let decompressed = decompress_bounded(&gz_bytes, MAX_GEOIP_DECOMPRESSED_BYTES)
        .map_err(|err| GeoipUpdateError::Decompress(err.to_string()))?;
    let reader =
        GeoipReader::from_bytes(decompressed.clone()).map_err(GeoipUpdateError::InvalidDatabase)?;
    let database_type = reader.database_type().to_ascii_lowercase();
    if !database_type.contains("country") {
        return Err(GeoipUpdateError::UnexpectedDatabaseType(database_type));
    }

    persist_atomically(target_path, &decompressed).map_err(GeoipUpdateError::Io)?;
    // The database's own embedded build time, not "when this refresh ran" -
    // this task polls on a fixed schedule regardless of whether db-ip.com
    // actually published anything new, so `SystemTime::now()` here would
    // always read as "today," true but useless for T-78's "is this stale"
    // indicator (see `GeoipReader::build_time`'s own doc comment).
    let updated_at = reader.build_time();
    state.update_geoip(GeoipState {
        reader: Some(Arc::new(reader)),
        updated_at,
    });
    Ok(())
}

/// [`try_one_maxmind_release`], bounded to [`GEOIP_FETCH_TIMEOUT`] — same
/// hazard and reasoning as [`try_one_release_bounded`] for the DB-IP path.
async fn try_one_maxmind_release_bounded(
    client: &reqwest::Client,
    creds: &MaxmindCredentials,
    target_path: &Path,
    state: &AppState<ReqwestDohClient>,
) -> Result<(), GeoipUpdateError> {
    match tokio::time::timeout(
        GEOIP_FETCH_TIMEOUT,
        try_one_maxmind_release(client, creds, target_path, state),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(GeoipUpdateError::Timeout),
    }
}

/// `MaxMind GeoLite2` advanced mode (T-80): one download-verify-swap of
/// `MaxMind`'s modern permalink, authenticated with HTTP Basic (account id :
/// license key). No calendar-month candidates — the permalink always serves
/// the latest release. See this module's doc comment for what is and isn't
/// verified about this path.
async fn try_one_maxmind_release(
    client: &reqwest::Client,
    creds: &MaxmindCredentials,
    target_path: &Path,
    state: &AppState<ReqwestDohClient>,
) -> Result<(), GeoipUpdateError> {
    let url = maxmind_download_url(MAXMIND_EDITION, "tar.gz");
    let gz_bytes = fetch_bounded_authed(client, &url, creds).await?;

    if let Some(expected) = fetch_maxmind_checksum_sidecar(client, creds).await {
        if !checksum_matches_sha256(&expected, &gz_bytes) {
            return Err(GeoipUpdateError::MaxmindChecksumMismatch);
        }
    }

    let decompressed = extract_mmdb_from_tar_gz(&gz_bytes, MAX_GEOIP_DECOMPRESSED_BYTES)
        .map_err(|err| GeoipUpdateError::MaxmindArchiveInvalid(err.to_string()))?;
    let reader =
        GeoipReader::from_bytes(decompressed.clone()).map_err(GeoipUpdateError::InvalidDatabase)?;
    let database_type = reader.database_type().to_ascii_lowercase();
    if !database_type.contains("country") {
        return Err(GeoipUpdateError::UnexpectedDatabaseType(database_type));
    }

    persist_atomically(target_path, &decompressed).map_err(GeoipUpdateError::Io)?;
    // The database's own embedded build time, not "when this refresh ran" -
    // same reasoning as the DB-IP path above (`GeoipReader::build_time`).
    let updated_at = reader.build_time();
    state.update_geoip(GeoipState {
        reader: Some(Arc::new(reader)),
        updated_at,
    });
    Ok(())
}

/// Like [`fetch_bounded`] but with an HTTP `Authorization: Basic` header
/// (T-80). Every `reqwest::Error` is dropped here — never wrapped, never
/// logged via `Display` — because this request carries a Basic-auth
/// credential; failures collapse to a coarse
/// [`GeoipUpdateError::MaxmindDownloadFailed`] (or
/// [`GeoipUpdateError::MaxmindAuthRejected`] on a `401`/`403`).
async fn fetch_bounded_authed(
    client: &reqwest::Client,
    url: &str,
    creds: &MaxmindCredentials,
) -> Result<Bytes, GeoipUpdateError> {
    let response = client
        .get(url)
        .basic_auth(&creds.account_id, Some(creds.license_key.expose_secret()))
        .send()
        .await
        .map_err(|_| GeoipUpdateError::MaxmindDownloadFailed)?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(GeoipUpdateError::MaxmindAuthRejected);
    }
    let response = response
        .error_for_status()
        .map_err(|_| GeoipUpdateError::MaxmindDownloadFailed)?;
    let mut body = BytesMut::new();
    let mut stream = std::pin::pin!(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| GeoipUpdateError::MaxmindDownloadFailed)?;
        let total = u64::try_from(body.len() + chunk.len()).unwrap_or(u64::MAX);
        if total > MAX_GEOIP_COMPRESSED_BYTES {
            return Err(GeoipUpdateError::CompressedTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// One authenticated probe of the `MaxMind` download endpoint, for the
/// save-time credential check behind `POST /admin/geoip/maxmind` (T-162).
/// Inspects **only** the HTTP status — a `Range: bytes=0-0` header keeps a
/// success from pulling the whole archive body. Bounded by
/// [`MAXMIND_CHECK_TIMEOUT`], not [`GEOIP_FETCH_TIMEOUT`]: this runs inline
/// in an interactive admin request.
///
/// Returns the same coarse error taxonomy the scheduled refresh already
/// uses, so the caller ([`crate::dispatch`]) maps it to a
/// `MaxmindCredentialCheck` without a new error type.
///
/// # Errors
///
/// [`GeoipUpdateError::MaxmindAuthRejected`] on `401`/`403` (bad account id
/// or key), [`GeoipUpdateError::MaxmindDownloadFailed`] for any other
/// non-`2xx` or a transport error, [`GeoipUpdateError::Timeout`] past
/// [`MAXMIND_CHECK_TIMEOUT`]. Every `reqwest::Error` is dropped, never
/// logged — the request URL embeds the account id (same rule as
/// [`fetch_bounded_authed`]).
pub(crate) async fn check_maxmind_credentials(
    client: &reqwest::Client,
    account_id: &str,
    license_key: &str,
) -> Result<(), GeoipUpdateError> {
    let url = maxmind_download_url(MAXMIND_EDITION, "tar.gz");
    let probe = async {
        let response = client
            .get(&url)
            .basic_auth(account_id, Some(license_key))
            .header(reqwest::header::RANGE, "bytes=0-0")
            .send()
            .await
            .map_err(|_| GeoipUpdateError::MaxmindDownloadFailed)?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(GeoipUpdateError::MaxmindAuthRejected);
        }
        if status.is_success() {
            Ok(())
        } else {
            Err(GeoipUpdateError::MaxmindDownloadFailed)
        }
    };
    match tokio::time::timeout(MAXMIND_CHECK_TIMEOUT, probe).await {
        Ok(result) => result,
        Err(_elapsed) => Err(GeoipUpdateError::Timeout),
    }
}

/// Fetches `MaxMind`'s `?suffix=tar.gz.sha256` sidecar and returns its hex
/// digest, or `None` if it isn't a `2xx`, isn't shaped like a SHA-256
/// digest, or couldn't be fetched — opportunistic, never an error (see this
/// module's doc comment and [`fetch_checksum_sidecar`]'s own note on why a
/// `2xx` alone isn't proof the sidecar exists).
async fn fetch_maxmind_checksum_sidecar(
    client: &reqwest::Client,
    creds: &MaxmindCredentials,
) -> Option<String> {
    let url = maxmind_download_url(MAXMIND_EDITION, "tar.gz.sha256");
    let response = client
        .get(&url)
        .basic_auth(&creds.account_id, Some(creds.license_key.expose_secret()))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let text = response.text().await.ok()?;
    // MaxMind's sidecar is `sha256sum` style: `<64 hex>  <filename>` - take
    // only the first whitespace-delimited token.
    let token = text.split_whitespace().next()?.to_ascii_lowercase();
    looks_like_sha256_hex(&token).then_some(token)
}

fn looks_like_sha256_hex(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn checksum_matches_sha256(expected_hex: &str, bytes: &[u8]) -> bool {
    expected_hex.trim().eq_ignore_ascii_case(&sha256_hex(bytes))
}

/// Downloads `url`, bounded to [`MAX_GEOIP_COMPRESSED_BYTES`] — streamed
/// and checked chunk-by-chunk as the bytes arrive, not checked against
/// `Content-Length` alone (a header an origin could omit, or a
/// misconfigured/compromised one could understate).
async fn fetch_bounded(client: &reqwest::Client, url: &str) -> Result<Bytes, GeoipUpdateError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(GeoipUpdateError::Http)?
        .error_for_status()
        .map_err(GeoipUpdateError::Http)?;
    let mut body = BytesMut::new();
    let mut stream = std::pin::pin!(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(GeoipUpdateError::Http)?;
        let total = u64::try_from(body.len() + chunk.len()).unwrap_or(u64::MAX);
        if total > MAX_GEOIP_COMPRESSED_BYTES {
            return Err(GeoipUpdateError::CompressedTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// Fetches `mmdb_url`'s `.sha1` sidecar and returns its hex digest, or
/// `None` if it doesn't exist (a 404), the body doesn't actually look like a
/// SHA-1 digest, or it otherwise couldn't be fetched — never an error, the
/// sidecar is opportunistic (see this module's own doc comment).
///
/// **A `2xx` status alone doesn't mean the path exists** — a server can
/// answer a missing path with `200` and an HTML error page instead of a
/// proper `404` (advisor-caught before commit: the first draft treated any
/// successful-status body as the checksum, so an HTML error page's first
/// "word" — `<!doctype` or similar — would have been compared as if it were
/// a real digest, always failed to match, and permanently hard-failed every
/// refresh via [`GeoipUpdateError::ChecksumMismatch`] with no working
/// fallback — worse than the sidecar simply not existing). Validating the
/// token's *shape* (40 hex characters) before trusting it as a checksum
/// keeps "sidecar absent" and "sidecar present but genuinely wrong" as the
/// two outcomes this module's own doc comment promises, rather than
/// collapsing every malformed response into a false mismatch.
async fn fetch_checksum_sidecar(client: &reqwest::Client, mmdb_url: &str) -> Option<String> {
    let url = checksum_sidecar_url(mmdb_url);
    let response = client.get(&url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let text = response.text().await.ok()?;
    // DB-IP's own page shows the hash as bare hex, but tolerate a
    // "<hex>  <filename>" sha1sum-style line too (the common sidecar
    // convention) by taking only the first whitespace-delimited token.
    let token = text.split_whitespace().next()?.to_ascii_lowercase();
    looks_like_sha1_hex(&token).then_some(token)
}

fn looks_like_sha1_hex(token: &str) -> bool {
    token.len() == 40 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha1_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    Sha1::digest(bytes)
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn checksum_matches(expected_hex: &str, gz_bytes: &[u8]) -> bool {
    expected_hex
        .trim()
        .eq_ignore_ascii_case(&sha1_hex(gz_bytes))
}

/// Writes `bytes` to a sibling temp path next to `target_path` and renames
/// it into place — a rename within the same directory (same volume) is
/// atomic, so a reader never observes a partially-written database file.
/// `GeoipReader::open`/`from_bytes` read the whole file into an owned
/// buffer with no lingering file handle (`geoip.rs`'s own doc comment), so
/// an in-memory reader built from the *previous* database's bytes is
/// unaffected by this rename even while still in use.
fn persist_atomically(target_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp_path = target_path.with_extension("mmdb.download");
    std::fs::write(&tmp_path, bytes)?;
    std::fs::rename(&tmp_path, target_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_is_case_and_whitespace_insensitive() {
        let hex = sha1_hex(b"hello geoip");
        assert!(checksum_matches(&hex.to_ascii_uppercase(), b"hello geoip"));
        assert!(checksum_matches(&format!(" {hex}\n"), b"hello geoip"));
    }

    #[test]
    fn looks_like_sha1_hex_accepts_a_real_digest() {
        assert!(looks_like_sha1_hex(&sha1_hex(b"anything")));
    }

    // The bug this guards against: a server answering a missing sidecar
    // path with 200 + an HTML error page, whose first whitespace-delimited
    // "token" would otherwise be compared as if it were a real checksum -
    // always mismatching, and (before this fix) hard-failing every refresh
    // forever instead of falling back to the CRC/structural integrity path.
    #[test]
    fn looks_like_sha1_hex_rejects_an_html_error_page_body() {
        assert!(!looks_like_sha1_hex("<!doctype"));
        assert!(!looks_like_sha1_hex(""));
        assert!(!looks_like_sha1_hex("not-even-close-to-hex"));
        // Right length, wrong alphabet.
        assert!(!looks_like_sha1_hex(&"g".repeat(40)));
    }

    #[test]
    fn checksum_matches_rejects_a_wrong_digest() {
        let hex = sha1_hex(b"hello geoip");
        assert!(!checksum_matches(&hex, b"something else entirely"));
    }

    #[test]
    fn persist_atomically_replaces_an_existing_file_and_the_old_reader_stays_usable() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let target = dir.path().join("geoip.mmdb");

        // Use the real fixture so the "old" reader is a genuine, loaded
        // GeoipReader, not just bytes - proves open_readfile really doesn't
        // keep the file open across the rename that follows (geoip.rs's own
        // documented claim, checked here rather than only reasoned about).
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/geoip/GeoIP2-Country-Test.mmdb");
        let Ok(original_bytes) = std::fs::read(&fixture) else {
            panic!("fixture must read");
        };
        if let Err(err) = std::fs::write(&target, &original_bytes) {
            panic!("must be able to write the fixture as the initial target: {err}");
        }
        let Ok(old_reader) = GeoipReader::open(&target) else {
            panic!("initial database must open");
        };

        let replacement = b"not a real mmdb, just proving the swap happened";
        if let Err(err) = persist_atomically(&target, replacement) {
            panic!("atomic replace must succeed on Windows CI, not just this dev machine: {err}");
        }

        let Ok(on_disk) = std::fs::read(&target) else {
            panic!("target must be readable after the swap");
        };
        assert_eq!(on_disk, replacement);
        // The old, still-in-memory reader must remain fully usable - it
        // already read every byte it needs, no lingering handle to the
        // now-replaced file.
        let Ok(ip) = "89.160.20.112".parse() else {
            panic!("valid IPv4 literal");
        };
        assert!(old_reader.country(ip).is_some());
    }

    /// Exercises the real network path end to end against `db-ip.com` — not
    /// run in CI (this project's `#[ignore]`d-live-test precedent,
    /// `upstream.rs`'s live-Quad9 test), and specifically also not runnable
    /// from this project's own dev sandbox (DNS-blocked, see this module's
    /// own doc comment). Whoever *can* run this should note in this
    /// module's doc comment which integrity path actually fired (checksum
    /// sidecar found, or the CRC32/structural-validation fallback).
    #[tokio::test]
    #[ignore = "hits the real network; also unreachable from this project's dev sandbox (DNS-blocked)"]
    async fn fetch_and_verify_against_live_db_ip() {
        let Ok(client) = reqwest::Client::builder().build() else {
            panic!("must be able to build a plain reqwest client");
        };
        let Ok(dir) = tempfile::tempdir() else {
            panic!("must be able to create a temp dir");
        };
        let target = dir.path().join("geoip.mmdb");
        for url in candidate_download_urls(SystemTime::now()) {
            match fetch_bounded(&client, &url).await {
                Ok(gz_bytes) => {
                    let sidecar = fetch_checksum_sidecar(&client, &url).await;
                    println!(
                        "checksum sidecar for {url}: {}",
                        sidecar.as_deref().unwrap_or("not found")
                    );
                    let Ok(decompressed) =
                        decompress_bounded(&gz_bytes, MAX_GEOIP_DECOMPRESSED_BYTES)
                    else {
                        panic!("live download must decompress cleanly");
                    };
                    let Ok(_reader) = GeoipReader::from_bytes(decompressed) else {
                        panic!("live download must parse as a valid GeoIP database");
                    };
                    std::fs::write(&target, &gz_bytes).ok();
                    return;
                }
                Err(err) => println!("candidate {url} failed: {err}"),
            }
        }
        panic!("no candidate release URL succeeded against the live db-ip.com");
    }

    // T-80: SHA-256 sidecar helpers, mirroring the SHA-1 tests above.

    #[test]
    fn looks_like_sha256_hex_accepts_a_real_digest() {
        assert!(looks_like_sha256_hex(&sha256_hex(b"anything")));
    }

    #[test]
    fn looks_like_sha256_hex_rejects_wrong_length_or_alphabet() {
        assert!(!looks_like_sha256_hex("<!doctype"));
        assert!(!looks_like_sha256_hex(""));
        // A real SHA-1 digest is 40 hex chars - right alphabet, wrong length.
        assert!(!looks_like_sha256_hex(&sha1_hex(b"anything")));
        // Right length, wrong alphabet.
        assert!(!looks_like_sha256_hex(&"g".repeat(64)));
    }

    #[test]
    fn checksum_matches_sha256_is_case_and_whitespace_insensitive() {
        let hex = sha256_hex(b"hello maxmind");
        assert!(checksum_matches_sha256(
            &hex.to_ascii_uppercase(),
            b"hello maxmind"
        ));
        assert!(checksum_matches_sha256(
            &format!("  {hex}\n"),
            b"hello maxmind"
        ));
    }

    #[test]
    fn checksum_matches_sha256_rejects_a_wrong_digest() {
        let hex = sha256_hex(b"hello maxmind");
        assert!(!checksum_matches_sha256(&hex, b"something else entirely"));
    }

    /// Exercises the real `MaxMind GeoLite2` download path end to end — needs
    /// real credentials (`MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY` env
    /// vars), so it's `#[ignore]`d, the same "manual, not CI-gated" precedent
    /// as `fetch_and_verify_against_live_db_ip` above. Whoever runs this
    /// should note in this module's doc comment whether the
    /// `?suffix=tar.gz.sha256` sidecar actually returned a usable digest.
    #[tokio::test]
    #[ignore = "hits the real network; needs real MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY env vars"]
    async fn fetch_and_verify_against_live_maxmind() {
        let (Ok(account_id), Ok(license_key)) = (
            std::env::var("MAXMIND_ACCOUNT_ID"),
            std::env::var("MAXMIND_LICENSE_KEY"),
        ) else {
            panic!("set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY to run this test");
        };
        let creds = MaxmindCredentials {
            account_id,
            license_key: crate::geoip_credentials::LicenseKey::new(license_key),
        };
        let Ok(client) = reqwest::Client::builder().build() else {
            panic!("must be able to build a plain reqwest client");
        };

        let url = maxmind_download_url(MAXMIND_EDITION, "tar.gz");
        let gz_bytes = match fetch_bounded_authed(&client, &url, &creds).await {
            Ok(bytes) => bytes,
            Err(err) => panic!("live MaxMind download failed: {err}"),
        };
        let sidecar = fetch_maxmind_checksum_sidecar(&client, &creds).await;
        println!(
            "MaxMind sha256 sidecar: {}",
            sidecar.as_deref().unwrap_or("not found / not usable")
        );
        if let Some(expected) = &sidecar {
            assert!(
                checksum_matches_sha256(expected, &gz_bytes),
                "sidecar digest must match the downloaded archive"
            );
        }
        let Ok(mmdb) = extract_mmdb_from_tar_gz(&gz_bytes, MAX_GEOIP_DECOMPRESSED_BYTES) else {
            panic!("live MaxMind archive must contain an extractable .mmdb member");
        };
        let Ok(reader) = GeoipReader::from_bytes(mmdb) else {
            panic!("extracted MaxMind database must parse");
        };
        assert!(
            reader
                .database_type()
                .to_ascii_lowercase()
                .contains("country"),
            "database_type was {:?}",
            reader.database_type()
        );
    }

    /// The save-time credential probe (T-162) against live `MaxMind`. Real
    /// creds → `Ok(())` (Verified); a deliberately-mangled key → an
    /// `Err(MaxmindAuthRejected)` (Rejected). `#[ignore]`d for the same
    /// reason as the download test above.
    #[tokio::test]
    #[ignore = "hits the real network; needs real MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY env vars"]
    async fn check_maxmind_credentials_verifies_good_creds_and_rejects_bad_ones() {
        let (Ok(account_id), Ok(license_key)) = (
            std::env::var("MAXMIND_ACCOUNT_ID"),
            std::env::var("MAXMIND_LICENSE_KEY"),
        ) else {
            panic!("set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY to run this test");
        };
        let Ok(client) = reqwest::Client::builder().build() else {
            panic!("must be able to build a plain reqwest client");
        };

        match check_maxmind_credentials(&client, &account_id, &license_key).await {
            Ok(()) => {}
            Err(err) => panic!("real credentials must verify: {err}"),
        }

        assert!(matches!(
            check_maxmind_credentials(&client, &account_id, "definitely-not-a-real-key").await,
            Err(GeoipUpdateError::MaxmindAuthRejected)
        ));
    }
}
