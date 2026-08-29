//! Pure helpers for T-75's `GeoIP` database updater: DB-IP Lite candidate
//! download-URL construction (the URL embeds the calendar year-month) and
//! bounded gzip decompression. Kept separate from `geoip_updater.rs`'s
//! network/orchestration code so this arithmetic and decompression logic is
//! testable with plain byte buffers, no HTTP mocking needed —
//! `geoip_updater.rs`'s own `#[ignore]`d live test is what exercises the
//! real network path.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;

/// Base URL DB-IP Lite's Country-level `MaxMind`-format database is served
/// from, no registration required (SPEC.md §3.5).
pub(crate) const DB_IP_BASE_URL: &str = "https://download.db-ip.com/free/";

/// Upper bound on the compressed download. The real file is a few MB as of
/// 2026-08 (per a live web search — `download.db-ip.com` itself isn't
/// reachable from this project's dev environment to measure directly); this
/// is generous headroom, not a measured limit.
pub(crate) const MAX_GEOIP_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound on the decompressed database — gzip-bomb headroom, not a
/// measured limit (the real decompressed file is on the order of tens of
/// MB).
pub(crate) const MAX_GEOIP_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// The two calendar-month `.mmdb.gz` URLs worth trying, current month
/// first — DB-IP Lite's URL embeds the release year-month
/// (`dbip-country-lite-YYYY-MM.mmdb.gz`) and updates monthly, so a check
/// made in the first few days of a new month may still need the *previous*
/// month's file if this month's hasn't been published yet.
pub(crate) fn candidate_download_urls(now: SystemTime) -> [String; 2] {
    let (year, month) = year_month(now);
    let (prev_year, prev_month) = previous_month(year, month);
    [mmdb_gz_url(year, month), mmdb_gz_url(prev_year, prev_month)]
}

/// The checksum sidecar `db-ip.com` may or may not actually publish next to
/// `mmdb_url` — unverified from this project's dev environment (see
/// `geoip_updater.rs`'s own module doc comment for why). Tried
/// opportunistically, never required.
pub(crate) fn checksum_sidecar_url(mmdb_url: &str) -> String {
    format!("{mmdb_url}.sha1")
}

fn mmdb_gz_url(year: i32, month: u32) -> String {
    format!("{DB_IP_BASE_URL}dbip-country-lite-{year:04}-{month:02}.mmdb.gz")
}

fn previous_month(year: i32, month: u32) -> (i32, u32) {
    if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    }
}

fn year_month(now: SystemTime) -> (i32, u32) {
    let unix_seconds = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    civil_year_month(unix_seconds.div_euclid(86_400))
}

/// Days-since-epoch to `(year, month)`, proleptic Gregorian calendar —
/// Howard Hinnant's `civil_from_days` algorithm
/// (<http://howardhinnant.github.io/date_algorithms.html#civil_from_days>),
/// day-of-month discarded (only the calendar month is needed here). No date
/// crate pulled in for this one calculation — pure integer arithmetic, no
/// allocation.
fn civil_year_month(days_since_epoch: i64) -> (i32, u32) {
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (
        i32::try_from(y).unwrap_or(i32::MAX),
        u32::try_from(m).unwrap_or(1),
    )
}

/// Decompresses `gz_bytes`, rejecting anything that would exceed
/// `max_bytes` (callers pass [`MAX_GEOIP_DECOMPRESSED_BYTES`]; a parameter
/// rather than the constant baked in directly so this stays testable
/// against a small bound instead of a real test having to allocate a
/// 256 MiB buffer) — the same "bound the allocation itself, not a
/// separately-measured length" discipline `overrides::load`/`config::load`
/// already use for on-disk files (T-58), applied here to a decompression
/// stream instead. Reading the underlying gzip stream to its own real EOF
/// (rather than stopping early) is what makes `flate2` validate the
/// trailer's CRC32/ISIZE against the decompressed bytes — hitting the size
/// cap therefore always rejects outright rather than silently returning a
/// CRC-unchecked prefix.
///
/// # Errors
///
/// Returns [`DecompressError::Io`] on a malformed gzip stream (including a
/// CRC32/ISIZE trailer mismatch — `flate2`'s own check) or
/// [`DecompressError::TooLarge`] if decompressing would exceed `max_bytes`.
pub(crate) fn decompress_bounded(
    gz_bytes: &[u8],
    max_bytes: u64,
) -> Result<Vec<u8>, DecompressError> {
    let mut limited = GzDecoder::new(gz_bytes).take(max_bytes + 1);
    let mut out = Vec::new();
    let read = limited.read_to_end(&mut out).map_err(DecompressError::Io)?;
    if u64::try_from(read).unwrap_or(u64::MAX) > max_bytes {
        return Err(DecompressError::TooLarge { max_bytes });
    }
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DecompressError {
    #[error("gzip stream is malformed or its checksum doesn't match: {0}")]
    Io(#[source] std::io::Error),
    #[error("decompressed database exceeds the {max_bytes}-byte size limit")]
    TooLarge { max_bytes: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    /// 2026-08-29T00:00:00Z — hand-computed from known month lengths, cross-
    /// checked as this project's own "known-good ground truth" convention
    /// (same discipline as `geoip.rs`'s fixture assertion) rather than
    /// trusted from the algorithm alone.
    const AUG_29_2026_UNIX: u64 = 1_787_961_600;
    /// 2024-02-29T00:00:00Z — a leap-day, to prove the algorithm actually
    /// applies the Gregorian leap-year rule, not just fixed month lengths.
    const FEB_29_2024_UNIX: u64 = 1_709_164_800;
    /// 2024-03-01T00:00:00Z — the very next day, proving February 2024 was
    /// correctly treated as having 29 days.
    const MAR_01_2024_UNIX: u64 = 1_709_251_200;
    /// 2000-01-01T00:00:00Z — a year/month/era boundary.
    const JAN_01_2000_UNIX: u64 = 946_684_800;

    fn at(unix_seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(unix_seconds)
    }

    #[test]
    fn year_month_matches_known_dates() {
        assert_eq!(year_month(at(AUG_29_2026_UNIX)), (2026, 8));
        assert_eq!(year_month(at(FEB_29_2024_UNIX)), (2024, 2));
        assert_eq!(year_month(at(MAR_01_2024_UNIX)), (2024, 3));
        assert_eq!(year_month(at(JAN_01_2000_UNIX)), (2000, 1));
    }

    #[test]
    fn previous_month_wraps_the_year_at_january() {
        assert_eq!(previous_month(2026, 1), (2025, 12));
        assert_eq!(previous_month(2026, 8), (2026, 7));
    }

    #[test]
    fn candidate_download_urls_are_current_month_then_previous() {
        let urls = candidate_download_urls(at(AUG_29_2026_UNIX));
        assert_eq!(
            urls,
            [
                format!("{DB_IP_BASE_URL}dbip-country-lite-2026-08.mmdb.gz"),
                format!("{DB_IP_BASE_URL}dbip-country-lite-2026-07.mmdb.gz"),
            ]
        );
    }

    #[test]
    fn candidate_download_urls_wraps_the_year_in_january() {
        // 2026-01-05T00:00:00Z.
        let urls = candidate_download_urls(at(1_767_571_200));
        assert_eq!(
            urls,
            [
                format!("{DB_IP_BASE_URL}dbip-country-lite-2026-01.mmdb.gz"),
                format!("{DB_IP_BASE_URL}dbip-country-lite-2025-12.mmdb.gz"),
            ]
        );
    }

    #[test]
    fn checksum_sidecar_url_appends_sha1() {
        assert_eq!(
            checksum_sidecar_url("https://download.db-ip.com/free/x.mmdb.gz"),
            "https://download.db-ip.com/free/x.mmdb.gz.sha1"
        );
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let Ok(()) = encoder.write_all(data) else {
            panic!("in-memory gzip write cannot fail");
        };
        let Ok(bytes) = encoder.finish() else {
            panic!("in-memory gzip finish cannot fail");
        };
        bytes
    }

    #[test]
    fn decompress_bounded_round_trips_a_small_payload() {
        let original = b"hello geoip";
        let Ok(decompressed) = decompress_bounded(&gzip(original), MAX_GEOIP_DECOMPRESSED_BYTES)
        else {
            panic!("well-formed gzip must decompress");
        };
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_bounded_rejects_malformed_input() {
        assert!(decompress_bounded(b"not gzip at all", MAX_GEOIP_DECOMPRESSED_BYTES).is_err());
    }

    #[test]
    fn decompress_bounded_rejects_a_corrupted_crc_trailer() {
        let mut gz = gzip(b"hello geoip");
        // Flip a byte in the trailer (last 8 bytes: CRC32 + ISIZE) - the
        // decompressed data itself is untouched, only flate2's own
        // end-of-stream integrity check should catch this.
        let last = gz.len() - 1;
        gz[last] ^= 0xFF;
        assert!(decompress_bounded(&gz, MAX_GEOIP_DECOMPRESSED_BYTES).is_err());
    }

    #[test]
    fn decompress_bounded_rejects_output_over_the_cap() {
        // A real gzip stream whose *decompressed* size exceeds a small test
        // cap - proves the rejection is driven by actual bytes read, not by
        // a pre-declared/spoofable length, without allocating a real
        // 256 MiB buffer just to exercise the boundary.
        let cap = 16;
        let oversized = vec![b'a'; usize::try_from(cap).unwrap_or(0) + 1];
        let Err(err) = decompress_bounded(&gzip(&oversized), cap) else {
            panic!("oversized payload must be rejected");
        };
        assert!(matches!(err, DecompressError::TooLarge { max_bytes } if max_bytes == cap));
    }
}
