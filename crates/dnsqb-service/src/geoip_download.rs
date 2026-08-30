//! Pure helpers for the `GeoIP` database updater: DB-IP Lite candidate
//! download-URL construction (the URL embeds the calendar year-month, T-75),
//! bounded gzip decompression, and — for T-80's `MaxMind GeoLite2` advanced
//! mode — permalink-URL construction and bounded `.tar.gz` member
//! extraction. Kept separate from `geoip_updater.rs`'s network/orchestration
//! code so this arithmetic / decompression / un-tar logic is testable with
//! plain byte buffers, no HTTP mocking needed — `geoip_updater.rs`'s own
//! `#[ignore]`d live tests are what exercise the real network paths.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;

/// Base URL DB-IP Lite's Country-level `MaxMind`-format database is served
/// from, no registration required (SPEC.md §3.5).
pub(crate) const DB_IP_BASE_URL: &str = "https://download.db-ip.com/free/";

/// The `MaxMind GeoLite2` edition this service downloads in advanced mode
/// (T-80) — a fixed country-level edition id, never user input.
pub(crate) const MAXMIND_EDITION: &str = "GeoLite2-Country";

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

/// `MaxMind`'s modern permalink download endpoint (T-80). `edition` and
/// `suffix` are the only variables; authentication is an HTTP
/// `Authorization: Basic` header (account id : license key), never a URL
/// query parameter — so this URL, unlike the legacy
/// `?license_key=` form, is safe to appear in a log line. Verified this
/// session that the built URL answers `401 WWW-Authenticate: Basic
/// realm="geoip-download"` (a real endpoint; a bogus sibling answers `404`).
/// Pass `"tar.gz"` for the database, `"tar.gz.sha256"` for the checksum
/// sidecar.
pub(crate) fn maxmind_download_url(edition: &str, suffix: &str) -> String {
    format!("https://download.maxmind.com/geoip/databases/{edition}/download?suffix={suffix}")
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

/// Decompresses a `MaxMind GeoLite2` `.tar.gz` and returns the bytes of its
/// single `.mmdb` member (T-80). The archive also carries `LICENSE.txt` /
/// `COPYRIGHT.txt` under a `GeoLite2-Country_YYYYMMDD/` directory; the first
/// entry whose path ends in `.mmdb` is the database.
///
/// **The allocation bound is the outer [`decompress_bounded`] call**, and it
/// covers the `.mmdb` member for free: a tar is its member plus a 512-byte
/// header, padding, and end blocks, so `member ≤ whole tar ≤ max_bytes`
/// whenever that call returns `Ok` (SPEC.md §8.1: bound the allocation, not a
/// separately-measured length). A second `take()` on the tar entry itself
/// would be dead code — it could never fire — so there isn't one, the same
/// reasoning that omits a path-traversal guard here: the entry path is used
/// only to *select* the `.mmdb` member; the bytes are returned in memory and
/// the caller writes them to its own fixed `geoip.mmdb`, so a `../`-laden
/// member name can't escape anywhere. `decompress_bounded` reads the gzip
/// stream to its real EOF, so its CRC32/ISIZE trailer check runs on anything
/// not already rejected as oversized.
///
/// Uses the `tar` crate rather than a hand-rolled 512-byte-header parser:
/// untrusted network input into a hand-written archive parser is exactly the
/// code class `hickory-dns` was chosen to avoid (SPEC.md §"Технічний стек").
///
/// # Errors
///
/// [`ArchiveError::TooLarge`] if the decompressed archive exceeds
/// `max_bytes`, [`ArchiveError::Gzip`] on a malformed outer gzip (including a
/// CRC32/ISIZE trailer mismatch), [`ArchiveError::Tar`] on a malformed tar
/// stream, or [`ArchiveError::NoDatabaseMember`] if no `.mmdb` entry is
/// present.
pub(crate) fn extract_mmdb_from_tar_gz(
    gz_bytes: &[u8],
    max_bytes: u64,
) -> Result<Vec<u8>, ArchiveError> {
    let tar_bytes = decompress_bounded(gz_bytes, max_bytes).map_err(|err| match err {
        DecompressError::Io(io) => ArchiveError::Gzip(io.to_string()),
        DecompressError::TooLarge { max_bytes } => ArchiveError::TooLarge { max_bytes },
    })?;

    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    let entries = archive
        .entries()
        .map_err(|err| ArchiveError::Tar(err.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|err| ArchiveError::Tar(err.to_string()))?;
        let is_mmdb = entry.path().is_ok_and(|path| {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("mmdb"))
        });
        if !is_mmdb {
            continue;
        }
        // A tar entry reader is already length-delimited by the archive
        // header, and the whole decompressed archive is bounded above - so
        // this read is transitively bounded without its own `take()` cap.
        let mut out = Vec::new();
        entry
            .read_to_end(&mut out)
            .map_err(|err| ArchiveError::Tar(err.to_string()))?;
        return Ok(out);
    }
    Err(ArchiveError::NoDatabaseMember)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ArchiveError {
    #[error("outer gzip stream is malformed or its checksum doesn't match: {0}")]
    Gzip(String),
    #[error("tar archive is malformed: {0}")]
    Tar(String),
    #[error("tar archive contains no .mmdb database member")]
    NoDatabaseMember,
    #[error("decompressed archive exceeds the {max_bytes}-byte size limit")]
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

    #[test]
    fn maxmind_download_url_is_the_modern_permalink() {
        assert_eq!(
            maxmind_download_url(MAXMIND_EDITION, "tar.gz"),
            "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
        );
        assert_eq!(
            maxmind_download_url(MAXMIND_EDITION, "tar.gz.sha256"),
            "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz.sha256"
        );
        // The key is never in the URL - it's an Authorization header.
        assert!(!maxmind_download_url(MAXMIND_EDITION, "tar.gz").contains("license_key"));
    }

    /// Builds a gzipped tar carrying `members` as `(path, contents)` pairs.
    fn tar_gz(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(u64::try_from(contents.len()).unwrap_or(0));
            header.set_mode(0o644);
            header.set_cksum();
            let Ok(()) = builder.append_data(&mut header, path, *contents) else {
                panic!("in-memory tar append cannot fail");
            };
        }
        let Ok(tar_bytes) = builder.into_inner() else {
            panic!("in-memory tar finish cannot fail");
        };
        gzip(&tar_bytes)
    }

    #[test]
    fn extract_mmdb_picks_the_database_member_past_the_license_decoys() {
        let db = b"\xde\xad\xbe\xef pretend this is an mmdb";
        let archive = tar_gz(&[
            ("GeoLite2-Country_20260830/COPYRIGHT.txt", b"(c) MaxMind"),
            ("GeoLite2-Country_20260830/LICENSE.txt", b"CC BY-SA 4.0"),
            ("GeoLite2-Country_20260830/GeoLite2-Country.mmdb", db),
        ]);
        let Ok(extracted) = extract_mmdb_from_tar_gz(&archive, MAX_GEOIP_DECOMPRESSED_BYTES) else {
            panic!("a well-formed archive with an .mmdb member must extract");
        };
        assert_eq!(extracted, db);
    }

    #[test]
    fn extract_mmdb_rejects_an_archive_with_no_database_member() {
        let archive = tar_gz(&[("GeoLite2-Country_20260830/LICENSE.txt", b"CC BY-SA 4.0")]);
        assert!(matches!(
            extract_mmdb_from_tar_gz(&archive, MAX_GEOIP_DECOMPRESSED_BYTES),
            Err(ArchiveError::NoDatabaseMember)
        ));
    }

    #[test]
    fn extract_mmdb_rejects_an_oversized_archive() {
        // A real gzipped tar whose *decompressed* size exceeds a small test
        // cap - proves the rejection is driven by bytes actually decompressed
        // (decompress_bounded reading the stream), not a spoofable declared
        // length, and without allocating a real 256 MiB buffer. The member
        // bytes are what push it over: 4 KiB of 'a' against a 2 KiB cap.
        let cap = 2 * 1024;
        let oversized = vec![b'a'; 4 * 1024];
        let archive = tar_gz(&[("dir/GeoLite2-Country.mmdb", &oversized)]);
        let Err(err) = extract_mmdb_from_tar_gz(&archive, cap) else {
            panic!("an oversized archive must be rejected");
        };
        assert!(matches!(err, ArchiveError::TooLarge { max_bytes } if max_bytes == cap));
    }

    #[test]
    fn extract_mmdb_rejects_a_malformed_outer_gzip() {
        assert!(matches!(
            extract_mmdb_from_tar_gz(b"not gzip at all", MAX_GEOIP_DECOMPRESSED_BYTES),
            Err(ArchiveError::Gzip(_))
        ));
    }

    #[test]
    fn extract_mmdb_rejects_a_gzip_that_is_not_a_tar() {
        // Valid gzip, but the decompressed bytes aren't a tar stream.
        let not_a_tar = gzip(b"just some plain text, definitely not a tar archive");
        assert!(extract_mmdb_from_tar_gz(&not_a_tar, MAX_GEOIP_DECOMPRESSED_BYTES).is_err());
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
