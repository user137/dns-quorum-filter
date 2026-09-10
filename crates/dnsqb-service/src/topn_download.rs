//! Pure helpers for the availability-zone list updater (T-124): stable-URL
//! construction, SHA-256 sidecar verification, and `.txt` parsing. Kept
//! separate from [`crate::topn_updater`]'s network/orchestration code so this
//! logic is testable with plain byte buffers, no HTTP mocking — the same
//! split as [`crate::geoip_download`] / [`crate::geoip_updater`].
//!
//! **Distribution contract (T-105).** The curated lists live at stable paths
//! in the repository (`data/topn/<list>.txt` + `<list>.txt.sha256`); the URL
//! never changes, only the file content does. The client fetches them over
//! TLS, verifies the sidecar, and atomic-swaps — exactly the mechanism the
//! `GeoIP` database already uses, "as is", no month discovery and no
//! manifest.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// Where the curated lists are published (T-105). `raw.githubusercontent.com`
/// serves the repository's `main` branch verbatim; a list's path under it is
/// fixed, so this is a constant, never user input.
pub(crate) const TOPN_RAW_BASE: &str =
    "https://raw.githubusercontent.com/user137/dns-quorum-filter/main/data/topn/";

/// Every availability-zone list the repository currently publishes (T-105) —
/// the set a client may select in `[rating_filter] lists`. Part of the same
/// distribution contract as [`TOPN_RAW_BASE`]: adding a curated dataset means
/// editing this list (and shipping `data/topn/<code>.txt` + its sidecar), and
/// nothing on the client side. Surfaced on `GET /admin/status`
/// ([`crate::admin::RatingFilterStatusView::available_lists`]) so the
/// `/admin/ui` zone-config card renders its checkboxes from the server, not a
/// hard-coded copy in the page's JavaScript.
pub(crate) const AVAILABLE_TOPN_LISTS: &[&str] = &["ua", "us", "de", "pl", "gb", "global"];

/// Upper bound on one list download. A published list is ~1000 rows of
/// ~40 bytes plus a short `#` header — well under 64 KiB; this is generous
/// headroom, not a measured limit (same spirit as
/// [`crate::geoip_download::MAX_GEOIP_COMPRESSED_BYTES`]).
pub(crate) const MAX_TOPN_BYTES: u64 = 8 * 1024 * 1024;

/// The download URL for one list (`"ua"`, `"global"`, …). Caller has
/// already validated `list` against `^([a-z]{2}|global)$`
/// ([`crate::config::validate_rating_filter_lists`]).
pub(crate) fn list_url(list: &str) -> String {
    format!("{TOPN_RAW_BASE}{list}.txt")
}

/// The SHA-256 sidecar URL for one list.
pub(crate) fn sha256_sidecar_url(list: &str) -> String {
    format!("{TOPN_RAW_BASE}{list}.txt.sha256")
}

/// Parses a curated list body into its registrable domains: one per line,
/// `#` comments and blank lines skipped, lowercased, deduplicated with
/// first-seen order preserved (so a bad list can't silently double its
/// memory). Whitespace around an entry is trimmed. This is the same "ignore
/// `#` and blanks" rule `data/topn/README.md` documents for the client.
pub(crate) fn parse_list(body: &str) -> Vec<String> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in body.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        let entry = entry.to_ascii_lowercase();
        if seen.insert(entry.clone()) {
            out.push(entry);
        }
    }
    out
}

/// `true` when `bytes` hash to the digest named in `sidecar_text` — a
/// `sha256sum`-style `"<hex>  <filename>"` line, of which only the first
/// whitespace-delimited token is read (case- and surrounding-whitespace
/// insensitive). A malformed sidecar (no hex token) never matches, so the
/// caller treats it as a verification failure, not a silent pass — the
/// published lists always ship a sidecar, unlike `GeoIP`'s opportunistic
/// one.
pub(crate) fn verify_sha256(bytes: &[u8], sidecar_text: &str) -> bool {
    let Some(token) = sidecar_text.split_whitespace().next() else {
        return false;
    };
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    token.eq_ignore_ascii_case(&sha256_hex(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

#[cfg(test)]
mod tests {
    use super::{list_url, parse_list, sha256_sidecar_url, verify_sha256, TOPN_RAW_BASE};

    #[test]
    fn urls_route_a_list_and_its_sidecar_under_the_stable_base() {
        assert_eq!(list_url("ua"), format!("{TOPN_RAW_BASE}ua.txt"));
        assert_eq!(list_url("global"), format!("{TOPN_RAW_BASE}global.txt"));
        assert_eq!(
            sha256_sidecar_url("ua"),
            format!("{TOPN_RAW_BASE}ua.txt.sha256")
        );
    }

    #[test]
    fn parse_list_skips_comments_and_blanks_and_dedups() {
        let body = "# CrUX 202608, curated 2026-09-09\n\
                    \n\
                    example.ua\n\
                    Rozetka.com.ua\n\
                    rozetka.com.ua\n\
                    #trailing comment\n\
                    \t olx.ua \t\n";
        assert_eq!(
            parse_list(body),
            vec![
                "example.ua".to_string(),
                "rozetka.com.ua".to_string(),
                "olx.ua".to_string()
            ]
        );
    }

    #[test]
    fn parse_list_of_an_all_comment_body_is_empty() {
        assert!(parse_list("# only\n# comments\n\n").is_empty());
    }

    #[test]
    fn verify_sha256_accepts_the_matching_digest_in_either_form() {
        let bytes = b"example.ua\nrozetka.com.ua\n";
        // Precomputed SHA-256 of the byte string above.
        let hex = "e3b1c9d0a4f2e6b8c1d5a9f0e2b4c6d8a0f1e3c5b7d9a1f3e5c7b9d1a3f5e7c9";
        // Not the real digest — assert the shape guard, then the real path.
        assert!(
            !verify_sha256(bytes, hex),
            "a wrong 64-hex digest must fail"
        );

        let real = super::sha256_hex(bytes);
        assert!(verify_sha256(bytes, &real));
        assert!(verify_sha256(bytes, &real.to_ascii_uppercase()));
        assert!(verify_sha256(bytes, &format!("{real}  ua.txt\n")));
    }

    #[test]
    fn verify_sha256_rejects_a_malformed_sidecar() {
        let bytes = b"anything";
        assert!(!verify_sha256(bytes, ""));
        assert!(!verify_sha256(bytes, "not-a-digest"));
        assert!(!verify_sha256(bytes, "deadbeef")); // too short
    }
}
