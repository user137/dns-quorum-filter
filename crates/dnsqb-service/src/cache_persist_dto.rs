//! T-97: the serialization shape of the persisted quorum-verdict cache
//! (SPEC.md §4). Sibling of [`crate::persist_dto`] (the query log's on-disk
//! form) and held to the same discipline — an explicit, stable, versioned
//! contract kept separate from the live types.
//!
//! Two things make the cache harder to persist than the log:
//!
//! - [`crate::cache::CacheEntry::expires_at`] is a [`std::time::Instant`] —
//!   monotonic, resets across a reboot, no serde impl. The on-disk form stores
//!   an **absolute wall-clock deadline** instead
//!   ([`PersistedCacheEntry::expiry_millis`]). [`to_json`] converts `Instant` →
//!   wall clock against an injected clock pair; [`from_json`] converts back and
//!   **drops** any entry whose deadline is already in the past (expired during
//!   downtime — RFC 8767 stale-if-error is not wired in, so a stale entry has
//!   no consumer). The reconstructed entry's `ttl` is the *remaining* lifetime,
//!   not the original — `ttl` is diagnostic only, never read on the hot path.
//!
//! - Only [`crate::cache::Verdict::Allow`] is persisted. [`to_json`] filters
//!   [`crate::cache::Verdict::Block`] out at snapshot time (user decision
//!   2026-09-03): a `fail_closed` timeout can cache a `Block` for
//!   `block_verdict_ttl` (default 24 h), and persisting that would let it
//!   survive a restart — including the watchdog's automatic one. A fresh quorum
//!   `Block` is one round-trip to re-derive and OR-logic re-blocks it
//!   immediately. [`PCacheVerdict`] keeps `Block` representable so the format
//!   needs no version bump if that policy ever changes.
//!
//! Like [`crate::persist_dto`], conversion *out* of the on-disk form is
//! infallible-per-field: the plaintext is AEAD-authenticated, so a byte-level
//! problem cannot occur; [`from_json`] lets `serde` fail the whole document if
//! a newer build's schema is unreadable. Dropping an individual entry on the
//! way back in — its deadline already passed, or its key no longer parses — is
//! expected pruning, not an error.

use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cache::{CacheEntry, CacheKey, Verdict};
use hickory_proto::rr::RecordType;

/// The whole persisted-cache file, before encryption. A struct wrapper (not a
/// bare array) so a future sibling field stays additive — same reasoning as
/// [`crate::persist_dto::PersistedFileV1`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PersistedCacheFileV1 {
    /// Every retained cache entry. Order is not significant (a cache, not a
    /// ring buffer).
    pub entries: Vec<PersistedCacheEntry>,
}

/// On-disk form of one cache slot.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PersistedCacheEntry {
    /// The normalized cache-key domain.
    pub domain: String,
    /// The cache-key record type, as its numeric code.
    pub qtype: u16,
    /// Absolute expiry as whole milliseconds since the Unix epoch — see the
    /// module docs on why this is wall-clock, not the live `Instant`.
    pub expiry_millis: u64,
    /// The cached verdict — only ever `Allow` on disk today (module docs).
    pub verdict: PCacheVerdict,
}

/// Mirror of [`Verdict`]. [`to_json`] only ever emits `Allow`; `Block` stays
/// representable so a future policy change needs no format bump (module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PCacheVerdict {
    /// At least one provider's block signature matched.
    Block,
    /// Domain resolved; the IPs the quorum answer carried.
    Allow(Vec<IpAddr>),
}

impl From<&Verdict> for PCacheVerdict {
    fn from(v: &Verdict) -> Self {
        match v {
            Verdict::Block => PCacheVerdict::Block,
            Verdict::Allow(ips) => PCacheVerdict::Allow(ips.clone()),
        }
    }
}

impl From<PCacheVerdict> for Verdict {
    fn from(v: PCacheVerdict) -> Self {
        match v {
            PCacheVerdict::Block => Verdict::Block,
            PCacheVerdict::Allow(ips) => Verdict::Allow(ips),
        }
    }
}

/// Converts one live `(key, entry)` to its persisted form against an injected
/// clock pair, or `None` if the entry must not be persisted: it is a
/// `Verdict::Block`, it is no longer fresh, or its wall-clock deadline would
/// overflow `SystemTime` (unreachable for any real TTL).
fn to_persisted(
    key: &CacheKey,
    entry: &CacheEntry,
    now_wall: SystemTime,
    now_mono: Instant,
) -> Option<PersistedCacheEntry> {
    if matches!(entry.verdict, Verdict::Block) || !entry.is_fresh(now_mono) {
        return None;
    }
    let remaining = entry.expires_at.saturating_duration_since(now_mono);
    let expiry_wall = now_wall.checked_add(remaining)?;
    let expiry_millis = u64::try_from(
        expiry_wall
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    Some(PersistedCacheEntry {
        domain: key.domain().to_owned(),
        qtype: key.qtype().into(),
        expiry_millis,
        verdict: PCacheVerdict::from(&entry.verdict),
    })
}

/// Converts one persisted entry back to a live `(key, entry)` against
/// `now_wall`, or `None` if it can no longer be used: its absolute deadline is
/// already in the past (expired during downtime), or its domain no longer
/// parses through [`CacheKey::new`] (a newer build's schema — not reachable
/// through AEAD, but the key is validated on the way in regardless).
///
/// `expires_at` is rebuilt from the *real* monotonic clock (`Instant::now()`),
/// not an injected one — the returned entry must be fresh for `remaining` from
/// now for `moka`'s eviction window and [`CacheEntry::is_fresh`] to agree.
fn from_persisted(p: PersistedCacheEntry, now_wall: SystemTime) -> Option<(CacheKey, CacheEntry)> {
    let expiry_wall = UNIX_EPOCH.checked_add(Duration::from_millis(p.expiry_millis))?;
    let remaining = expiry_wall.duration_since(now_wall).ok()?;
    if remaining.is_zero() {
        return None;
    }
    let key = CacheKey::new(&p.domain, RecordType::from(p.qtype)).ok()?;
    let entry = CacheEntry {
        verdict: Verdict::from(p.verdict),
        ttl: remaining,
        expires_at: Instant::now() + remaining,
    };
    Some((key, entry))
}

/// Serializes a [`crate::cache::Cache::snapshot`] result to the JSON plaintext
/// that `encrypted_file::seal` then encrypts, filtering out `Block` verdicts
/// and stale entries and converting each `Instant` deadline to wall-clock
/// against `now_wall` / `now_mono` (injected for deterministic tests).
///
/// # Errors
///
/// Propagates a `serde_json` serialization error (not expected for these field
/// types).
pub(crate) fn to_json(
    snapshot: &[(CacheKey, CacheEntry)],
    now_wall: SystemTime,
    now_mono: Instant,
) -> Result<Vec<u8>, serde_json::Error> {
    let file = PersistedCacheFileV1 {
        entries: snapshot
            .iter()
            .filter_map(|(key, entry)| to_persisted(key, entry, now_wall, now_mono))
            .collect(),
    };
    serde_json::to_vec(&file)
}

/// Parses the decrypted plaintext back into live `(key, entry)` pairs against
/// `now_wall`, dropping any whose deadline has already passed. A top-level JSON
/// error fails the whole document (the caller then starts from an empty cache).
///
/// # Errors
///
/// Returns the `serde_json` error if `plaintext` is not a valid
/// [`PersistedCacheFileV1`].
pub(crate) fn from_json(
    plaintext: &[u8],
    now_wall: SystemTime,
) -> Result<Vec<(CacheKey, CacheEntry)>, serde_json::Error> {
    let file: PersistedCacheFileV1 = serde_json::from_slice(plaintext)?;
    Ok(file
        .entries
        .into_iter()
        .filter_map(|p| from_persisted(p, now_wall))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{from_json, to_json};
    use crate::cache::{CacheEntry, CacheKey, Verdict};
    use hickory_proto::rr::RecordType;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant, SystemTime};

    fn key(domain: &str, qtype: RecordType) -> CacheKey {
        match CacheKey::new(domain, qtype) {
            Ok(k) => k,
            Err(err) => panic!("valid fixture domain: {err}"),
        }
    }

    fn allow(ip: [u8; 4]) -> Verdict {
        Verdict::Allow(vec![Ipv4Addr::from(ip).into()])
    }

    #[test]
    fn round_trips_an_allow_entry_through_json() {
        let snapshot = vec![(
            key("example.com", RecordType::AAAA),
            CacheEntry::new(allow([1, 2, 3, 4]), Duration::from_secs(600)),
        )];
        // Read the clocks the way the real persister does — at flush time,
        // after the snapshot already exists.
        let now_wall = SystemTime::now();
        let now_mono = Instant::now();

        let json = match to_json(&snapshot, now_wall, now_mono) {
            Ok(bytes) => bytes,
            Err(err) => panic!("serialize: {err}"),
        };
        let back = match from_json(&json, now_wall) {
            Ok(v) => v,
            Err(err) => panic!("deserialize: {err}"),
        };

        assert_eq!(back.len(), 1);
        let (k, e) = &back[0];
        assert_eq!(k.domain(), "example.com");
        assert_eq!(k.qtype(), RecordType::AAAA);
        let expected_ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, 4));
        assert!(matches!(&e.verdict, Verdict::Allow(ips) if ips.as_slice() == [expected_ip]));
        // Same wall clock on both sides -> essentially the full TTL comes back
        // (a couple of seconds of slack for the `Instant::now()` reads inside
        // `CacheEntry::new` and `from_persisted`).
        assert!(
            e.ttl <= Duration::from_secs(600) && e.ttl >= Duration::from_secs(598),
            "expected ~600s, got {:?}",
            e.ttl
        );
        assert!(e.is_fresh(Instant::now()));
    }

    #[test]
    fn a_block_verdict_is_dropped_at_snapshot() {
        let now_wall = SystemTime::now();
        let now_mono = Instant::now();
        let snapshot = vec![
            (
                key("blocked.example", RecordType::A),
                CacheEntry::new(Verdict::Block, Duration::from_secs(600)),
            ),
            (
                key("allowed.example", RecordType::A),
                CacheEntry::new(allow([9, 9, 9, 9]), Duration::from_secs(600)),
            ),
        ];

        let json = match to_json(&snapshot, now_wall, now_mono) {
            Ok(bytes) => bytes,
            Err(err) => panic!("serialize: {err}"),
        };
        let back = match from_json(&json, now_wall) {
            Ok(v) => v,
            Err(err) => panic!("deserialize: {err}"),
        };

        assert_eq!(back.len(), 1, "only the Allow entry is persisted");
        assert_eq!(back[0].0.domain(), "allowed.example");
    }

    #[test]
    fn a_not_fresh_entry_is_dropped_at_snapshot() {
        let now_wall = SystemTime::now();
        let now_mono = Instant::now();
        let Some(already_expired) = now_mono.checked_sub(Duration::from_secs(1)) else {
            panic!("Instant::now() must be at least 1s past the process epoch");
        };
        let snapshot = vec![(
            key("stale.example", RecordType::A),
            CacheEntry {
                verdict: allow([1, 1, 1, 1]),
                ttl: Duration::from_secs(600),
                expires_at: already_expired,
            },
        )];

        let json = match to_json(&snapshot, now_wall, now_mono) {
            Ok(bytes) => bytes,
            Err(err) => panic!("serialize: {err}"),
        };
        let back = match from_json(&json, now_wall) {
            Ok(v) => v,
            Err(err) => panic!("deserialize: {err}"),
        };
        assert!(back.is_empty(), "a stale entry is not written");
    }

    #[test]
    fn an_entry_whose_deadline_passed_during_downtime_is_dropped_on_restore() {
        let write_wall = SystemTime::now();
        let now_mono = Instant::now();
        let snapshot = vec![(
            key("short.example", RecordType::A),
            CacheEntry::new(allow([1, 2, 3, 4]), Duration::from_secs(60)),
        )];
        let json = match to_json(&snapshot, write_wall, now_mono) {
            Ok(bytes) => bytes,
            Err(err) => panic!("serialize: {err}"),
        };

        // Restart happens an hour later — well past the 60s deadline.
        let restore_wall = write_wall + Duration::from_secs(3600);
        let back = match from_json(&json, restore_wall) {
            Ok(v) => v,
            Err(err) => panic!("deserialize: {err}"),
        };
        assert!(
            back.is_empty(),
            "an entry that expired during downtime is not restored"
        );
    }

    #[test]
    fn a_monotonic_clock_reset_does_not_inflate_the_remaining_ttl() {
        // The core of the design: `expires_at` (an Instant) is meaningless
        // across a reboot, so the deadline is persisted as wall-clock. A
        // restart 10 minutes after the write must leave ~50 minutes on a
        // 60-minute entry, regardless of what the monotonic clock reads.
        let snapshot = vec![(
            key("hour.example", RecordType::A),
            CacheEntry::new(allow([1, 2, 3, 4]), Duration::from_secs(3600)),
        )];
        let write_wall = SystemTime::now();
        let write_mono = Instant::now();
        let json = match to_json(&snapshot, write_wall, write_mono) {
            Ok(bytes) => bytes,
            Err(err) => panic!("serialize: {err}"),
        };

        let restore_wall = write_wall + Duration::from_secs(600);
        let back = match from_json(&json, restore_wall) {
            Ok(v) => v,
            Err(err) => panic!("deserialize: {err}"),
        };
        assert_eq!(back.len(), 1);
        let remaining = back[0].1.ttl;
        assert!(
            remaining <= Duration::from_secs(3001) && remaining >= Duration::from_secs(2998),
            "expected ~3000s remaining, got {remaining:?}"
        );
    }

    #[test]
    fn empty_snapshot_round_trips() {
        let now_wall = SystemTime::now();
        let json = match to_json(&[], now_wall, Instant::now()) {
            Ok(bytes) => bytes,
            Err(err) => panic!("serialize: {err}"),
        };
        match from_json(&json, now_wall) {
            Ok(v) => assert!(v.is_empty()),
            Err(err) => panic!("deserialize: {err}"),
        }
    }

    #[test]
    fn from_json_rejects_a_garbage_or_unknown_shape() {
        let now_wall = SystemTime::now();
        assert!(from_json(b"not json at all", now_wall).is_err());
        assert!(
            from_json(b"{}", now_wall).is_err(),
            "missing `entries` is an error"
        );
        // An unrecognized verdict tag fails the whole document (serde), not
        // just the one entry.
        let bad = br#"{"entries":[{"domain":"x","qtype":1,"expiry_millis":99999999999999,"verdict":{"telepathy":[]}}]}"#;
        assert!(from_json(bad, now_wall).is_err());
    }
}
