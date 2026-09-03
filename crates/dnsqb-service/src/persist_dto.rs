//! T-146: the serialization shape of the persisted query log. Kept separate
//! from [`crate::query_log`]'s live [`LogEntry`] (which carries non-serde
//! types — `SystemTime`, `RecordType`, `&'static str`) so the on-disk format
//! is an explicit, stable contract rather than whatever `derive(Serialize)`
//! on the internal type would happen to produce.
//!
//! Wrapped in [`PersistedFileV1`] (a struct, not a bare array) so a future
//! field — a `saved_at`, a schema note — is an additive change. The
//! container itself is versioned by `encrypted_file`'s header byte; this
//! `V1` suffix tracks the *inner* JSON shape, bumped only if a field's
//! meaning changes incompatibly.
//!
//! [`From`], not [`TryFrom`], on the way *in* from disk: the plaintext is
//! AEAD-authenticated, so if it decrypts at all every byte is intact and a
//! malformed *entry* can only come from a newer build's schema. [`from_json`]
//! lets `serde` fail the whole document in that case; the caller
//! ([`crate::log_persist`]) renames the file aside and starts from an empty
//! log rather than recovering a partial one.

use serde::{Deserialize, Serialize};

use crate::query_log::{Decision, DecisionSource, LogEntry};
use crate::quorum::{VoterRecord, VoterVerdict};
use hickory_proto::rr::RecordType;
use std::time::{Duration, UNIX_EPOCH};

/// The whole persisted-log file, before encryption.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PersistedFileV1 {
    /// Every retained log entry, oldest first (the order
    /// [`crate::query_log::QueryLog::snapshot`] returns).
    pub entries: Vec<PersistedLogEntry>,
}

/// On-disk form of one [`LogEntry`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PersistedLogEntry {
    /// `timestamp` as whole milliseconds since the Unix epoch.
    pub ts_millis: u64,
    /// The normalized query domain.
    pub domain: String,
    /// The query's record type, as its numeric code.
    pub qtype: u16,
    pub decision: PDecision,
    pub decision_source: PDecisionSource,
    #[serde(default)]
    pub voters: Vec<PersistedVoter>,
    #[serde(default)]
    pub geoip_country: Option<String>,
    #[serde(default)]
    pub resolved_ip_country: Option<String>,
    pub latency_ms: u64,
}

/// On-disk form of one [`VoterRecord`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PersistedVoter {
    pub provider_id: String,
    pub verdict: PVerdict,
    #[serde(default)]
    pub allow_ip_count: Option<u32>,
    /// The coarse `error_kind` label, if any — re-interned to a `&'static str`
    /// on the way back (see [`static_error_kind`]); an unknown string becomes
    /// `None`.
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Mirror of [`Decision`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PDecision {
    Allowed,
    Blocked,
    Failed,
}

/// Mirror of [`DecisionSource`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PDecisionSource {
    Allowlist,
    Blocklist,
    Cache,
    Quorum,
    Geoip,
    BaselineFallback,
}

/// Mirror of [`VoterVerdict`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PVerdict {
    Block,
    Allow,
    Timeout,
    Error,
    Canceled,
    Disabled,
}

/// The closed set of coarse error-kind labels `quorum::error_kind` produces —
/// re-interned to `'static` so a restored [`VoterRecord`] can hold the same
/// `Option<&'static str>` a live one does. Anything else (a newer build's
/// label, a corrupted string) becomes `None`.
fn static_error_kind(s: &str) -> Option<&'static str> {
    match s {
        "encode" => Some("encode"),
        "http" => Some("http"),
        "decode" => Some("decode"),
        _ => None,
    }
}

impl From<Decision> for PDecision {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Allowed => PDecision::Allowed,
            Decision::Blocked => PDecision::Blocked,
            Decision::Failed => PDecision::Failed,
        }
    }
}

impl From<PDecision> for Decision {
    fn from(d: PDecision) -> Self {
        match d {
            PDecision::Allowed => Decision::Allowed,
            PDecision::Blocked => Decision::Blocked,
            PDecision::Failed => Decision::Failed,
        }
    }
}

impl From<DecisionSource> for PDecisionSource {
    fn from(s: DecisionSource) -> Self {
        match s {
            DecisionSource::Allowlist => PDecisionSource::Allowlist,
            DecisionSource::Blocklist => PDecisionSource::Blocklist,
            DecisionSource::Cache => PDecisionSource::Cache,
            DecisionSource::Quorum => PDecisionSource::Quorum,
            DecisionSource::Geoip => PDecisionSource::Geoip,
            DecisionSource::BaselineFallback => PDecisionSource::BaselineFallback,
        }
    }
}

impl From<PDecisionSource> for DecisionSource {
    fn from(s: PDecisionSource) -> Self {
        match s {
            PDecisionSource::Allowlist => DecisionSource::Allowlist,
            PDecisionSource::Blocklist => DecisionSource::Blocklist,
            PDecisionSource::Cache => DecisionSource::Cache,
            PDecisionSource::Quorum => DecisionSource::Quorum,
            PDecisionSource::Geoip => DecisionSource::Geoip,
            PDecisionSource::BaselineFallback => DecisionSource::BaselineFallback,
        }
    }
}

impl From<VoterVerdict> for PVerdict {
    fn from(v: VoterVerdict) -> Self {
        match v {
            VoterVerdict::Block => PVerdict::Block,
            VoterVerdict::Allow => PVerdict::Allow,
            VoterVerdict::Timeout => PVerdict::Timeout,
            VoterVerdict::Error => PVerdict::Error,
            VoterVerdict::Canceled => PVerdict::Canceled,
            VoterVerdict::Disabled => PVerdict::Disabled,
        }
    }
}

impl From<PVerdict> for VoterVerdict {
    fn from(v: PVerdict) -> Self {
        match v {
            PVerdict::Block => VoterVerdict::Block,
            PVerdict::Allow => VoterVerdict::Allow,
            PVerdict::Timeout => VoterVerdict::Timeout,
            PVerdict::Error => VoterVerdict::Error,
            PVerdict::Canceled => VoterVerdict::Canceled,
            PVerdict::Disabled => VoterVerdict::Disabled,
        }
    }
}

impl From<&VoterRecord> for PersistedVoter {
    fn from(v: &VoterRecord) -> Self {
        Self {
            provider_id: v.provider_id.clone(),
            verdict: v.verdict.into(),
            allow_ip_count: v.allow_ip_count,
            error_message: v.error_message.map(str::to_owned),
        }
    }
}

impl From<PersistedVoter> for VoterRecord {
    fn from(v: PersistedVoter) -> Self {
        Self {
            provider_id: v.provider_id,
            verdict: v.verdict.into(),
            allow_ip_count: v.allow_ip_count,
            error_message: v.error_message.as_deref().and_then(static_error_kind),
        }
    }
}

impl From<&LogEntry> for PersistedLogEntry {
    fn from(e: &LogEntry) -> Self {
        Self {
            ts_millis: u64::try_from(
                e.timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
            domain: e.domain.clone(),
            qtype: e.qtype.into(),
            decision: e.decision.into(),
            decision_source: e.decision_source.into(),
            voters: e.voters.iter().map(PersistedVoter::from).collect(),
            geoip_country: e.geoip_country.clone(),
            resolved_ip_country: e.resolved_ip_country.clone(),
            latency_ms: e.latency_ms,
        }
    }
}

impl From<PersistedLogEntry> for LogEntry {
    /// Infallible today — every field maps 1:1 and `serde` already rejected an
    /// unknown enum string before this runs. Kept as `From` (not `TryFrom`)
    /// for that reason; the "drop a bad entry" behaviour lives one level up,
    /// where `serde_json` reports *which* entry failed to decode.
    fn from(e: PersistedLogEntry) -> Self {
        Self {
            timestamp: UNIX_EPOCH + Duration::from_millis(e.ts_millis),
            domain: e.domain,
            qtype: RecordType::from(e.qtype),
            decision: e.decision.into(),
            decision_source: e.decision_source.into(),
            voters: e.voters.into_iter().map(VoterRecord::from).collect(),
            geoip_country: e.geoip_country,
            resolved_ip_country: e.resolved_ip_country,
            latency_ms: e.latency_ms,
        }
    }
}

/// Serializes `entries` (a [`crate::query_log::QueryLog::snapshot`] result)
/// to the JSON plaintext that `encrypted_file::seal` then encrypts.
///
/// # Errors
///
/// Propagates a `serde_json` serialization error (not expected for these
/// field types).
pub(crate) fn to_json(entries: &[LogEntry]) -> Result<Vec<u8>, serde_json::Error> {
    let file = PersistedFileV1 {
        entries: entries.iter().map(PersistedLogEntry::from).collect(),
    };
    serde_json::to_vec(&file)
}

/// Parses the decrypted plaintext back into [`LogEntry`] values. A top-level
/// JSON error is returned; per-entry problems can't occur here because
/// [`PersistedLogEntry`] -> [`LogEntry`] is infallible and `serde` already
/// validated every enum string.
///
/// # Errors
///
/// Returns the `serde_json` error if `plaintext` is not a valid
/// [`PersistedFileV1`].
pub(crate) fn from_json(plaintext: &[u8]) -> Result<Vec<LogEntry>, serde_json::Error> {
    let file: PersistedFileV1 = serde_json::from_slice(plaintext)?;
    Ok(file.entries.into_iter().map(LogEntry::from).collect())
}

#[cfg(test)]
mod tests {
    use super::{from_json, static_error_kind, to_json, PersistedFileV1};
    use crate::query_log::{Decision, DecisionSource, LogEntry};
    use crate::quorum::{VoterRecord, VoterVerdict};
    use hickory_proto::rr::RecordType;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn sample_entry() -> LogEntry {
        LogEntry {
            timestamp: UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
            domain: "example.com".to_string(),
            qtype: RecordType::AAAA,
            decision: Decision::Blocked,
            decision_source: DecisionSource::BaselineFallback,
            voters: vec![
                VoterRecord {
                    provider_id: "quad9".to_string(),
                    verdict: VoterVerdict::Timeout,
                    allow_ip_count: None,
                    error_message: None,
                },
                VoterRecord {
                    provider_id: "adguard".to_string(),
                    verdict: VoterVerdict::Error,
                    allow_ip_count: None,
                    error_message: Some("http"),
                },
            ],
            geoip_country: None,
            resolved_ip_country: Some("US".to_string()),
            latency_ms: 42,
        }
    }

    #[test]
    fn round_trips_every_field_through_json() {
        let entries = vec![sample_entry()];
        let json = match to_json(&entries) {
            Ok(bytes) => bytes,
            Err(err) => panic!("serialize: {err}"),
        };
        let back = match from_json(&json) {
            Ok(v) => v,
            Err(err) => panic!("deserialize: {err}"),
        };
        assert_eq!(back.len(), 1);
        let (a, b) = (&entries[0], &back[0]);
        assert_eq!(a.timestamp, b.timestamp);
        assert_eq!(a.domain, b.domain);
        assert_eq!(a.qtype, b.qtype);
        assert_eq!(a.decision, b.decision);
        assert_eq!(a.decision_source, b.decision_source);
        assert_eq!(a.geoip_country, b.geoip_country);
        assert_eq!(a.resolved_ip_country, b.resolved_ip_country);
        assert_eq!(a.latency_ms, b.latency_ms);
        assert_eq!(a.voters.len(), b.voters.len());
        for (va, vb) in a.voters.iter().zip(&b.voters) {
            assert_eq!(va.provider_id, vb.provider_id);
            assert_eq!(va.verdict, vb.verdict);
            assert_eq!(va.allow_ip_count, vb.allow_ip_count);
            assert_eq!(va.error_message, vb.error_message);
        }
    }

    #[test]
    fn every_decision_source_variant_survives_the_round_trip() {
        let sources = [
            DecisionSource::Allowlist,
            DecisionSource::Blocklist,
            DecisionSource::Cache,
            DecisionSource::Quorum,
            DecisionSource::Geoip,
            DecisionSource::BaselineFallback,
        ];
        let entries: Vec<LogEntry> = sources
            .iter()
            .map(|&s| {
                let mut e = sample_entry();
                e.decision_source = s;
                e.voters.clear();
                e
            })
            .collect();
        let json = match to_json(&entries) {
            Ok(b) => b,
            Err(err) => panic!("serialize: {err}"),
        };
        let back = match from_json(&json) {
            Ok(v) => v,
            Err(err) => panic!("deserialize: {err}"),
        };
        let got: Vec<DecisionSource> = back.iter().map(|e| e.decision_source).collect();
        assert_eq!(got, sources);
    }

    #[test]
    fn an_unknown_error_kind_string_becomes_none_not_a_leak() {
        assert_eq!(static_error_kind("http"), Some("http"));
        assert_eq!(static_error_kind("some-future-kind"), None);
    }

    #[test]
    fn from_json_rejects_a_garbage_top_level_document() {
        assert!(from_json(b"not json at all").is_err());
        assert!(from_json(b"{}").is_err(), "missing `entries` is an error");
    }

    #[test]
    fn from_json_rejects_an_unrecognized_enum_string() {
        // serde fails the whole document - the "drop just the bad entry"
        // behaviour is the caller's (main.rs logs which entry / falls back
        // to an empty log), not this function's.
        let bad = br#"{"entries":[{"ts_millis":1,"domain":"x","qtype":1,"decision":"allowed","decision_source":"telepathy","latency_ms":0}]}"#;
        assert!(from_json(bad).is_err());
    }

    #[test]
    fn a_far_future_timestamp_does_not_panic_on_serialize() {
        let mut e = sample_entry();
        e.timestamp = SystemTime::now() + Duration::from_hours(100 * 365 * 24);
        match to_json(std::slice::from_ref(&e)) {
            Ok(json) => assert!(from_json(&json).is_ok()),
            Err(err) => panic!("serialize must not fail on a far-future ts: {err}"),
        }
    }

    #[test]
    fn persisted_file_is_a_struct_so_new_fields_stay_additive() {
        // A bare-array format would break the moment a sibling field is
        // added; assert the wrapper shape.
        let json = to_json(&[]).unwrap_or_default();
        let value: serde_json::Value = match serde_json::from_slice(&json) {
            Ok(v) => v,
            Err(err) => panic!("deserialize as Value: {err}"),
        };
        assert!(
            value.get("entries").is_some(),
            "top level must be an object"
        );
        let _ = PersistedFileV1 { entries: vec![] };
    }
}
