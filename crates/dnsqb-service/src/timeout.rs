//! Upstream timeout modes and the per-voter timeout wrapper (SPEC.md §3.3,
//! T-27). Combining [`VoterOutcome`]s into a [`crate::QuorumVerdict`] is
//! `quorum::combine` — this module only produces the per-voter outcome, it
//! doesn't interpret one.

use crate::upstream::{DohClient, UpstreamError};
use hickory_proto::op::Message;
use std::time::Duration;

/// SPEC.md §3.3: how an unresponsive voter (timeout, or any other upstream
/// error — SPEC.md §3.3 addendum) is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutMode {
    /// A voter that didn't answer in time is treated as not blocking.
    /// Availability priority: one degraded provider doesn't break the
    /// internet. Default.
    FailOpen,
    /// A voter that didn't answer in time is treated as blocking. Safety
    /// priority: one degraded provider can make the internet look "down".
    FailClosed,
    /// Same verdict as `FailOpen` computed over the voters that did answer,
    /// but the incompleteness is a first-class fact (T-29 logs it, T-56's
    /// planned UI indicator will surface it) — and, unlike `FailOpen`, it
    /// does not get the `stale-if-error` fallback (T-28, SPEC.md §3.3).
    Degraded,
}

/// SPEC.md §3.3 (T-27): timeout mode and duration for upstream/baseline
/// queries. `Default` is the spec's stated default: `fail-open`, ~2s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutConfig {
    /// How an unresponsive voter is interpreted.
    pub mode: TimeoutMode,
    /// Per-query timeout duration.
    pub duration: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_secs(2),
        }
    }
}

/// The result of querying one voter (or the baseline) within `duration`.
#[derive(Debug)]
pub enum VoterOutcome {
    /// The upstream answered in time.
    Responded(Message),
    /// The upstream did not answer within `duration`.
    TimedOut,
    /// The upstream answered with an error (network, TLS, decode, or the
    /// local, deterministic [`UpstreamError::Encode`] — SPEC.md §3.3
    /// addendum on why `Encode` still lands here, logged louder by the
    /// caller rather than treated as a distinct case).
    Errored(UpstreamError),
}

/// SPEC.md §3.3 (T-27): run `client.query(url, query)` under `duration`,
/// turning a timeout into [`VoterOutcome::TimedOut`] instead of propagating
/// it as an error — the caller (`quorum::combine`) is what interprets
/// timeout/error outcomes per [`TimeoutMode`], not this function.
pub async fn query_with_timeout<C: DohClient>(
    client: &C,
    url: &str,
    query: &Message,
    duration: Duration,
) -> VoterOutcome {
    match tokio::time::timeout(duration, client.query(url, query)).await {
        Ok(Ok(message)) => VoterOutcome::Responded(message),
        Ok(Err(err)) => VoterOutcome::Errored(err),
        Err(_) => VoterOutcome::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::{query_with_timeout, TimeoutMode, VoterOutcome};
    use crate::upstream::{DohClient, UpstreamError};
    use hickory_proto::op::Message;
    use std::time::Duration;

    // T-144: proves the on-disk shape `config.rs`'s `ResolverConfigFile`
    // relies on is the intentional snake_case form, not whatever serde's
    // own default happened to pick.
    #[test]
    fn timeout_mode_round_trips_through_the_expected_snake_case_json() {
        let cases = [
            (TimeoutMode::FailOpen, "\"fail_open\""),
            (TimeoutMode::FailClosed, "\"fail_closed\""),
            (TimeoutMode::Degraded, "\"degraded\""),
        ];
        for (mode, expected_json) in cases {
            let json = match serde_json::to_string(&mode) {
                Ok(json) => json,
                Err(err) => panic!("must serialize: {err}"),
            };
            assert_eq!(json, expected_json);
            let round_tripped: TimeoutMode = match serde_json::from_str(&json) {
                Ok(mode) => mode,
                Err(err) => panic!("must deserialize its own output: {err}"),
            };
            assert_eq!(round_tripped, mode);
        }
    }

    struct DelayedClient {
        delay: Duration,
        response: Message,
    }

    impl DohClient for DelayedClient {
        async fn query(&self, _url: &str, _query: &Message) -> Result<Message, UpstreamError> {
            tokio::time::sleep(self.delay).await;
            Ok(self.response.clone())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn responds_in_time_yields_responded() {
        let client = DelayedClient {
            delay: Duration::from_millis(100),
            response: Message::query(),
        };
        let outcome = query_with_timeout(
            &client,
            "https://example.invalid",
            &Message::query(),
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(outcome, VoterOutcome::Responded(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn exceeding_duration_yields_timed_out() {
        let client = DelayedClient {
            delay: Duration::from_secs(5),
            response: Message::query(),
        };
        let outcome = query_with_timeout(
            &client,
            "https://example.invalid",
            &Message::query(),
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(outcome, VoterOutcome::TimedOut));
    }
}
