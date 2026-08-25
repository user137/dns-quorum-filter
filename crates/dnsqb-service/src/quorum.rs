//! Block-signature recognition (T-23) and OR-logic quorum across the two
//! Phase-1 upstreams, with timeout-mode interpretation (T-27), early
//! return/cancellation (T-30), and diagnostic logging (T-29) — SPEC.md
//! §3.3/§3.6.

use crate::timeout::{query_with_timeout, TimeoutConfig, TimeoutMode, VoterOutcome};
use crate::upstream::{DohClient, Provider, UpstreamError, BASELINE_DOH_URL};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

fn is_null_ip(record: &Record) -> bool {
    match &record.data {
        RData::A(A(ip)) => *ip == Ipv4Addr::UNSPECIFIED,
        RData::AAAA(AAAA(ip)) => *ip == Ipv6Addr::UNSPECIFIED,
        _ => false,
    }
}

/// A single voter's contribution to the OR-decision, once any
/// baseline-dependence has been resolved (or ruled undecidable — SPEC.md
/// §3.3 addendum). Not part of the public API: [`is_blocked`] is the public
/// entry point, this is `combine`'s internal building block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    /// This voter's block signature matched.
    Blocked,
    /// This voter's block signature did not match.
    NotBlocked,
    /// Quad9 NXDOMAIN specifically — undecidable without comparing against
    /// the baseline resolver (SPEC.md §3.1).
    NeedsBaseline,
}

/// SPEC.md §3.1: per-provider block-signature match, live-verified T-20
/// (DECISIONS.md 2026-08-25) — **n=1 per provider**. `AdGuard`'s signature is
/// self-sufficient; Quad9's NXDOMAIN needs baseline comparison, which this
/// function alone can't do (see `resolve_needs_baseline`, `combine`).
fn evaluate(provider: Provider, response: &Message) -> Signal {
    match provider {
        Provider::AdGuard => {
            if response.answers.iter().any(is_null_ip) {
                Signal::Blocked
            } else {
                Signal::NotBlocked
            }
        }
        Provider::Quad9 => {
            if response.metadata.response_code == ResponseCode::NXDomain {
                Signal::NeedsBaseline
            } else {
                Signal::NotBlocked
            }
        }
    }
}

/// SPEC.md §3.1, §3.1.3.3-addendum: resolve a [`Signal::NeedsBaseline`]
/// against the baseline's own outcome. A baseline that itself didn't
/// respond makes Quad9's NXDOMAIN undecidable — SPEC.md §3.3's three modes
/// apply here exactly as they do to an ordinary voter timeout (documented
/// gap-filling, SPEC.md §3.3 addendum, not a literal spec requirement).
fn resolve_needs_baseline(baseline: &VoterOutcome, mode: TimeoutMode) -> Signal {
    match baseline {
        VoterOutcome::Responded(message) => {
            if message.metadata.response_code == ResponseCode::NoError {
                Signal::Blocked
            } else {
                Signal::NotBlocked
            }
        }
        VoterOutcome::TimedOut | VoterOutcome::Errored(_) => unresponsive_signal(mode),
    }
}

/// How a voter that never answered (timeout, or any other upstream error —
/// SPEC.md §3.3 addendum) is interpreted, per [`TimeoutMode`].
fn unresponsive_signal(mode: TimeoutMode) -> Signal {
    match mode {
        TimeoutMode::FailClosed => Signal::Blocked,
        TimeoutMode::FailOpen | TimeoutMode::Degraded => Signal::NotBlocked,
    }
}

/// The single predicate behind both `resolve`'s early-return check and
/// `combine`'s final verdict (advisor review: two separate implementations
/// of "is this voter a block" risked drifting apart — e.g. the loop
/// originally only recognized a *responded* block, never an unresponsive
/// voter that `fail-closed` also treats as blocking, silently deferring
/// that case to `combine`'s fallback instead of it being provably the same
/// rule). `outcome`/`baseline` are `Option` because during the loop a slot
/// may not have arrived yet; `None` means "not decidable yet", not "not
/// blocked" — callers must not treat it as `NotBlocked`.
fn known_signal(
    provider: Provider,
    outcome: Option<&VoterOutcome>,
    baseline: Option<&VoterOutcome>,
    mode: TimeoutMode,
) -> Option<Signal> {
    match outcome? {
        VoterOutcome::TimedOut | VoterOutcome::Errored(_) => Some(unresponsive_signal(mode)),
        VoterOutcome::Responded(message) => match evaluate(provider, message) {
            Signal::NeedsBaseline => baseline.map(|outcome| resolve_needs_baseline(outcome, mode)),
            resolved => Some(resolved),
        },
    }
}

/// SPEC.md §3.1 (T-23): public per-provider block predicate — always has a
/// concrete baseline `Message` (unlike [`resolve_needs_baseline`], which
/// also has to handle a baseline that never answered; `resolve` is the only
/// caller that needs that). Behavior unchanged from the pre-T-27 version.
#[must_use]
pub fn is_blocked(provider: Provider, response: &Message, baseline: &Message) -> bool {
    match evaluate(provider, response) {
        Signal::Blocked => true,
        Signal::NotBlocked => false,
        Signal::NeedsBaseline => baseline.metadata.response_code == ResponseCode::NoError,
    }
}

/// RFC 9460 SVCB/HTTPS (T-25): quorum applies only to A/AAAA (SPEC.md §3) —
/// every other type (MX, TXT, HTTPS/SVCB, ...) bypasses quorum and proxies
/// to a single upstream, so ECH keys carried in an HTTPS RR aren't silently
/// broken by OR-logic across providers.
#[must_use]
pub fn requires_quorum(qtype: RecordType) -> bool {
    matches!(qtype, RecordType::A | RecordType::AAAA)
}

/// The quorum's OR-logic verdict (SPEC.md §3: block if either provider
/// blocks) — or a signal that quorum doesn't apply to `query`'s type at all
/// (RFC 9460, T-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumVerdict {
    /// Neither provider's block signature matched.
    Allow,
    /// At least one provider's block signature matched.
    Block,
    /// `query`'s type isn't A/AAAA ([`requires_quorum`] returned `false`) —
    /// quorum was never consulted. The caller must proxy this query to a
    /// single upstream instead (SPEC.md §3): treating this as `Allow` would
    /// silently apply OR-logic to e.g. an HTTPS RR and break ECH.
    NotApplicable,
}

/// Combine three completed voter outcomes into a verdict (SPEC.md §3, §3.3)
/// — pure and synchronous, deliberately separate from the async/timeout
/// machinery in `resolve` so the timeout-mode policy is unit-testable
/// without any timing involved. Returns whether the verdict was computed
/// from a complete voter set — `true` (incomplete) as soon as any of the
/// three isn't [`VoterOutcome::Responded`], independent of `mode`: T-29
/// logs every timeout regardless of mode, and a future UI indicator (T-56)
/// needs the fact of incompleteness, not which mode produced it.
fn combine(
    quad9: &VoterOutcome,
    adguard: &VoterOutcome,
    baseline: &VoterOutcome,
    mode: TimeoutMode,
) -> (QuorumVerdict, bool) {
    let incomplete = !matches!(quad9, VoterOutcome::Responded(_))
        || !matches!(adguard, VoterOutcome::Responded(_))
        || !matches!(baseline, VoterOutcome::Responded(_));

    // Both outcomes are always `Some` at this call site (all three voters
    // have settled by the time `combine` runs), so `known_signal` never
    // actually returns `None` here - `unwrap_or` is just satisfying the
    // `Option` the shared-with-the-loop signature requires.
    let adguard_signal = known_signal(Provider::AdGuard, Some(adguard), Some(baseline), mode)
        .unwrap_or(Signal::NotBlocked);
    let quad9_signal = known_signal(Provider::Quad9, Some(quad9), Some(baseline), mode)
        .unwrap_or(Signal::NotBlocked);

    let blocked =
        matches!(adguard_signal, Signal::Blocked) || matches!(quad9_signal, Signal::Blocked);
    let verdict = if blocked {
        QuorumVerdict::Block
    } else {
        QuorumVerdict::Allow
    };
    (verdict, incomplete)
}

/// Which of the three concurrent queries a [`VoterOutcome`] belongs to
/// (SPEC.md §3.6, T-30) — carried alongside the outcome in `resolve`'s
/// `FuturesUnordered` loop so results can be routed back and, on early
/// return, so the still-pending slots can be identified for the
/// [`CANCELED`](VoterOutcome) diagnostic log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Quad9,
    AdGuard,
    Baseline,
}

/// Coarse, domain-name-free classification of an [`UpstreamError`] for
/// diagnostic logging (SPEC.md, Наскрізні вимоги: no domain names in
/// service logs). Deliberately does **not** log the error's own `Display` —
/// `UpstreamError::Http`'s source is a `reqwest::Error`, whose `Display`
/// includes the failed request URL, which embeds the base64url-encoded DNS
/// query (i.e. the domain name). Logging the error message itself would
/// leak exactly what this function exists to avoid.
fn error_kind(err: &UpstreamError) -> &'static str {
    match err {
        UpstreamError::Encode(_) => "encode",
        UpstreamError::Http(_) => "http",
        UpstreamError::Decode(_) => "decode",
    }
}

fn log_outcome(slot: Slot, outcome: &VoterOutcome) {
    match outcome {
        VoterOutcome::Responded(_) => {}
        VoterOutcome::TimedOut => {
            tracing::warn!(provider = ?slot, "upstream did not respond within the configured timeout");
        }
        // Encode failures are local and deterministic, not a transient
        // upstream problem - under fail-open they'd otherwise turn into a
        // silent Allow with only a log line, which is exactly the failure
        // mode Три Б (User safety) flags as worse than no filtering at all.
        // Logged louder (error!, not warn!) so it doesn't blend into
        // ordinary upstream flakiness.
        VoterOutcome::Errored(err @ UpstreamError::Encode(_)) => {
            tracing::error!(provider = ?slot, kind = error_kind(err), "outgoing query failed to encode");
        }
        VoterOutcome::Errored(err) => {
            tracing::warn!(provider = ?slot, kind = error_kind(err), "upstream query failed");
        }
    }
}

fn log_canceled(slot: Slot) {
    tracing::debug!(provider = ?slot, "upstream call canceled - decision already reached");
}

type TaggedFuture<'a> = Pin<Box<dyn Future<Output = (Slot, VoterOutcome)> + Send + 'a>>;

fn tagged_query<'a, C: DohClient + Sync>(
    slot: Slot,
    client: &'a C,
    url: &'a str,
    query: &'a Message,
    duration: std::time::Duration,
) -> TaggedFuture<'a> {
    Box::pin(async move { (slot, query_with_timeout(client, url, query, duration).await) })
}

/// SPEC.md §3, §3.3, §3.6 (T-24, T-27, T-30): OR-logic quorum across the two
/// fixed Phase-1 upstreams. Queries both providers and the baseline resolver
/// concurrently through a `FuturesUnordered` (SPEC.md §3.6) with a per-query
/// timeout (SPEC.md §3.3); returns as soon as a `Block` verdict is
/// confirmed, dropping (canceling) whichever calls haven't completed yet.
///
/// Refuses to run quorum at all when [`requires_quorum`] says `query`'s type
/// shouldn't go through it (T-25) — returns [`QuorumVerdict::NotApplicable`]
/// without making any upstream call.
///
/// Never returns an error: an unresponsive or failing voter is interpreted
/// per `config.mode` rather than propagated (SPEC.md §3.3) — see `combine`.
pub async fn resolve<C: DohClient + Sync>(
    client: &C,
    query: &Message,
    config: &TimeoutConfig,
) -> QuorumVerdict {
    let applies = query
        .queries
        .first()
        .is_some_and(|question| requires_quorum(question.query_type()));
    if !applies {
        return QuorumVerdict::NotApplicable;
    }

    let mut futures: FuturesUnordered<TaggedFuture<'_>> = FuturesUnordered::new();
    futures.push(tagged_query(
        Slot::Quad9,
        client,
        Provider::Quad9.doh_url(),
        query,
        config.duration,
    ));
    futures.push(tagged_query(
        Slot::AdGuard,
        client,
        Provider::AdGuard.doh_url(),
        query,
        config.duration,
    ));
    futures.push(tagged_query(
        Slot::Baseline,
        client,
        BASELINE_DOH_URL,
        query,
        config.duration,
    ));

    let mut quad9: Option<VoterOutcome> = None;
    let mut adguard: Option<VoterOutcome> = None;
    let mut baseline: Option<VoterOutcome> = None;

    while let Some((slot, outcome)) = futures.next().await {
        log_outcome(slot, &outcome);
        match slot {
            Slot::Quad9 => quad9 = Some(outcome),
            Slot::AdGuard => adguard = Some(outcome),
            Slot::Baseline => baseline = Some(outcome),
        }

        // Same `known_signal` predicate `combine` uses at the end - an
        // unresponsive voter under `fail-closed` is just as much an early
        // "Block" here as a responded one, not only a case `combine`
        // happens to catch once the loop runs out of voters to wait on.
        let adguard_signal = known_signal(
            Provider::AdGuard,
            adguard.as_ref(),
            baseline.as_ref(),
            config.mode,
        );
        let quad9_signal = known_signal(
            Provider::Quad9,
            quad9.as_ref(),
            baseline.as_ref(),
            config.mode,
        );

        if matches!(adguard_signal, Some(Signal::Blocked))
            || matches!(quad9_signal, Some(Signal::Blocked))
        {
            if quad9.is_none() {
                log_canceled(Slot::Quad9);
            }
            if adguard.is_none() {
                log_canceled(Slot::AdGuard);
            }
            if baseline.is_none() {
                log_canceled(Slot::Baseline);
            }
            return QuorumVerdict::Block;
        }
    }

    let quad9 = quad9.unwrap_or(VoterOutcome::TimedOut);
    let adguard = adguard.unwrap_or(VoterOutcome::TimedOut);
    let baseline = baseline.unwrap_or(VoterOutcome::TimedOut);

    let (verdict, incomplete) = combine(&quad9, &adguard, &baseline, config.mode);
    if config.mode == TimeoutMode::Degraded && incomplete {
        tracing::warn!("quorum verdict computed from an incomplete voter set (degraded mode)");
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::{combine, is_blocked, requires_quorum, resolve, Provider, QuorumVerdict};
    use crate::timeout::{TimeoutConfig, TimeoutMode, VoterOutcome};
    use crate::upstream::{DohClient, UpstreamError};
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn query_of_type(qtype: RecordType) -> Message {
        let mut question = Query::new();
        question.set_query_type(qtype);
        let mut message = Message::query();
        message.add_query(question);
        message
    }

    fn allow_message() -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NoError;
        message.answers.push(Record::from_rdata(
            Name::root(),
            60,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        message
    }

    fn nxdomain_message() -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NXDomain;
        message
    }

    fn null_ip_message() -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NoError;
        message.answers.push(Record::from_rdata(
            Name::root(),
            60,
            RData::A(A(Ipv4Addr::UNSPECIFIED)),
        ));
        message
    }

    // T-61: is_blocked() per provider (unchanged behavior).

    #[test]
    fn quad9_nxdomain_with_resolving_baseline_is_blocked() {
        assert!(is_blocked(
            Provider::Quad9,
            &nxdomain_message(),
            &allow_message()
        ));
    }

    #[test]
    fn quad9_nxdomain_matching_baseline_nxdomain_is_not_blocked() {
        assert!(!is_blocked(
            Provider::Quad9,
            &nxdomain_message(),
            &nxdomain_message()
        ));
    }

    #[test]
    fn quad9_allow_is_not_blocked() {
        assert!(!is_blocked(
            Provider::Quad9,
            &allow_message(),
            &allow_message()
        ));
    }

    #[test]
    fn adguard_null_ip_is_blocked() {
        assert!(is_blocked(
            Provider::AdGuard,
            &null_ip_message(),
            &allow_message()
        ));
    }

    #[test]
    fn adguard_real_ip_is_not_blocked() {
        assert!(!is_blocked(
            Provider::AdGuard,
            &allow_message(),
            &allow_message()
        ));
    }

    #[test]
    fn requires_quorum_limits_to_a_and_aaaa() {
        assert!(requires_quorum(RecordType::A));
        assert!(requires_quorum(RecordType::AAAA));
        assert!(!requires_quorum(RecordType::HTTPS));
        assert!(!requires_quorum(RecordType::MX));
    }

    // T-27: combine() - pure timeout-mode interpretation, no async/timing.

    #[test]
    fn combine_both_allow_is_allow_and_complete() {
        let (verdict, incomplete) = combine(
            &VoterOutcome::Responded(allow_message()),
            &VoterOutcome::Responded(allow_message()),
            &VoterOutcome::Responded(allow_message()),
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Allow));
        assert!(!incomplete);
    }

    #[test]
    fn combine_adguard_block_is_self_sufficient() {
        // Baseline itself timed out - AdGuard's null-IP signature doesn't need it.
        let (verdict, _) = combine(
            &VoterOutcome::Responded(allow_message()),
            &VoterOutcome::Responded(null_ip_message()),
            &VoterOutcome::TimedOut,
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
    }

    #[test]
    fn combine_quad9_nxdomain_with_resolving_baseline_is_block() {
        let (verdict, incomplete) = combine(
            &VoterOutcome::Responded(nxdomain_message()),
            &VoterOutcome::Responded(allow_message()),
            &VoterOutcome::Responded(allow_message()),
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
        assert!(!incomplete);
    }

    #[test]
    fn combine_quad9_nxdomain_with_baseline_timeout_under_fail_open_is_allow() {
        // Undecidable (SPEC.md §3.3 addendum) - fail-open can't confirm, so it doesn't block.
        let (verdict, incomplete) = combine(
            &VoterOutcome::Responded(nxdomain_message()),
            &VoterOutcome::Responded(allow_message()),
            &VoterOutcome::TimedOut,
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Allow));
        assert!(incomplete);
    }

    #[test]
    fn combine_quad9_nxdomain_with_baseline_timeout_under_fail_closed_is_block() {
        let (verdict, incomplete) = combine(
            &VoterOutcome::Responded(nxdomain_message()),
            &VoterOutcome::Responded(allow_message()),
            &VoterOutcome::TimedOut,
            TimeoutMode::FailClosed,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
        assert!(incomplete);
    }

    #[test]
    fn combine_adguard_timeout_under_fail_open_is_allow() {
        let (verdict, incomplete) = combine(
            &VoterOutcome::Responded(allow_message()),
            &VoterOutcome::TimedOut,
            &VoterOutcome::Responded(allow_message()),
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Allow));
        assert!(incomplete);
    }

    #[test]
    fn combine_adguard_timeout_under_fail_closed_is_block() {
        let (verdict, incomplete) = combine(
            &VoterOutcome::Responded(allow_message()),
            &VoterOutcome::TimedOut,
            &VoterOutcome::Responded(allow_message()),
            TimeoutMode::FailClosed,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
        assert!(incomplete);
    }

    #[test]
    fn combine_degraded_matches_fail_open_verdict_over_answered_voters() {
        let inputs = (
            VoterOutcome::Responded(nxdomain_message()),
            VoterOutcome::Responded(allow_message()),
            VoterOutcome::TimedOut,
        );
        let (fail_open_verdict, _) =
            combine(&inputs.0, &inputs.1, &inputs.2, TimeoutMode::FailOpen);
        let (degraded_verdict, degraded_incomplete) =
            combine(&inputs.0, &inputs.1, &inputs.2, TimeoutMode::Degraded);
        assert_eq!(fail_open_verdict, degraded_verdict);
        assert!(degraded_incomplete);
    }

    // T-62: quorum OR-logic end-to-end through resolve(), with mocked upstreams.

    #[derive(Clone)]
    enum MockResponse {
        Instant(Message),
        Pending,
    }

    struct MockDohClient {
        quad9: MockResponse,
        adguard: MockResponse,
        baseline: MockResponse,
    }

    impl DohClient for MockDohClient {
        async fn query(&self, url: &str, _query: &Message) -> Result<Message, UpstreamError> {
            let response = if url == Provider::Quad9.doh_url() {
                &self.quad9
            } else if url == Provider::AdGuard.doh_url() {
                &self.adguard
            } else {
                &self.baseline
            };
            match response {
                MockResponse::Instant(message) => Ok(message.clone()),
                MockResponse::Pending => std::future::pending().await,
            }
        }
    }

    #[tokio::test]
    async fn both_allow_yields_allow() {
        let client = MockDohClient {
            quad9: MockResponse::Instant(allow_message()),
            adguard: MockResponse::Instant(allow_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let verdict = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
        )
        .await;
        assert!(matches!(verdict, QuorumVerdict::Allow));
    }

    #[tokio::test]
    async fn one_block_yields_block() {
        let client = MockDohClient {
            quad9: MockResponse::Instant(nxdomain_message()),
            adguard: MockResponse::Instant(allow_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let verdict = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
        )
        .await;
        assert!(matches!(verdict, QuorumVerdict::Block));
    }

    #[tokio::test]
    async fn both_block_yields_block() {
        let client = MockDohClient {
            quad9: MockResponse::Instant(nxdomain_message()),
            adguard: MockResponse::Instant(null_ip_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let verdict = resolve(
            &client,
            &query_of_type(RecordType::AAAA),
            &TimeoutConfig::default(),
        )
        .await;
        assert!(matches!(verdict, QuorumVerdict::Block));
    }

    #[tokio::test]
    async fn non_a_aaaa_type_is_not_applicable_even_with_blocking_fixtures() {
        let client = MockDohClient {
            quad9: MockResponse::Instant(nxdomain_message()),
            adguard: MockResponse::Instant(null_ip_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let verdict = resolve(
            &client,
            &query_of_type(RecordType::HTTPS),
            &TimeoutConfig::default(),
        )
        .await;
        assert!(matches!(verdict, QuorumVerdict::NotApplicable));
    }

    // T-30: early return actually cancels the still-pending calls, rather
    // than just short-circuiting the *decision* while still waiting on them.
    // A response that never resolves proves resolve() doesn't need it to
    // finish - but on its own that doesn't prove cancellation happened
    // instead of resolve() just waiting out the pending voters' own
    // `tokio::time::timeout(config.duration, ...)` before falling through to
    // combine() (which would also reach Block here, just slower). Paused
    // time makes the difference observable without a real wall-clock wait:
    // `Instant::now()` under `start_paused` only advances when something
    // makes it advance, so if resolve() actually returns before the pending
    // voters' timeout would fire, elapsed stays near zero; if it silently
    // waited them out, elapsed jumps to ~`config.duration`.

    #[tokio::test(start_paused = true)]
    async fn adguard_self_sufficient_block_cancels_quad9_and_baseline() {
        let client = MockDohClient {
            quad9: MockResponse::Pending,
            adguard: MockResponse::Instant(null_ip_message()),
            baseline: MockResponse::Pending,
        };
        let config = TimeoutConfig::default();
        let started = tokio::time::Instant::now();
        let verdict = resolve(&client, &query_of_type(RecordType::A), &config).await;
        assert!(matches!(verdict, QuorumVerdict::Block));
        assert!(
            started.elapsed() < config.duration,
            "resolve() waited out the pending voters' timeout instead of canceling them"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn quad9_plus_baseline_block_cancels_adguard() {
        let client = MockDohClient {
            quad9: MockResponse::Instant(nxdomain_message()),
            adguard: MockResponse::Pending,
            baseline: MockResponse::Instant(allow_message()),
        };
        let config = TimeoutConfig::default();
        let started = tokio::time::Instant::now();
        let verdict = resolve(&client, &query_of_type(RecordType::A), &config).await;
        assert!(
            started.elapsed() < config.duration,
            "resolve() waited out the pending AdGuard voter's timeout instead of canceling it"
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
    }

    // T-27 end-to-end: a real (short) timeout propagates through resolve()
    // and is interpreted per the configured mode.

    #[tokio::test]
    async fn slow_adguard_under_fail_open_is_allow_end_to_end() {
        let client = SlowAdGuardClient;
        let config = TimeoutConfig {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_millis(5),
        };
        let verdict = resolve(&client, &query_of_type(RecordType::A), &config).await;
        assert!(matches!(verdict, QuorumVerdict::Allow));
    }

    #[tokio::test]
    async fn slow_adguard_under_fail_closed_is_block_end_to_end() {
        let client = SlowAdGuardClient;
        let config = TimeoutConfig {
            mode: TimeoutMode::FailClosed,
            duration: Duration::from_millis(5),
        };
        let verdict = resolve(&client, &query_of_type(RecordType::A), &config).await;
        assert!(matches!(verdict, QuorumVerdict::Block));
    }

    struct SlowAdGuardClient;

    impl DohClient for SlowAdGuardClient {
        async fn query(&self, url: &str, _query: &Message) -> Result<Message, UpstreamError> {
            if url == Provider::AdGuard.doh_url() {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Ok(allow_message())
        }
    }

    // Advisor-review regression: an *unresponsive* voter (not just a
    // responded block signature) is itself a block signal under
    // fail-closed - the early-return loop has to recognize that via the
    // same `known_signal` predicate `combine` uses, not just rely on
    // `combine`'s fallback to get the verdict right eventually.
    struct AdGuardErrorsClient;

    impl DohClient for AdGuardErrorsClient {
        fn query(
            &self,
            url: &str,
            _query: &Message,
        ) -> impl std::future::Future<Output = Result<Message, UpstreamError>> {
            let result = if url == Provider::AdGuard.doh_url() {
                Err(UpstreamError::Decode(
                    "mock decode failure".to_string().into(),
                ))
            } else {
                Ok(allow_message())
            };
            std::future::ready(result)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn adguard_error_under_fail_closed_is_block_via_early_return() {
        let client = AdGuardErrorsClient;
        let config = TimeoutConfig {
            mode: TimeoutMode::FailClosed,
            duration: Duration::from_secs(2),
        };
        let started = tokio::time::Instant::now();
        let verdict = resolve(&client, &query_of_type(RecordType::A), &config).await;
        assert!(matches!(verdict, QuorumVerdict::Block));
        // AdGuard's error resolves instantly (no timeout involved) - Quad9
        // and baseline both answer NoError immediately too, so if the loop
        // recognizes the unresponsive-under-fail-closed signal itself
        // (rather than only via combine's post-loop fallback), this returns
        // effectively instantly either way. The real point of this test is
        // the verdict, not the timing - kept for symmetry with the other
        // T-30 tests.
        assert!(started.elapsed() < config.duration);
    }
}
