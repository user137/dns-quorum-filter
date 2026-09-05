//! Block-signature recognition (T-23) and OR-logic quorum across a
//! runtime-configured voter set (T-72/T-73 generalized the fixed 2-provider
//! model), with timeout-mode interpretation (T-27), early return/cancellation
//! (T-30), and diagnostic logging (T-29) — SPEC.md §3.3/§3.6.
//!
//! [`resolve`] is called with the **active** voter slice (`&[ProviderSpec]`) —
//! the caller (`pipeline::handle_query`) filters out disabled providers and
//! handles the empty-set pass-through (SPEC.md §3/§8.1) itself. Each voter's
//! block shape is read per its [`crate::upstream::BlockSignature`], not a
//! per-provider `match`.

use crate::timeout::{query_with_timeout, TimeoutConfig, TimeoutMode, VoterOutcome};
use crate::upstream::{
    sinkhole_nets_for, BlockSignature, DohClient, ProviderEntry, SinkholeNet, UpstreamError,
};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

/// SPEC.md §6 `voters` column, per-voter value — five variants, matching
/// SPEC.md §6's own list exactly (`Pending` in the Tauri DTO's `VoterStatus`
/// is a live-update-only transit state, per `diagrams/ui-dto-model.md`'s
/// resolved source discrepancy — it can never appear in an already-completed
/// backend `LogEntry`, so this internal type omits it, not just the DTO's
/// naming choice of `Timeout` over `TIMEOUT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoterVerdict {
    /// This voter's block signature matched.
    Block,
    /// This voter did not block.
    Allow,
    /// This voter did not respond within the configured timeout.
    Timeout,
    /// This voter's query failed (transport/decode error).
    Error,
    /// Not waited on — the decision was already reached before this voter
    /// settled (SPEC.md §3.6 early return), **or** it did respond but its
    /// signal needed baseline and baseline itself got canceled first
    /// (`voter_record`'s own doc comment) — either way, the system never
    /// reached a final classification for this voter.
    Canceled,
    /// This provider was never queried at all — the user administratively
    /// disabled it (T-148 — a disabled `ProviderEntry`). Deliberately distinct from
    /// `Canceled` (which was at least *eligible* to be asked) and `Timeout`
    /// (which was asked and never answered) — collapsing "disabled" into
    /// either of those would make a disabled provider indistinguishable in
    /// the log from a real upstream problem, and would be actively unsafe if
    /// collapsed into `Timeout` specifically (see [`resolve`]'s own doc
    /// comment on why a disabled voter must never be treated as timed out).
    Disabled,
}

/// One provider's contribution to a completed query, for the log's `voters`
/// column (T-147: moved here from `query_log.rs` — which providers cast a
/// vote and what their outcome means is quorum's own domain, not the log's;
/// `query_log.rs` just records it).
///
/// Deliberately carries the voter's `provider_id` string, not the baseline —
/// SPEC.md §3.1 only calls the filtering upstreams "voters"; baseline exists
/// to break an `NxdomainVsBaseline` tie and to source real answer data, it
/// never casts an OR-logic block/allow vote itself. Excluding it from
/// `voters` is a SPEC-silent choice made here, not a documented requirement —
/// flagged per this project's own rule for filling such gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterRecord {
    /// The active voter's lowercase `id` (`ProviderSpec::id`) — the value the
    /// `GET /admin/log?voter=` facet matches against.
    pub provider_id: String,
    /// That provider's outcome.
    pub verdict: VoterVerdict,
    /// Number of A/AAAA records in this voter's response (T-54, DTO
    /// `admin::VoterVerdictView::Allow { ip_count }`) — set only when
    /// `verdict == VoterVerdict::Allow`, `None` for every other verdict
    /// (there's no response, or no *usable* one, to count).
    pub allow_ip_count: Option<u32>,
    /// Coarse error-kind label (`error_kind()`) — set only when
    /// `verdict == VoterVerdict::Error` (T-54, DTO `admin::VoterVerdictView::
    /// Error { message }`). Deliberately never the raw `UpstreamError::Http`
    /// `Display` text: that embeds the outgoing request URL, which embeds
    /// the queried domain as base64url (this crate's own gotcha notes flag
    /// exactly this leak class for `reqwest::Error`) — `error_kind()` exists
    /// specifically to give a safe, coarse substitute. `None` for every
    /// other verdict.
    pub error_message: Option<&'static str>,
}

fn is_null_ip(record: &Record) -> bool {
    match &record.data {
        RData::A(A(ip)) => *ip == Ipv4Addr::UNSPECIFIED,
        RData::AAAA(AAAA(ip)) => *ip == Ipv6Addr::UNSPECIFIED,
        _ => false,
    }
}

/// Whether `record` is an A record inside one of `nets` — a provider-specific
/// sinkhole / block-page address (T-175). Same `RData::A` read shape as
/// [`is_null_ip`]; AAAA is not covered (no observed provider sinkholes an
/// AAAA answer, and the prefixes are IPv4).
fn is_sinkhole_ip(record: &Record, nets: &[SinkholeNet]) -> bool {
    let RData::A(A(ip)) = &record.data else {
        return false;
    };
    nets.iter().any(|net| net.contains(*ip))
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
    /// A bare `NXDOMAIN` — undecidable without comparing against the baseline
    /// resolver (SPEC.md §3.1). Produced by an [`BlockSignature::
    /// NxdomainVsBaseline`] voter, and by a [`BlockSignature::NullIpOrNxdomain`]
    /// voter that returned `NXDOMAIN` rather than a null IP.
    NeedsBaseline,
}

/// SPEC.md §3.1: block-signature match for one voter, per its
/// [`BlockSignature`]. Only `quad9`/`adguard` were live-verified (DECISIONS.md
/// 2026-08-25, n=1); the other presets' `BlockSignature` values are
/// doc-derived and carry `#[ignore]`d live-verify tests. A `NullIp` signature
/// is self-sufficient; an `NxdomainVsBaseline` one needs baseline comparison,
/// which this function alone can't do (see `resolve_needs_baseline`, `combine`).
///
/// `sinkhole_nets` (T-175, [`sinkhole_nets_for`]) composes with **every**
/// signature: a provider-specific sinkhole/block-page IP in the answer is a
/// substituted response, but — unlike `0.0.0.0` — indistinguishable from a
/// genuine resolution without the baseline (the domain *could* legitimately
/// live at that address), so it yields [`Signal::NeedsBaseline`], the same
/// baseline guard a bare `NXDOMAIN` gets. `0.0.0.0` still wins if somehow both
/// are present: it is an unconditional block that needs no baseline. `&[]`
/// (custom provider, or a preset with no known sinkhole) ⇒ old behaviour
/// exactly.
fn evaluate(
    signature: BlockSignature,
    response: &Message,
    sinkhole_nets: &[SinkholeNet],
) -> Signal {
    let has_null_ip = response.answers.iter().any(is_null_ip);
    if !has_null_ip
        && response
            .answers
            .iter()
            .any(|record| is_sinkhole_ip(record, sinkhole_nets))
    {
        return Signal::NeedsBaseline;
    }
    let is_nxdomain = response.metadata.response_code == ResponseCode::NXDomain;
    match signature {
        BlockSignature::NullIp => {
            if has_null_ip {
                Signal::Blocked
            } else {
                Signal::NotBlocked
            }
        }
        BlockSignature::NxdomainVsBaseline => {
            if is_nxdomain {
                Signal::NeedsBaseline
            } else {
                Signal::NotBlocked
            }
        }
        BlockSignature::NullIpOrNxdomain => {
            if has_null_ip {
                Signal::Blocked
            } else if is_nxdomain {
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
    signature: BlockSignature,
    sinkhole_nets: &[SinkholeNet],
    outcome: Option<&VoterOutcome>,
    baseline: Option<&VoterOutcome>,
    mode: TimeoutMode,
) -> Option<Signal> {
    match outcome? {
        VoterOutcome::TimedOut | VoterOutcome::Errored(_) => Some(unresponsive_signal(mode)),
        VoterOutcome::Responded(message) => match evaluate(signature, message, sinkhole_nets) {
            Signal::NeedsBaseline => baseline.map(|outcome| resolve_needs_baseline(outcome, mode)),
            resolved => Some(resolved),
        },
    }
}

/// One provider's [`VoterRecord`] for the query log (T-147). `outcome` is
/// `Option` for the same reason `known_signal`'s is: at an early return, a
/// slot that hadn't arrived yet is `None`, not a stand-in `TimedOut`.
///
/// Reuses `known_signal` for the `Responded` case rather than a parallel
/// classification — same "one predicate, no drift" discipline `known_signal`
/// itself documents. `known_signal` can return `None` here in exactly one
/// *runtime* case: `outcome` is `Responded` with a signal that needed
/// baseline ([`Signal::NeedsBaseline`]), and `baseline` is itself `None` —
/// i.e. this voter's own HTTP round-trip completed, but baseline got
/// canceled by the same early return before the classification could
/// finish. The system never reached a final Block/Allow verdict for that
/// response, so this counts it as `Canceled` too, not a guess.
///
/// `Some(Signal::NeedsBaseline)` itself can never actually come back from
/// `known_signal` (its own body always resolves that case down to
/// `Some(Blocked)`/`Some(NotBlocked)`/`None` before returning) — but
/// `known_signal`'s declared return type is the shared, 3-variant `Signal`,
/// so the match below still has to name that arm for the compiler's
/// exhaustiveness check to pass. Folded into the same `Canceled` case as
/// `None` rather than `unreachable!()` (forbidden in this crate, rust.md
/// "Panic-Free Production Code") — if `known_signal` ever changed shape and
/// this arm became reachable, `Canceled` is still the correct answer for
/// "never reached a final classification".
///
/// `enabled` is checked *first*, before any outcome-based logic (T-148) — a
/// disabled provider's `outcome` is always `None` for the same reason a
/// not-yet-arrived one is, but the two must never collapse into the same
/// verdict: `Disabled` is administrative, `Canceled` means the provider was
/// at least eligible to be asked.
/// Number of A/AAAA answer records in `message` — the `VoterRecord::
/// allow_ip_count` payload for an `Allow` verdict (T-54). Saturates at
/// `u32::MAX` rather than panicking on an implausible answer count.
fn count_ip_answers(message: &Message) -> u32 {
    let count = message
        .answers
        .iter()
        .filter(|record| matches!(record.data, RData::A(_) | RData::AAAA(_)))
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// One configured voter's [`VoterRecord`] (T-147/T-148/T-72). A disabled
/// entry yields [`VoterVerdict::Disabled`] before any outcome logic — never
/// coerced into `Timeout` (safety-critical under fail-closed, see [`resolve`]);
/// `outcome` is `None` for an enabled voter whose call hadn't settled at an
/// early return (`Canceled`).
fn voter_record(
    entry: &ProviderEntry,
    outcome: Option<&VoterOutcome>,
    baseline: Option<&VoterOutcome>,
    mode: TimeoutMode,
) -> VoterRecord {
    if !entry.enabled {
        return VoterRecord {
            provider_id: entry.spec.id.clone(),
            verdict: VoterVerdict::Disabled,
            allow_ip_count: None,
            error_message: None,
        };
    }
    let (verdict, allow_ip_count, error_message) = match outcome {
        None => (VoterVerdict::Canceled, None, None),
        Some(VoterOutcome::TimedOut) => (VoterVerdict::Timeout, None, None),
        Some(VoterOutcome::Errored(err)) => (VoterVerdict::Error, None, Some(error_kind(err))),
        Some(VoterOutcome::Responded(message)) => {
            match known_signal(
                entry.spec.block_signature,
                sinkhole_nets_for(&entry.spec.id),
                outcome,
                baseline,
                mode,
            ) {
                Some(Signal::Blocked) => (VoterVerdict::Block, None, None),
                Some(Signal::NotBlocked) => {
                    (VoterVerdict::Allow, Some(count_ip_answers(message)), None)
                }
                None | Some(Signal::NeedsBaseline) => (VoterVerdict::Canceled, None, None),
            }
        }
    };
    VoterRecord {
        provider_id: entry.spec.id.clone(),
        verdict,
        allow_ip_count,
        error_message,
    }
}

/// A [`VoterRecord`] per configured voter (T-147/T-148/T-72) — never
/// baseline, see [`VoterRecord`]'s own doc comment. One entry per element of
/// `entries`, same order; `outcomes` is index-aligned with `entries` (a
/// disabled entry's slot is always `None`, and so is an enabled one whose
/// call never settled — `voter_record` tells them apart via `entry.enabled`).
fn voter_records(
    entries: &[ProviderEntry],
    outcomes: &[Option<VoterOutcome>],
    baseline: Option<&VoterOutcome>,
    mode: TimeoutMode,
) -> Vec<VoterRecord> {
    entries
        .iter()
        .zip(outcomes)
        .map(|(entry, outcome)| voter_record(entry, outcome.as_ref(), baseline, mode))
        .collect()
}

/// SPEC.md §3.1 (T-23): public block predicate for one response against a
/// given [`BlockSignature`] — always has a concrete baseline `Message`
/// (unlike [`resolve_needs_baseline`], which also has to handle a baseline
/// that never answered; `resolve` is the only caller that needs that).
///
/// `sinkhole_nets` (T-175) is this voter's [`sinkhole_nets_for`] slice — `&[]`
/// for any provider without a known sinkhole, which reproduces the pre-T-175
/// behaviour exactly.
#[must_use]
pub fn is_blocked(
    signature: BlockSignature,
    response: &Message,
    baseline: &Message,
    sinkhole_nets: &[SinkholeNet],
) -> bool {
    match evaluate(signature, response, sinkhole_nets) {
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

/// [`resolve`]'s full result (T-39): the verdict plus, when it's `Allow`, the
/// actual upstream data a caller needs to answer the client (SPEC.md §5 step
/// 5 bundles "get ALLOW + IP" as one action — a bare [`QuorumVerdict`] can't
/// carry the IP half).
#[derive(Debug, Clone)]
pub struct QuorumOutcome {
    /// The OR-logic verdict.
    pub verdict: QuorumVerdict,
    /// A representative real answer, present only when `verdict ==
    /// QuorumVerdict::Allow` — see [`representative_allow_answer`]. `None`
    /// under `Allow` means no voter had a usable answer (deeply degraded
    /// fail-open case); a `Block` or `NotApplicable` verdict never carries
    /// upstream data (a block response is always synthesized, never sourced
    /// from an upstream `Message` — same principle as
    /// `wire::build_block_response`).
    ///
    /// **Carries the query domain and its records** (SPEC.md, Наскрізні
    /// вимоги: no domain names in service logs) — never pass `QuorumOutcome`
    /// or this field to `tracing`/`{:?}` in a diagnostic-log context, same
    /// discipline as `UpstreamError`'s `error_kind()` (T-29) and
    /// `overrides::InvalidReason` (T-37).
    pub answer: Option<Message>,
    /// One entry per **configured** voter (T-147/T-72), in the configured
    /// order — `vec![]` under [`QuorumVerdict::NotApplicable`] (never
    /// queried), otherwise one `VoterRecord` per element of the `voters`
    /// slice `resolve` was called with, regardless of verdict.
    /// [`VoterVerdict::Disabled`] means that provider was administratively
    /// turned off, not queried at all this round.
    pub voters: Vec<VoterRecord>,
    /// Every *enabled* voter failed to give an answer this round (timeout or
    /// error — never `Responded`), so `verdict` rests entirely on the
    /// baseline / timeout-mode policy, not on any filter (T-155). `false`
    /// when at least one enabled voter answered, and `false` when there are
    /// no enabled voters at all (that is the caller's own pass-through
    /// branch, `pipeline::handle_query`, not this case). Computed from the
    /// raw [`VoterOutcome`]s before they are projected to [`VoterRecord`]s —
    /// `VoterRecord::verdict` alone is lossy (`Canceled` folds several
    /// causes together). Mirrors how `incomplete` is derived in `combine`,
    /// but is a stricter question: `incomplete` fires on a single
    /// unresponsive voter, this needs *all* of them. Can be `true`
    /// alongside a `Block` verdict — under `fail_closed` an unresponsive
    /// voter *is* a block (`unresponsive_signal`), so the early-return path
    /// can reach `Block` with no voter having answered.
    pub filters_unreachable: bool,
    /// The baseline resolver's own usable answer this round ([`is_usable_answer`]
    /// — `NoError`/`NXDomain`, not `SERVFAIL`), independent of `verdict`.
    /// `None` on timeout, transport error, `SERVFAIL`, or
    /// [`QuorumVerdict::NotApplicable`]. Two consumers: T-154's
    /// `baseline_selector` reads presence as `BaselineHealth`, and a T-155
    /// `filters_unreachable` caller under `toggle ON` serves this message
    /// directly even when `verdict` came back `Block` (fail-closed).
    pub baseline_answer: Option<Message>,
}

/// A `Responded` voter's message actually represents a resolved DNS answer
/// (`NoError` or a genuine `NXDomain`) — not merely that the HTTP round-trip
/// succeeded. A baseline `SERVFAIL`/`REFUSED` is still HTTP 200 with an rcode
/// set, so it decodes as `Responded` too; without this check
/// [`representative_allow_answer`] would hand a failed resolution back to
/// the caller as if it were real data. Advisor review, not a test, caught
/// this — the fixtures didn't happen to exercise a non-`NoError`/`NXDomain`
/// `Responded` message.
fn is_usable_answer(message: &Message) -> bool {
    matches!(
        message.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    )
}

/// SPEC.md §5 step 5 (T-39/T-72): which voter's `Message` a caller should
/// treat as the real answer when the verdict is `Allow`. Preference order:
/// baseline (canonical, unfiltered) → the first enabled voter, in configured
/// order, whose signal is definitively [`Signal::NotBlocked`] and whose
/// answer is [`is_usable_answer`].
///
/// A voter whose signal is [`Signal::NeedsBaseline`] (a bare `NXDOMAIN` from
/// an `NxdomainVsBaseline`/`NullIpOrNxdomain` signature, not yet confirmed
/// against baseline) is deliberately **not** a candidate — treating an
/// unconfirmed `NXDOMAIN` as trustworthy real data whenever baseline itself
/// didn't respond would silently cache a possibly-blocked domain as
/// genuinely nonexistent. `matches!(.., Signal::NotBlocked)` already excludes
/// it (the same guard the pre-T-72 Quad9-specific code used, now uniform).
///
/// `outcomes` is index-aligned with `entries`; a `None` slot (disabled, or a
/// call that never settled) is simply skipped — the order still falls
/// through to whichever remaining candidate has real data.
fn representative_allow_answer(
    entries: &[ProviderEntry],
    outcomes: &[Option<VoterOutcome>],
    baseline: &VoterOutcome,
) -> Option<Message> {
    if let VoterOutcome::Responded(message) = baseline {
        if is_usable_answer(message) {
            return Some(message.clone());
        }
    }
    for (entry, outcome) in entries.iter().zip(outcomes) {
        if !entry.enabled {
            continue;
        }
        if let Some(VoterOutcome::Responded(message)) = outcome {
            if matches!(
                evaluate(
                    entry.spec.block_signature,
                    message,
                    sinkhole_nets_for(&entry.spec.id),
                ),
                Signal::NotBlocked
            ) && is_usable_answer(message)
            {
                return Some(message.clone());
            }
        }
    }
    None
}

/// Combine three completed voter outcomes into a verdict (SPEC.md §3, §3.3)
/// — pure and synchronous, deliberately separate from the async/timeout
/// machinery in `resolve` so the timeout-mode policy is unit-testable
/// without any timing involved. Returns whether the verdict was computed
/// from a complete voter set — `true` (incomplete) as soon as any *enabled*
/// voter isn't [`VoterOutcome::Responded`], independent of `mode`: T-29
/// logs every timeout regardless of mode, and a future UI indicator (T-56)
/// needs the fact of incompleteness, not which mode produced it.
///
/// `outcomes` is index-aligned with `entries`. A disabled entry's slot is
/// `None` and contributes nothing — neither to `incomplete` (turning a
/// provider off on purpose isn't a degraded state) nor to the block fold
/// (`known_signal`'s `outcome?` early return yields `None`, treated as
/// `NotBlocked`). **`incomplete` keeps its weaker `Responded`-means-complete
/// semantics** — it does not fire on a `SERVFAIL` `Responded` voter (see the
/// `should_serve_stale` note in `CLAUDE.md`, which depends on this).
fn combine(
    entries: &[ProviderEntry],
    outcomes: &[Option<VoterOutcome>],
    baseline: &VoterOutcome,
    mode: TimeoutMode,
) -> (QuorumVerdict, bool) {
    let mut incomplete = !matches!(baseline, VoterOutcome::Responded(_));
    let mut blocked = false;
    for (entry, outcome) in entries.iter().zip(outcomes) {
        if !entry.enabled {
            continue;
        }
        if outcome
            .as_ref()
            .is_some_and(|o| !matches!(o, VoterOutcome::Responded(_)))
        {
            incomplete = true;
        }
        if matches!(
            known_signal(
                entry.spec.block_signature,
                sinkhole_nets_for(&entry.spec.id),
                outcome.as_ref(),
                Some(baseline),
                mode
            ),
            Some(Signal::Blocked)
        ) {
            blocked = true;
        }
    }
    let verdict = if blocked {
        QuorumVerdict::Block
    } else {
        QuorumVerdict::Allow
    };
    (verdict, incomplete)
}

/// Which concurrent query a [`VoterOutcome`] belongs to (SPEC.md §3.6, T-30) —
/// a voter's index into `resolve`'s `entries` slice, or the baseline.
/// Carried alongside the outcome in the `FuturesUnordered` loop so results
/// route back and still-pending slots can be named in the `CANCELED`
/// diagnostic log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Voter(usize),
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

/// `label` is a coarse, domain-name-free tag — a provider `id` or
/// `"baseline"` (SPEC.md, Наскрізні вимоги: no domain names in service logs;
/// a provider id is this service's own config, not user browsing data).
fn log_outcome(label: &str, outcome: &VoterOutcome) {
    match outcome {
        VoterOutcome::Responded(_) => {}
        VoterOutcome::TimedOut => {
            tracing::warn!(
                provider = label,
                "upstream did not respond within the configured timeout"
            );
        }
        // Encode failures are local and deterministic, not a transient
        // upstream problem - under fail-open they'd otherwise turn into a
        // silent Allow with only a log line, which is exactly the failure
        // mode Три Б (User safety) flags as worse than no filtering at all.
        // Logged louder (error!, not warn!) so it doesn't blend into
        // ordinary upstream flakiness.
        VoterOutcome::Errored(err @ UpstreamError::Encode(_)) => {
            tracing::error!(
                provider = label,
                kind = error_kind(err),
                "outgoing query failed to encode"
            );
        }
        VoterOutcome::Errored(err) => {
            tracing::warn!(
                provider = label,
                kind = error_kind(err),
                "upstream query failed"
            );
        }
    }
}

fn log_canceled(label: &str) {
    tracing::debug!(
        provider = label,
        "upstream call canceled - decision already reached"
    );
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

/// SPEC.md §3, §3.3, §3.6 (T-24, T-27, T-30, T-72): OR-logic quorum across the
/// enabled entries of `voters`, plus the baseline resolver — concurrently
/// through a `FuturesUnordered` (SPEC.md §3.6) with a per-query timeout
/// (SPEC.md §3.3); returns as soon as a `Block` verdict is confirmed,
/// dropping (canceling) whichever calls haven't completed yet.
///
/// Baseline is **always** queried regardless of which voters are enabled —
/// still needed to resolve an `NxdomainVsBaseline` voter's signal, and still
/// the preferred source of real answer data on `Allow`. Callers must not
/// call this with `ProviderEntry::any_enabled(voters) == false` — SPEC.md
/// §3/§8.1's pass-through case is handled entirely by the caller
/// (`pipeline::handle_query`), not here. **Documented, not type-enforced**:
/// an all-disabled `voters` slice still returns a well-formed `QuorumOutcome`
/// (`Allow` from baseline, every `voters` entry `Disabled`), indistinguishable
/// from a legitimate filtered `Allow` to a caller not inspecting individual
/// verdicts; the one shipped caller gates this out first.
///
/// A disabled entry's outcome is never coerced into
/// [`VoterOutcome::TimedOut`] — doing so would make `fail_closed` mode treat
/// "administratively disabled" the same as "timed out" and silently BLOCK
/// every query the moment a provider is turned off, worse than no filtering
/// at all (Три Б, user safety). Disabled entries stay `None` all the way
/// through to `combine`/`voter_records`.
///
/// Refuses to run quorum at all when [`requires_quorum`] says `query`'s type
/// shouldn't go through it (T-25) — returns [`QuorumVerdict::NotApplicable`]
/// (with `answer: None`) without making any upstream call.
///
/// Never returns an error: an unresponsive or failing voter is interpreted
/// per `config.mode` rather than propagated (SPEC.md §3.3) — see `combine`.
///
/// `baseline_url` is resolved by the caller *before* the fan-out (T-154 —
/// `baseline_selector::BaselineSelector::current`), not hardcoded here: it
/// goes into the same `FuturesUnordered` as the voters, so the choice has to
/// be made up front. Pass `baseline_selector::BASELINE_CHAIN[0]` for the
/// unchanged default.
pub async fn resolve<C: DohClient + Sync>(
    client: &C,
    query: &Message,
    config: &TimeoutConfig,
    voters: &[ProviderEntry],
    baseline_url: &str,
) -> QuorumOutcome {
    let applies = query
        .queries
        .first()
        .is_some_and(|question| requires_quorum(question.query_type()));
    if !applies {
        return QuorumOutcome {
            verdict: QuorumVerdict::NotApplicable,
            answer: None,
            voters: Vec::new(),
            filters_unreachable: false,
            baseline_answer: None,
        };
    }

    let mut futures: FuturesUnordered<TaggedFuture<'_>> = FuturesUnordered::new();
    for (index, entry) in voters.iter().enumerate() {
        if entry.enabled {
            futures.push(tagged_query(
                Slot::Voter(index),
                client,
                &entry.spec.doh_url,
                query,
                config.duration,
            ));
        }
    }
    futures.push(tagged_query(
        Slot::Baseline,
        client,
        baseline_url,
        query,
        config.duration,
    ));

    // `VoterOutcome` is not `Clone` (its `Errored` arm holds a
    // `reqwest::Error`), so `vec![None; n]` won't do.
    let mut outcomes: Vec<Option<VoterOutcome>> = (0..voters.len()).map(|_| None).collect();
    let mut baseline: Option<VoterOutcome> = None;

    while let Some((slot, outcome)) = futures.next().await {
        let label = match slot {
            Slot::Voter(index) => voters[index].spec.id.as_str(),
            Slot::Baseline => "baseline",
        };
        log_outcome(label, &outcome);
        match slot {
            Slot::Voter(index) => outcomes[index] = Some(outcome),
            Slot::Baseline => baseline = Some(outcome),
        }

        // Same `known_signal` predicate `combine` uses at the end - an
        // unresponsive voter under `fail-closed` is just as much an early
        // "Block" here as a responded one. A disabled entry's slot stays
        // `None` (no future was ever pushed), so `known_signal` sees `None`
        // and contributes no signal, no extra check needed.
        let early_block = voters.iter().enumerate().any(|(index, entry)| {
            entry.enabled
                && matches!(
                    known_signal(
                        entry.spec.block_signature,
                        sinkhole_nets_for(&entry.spec.id),
                        outcomes[index].as_ref(),
                        baseline.as_ref(),
                        config.mode,
                    ),
                    Some(Signal::Blocked)
                )
        });

        if early_block {
            for (index, entry) in voters.iter().enumerate() {
                if entry.enabled && outcomes[index].is_none() {
                    log_canceled(&entry.spec.id);
                }
            }
            if baseline.is_none() {
                log_canceled("baseline");
            }
            return QuorumOutcome {
                verdict: QuorumVerdict::Block,
                answer: None,
                voters: voter_records(voters, &outcomes, baseline.as_ref(), config.mode),
                filters_unreachable: all_enabled_voters_unreachable(voters, &outcomes),
                baseline_answer: baseline_usable_answer(baseline.as_ref()),
            };
        }
    }

    finalize_outcome(voters, outcomes, baseline, config)
}

/// `true` when there is at least one enabled voter and *none* of them
/// produced a [`VoterOutcome::Responded`] this round — the T-155
/// "both filters unreachable" condition. Works on either the pre-projection
/// `outcomes` (unsettled enabled voter = `None`) or the coerced one
/// (unsettled = `Some(TimedOut)`): neither is `Responded`, so both read the
/// same. An all-disabled slice returns `false` — that is the caller's own
/// pass-through branch, not this one.
fn all_enabled_voters_unreachable(
    voters: &[ProviderEntry],
    outcomes: &[Option<VoterOutcome>],
) -> bool {
    let mut any_enabled = false;
    for (entry, outcome) in voters.iter().zip(outcomes) {
        if !entry.enabled {
            continue;
        }
        any_enabled = true;
        if matches!(outcome, Some(VoterOutcome::Responded(_))) {
            return false;
        }
    }
    any_enabled
}

/// The baseline slot's own usable answer ([`is_usable_answer`]), cloned —
/// `None` for a missing/timed-out/errored slot or a `SERVFAIL` response.
fn baseline_usable_answer(baseline: Option<&VoterOutcome>) -> Option<Message> {
    match baseline {
        Some(VoterOutcome::Responded(message)) if is_usable_answer(message) => {
            Some(message.clone())
        }
        _ => None,
    }
}

/// Builds the final [`QuorumOutcome`] once `resolve`'s loop has run to
/// completion without an early Block return — pulled out purely to keep
/// `resolve` itself under `clippy::too_many_lines`. A disabled entry's
/// outcome stays `None` here (never coerced into [`VoterOutcome::TimedOut`]) —
/// see `resolve`'s own doc comment for why that is safety-critical under
/// fail-closed.
fn finalize_outcome(
    voters: &[ProviderEntry],
    outcomes: Vec<Option<VoterOutcome>>,
    baseline: Option<VoterOutcome>,
    config: &TimeoutConfig,
) -> QuorumOutcome {
    let outcomes: Vec<Option<VoterOutcome>> = voters
        .iter()
        .zip(outcomes)
        .map(|(entry, outcome)| {
            entry
                .enabled
                .then(|| outcome.unwrap_or(VoterOutcome::TimedOut))
        })
        .collect();
    let baseline = baseline.unwrap_or(VoterOutcome::TimedOut);

    let (verdict, incomplete) = combine(voters, &outcomes, &baseline, config.mode);
    if config.mode == TimeoutMode::Degraded && incomplete {
        tracing::warn!("quorum verdict computed from an incomplete voter set (degraded mode)");
    }
    let answer = if verdict == QuorumVerdict::Allow {
        representative_allow_answer(voters, &outcomes, &baseline)
    } else {
        None
    };
    let voter_records = voter_records(voters, &outcomes, Some(&baseline), config.mode);
    QuorumOutcome {
        verdict,
        answer,
        voters: voter_records,
        filters_unreachable: all_enabled_voters_unreachable(voters, &outcomes),
        baseline_answer: baseline_usable_answer(Some(&baseline)),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_blocked, requires_quorum, resolve, QuorumVerdict, VoterRecord, VoterVerdict};
    use crate::timeout::{TimeoutConfig, TimeoutMode, VoterOutcome};
    use crate::upstream::{
        builtin_preset, BlockSignature, DohClient, ProviderEntry, SinkholeNet, UpstreamError,
    };

    const QUAD9_URL: &str = "https://dns.quad9.net/dns-query";
    const ADGUARD_URL: &str = "https://dns.adguard-dns.com/dns-query";
    const BASELINE_URL: &str = crate::baseline_selector::BASELINE_CHAIN[0];

    /// One built-in-preset voter entry with the given `enabled` flag.
    fn preset_entry(id: &str, enabled: bool) -> ProviderEntry {
        let Some(spec) = builtin_preset(id) else {
            panic!("{id} is a builtin preset");
        };
        ProviderEntry { spec, enabled }
    }

    /// Both Phase-1 voters enabled — the old `EnabledProviders::default()`.
    /// A fixed `quad9` + `adguard` pair for these `resolve` mechanics tests,
    /// deliberately independent of the shipped `DEFAULT_PROVIDER_IDS` (T-170
    /// widened that to three); `MockDohClient` only mocks these two.
    fn default_voters() -> Vec<ProviderEntry> {
        voters(true, true)
    }

    /// Named built-in presets with per-voter `enabled` flags — the old
    /// `EnabledProviders { quad9, adguard }`.
    fn voters(quad9: bool, adguard: bool) -> Vec<ProviderEntry> {
        vec![
            preset_entry("quad9", quad9),
            preset_entry("adguard", adguard),
        ]
    }

    /// Bridge to the pre-T-72 two-voter `combine` shape. `None` for a voter
    /// slot means "disabled" (the old semantics).
    fn combine2(
        quad9: Option<VoterOutcome>,
        adguard: Option<VoterOutcome>,
        baseline: &VoterOutcome,
        mode: TimeoutMode,
    ) -> (QuorumVerdict, bool) {
        let entries = [
            preset_entry("quad9", quad9.is_some()),
            preset_entry("adguard", adguard.is_some()),
        ];
        let outcomes = [quad9, adguard];
        super::combine(&entries, &outcomes, baseline, mode)
    }

    /// Bridge to the pre-T-72 `voter_record(Provider, enabled, ...)` shape.
    fn voter_record2(
        id: &str,
        enabled: bool,
        outcome: Option<&VoterOutcome>,
        baseline: Option<&VoterOutcome>,
        mode: TimeoutMode,
    ) -> VoterRecord {
        super::voter_record(&preset_entry(id, enabled), outcome, baseline, mode)
    }
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
        allow_message_with_ip(Ipv4Addr::new(93, 184, 216, 34))
    }

    fn allow_message_with_ip(ip: Ipv4Addr) -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NoError;
        message
            .answers
            .push(Record::from_rdata(Name::root(), 60, RData::A(A(ip))));
        message
    }

    fn nxdomain_message() -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::NXDomain;
        message
    }

    fn servfail_message() -> Message {
        let mut message = Message::query();
        message.metadata.response_code = ResponseCode::ServFail;
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

    // T-54: VoterRecord's allow_ip_count/error_message payloads - these feed
    // admin::VoterVerdictView::Allow{ip_count}/Error{message} directly on
    // the wire, so a wrong count/label here is a wrong DTO value, not just
    // an internal detail.

    #[test]
    fn voter_record_allow_carries_the_answer_ip_count() {
        let mut message = allow_message();
        message.answers.push(Record::from_rdata(
            Name::root(),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let record = voter_record2(
            "quad9",
            true,
            Some(&VoterOutcome::Responded(message)),
            Some(&VoterOutcome::Responded(allow_message())),
            TimeoutMode::FailOpen,
        );
        assert_eq!(record.verdict, VoterVerdict::Allow);
        assert_eq!(record.allow_ip_count, Some(2));
        assert_eq!(record.error_message, None);
    }

    #[test]
    fn voter_record_block_and_timeout_carry_no_payload() {
        let blocked = voter_record2(
            "adguard",
            true,
            Some(&VoterOutcome::Responded(null_ip_message())),
            Some(&VoterOutcome::Responded(allow_message())),
            TimeoutMode::FailOpen,
        );
        assert_eq!(blocked.verdict, VoterVerdict::Block);
        assert_eq!(blocked.allow_ip_count, None);
        assert_eq!(blocked.error_message, None);

        let timed_out = voter_record2(
            "quad9",
            true,
            Some(&VoterOutcome::TimedOut),
            None,
            TimeoutMode::FailOpen,
        );
        assert_eq!(timed_out.verdict, VoterVerdict::Timeout);
        assert_eq!(timed_out.allow_ip_count, None);
        assert_eq!(timed_out.error_message, None);
    }

    #[test]
    fn voter_record_error_carries_a_coarse_error_kind_never_the_raw_upstream_error() {
        let record = voter_record2(
            "quad9",
            true,
            Some(&VoterOutcome::Errored(UpstreamError::Decode(
                "malformed response".to_string().into(),
            ))),
            None,
            TimeoutMode::FailOpen,
        );
        assert_eq!(record.verdict, VoterVerdict::Error);
        assert_eq!(record.error_message, Some("decode"));
        assert_eq!(record.allow_ip_count, None);
    }

    #[test]
    fn voter_record_disabled_carries_no_payload() {
        let record = voter_record2("adguard", false, None, None, TimeoutMode::FailOpen);
        assert_eq!(record.verdict, VoterVerdict::Disabled);
        assert_eq!(record.allow_ip_count, None);
        assert_eq!(record.error_message, None);
    }

    // T-61: is_blocked() per provider (unchanged behavior). `&[]` = no
    // sinkhole prefixes, i.e. the pre-T-175 signature-only path.

    #[test]
    fn quad9_nxdomain_with_resolving_baseline_is_blocked() {
        assert!(is_blocked(
            BlockSignature::NxdomainVsBaseline,
            &nxdomain_message(),
            &allow_message(),
            &[],
        ));
    }

    #[test]
    fn quad9_nxdomain_matching_baseline_nxdomain_is_not_blocked() {
        assert!(!is_blocked(
            BlockSignature::NxdomainVsBaseline,
            &nxdomain_message(),
            &nxdomain_message(),
            &[],
        ));
    }

    #[test]
    fn quad9_allow_is_not_blocked() {
        assert!(!is_blocked(
            BlockSignature::NxdomainVsBaseline,
            &allow_message(),
            &allow_message(),
            &[],
        ));
    }

    #[test]
    fn adguard_null_ip_is_blocked() {
        assert!(is_blocked(
            BlockSignature::NullIp,
            &null_ip_message(),
            &allow_message(),
            &[],
        ));
    }

    #[test]
    fn adguard_real_ip_is_not_blocked() {
        assert!(!is_blocked(
            BlockSignature::NullIp,
            &allow_message(),
            &allow_message(),
            &[],
        ));
    }

    // --- T-175: sinkhole-IP detection through `is_blocked` / `evaluate` ---

    /// `adguard`'s real sinkhole prefix, and an address inside it that the
    /// probe never saw (proves prefix-match, not a `/32` list).
    fn adguard_sinkhole_nets() -> &'static [SinkholeNet] {
        crate::upstream::sinkhole_nets_for("adguard")
    }

    fn message_with_ip(ip: Ipv4Addr) -> Message {
        allow_message_with_ip(ip)
    }

    #[test]
    fn sinkhole_ip_with_resolving_baseline_is_blocked() {
        // NullIp-signature preset (`adguard`) that answered with a sinkhole
        // IP, not `0.0.0.0`; baseline resolved the domain for real.
        assert!(is_blocked(
            BlockSignature::NullIp,
            &message_with_ip(Ipv4Addr::new(94, 140, 14, 200)),
            &allow_message(),
            adguard_sinkhole_nets(),
        ));
    }

    #[test]
    fn sinkhole_ip_with_servfail_baseline_is_not_blocked() {
        // Baseline could not resolve it → the domain may genuinely be dead;
        // do not count it as a block (safe side).
        assert!(!is_blocked(
            BlockSignature::NullIp,
            &message_with_ip(Ipv4Addr::new(94, 140, 14, 35)),
            &servfail_message(),
            adguard_sinkhole_nets(),
        ));
    }

    #[test]
    fn sinkhole_ip_alongside_a_real_ip_still_blocks() {
        let mut message = message_with_ip(Ipv4Addr::new(94, 140, 14, 33));
        message.answers.push(Record::from_rdata(
            Name::root(),
            60,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        assert!(is_blocked(
            BlockSignature::NullIp,
            &message,
            &allow_message(),
            adguard_sinkhole_nets(),
        ));
    }

    #[test]
    fn empty_sinkhole_nets_keeps_pre_t175_behaviour() {
        // Same message as `sinkhole_ip_with_resolving_baseline_is_blocked`,
        // but with no prefixes: a NullIp preset sees a plain real IP → allow.
        assert!(!is_blocked(
            BlockSignature::NullIp,
            &message_with_ip(Ipv4Addr::new(94, 140, 14, 200)),
            &allow_message(),
            &[],
        ));
    }

    #[test]
    fn sinkhole_composes_with_the_presets_own_null_ip_signature() {
        // `adguard` keeps NullIp for its `0.0.0.0` ad-blocks *and* gains
        // sinkhole detection — both must still register as a block.
        assert!(is_blocked(
            BlockSignature::NullIp,
            &null_ip_message(),
            &allow_message(),
            adguard_sinkhole_nets(),
        ));
        assert!(is_blocked(
            BlockSignature::NullIp,
            &message_with_ip(Ipv4Addr::new(94, 140, 14, 33)),
            &allow_message(),
            adguard_sinkhole_nets(),
        ));
    }

    #[test]
    fn negative_control_provider_own_domain_is_not_a_sinkhole() {
        // A preset carrying a populated sinkhole set that answers a normal
        // query with a real IP *outside* its prefix must not block — this is
        // the assertion that catches a prefix widened too far.
        // `res.cloudinary.com` (unrelated host) and `adguard.com`
        // (AdGuard's own site, on Cloudflare `104.18.188.9`) both resolve
        // outside `94.140.14.0/24`.
        assert!(!is_blocked(
            BlockSignature::NullIp,
            &message_with_ip(Ipv4Addr::new(140, 248, 137, 137)),
            &allow_message(),
            adguard_sinkhole_nets(),
        ));
        assert!(!is_blocked(
            BlockSignature::NullIp,
            &message_with_ip(Ipv4Addr::new(104, 18, 188, 9)),
            &allow_message(),
            adguard_sinkhole_nets(),
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
        let (verdict, incomplete) = combine2(
            Some(VoterOutcome::Responded(allow_message())),
            Some(VoterOutcome::Responded(allow_message())),
            &VoterOutcome::Responded(allow_message()),
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Allow));
        assert!(!incomplete);
    }

    #[test]
    fn combine_adguard_block_is_self_sufficient() {
        // Baseline itself timed out - AdGuard's null-IP signature doesn't need it.
        let (verdict, _) = combine2(
            Some(VoterOutcome::Responded(allow_message())),
            Some(VoterOutcome::Responded(null_ip_message())),
            &VoterOutcome::TimedOut,
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
    }

    #[test]
    fn combine_quad9_nxdomain_with_resolving_baseline_is_block() {
        let (verdict, incomplete) = combine2(
            Some(VoterOutcome::Responded(nxdomain_message())),
            Some(VoterOutcome::Responded(allow_message())),
            &VoterOutcome::Responded(allow_message()),
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
        assert!(!incomplete);
    }

    #[test]
    fn combine_quad9_nxdomain_with_baseline_timeout_under_fail_open_is_allow() {
        // Undecidable (SPEC.md §3.3 addendum) - fail-open can't confirm, so it doesn't block.
        let (verdict, incomplete) = combine2(
            Some(VoterOutcome::Responded(nxdomain_message())),
            Some(VoterOutcome::Responded(allow_message())),
            &VoterOutcome::TimedOut,
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Allow));
        assert!(incomplete);
    }

    #[test]
    fn combine_quad9_nxdomain_with_baseline_timeout_under_fail_closed_is_block() {
        let (verdict, incomplete) = combine2(
            Some(VoterOutcome::Responded(nxdomain_message())),
            Some(VoterOutcome::Responded(allow_message())),
            &VoterOutcome::TimedOut,
            TimeoutMode::FailClosed,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
        assert!(incomplete);
    }

    #[test]
    fn combine_adguard_timeout_under_fail_open_is_allow() {
        let (verdict, incomplete) = combine2(
            Some(VoterOutcome::Responded(allow_message())),
            Some(VoterOutcome::TimedOut),
            &VoterOutcome::Responded(allow_message()),
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Allow));
        assert!(incomplete);
    }

    #[test]
    fn combine_adguard_timeout_under_fail_closed_is_block() {
        let (verdict, incomplete) = combine2(
            Some(VoterOutcome::Responded(allow_message())),
            Some(VoterOutcome::TimedOut),
            &VoterOutcome::Responded(allow_message()),
            TimeoutMode::FailClosed,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
        assert!(incomplete);
    }

    #[test]
    fn combine_degraded_matches_fail_open_verdict_over_answered_voters() {
        let entries = voters(true, true);
        let baseline = VoterOutcome::TimedOut;
        let outcomes = [
            Some(VoterOutcome::Responded(nxdomain_message())),
            Some(VoterOutcome::Responded(allow_message())),
        ];
        let (fail_open_verdict, _) =
            super::combine(&entries, &outcomes, &baseline, TimeoutMode::FailOpen);
        let (degraded_verdict, degraded_incomplete) =
            super::combine(&entries, &outcomes, &baseline, TimeoutMode::Degraded);
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
            let response = if url == QUAD9_URL {
                &self.quad9
            } else if url == ADGUARD_URL {
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
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
    }

    #[tokio::test]
    async fn one_block_yields_block() {
        let client = MockDohClient {
            quad9: MockResponse::Instant(nxdomain_message()),
            adguard: MockResponse::Instant(allow_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
    }

    #[tokio::test]
    async fn both_block_yields_block() {
        let client = MockDohClient {
            quad9: MockResponse::Instant(nxdomain_message()),
            adguard: MockResponse::Instant(null_ip_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::AAAA),
            &TimeoutConfig::default(),
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
    }

    #[tokio::test]
    async fn non_a_aaaa_type_is_not_applicable_even_with_blocking_fixtures() {
        let client = MockDohClient {
            quad9: MockResponse::Instant(nxdomain_message()),
            adguard: MockResponse::Instant(null_ip_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::HTTPS),
            &TimeoutConfig::default(),
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::NotApplicable));
        assert!(outcome.answer.is_none());
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
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
        // T-39: an early-return Block never carries an `answer` - a block
        // response is always synthesized, never sourced from upstream data.
        assert!(outcome.answer.is_none());
        assert!(
            started.elapsed() < config.duration,
            "resolve() waited out the pending voters' timeout instead of canceling them"
        );
    }

    // T-147: the query log needs the *per-voter* breakdown, not just the
    // final verdict - a test asserting only `outcome.verdict == Block` would
    // pass even if `voters` wrongly marked the canceled voter as `Allow` or
    // omitted it entirely.
    #[tokio::test(start_paused = true)]
    async fn adguard_self_sufficient_block_records_adguard_block_and_quad9_canceled() {
        let client = MockDohClient {
            quad9: MockResponse::Pending,
            adguard: MockResponse::Instant(null_ip_message()),
            baseline: MockResponse::Pending,
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
        assert_eq!(outcome.voters.len(), 2);
        let Some(adguard) = outcome.voters.iter().find(|v| v.provider_id == "adguard") else {
            panic!("expected an AdGuard voter record");
        };
        assert_eq!(adguard.verdict, VoterVerdict::Block);
        let Some(quad9) = outcome.voters.iter().find(|v| v.provider_id == "quad9") else {
            panic!("expected a Quad9 voter record");
        };
        assert_eq!(quad9.verdict, VoterVerdict::Canceled);
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
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(
            started.elapsed() < config.duration,
            "resolve() waited out the pending AdGuard voter's timeout instead of canceling it"
        );
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
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
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
    }

    #[tokio::test]
    async fn slow_adguard_under_fail_closed_is_block_end_to_end() {
        let client = SlowAdGuardClient;
        let config = TimeoutConfig {
            mode: TimeoutMode::FailClosed,
            duration: Duration::from_millis(5),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
    }

    // T-154/T-155: `filters_unreachable` — true only when *every* enabled
    // voter failed to answer, computed from the raw `VoterOutcome`s.

    #[tokio::test(start_paused = true)]
    async fn filters_unreachable_is_true_when_every_voter_times_out_but_baseline_answers() {
        let client = MockDohClient {
            quad9: MockResponse::Pending,
            adguard: MockResponse::Pending,
            baseline: MockResponse::Instant(allow_message()),
        };
        let config = TimeoutConfig {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_millis(5),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(outcome.filters_unreachable);
        assert!(
            outcome.baseline_answer.is_some(),
            "baseline gave a usable answer"
        );
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
    }

    #[tokio::test(start_paused = true)]
    async fn filters_unreachable_is_false_when_one_voter_still_answers() {
        let client = MockDohClient {
            quad9: MockResponse::Instant(allow_message()),
            adguard: MockResponse::Pending,
            baseline: MockResponse::Instant(allow_message()),
        };
        let config = TimeoutConfig {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_millis(5),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(!outcome.filters_unreachable);
    }

    #[tokio::test(start_paused = true)]
    async fn filters_unreachable_can_coexist_with_a_fail_closed_early_block() {
        // Every voter unresponsive under fail-closed: `unresponsive_signal`
        // makes the first timeout an early-return Block — the flag still
        // reports that no filter actually answered.
        let client = MockDohClient {
            quad9: MockResponse::Pending,
            adguard: MockResponse::Pending,
            baseline: MockResponse::Instant(allow_message()),
        };
        let config = TimeoutConfig {
            mode: TimeoutMode::FailClosed,
            duration: Duration::from_millis(5),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
        assert!(outcome.filters_unreachable);
        assert!(
            outcome.baseline_answer.is_some(),
            "baseline answer is carried even on the early-block path"
        );
    }

    struct SlowAdGuardClient;

    impl DohClient for SlowAdGuardClient {
        async fn query(&self, url: &str, _query: &Message) -> Result<Message, UpstreamError> {
            if url == ADGUARD_URL {
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
            let result = if url == ADGUARD_URL {
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
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
        assert!(outcome.answer.is_none());
        // AdGuard's error resolves instantly (no timeout involved) - Quad9
        // and baseline both answer NoError immediately too, so if the loop
        // recognizes the unresponsive-under-fail-closed signal itself
        // (rather than only via combine's post-loop fallback), this returns
        // effectively instantly either way. The real point of this test is
        // the verdict, not the timing - kept for symmetry with the other
        // T-30 tests.
        assert!(started.elapsed() < config.duration);
    }

    // T-39: QuorumOutcome.answer - the actual data a caller needs to answer
    // an Allow verdict (SPEC.md §5 step 5's "get ALLOW + IP").

    #[tokio::test]
    async fn resolve_allow_carries_baseline_answer_when_baseline_responded() {
        let baseline_ip = Ipv4Addr::new(1, 1, 1, 1);
        let client = MockDohClient {
            quad9: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(9, 9, 9, 9))),
            // TEST-NET-3, outside AdGuard's `94.140.14.0/24` sinkhole prefix
            // (T-175) — a distinguishable answer that stays a plain Allow.
            adguard: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(203, 0, 113, 14))),
            baseline: MockResponse::Instant(allow_message_with_ip(baseline_ip)),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
        let Some(answer) = outcome.answer else {
            panic!("expected an answer when baseline responded");
        };
        // Baseline, Quad9, and AdGuard carry distinguishable IPs - proves
        // baseline specifically won the preference order, not merely that
        // some voter's answer came through.
        assert_eq!(answer.answers, allow_message_with_ip(baseline_ip).answers);
    }

    #[tokio::test]
    async fn resolve_allow_falls_back_to_quad9_answer_when_baseline_timed_out() {
        let quad9_ip = Ipv4Addr::new(9, 9, 9, 9);
        let client = MockDohClient {
            quad9: MockResponse::Instant(allow_message_with_ip(quad9_ip)),
            // TEST-NET-3, outside AdGuard's `94.140.14.0/24` sinkhole prefix
            // (T-175) — a distinguishable answer that stays a plain Allow.
            adguard: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(203, 0, 113, 14))),
            baseline: MockResponse::Pending,
        };
        let config = TimeoutConfig {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_millis(5),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
        let Some(answer) = outcome.answer else {
            panic!("expected a Quad9-sourced answer when baseline never responded");
        };
        assert_eq!(answer.answers, allow_message_with_ip(quad9_ip).answers);
    }

    #[tokio::test]
    async fn resolve_allow_skips_baseline_servfail_and_falls_back_to_quad9() {
        // Baseline itself succeeded as an HTTP round-trip (Responded), but
        // its DNS answer is a failure code, not real data - representative_
        // allow_answer must not treat that as usable just because the voter
        // responded (advisor-review regression, T-39).
        let quad9_ip = Ipv4Addr::new(9, 9, 9, 9);
        let client = MockDohClient {
            quad9: MockResponse::Instant(allow_message_with_ip(quad9_ip)),
            // TEST-NET-3, outside AdGuard's `94.140.14.0/24` sinkhole prefix
            // (T-175) — a distinguishable answer that stays a plain Allow.
            adguard: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(203, 0, 113, 14))),
            baseline: MockResponse::Instant(servfail_message()),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
        let Some(answer) = outcome.answer else {
            panic!("expected a Quad9-sourced answer when baseline returned SERVFAIL");
        };
        assert_eq!(answer.answers, allow_message_with_ip(quad9_ip).answers);
    }

    #[tokio::test]
    async fn resolve_allow_answer_is_none_when_all_three_voters_unresponsive() {
        // Fail-open with every voter dead still yields Allow (nothing
        // confirmed a block) - but there is no real data to hand back.
        let client = MockDohClient {
            quad9: MockResponse::Pending,
            adguard: MockResponse::Pending,
            baseline: MockResponse::Pending,
        };
        let config = TimeoutConfig {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_millis(5),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &default_voters(),
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
        assert!(outcome.answer.is_none());
    }

    // T-148: EnabledProviders - a per-provider toggle the resolver actually
    // honors, not just an all-or-nothing switch.

    struct PanicsIfQueriedClient {
        forbidden_url: &'static str,
        quad9: MockResponse,
        adguard: MockResponse,
        baseline: MockResponse,
    }

    impl DohClient for PanicsIfQueriedClient {
        async fn query(&self, url: &str, _query: &Message) -> Result<Message, UpstreamError> {
            assert!(
                url != self.forbidden_url,
                "disabled provider must never be queried, but {url} was"
            );
            let response = if url == QUAD9_URL {
                &self.quad9
            } else if url == ADGUARD_URL {
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
    async fn quad9_disabled_still_runs_real_quorum_over_adguard_and_never_queries_quad9() {
        let client = PanicsIfQueriedClient {
            forbidden_url: QUAD9_URL,
            quad9: MockResponse::Instant(allow_message()),
            adguard: MockResponse::Instant(null_ip_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let enabled = voters(false, true);
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            &enabled,
            BASELINE_URL,
        )
        .await;
        // AdGuard's own null-IP signature still blocks - disabling Quad9
        // doesn't turn off quorum entirely, just that one voter.
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
        assert_eq!(outcome.voters.len(), 2);
        let Some(quad9) = outcome.voters.iter().find(|v| v.provider_id == "quad9") else {
            panic!("expected a Quad9 voter record");
        };
        assert_eq!(quad9.verdict, VoterVerdict::Disabled);
    }

    // Advisor-caught regression: a disabled provider's outcome must never be
    // coerced into VoterOutcome::TimedOut internally, or fail_closed mode
    // would treat "administratively disabled" the same as "timed out" and
    // silently BLOCK every query the moment one provider is turned off -
    // worse than no filtering at all (Три Б, user safety). This test would
    // fail if resolve() ever regressed to defaulting a disabled provider's
    // missing outcome to TimedOut.
    #[tokio::test]
    async fn quad9_disabled_under_fail_closed_is_still_allow_not_falsely_blocked() {
        let client = PanicsIfQueriedClient {
            forbidden_url: QUAD9_URL,
            quad9: MockResponse::Instant(allow_message()),
            adguard: MockResponse::Instant(allow_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let enabled = voters(false, true);
        let config = TimeoutConfig {
            mode: TimeoutMode::FailClosed,
            duration: Duration::from_secs(2),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &enabled,
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
    }

    #[tokio::test]
    async fn quad9_disabled_answer_is_none_when_adguard_and_baseline_both_unresponsive() {
        // representative_allow_answer must skip a disabled provider as a
        // candidate (not treat it as an unusable-but-present one) and still
        // correctly fall through to "no usable data" when nothing else has
        // an answer either.
        let client = PanicsIfQueriedClient {
            forbidden_url: QUAD9_URL,
            quad9: MockResponse::Instant(allow_message()),
            adguard: MockResponse::Pending,
            baseline: MockResponse::Pending,
        };
        let enabled = voters(false, true);
        let config = TimeoutConfig {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_millis(5),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            &enabled,
            BASELINE_URL,
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
        assert!(outcome.answer.is_none());
    }
}
