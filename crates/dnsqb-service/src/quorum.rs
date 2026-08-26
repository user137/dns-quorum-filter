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
use serde::Deserialize;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

/// Which Phase-1 providers actually get queried (T-148) — replaces the old
/// all-or-nothing `pipeline::Voters` switch with a real per-provider toggle.
/// Lives here, not in `config.rs`: which providers vote is quorum's own
/// domain, not the config file's (same precedent T-147 already set for
/// [`VoterVerdict`]/[`VoterRecord`]). `config::ResolverConfig` reuses this
/// type directly as its `providers` field rather than a parallel
/// config-only copy — a second type here could drift from what [`resolve`]
/// actually honors, the literal T-41 lesson this type exists to fix, applied
/// to itself. `Deserialize` (`#[serde(default, deny_unknown_fields)]`, same
/// split as every other on-disk shape in this crate) is derived directly on
/// this type rather than a config-only wrapper, mirroring how
/// `timeout::TimeoutMode` gained `Serialize`/`Deserialize` directly at T-144.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnabledProviders {
    /// Whether Quad9 is queried at all.
    pub quad9: bool,
    /// Whether `AdGuard` is queried at all.
    pub adguard: bool,
}

impl Default for EnabledProviders {
    /// The MVP default (both on) — same value `pipeline::Voters::Enabled`
    /// represented before T-148.
    fn default() -> Self {
        Self {
            quad9: true,
            adguard: true,
        }
    }
}

impl EnabledProviders {
    /// Whether at least one provider is enabled. `false` is SPEC.md §3/
    /// §8.1's explicit pass-through case — resolution goes through the
    /// unfiltered baseline resolver instead of calling [`resolve`] at all.
    #[must_use]
    pub fn any_enabled(&self) -> bool {
        self.quad9 || self.adguard
    }
}

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
    /// disabled it (T-148, [`EnabledProviders`]). Deliberately distinct from
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
/// Deliberately carries [`Provider`] (two variants: Quad9, `AdGuard`), not
/// [`Slot`]'s three (which also includes `Baseline`) — SPEC.md §3.1 only
/// calls Quad9/`AdGuard` "voters"; baseline exists to break Quad9's NXDOMAIN
/// tie and to source real answer data, it never casts an OR-logic block/allow
/// vote itself. Excluding it from `voters` is a SPEC-silent choice made here,
/// not a documented requirement — flagged per this project's own rule for
/// filling such gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterRecord {
    /// Which provider this result belongs to.
    pub provider: Provider,
    /// That provider's outcome.
    pub verdict: VoterVerdict,
}

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
fn voter_record(
    provider: Provider,
    enabled: bool,
    outcome: Option<&VoterOutcome>,
    baseline: Option<&VoterOutcome>,
    mode: TimeoutMode,
) -> VoterRecord {
    if !enabled {
        return VoterRecord {
            provider,
            verdict: VoterVerdict::Disabled,
        };
    }
    let verdict = match outcome {
        None => VoterVerdict::Canceled,
        Some(VoterOutcome::TimedOut) => VoterVerdict::Timeout,
        Some(VoterOutcome::Errored(_)) => VoterVerdict::Error,
        Some(VoterOutcome::Responded(_)) => match known_signal(provider, outcome, baseline, mode) {
            Some(Signal::Blocked) => VoterVerdict::Block,
            Some(Signal::NotBlocked) => VoterVerdict::Allow,
            None | Some(Signal::NeedsBaseline) => VoterVerdict::Canceled,
        },
    };
    VoterRecord { provider, verdict }
}

/// Both Phase-1 voters' [`VoterRecord`]s (T-147) — never baseline, see
/// [`VoterRecord`]'s own doc comment. Always exactly two entries regardless
/// of `enabled` (T-148) — a disabled provider still gets a record, just with
/// [`VoterVerdict::Disabled`], preserving the documented invariant on
/// [`QuorumOutcome::voters`].
fn voter_records(
    enabled: EnabledProviders,
    quad9: Option<&VoterOutcome>,
    adguard: Option<&VoterOutcome>,
    baseline: Option<&VoterOutcome>,
    mode: TimeoutMode,
) -> Vec<VoterRecord> {
    vec![
        voter_record(Provider::Quad9, enabled.quad9, quad9, baseline, mode),
        voter_record(Provider::AdGuard, enabled.adguard, adguard, baseline, mode),
    ]
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
    /// Both Phase-1 voters' per-provider verdicts (T-147) — `vec![]` under
    /// [`QuorumVerdict::NotApplicable`] (never queried), otherwise always
    /// exactly two entries (Quad9, `AdGuard`), regardless of verdict.
    /// [`VoterVerdict::Disabled`] (T-148) means that provider was
    /// administratively turned off, not queried at all this round.
    pub voters: Vec<VoterRecord>,
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

/// SPEC.md §5 step 5 (T-39): which voter's `Message` a caller should treat as
/// the real answer when the verdict is `Allow`. Preference order: baseline
/// (canonical, unfiltered) → Quad9 → `AdGuard` — all three gated on
/// [`is_usable_answer`], and the latter two additionally only when their own
/// signal is definitively [`Signal::NotBlocked`] (a filtering resolver
/// returns real, unmodified records when it isn't blocking — for `AdGuard`
/// that includes a genuine NXDOMAIN, itself valid data for negative
/// caching, not an error; Quad9's own NXDOMAIN is excluded from this
/// fallback entirely, see below).
///
/// Quad9's [`Signal::NeedsBaseline`] (its own NXDOMAIN) is deliberately
/// **excluded** here, not just its (unreachable) `Blocked` — `evaluate`
/// never actually returns `Signal::Blocked` for Quad9 (its `evaluate()` only
/// distinguishes `NeedsBaseline`/`NotBlocked`), so guarding on `Blocked`
/// alone would treat an *unconfirmed* Quad9 NXDOMAIN as trustworthy real
/// data whenever baseline itself didn't respond (fail-open's undecidable
/// case, `unresponsive_signal` in `resolve_needs_baseline`) — silently
/// caching a domain that might actually be Quad9-blocked as genuinely
/// nonexistent. Caught in self-review while writing this function, not by a
/// test.
///
/// `quad9`/`adguard` are `Option` (T-148) — `None` means that provider is
/// disabled this round, simply skipped as a candidate rather than treated as
/// an unusable answer; the preference order still falls through to whichever
/// of the remaining candidates has real data.
fn representative_allow_answer(
    quad9: Option<&VoterOutcome>,
    adguard: Option<&VoterOutcome>,
    baseline: &VoterOutcome,
) -> Option<Message> {
    if let VoterOutcome::Responded(message) = baseline {
        if is_usable_answer(message) {
            return Some(message.clone());
        }
    }
    if let Some(VoterOutcome::Responded(message)) = quad9 {
        if matches!(evaluate(Provider::Quad9, message), Signal::NotBlocked)
            && is_usable_answer(message)
        {
            return Some(message.clone());
        }
    }
    if let Some(VoterOutcome::Responded(message)) = adguard {
        if matches!(evaluate(Provider::AdGuard, message), Signal::NotBlocked)
            && is_usable_answer(message)
        {
            return Some(message.clone());
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
/// `quad9`/`adguard` are `Option` (T-148) — `None` means that provider is
/// disabled this round: it must never count toward `incomplete` (turning a
/// provider off on purpose isn't a degraded state) and must never contribute
/// a block signal (`known_signal`'s existing `outcome?` early return already
/// makes a `None` outcome yield `None`/no signal, which the fold below
/// already treats as `NotBlocked` — no new special-casing needed here).
fn combine(
    quad9: Option<&VoterOutcome>,
    adguard: Option<&VoterOutcome>,
    baseline: &VoterOutcome,
    mode: TimeoutMode,
) -> (QuorumVerdict, bool) {
    let incomplete = quad9.is_some_and(|o| !matches!(o, VoterOutcome::Responded(_)))
        || adguard.is_some_and(|o| !matches!(o, VoterOutcome::Responded(_)))
        || !matches!(baseline, VoterOutcome::Responded(_));

    let adguard_signal = known_signal(Provider::AdGuard, adguard, Some(baseline), mode)
        .unwrap_or(Signal::NotBlocked);
    let quad9_signal =
        known_signal(Provider::Quad9, quad9, Some(baseline), mode).unwrap_or(Signal::NotBlocked);

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

/// SPEC.md §3, §3.3, §3.6 (T-24, T-27, T-30): OR-logic quorum across whichever
/// Phase-1 upstreams [`EnabledProviders`] (T-148) has turned on, plus the
/// baseline resolver — concurrently through a `FuturesUnordered` (SPEC.md
/// §3.6) with a per-query timeout (SPEC.md §3.3); returns as soon as a
/// `Block` verdict is confirmed, dropping (canceling) whichever calls
/// haven't completed yet.
///
/// Baseline is **always** queried regardless of `enabled` — it's still
/// needed to resolve Quad9's NXDOMAIN-needs-baseline signal when Quad9 is
/// on, and it's still the preferred source of real answer data on `Allow`
/// even when only one filtering voter is enabled. Callers must not call this
/// with `enabled.any_enabled() == false` — SPEC.md §3/§8.1's pass-through
/// case is handled entirely by the caller (`pipeline::handle_query`), not
/// here; this function has no meaningful "zero voters" behavior of its own.
/// **This precondition is documented, not type-enforced** — `EnabledProviders`
/// permits `{ quad9: false, adguard: false }` here too, and this function
/// would still return a well-formed `QuorumOutcome` for it (`Allow`, sourced
/// entirely from baseline, both `voters` entries `Disabled`) rather than
/// erroring — indistinguishable from a legitimate filtered `Allow` to any
/// caller that isn't inspecting individual verdicts, and `handle_query` would
/// cache it. The one shipped caller (`pipeline::handle_query`) never reaches
/// this state (its own `any_enabled()` gate runs first), so this is a
/// latent, not exercised, gap — not a newtype to close it: the shape of a
/// dedicated "at least one enabled" type would be over-engineering for two
/// providers, same reasoning as [`EnabledProviders`] staying two plain
/// `bool`s instead of a richer type.
///
/// A disabled provider's outcome is never coerced into
/// [`VoterOutcome::TimedOut`] — doing so would make `fail_closed` mode treat
/// "administratively disabled" the same as "timed out" and silently BLOCK
/// every query the moment a provider is turned off, worse than no filtering
/// at all (Три Б, user safety). Disabled providers stay `None` all the way
/// through to `combine`/`voter_records`, which both already treat `None` as
/// "contributes nothing" rather than "unresponsive".
///
/// Refuses to run quorum at all when [`requires_quorum`] says `query`'s type
/// shouldn't go through it (T-25) — returns [`QuorumVerdict::NotApplicable`]
/// (with `answer: None`) without making any upstream call.
///
/// Never returns an error: an unresponsive or failing voter is interpreted
/// per `config.mode` rather than propagated (SPEC.md §3.3) — see `combine`.
pub async fn resolve<C: DohClient + Sync>(
    client: &C,
    query: &Message,
    config: &TimeoutConfig,
    enabled: EnabledProviders,
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
        };
    }

    let mut futures: FuturesUnordered<TaggedFuture<'_>> = FuturesUnordered::new();
    if enabled.quad9 {
        futures.push(tagged_query(
            Slot::Quad9,
            client,
            Provider::Quad9.doh_url(),
            query,
            config.duration,
        ));
    }
    if enabled.adguard {
        futures.push(tagged_query(
            Slot::AdGuard,
            client,
            Provider::AdGuard.doh_url(),
            query,
            config.duration,
        ));
    }
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
        // happens to catch once the loop runs out of voters to wait on. A
        // disabled provider's local var never gets set (no future was ever
        // pushed for it), so `known_signal` sees `None` and naturally
        // contributes no signal here, with no extra check needed.
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
            // Only log "canceled" for a provider that was actually eligible
            // to be asked - a disabled provider was never asked, so it was
            // never canceled either.
            if enabled.quad9 && quad9.is_none() {
                log_canceled(Slot::Quad9);
            }
            if enabled.adguard && adguard.is_none() {
                log_canceled(Slot::AdGuard);
            }
            if baseline.is_none() {
                log_canceled(Slot::Baseline);
            }
            return QuorumOutcome {
                verdict: QuorumVerdict::Block,
                answer: None,
                voters: voter_records(
                    enabled,
                    quad9.as_ref(),
                    adguard.as_ref(),
                    baseline.as_ref(),
                    config.mode,
                ),
            };
        }
    }

    finalize_outcome(enabled, quad9, adguard, baseline, config)
}

/// Builds the final [`QuorumOutcome`] once `resolve`'s loop has run to
/// completion without an early Block return — pulled out purely to keep
/// `resolve` itself under `clippy::too_many_lines`, not reused elsewhere.
/// A disabled provider's outcome stays `None` here (never coerced into
/// [`VoterOutcome::TimedOut`]) — see `resolve`'s own doc comment for why
/// that distinction is safety-critical under fail-closed.
fn finalize_outcome(
    enabled: EnabledProviders,
    quad9: Option<VoterOutcome>,
    adguard: Option<VoterOutcome>,
    baseline: Option<VoterOutcome>,
    config: &TimeoutConfig,
) -> QuorumOutcome {
    let quad9 = enabled
        .quad9
        .then(|| quad9.unwrap_or(VoterOutcome::TimedOut));
    let adguard = enabled
        .adguard
        .then(|| adguard.unwrap_or(VoterOutcome::TimedOut));
    let baseline = baseline.unwrap_or(VoterOutcome::TimedOut);

    let (verdict, incomplete) = combine(quad9.as_ref(), adguard.as_ref(), &baseline, config.mode);
    if config.mode == TimeoutMode::Degraded && incomplete {
        tracing::warn!("quorum verdict computed from an incomplete voter set (degraded mode)");
    }
    let answer = if verdict == QuorumVerdict::Allow {
        representative_allow_answer(quad9.as_ref(), adguard.as_ref(), &baseline)
    } else {
        None
    };
    let voters = voter_records(
        enabled,
        quad9.as_ref(),
        adguard.as_ref(),
        Some(&baseline),
        config.mode,
    );
    QuorumOutcome {
        verdict,
        answer,
        voters,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        combine, is_blocked, requires_quorum, resolve, EnabledProviders, Provider, QuorumVerdict,
        VoterVerdict,
    };
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
            Some(&VoterOutcome::Responded(allow_message())),
            Some(&VoterOutcome::Responded(allow_message())),
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
            Some(&VoterOutcome::Responded(allow_message())),
            Some(&VoterOutcome::Responded(null_ip_message())),
            &VoterOutcome::TimedOut,
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
    }

    #[test]
    fn combine_quad9_nxdomain_with_resolving_baseline_is_block() {
        let (verdict, incomplete) = combine(
            Some(&VoterOutcome::Responded(nxdomain_message())),
            Some(&VoterOutcome::Responded(allow_message())),
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
            Some(&VoterOutcome::Responded(nxdomain_message())),
            Some(&VoterOutcome::Responded(allow_message())),
            &VoterOutcome::TimedOut,
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Allow));
        assert!(incomplete);
    }

    #[test]
    fn combine_quad9_nxdomain_with_baseline_timeout_under_fail_closed_is_block() {
        let (verdict, incomplete) = combine(
            Some(&VoterOutcome::Responded(nxdomain_message())),
            Some(&VoterOutcome::Responded(allow_message())),
            &VoterOutcome::TimedOut,
            TimeoutMode::FailClosed,
        );
        assert!(matches!(verdict, QuorumVerdict::Block));
        assert!(incomplete);
    }

    #[test]
    fn combine_adguard_timeout_under_fail_open_is_allow() {
        let (verdict, incomplete) = combine(
            Some(&VoterOutcome::Responded(allow_message())),
            Some(&VoterOutcome::TimedOut),
            &VoterOutcome::Responded(allow_message()),
            TimeoutMode::FailOpen,
        );
        assert!(matches!(verdict, QuorumVerdict::Allow));
        assert!(incomplete);
    }

    #[test]
    fn combine_adguard_timeout_under_fail_closed_is_block() {
        let (verdict, incomplete) = combine(
            Some(&VoterOutcome::Responded(allow_message())),
            Some(&VoterOutcome::TimedOut),
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
        let (fail_open_verdict, _) = combine(
            Some(&inputs.0),
            Some(&inputs.1),
            &inputs.2,
            TimeoutMode::FailOpen,
        );
        let (degraded_verdict, degraded_incomplete) = combine(
            Some(&inputs.0),
            Some(&inputs.1),
            &inputs.2,
            TimeoutMode::Degraded,
        );
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
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            EnabledProviders::default(),
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
            EnabledProviders::default(),
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
            EnabledProviders::default(),
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
            EnabledProviders::default(),
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
            EnabledProviders::default(),
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
            EnabledProviders::default(),
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
        assert_eq!(outcome.voters.len(), 2);
        let Some(adguard) = outcome
            .voters
            .iter()
            .find(|v| v.provider == Provider::AdGuard)
        else {
            panic!("expected an AdGuard voter record");
        };
        assert_eq!(adguard.verdict, VoterVerdict::Block);
        let Some(quad9) = outcome
            .voters
            .iter()
            .find(|v| v.provider == Provider::Quad9)
        else {
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
            EnabledProviders::default(),
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
            EnabledProviders::default(),
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
            EnabledProviders::default(),
        )
        .await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
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
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &config,
            EnabledProviders::default(),
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
            adguard: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(94, 140, 14, 14))),
            baseline: MockResponse::Instant(allow_message_with_ip(baseline_ip)),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            EnabledProviders::default(),
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
            adguard: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(94, 140, 14, 14))),
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
            EnabledProviders::default(),
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
            adguard: MockResponse::Instant(allow_message_with_ip(Ipv4Addr::new(94, 140, 14, 14))),
            baseline: MockResponse::Instant(servfail_message()),
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            EnabledProviders::default(),
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
            EnabledProviders::default(),
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
    async fn quad9_disabled_still_runs_real_quorum_over_adguard_and_never_queries_quad9() {
        let client = PanicsIfQueriedClient {
            forbidden_url: Provider::Quad9.doh_url(),
            quad9: MockResponse::Instant(allow_message()),
            adguard: MockResponse::Instant(null_ip_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let enabled = EnabledProviders {
            quad9: false,
            adguard: true,
        };
        let outcome = resolve(
            &client,
            &query_of_type(RecordType::A),
            &TimeoutConfig::default(),
            enabled,
        )
        .await;
        // AdGuard's own null-IP signature still blocks - disabling Quad9
        // doesn't turn off quorum entirely, just that one voter.
        assert!(matches!(outcome.verdict, QuorumVerdict::Block));
        assert_eq!(outcome.voters.len(), 2);
        let Some(quad9) = outcome
            .voters
            .iter()
            .find(|v| v.provider == Provider::Quad9)
        else {
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
            forbidden_url: Provider::Quad9.doh_url(),
            quad9: MockResponse::Instant(allow_message()),
            adguard: MockResponse::Instant(allow_message()),
            baseline: MockResponse::Instant(allow_message()),
        };
        let enabled = EnabledProviders {
            quad9: false,
            adguard: true,
        };
        let config = TimeoutConfig {
            mode: TimeoutMode::FailClosed,
            duration: Duration::from_secs(2),
        };
        let outcome = resolve(&client, &query_of_type(RecordType::A), &config, enabled).await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
    }

    #[tokio::test]
    async fn quad9_disabled_answer_is_none_when_adguard_and_baseline_both_unresponsive() {
        // representative_allow_answer must skip a disabled provider as a
        // candidate (not treat it as an unusable-but-present one) and still
        // correctly fall through to "no usable data" when nothing else has
        // an answer either.
        let client = PanicsIfQueriedClient {
            forbidden_url: Provider::Quad9.doh_url(),
            quad9: MockResponse::Instant(allow_message()),
            adguard: MockResponse::Pending,
            baseline: MockResponse::Pending,
        };
        let enabled = EnabledProviders {
            quad9: false,
            adguard: true,
        };
        let config = TimeoutConfig {
            mode: TimeoutMode::FailOpen,
            duration: Duration::from_millis(5),
        };
        let outcome = resolve(&client, &query_of_type(RecordType::A), &config, enabled).await;
        assert!(matches!(outcome.verdict, QuorumVerdict::Allow));
        assert!(outcome.answer.is_none());
    }
}
