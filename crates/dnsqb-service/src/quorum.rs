//! Block-signature recognition (T-23) and OR-logic quorum across the two
//! Phase-1 upstreams (T-24, T-25). No early-return/cancellation yet (T-30)
//! and no timeout-mode handling yet (T-27/T-28) — SPEC.md §3.6/§3.3
//! refinements land in a later batch.

use crate::upstream::{DohClient, Provider, UpstreamError, BASELINE_DOH_URL};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};

fn is_null_ip(record: &Record) -> bool {
    match &record.data {
        RData::A(A(ip)) => *ip == Ipv4Addr::UNSPECIFIED,
        RData::AAAA(AAAA(ip)) => *ip == Ipv6Addr::UNSPECIFIED,
        _ => false,
    }
}

/// SPEC.md §3.1 (T-23): per-provider block-signature table, live-verified
/// T-20 (DECISIONS.md 2026-08-25) — **n=1 per provider**, one test domain,
/// one point of presence, one moment in time. `baseline` disambiguates
/// Quad9's NXDOMAIN from a genuinely nonexistent domain; that comparison is
/// the actual mechanism, not the NXDOMAIN/empty-authority-section detail
/// alone (SPEC.md §3.1 carries the full caveat).
#[must_use]
pub fn is_blocked(provider: Provider, response: &Message, baseline: &Message) -> bool {
    match provider {
        Provider::AdGuard => response.answers.iter().any(is_null_ip),
        Provider::Quad9 => {
            response.metadata.response_code == ResponseCode::NXDomain
                && baseline.metadata.response_code == ResponseCode::NoError
        }
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

/// SPEC.md §3, §3.4 (T-24): OR-logic quorum across the two fixed Phase-1
/// upstreams. Queries both providers and the baseline resolver concurrently;
/// blocks if either provider's [`is_blocked`] signature matches.
///
/// Refuses to run quorum at all when [`requires_quorum`] says `query`'s type
/// shouldn't go through it (T-25) — returns [`QuorumVerdict::NotApplicable`]
/// without making any upstream call, rather than relying on every future
/// caller to check `requires_quorum` first.
///
/// # Errors
///
/// Returns `Err` if a required upstream/baseline query fails outright —
/// T-27's timeout-mode policy (fail-open/fail-closed/degraded) isn't wired
/// yet, so any failure here propagates rather than being interpreted.
pub async fn resolve<C: DohClient>(
    client: &C,
    query: &Message,
) -> Result<QuorumVerdict, UpstreamError> {
    let applies = query
        .queries
        .first()
        .is_some_and(|question| requires_quorum(question.query_type()));
    if !applies {
        return Ok(QuorumVerdict::NotApplicable);
    }

    let (quad9, adguard, baseline) = tokio::join!(
        client.query(Provider::Quad9.doh_url(), query),
        client.query(Provider::AdGuard.doh_url(), query),
        client.query(BASELINE_DOH_URL, query),
    );
    let baseline = baseline?;
    let quad9 = quad9?;
    let adguard = adguard?;

    let blocked = is_blocked(Provider::Quad9, &quad9, &baseline)
        || is_blocked(Provider::AdGuard, &adguard, &baseline);
    Ok(if blocked {
        QuorumVerdict::Block
    } else {
        QuorumVerdict::Allow
    })
}

#[cfg(test)]
mod tests {
    use super::{is_blocked, requires_quorum, resolve, Provider, QuorumVerdict};
    use crate::upstream::{DohClient, UpstreamError};
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;

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

    // T-61: is_blocked() per provider.

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
        // Baseline also NXDOMAIN => the domain genuinely doesn't exist
        // anywhere, not a Quad9 block (SPEC.md §3.1).
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

    // T-62: quorum OR-logic with mocked upstreams.

    struct MockDohClient {
        quad9: Message,
        adguard: Message,
        baseline: Message,
    }

    impl DohClient for MockDohClient {
        fn query(
            &self,
            url: &str,
            _query: &Message,
        ) -> impl std::future::Future<Output = Result<Message, UpstreamError>> {
            let response = if url == Provider::Quad9.doh_url() {
                &self.quad9
            } else if url == Provider::AdGuard.doh_url() {
                &self.adguard
            } else {
                &self.baseline
            };
            std::future::ready(Ok(response.clone()))
        }
    }

    #[tokio::test]
    async fn both_allow_yields_allow() {
        let client = MockDohClient {
            quad9: allow_message(),
            adguard: allow_message(),
            baseline: allow_message(),
        };
        let verdict = resolve(&client, &query_of_type(RecordType::A)).await;
        assert!(matches!(verdict, Ok(QuorumVerdict::Allow)));
    }

    #[tokio::test]
    async fn one_block_yields_block() {
        let client = MockDohClient {
            quad9: nxdomain_message(),
            adguard: allow_message(),
            baseline: allow_message(),
        };
        let verdict = resolve(&client, &query_of_type(RecordType::A)).await;
        assert!(matches!(verdict, Ok(QuorumVerdict::Block)));
    }

    #[tokio::test]
    async fn both_block_yields_block() {
        let client = MockDohClient {
            quad9: nxdomain_message(),
            adguard: null_ip_message(),
            baseline: allow_message(),
        };
        let verdict = resolve(&client, &query_of_type(RecordType::AAAA)).await;
        assert!(matches!(verdict, Ok(QuorumVerdict::Block)));
    }

    #[tokio::test]
    async fn non_a_aaaa_type_is_not_applicable_even_with_blocking_fixtures() {
        // Fixtures alone would produce Block if the type gate didn't fire -
        // proves resolve() actually refuses to quorum an HTTPS query rather
        // than silently applying OR-logic to it (SPEC.md §3).
        let client = MockDohClient {
            quad9: nxdomain_message(),
            adguard: null_ip_message(),
            baseline: allow_message(),
        };
        let verdict = resolve(&client, &query_of_type(RecordType::HTTPS)).await;
        assert!(matches!(verdict, Ok(QuorumVerdict::NotApplicable)));
    }
}
