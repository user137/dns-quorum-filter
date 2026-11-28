//! Names that are answered here and never sent to a provider (T-305 batch
//! 3a, SPEC.md RFC table): special-use names (RFC 6761, 6762, 7686, 8375),
//! locally served reverse zones (RFC 6303, 7793) and single-label names.
//!
//! A provider can't answer any of them usefully, and sending one leaks a
//! local host name or address (a printer, a router, a LAN reverse lookup).
//! Single-label names come from OS search lists and typing mistakes; only
//! address-shaped types (A/AAAA/HTTPS/SVCB) are answered here, and a name
//! that is an ICANN top-level domain still goes out (`com. DS` is real).

use crate::public_suffix::is_icann_tld;
use hickory_proto::rr::RecordType;

/// What a local name gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalAnswer {
    /// `localhost` and below (RFC 6761 §6.3): the loopback address for A
    /// and AAAA, no data for other types.
    Loopback,
    /// The name does not exist.
    NxDomain,
    /// The name exists (a locally served zone's apex) but has no data.
    NoData,
}

/// A local answer and the zone it comes from: how many trailing labels of
/// the queried name make the zone, `None` for a single-label name (no zone
/// of ours — its parent is the root).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalReply {
    pub(crate) answer: LocalAnswer,
    pub(crate) zone_labels: Option<u8>,
}

/// Special-use domains answered NXDOMAIN at every level, apex included.
const NXDOMAIN_ZONES: [&str; 4] = [
    "invalid",   // RFC 6761 §6.4
    "local",     // RFC 6762 §3: mDNS, never unicast DNS
    "onion",     // RFC 7686 §2
    "home.arpa", // RFC 8375 §4
];

/// The local answer for `name` (ASCII, any case, root dot optional) and
/// `qtype`, or `None` when the query goes on to the pipeline.
pub(crate) fn local_answer(name: &str, qtype: RecordType) -> Option<LocalReply> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    let in_zone = |answer, zone: &str| LocalReply {
        answer,
        zone_labels: Some(label_count(zone)),
    };
    if is_at_or_below(&name, "localhost") {
        return Some(in_zone(LocalAnswer::Loopback, "localhost"));
    }
    if let Some(zone) = NXDOMAIN_ZONES
        .iter()
        .find(|zone| is_at_or_below(&name, zone))
    {
        return Some(in_zone(LocalAnswer::NxDomain, zone));
    }
    if let Some(reply) = reverse_zone_answer(&name) {
        return Some(reply);
    }
    let address_shaped = matches!(
        qtype,
        RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
    );
    (!name.contains('.') && address_shaped && !is_icann_tld(&name)).then_some(LocalReply {
        answer: LocalAnswer::NxDomain,
        zone_labels: None,
    })
}

/// Labels in one of this module's zone names (short constants).
fn label_count(zone: &str) -> u8 {
    u8::try_from(zone.split('.').count()).unwrap_or(u8::MAX)
}

/// `name` is `zone` or a name below it.
fn is_at_or_below(name: &str, zone: &str) -> bool {
    name.strip_suffix(zone)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// RFC 6303 §4 (plus RFC 7793's `100.64/10`): the answer for a name in a
/// locally served reverse zone — NODATA at the zone apex, NXDOMAIN below.
fn reverse_zone_answer(name: &str) -> Option<LocalReply> {
    let (labels, zone_len) = if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let octets: Vec<&str> = rest.rsplit('.').collect();
        (octets.len(), private_v4_zone_len(&octets)?)
    } else {
        let rest = name.strip_suffix(".ip6.arpa")?;
        let nibbles: Vec<&str> = rest.rsplit('.').collect();
        (nibbles.len(), private_v6_zone_len(&nibbles)?)
    };
    let answer = match labels.cmp(&zone_len) {
        std::cmp::Ordering::Less => return None,
        std::cmp::Ordering::Equal => LocalAnswer::NoData,
        std::cmp::Ordering::Greater => LocalAnswer::NxDomain,
    };
    // Plus the two labels of `in-addr.arpa` / `ip6.arpa`; zones are ≤ 34.
    let zone_labels = u8::try_from(zone_len.saturating_add(2)).ok()?;
    Some(LocalReply {
        answer,
        zone_labels: Some(zone_labels),
    })
}

/// The label count of the RFC 6303 zone the leading `octets` (most
/// significant first) fall in. `None` if no such zone, or if an octet the
/// decision needs is missing or not a number.
fn private_v4_zone_len(octets: &[&str]) -> Option<usize> {
    let octet = |i: usize| octets.get(i).and_then(|o| o.parse::<u8>().ok());
    match octet(0)? {
        0 | 10 | 127 => Some(1),
        169 if octet(1)? == 254 => Some(2),
        172 if (16..=31).contains(&octet(1)?) => Some(2),
        192 if octet(1)? == 168 => Some(2),
        100 if (64..=127).contains(&octet(1)?) => Some(2),
        192 if octet(1)? == 0 && octet(2)? == 2 => Some(3),
        198 if octet(1)? == 51 && octet(2)? == 100 => Some(3),
        203 if octet(1)? == 0 && octet(2)? == 113 => Some(3),
        255 if octets.len() >= 4 && (0..4).all(|i| octet(i) == Some(255)) => Some(4),
        _ => None,
    }
}

/// The nibble count of the RFC 6303 IPv6 zone the leading `nibbles` (most
/// significant first) fall in.
fn private_v6_zone_len(nibbles: &[&str]) -> Option<usize> {
    let starts = |prefix: &[&str]| nibbles.get(..prefix.len()) == Some(prefix);
    if starts(&["f", "d"]) {
        return Some(2); // fd00::/8, the ULA half in use
    }
    if ["8", "9", "a", "b"].iter().any(|n| starts(&["f", "e", n])) {
        return Some(3); // fe80::/10 link-local
    }
    if starts(&["2", "0", "0", "1", "0", "d", "b", "8"]) {
        return Some(8); // 2001:db8::/32 documentation
    }
    // :: and ::1 — whole 32-nibble names, each its own zone.
    let zeros = nibbles.len() == 32 && nibbles.get(..31)?.iter().all(|n| *n == "0");
    (zeros && matches!(nibbles.get(31), Some(&("0" | "1")))).then_some(32)
}

#[cfg(test)]
mod tests {
    use super::{local_answer, LocalAnswer, LocalReply};
    use hickory_proto::rr::RecordType;

    fn answer(name: &str) -> Option<LocalAnswer> {
        local_answer(name, RecordType::A).map(|reply| reply.answer)
    }

    fn zone(name: &str) -> Option<u8> {
        local_answer(name, RecordType::A).and_then(|reply| reply.zone_labels)
    }

    #[test]
    fn each_local_answer_names_its_zone() {
        assert_eq!(zone("app.localhost"), Some(1));
        assert_eq!(zone("router.home.arpa."), Some(2));
        assert_eq!(zone("1.1.168.192.in-addr.arpa"), Some(4));
        assert_eq!(zone("1.0.0.10.in-addr.arpa"), Some(3));
        assert_eq!(zone("1.0.0.0.d.f.ip6.arpa"), Some(4));
        assert_eq!(
            local_answer("printer", RecordType::A),
            Some(LocalReply {
                answer: LocalAnswer::NxDomain,
                zone_labels: None
            })
        );
    }

    #[test]
    fn localhost_and_below_are_loopback() {
        for name in ["localhost", "localhost.", "LocalHost", "app.localhost."] {
            assert_eq!(answer(name), Some(LocalAnswer::Loopback), "{name}");
        }
        assert_eq!(
            local_answer("localhost", RecordType::MX).map(|r| r.answer),
            Some(LocalAnswer::Loopback)
        );
    }

    #[test]
    fn special_use_zones_are_nxdomain_at_every_level() {
        for name in [
            "invalid",
            "x.invalid",
            "printer.local.",
            "local",
            "abc.onion",
            "home.arpa",
            "router.home.arpa",
        ] {
            assert_eq!(answer(name), Some(LocalAnswer::NxDomain), "{name}");
            assert_eq!(
                local_answer(name, RecordType::TXT).map(|r| r.answer),
                Some(LocalAnswer::NxDomain),
                "{name}"
            );
        }
    }

    // Boundary: a label that merely ends with a special-use name is public.
    #[test]
    fn a_lookalike_suffix_is_not_special_use() {
        for name in [
            "notlocalhost.com",
            "mylocal.example",
            "evilonion.net",
            "myhome.arpa.example",
            "example.com",
        ] {
            assert_eq!(answer(name), None, "{name}");
        }
    }

    #[test]
    fn private_ipv4_reverse_names_are_answered_locally() {
        assert_eq!(answer("1.0.0.10.in-addr.arpa"), Some(LocalAnswer::NxDomain));
        assert_eq!(answer("10.in-addr.arpa"), Some(LocalAnswer::NoData));
        assert_eq!(
            answer("1.0.0.127.in-addr.arpa."),
            Some(LocalAnswer::NxDomain)
        );
        assert_eq!(
            answer("5.1.168.192.in-addr.arpa"),
            Some(LocalAnswer::NxDomain)
        );
        assert_eq!(answer("168.192.in-addr.arpa"), Some(LocalAnswer::NoData));
        assert_eq!(
            answer("1.2.16.172.in-addr.arpa"),
            Some(LocalAnswer::NxDomain)
        );
        assert_eq!(
            answer("1.2.31.172.in-addr.arpa"),
            Some(LocalAnswer::NxDomain)
        );
        assert_eq!(
            answer("1.1.254.169.in-addr.arpa"),
            Some(LocalAnswer::NxDomain)
        );
        assert_eq!(
            answer("1.0.64.100.in-addr.arpa"),
            Some(LocalAnswer::NxDomain)
        );
        assert_eq!(
            answer("7.2.0.192.in-addr.arpa"),
            Some(LocalAnswer::NxDomain)
        );
        assert_eq!(
            answer("255.255.255.255.in-addr.arpa"),
            Some(LocalAnswer::NoData)
        );
    }

    #[test]
    fn public_ipv4_reverse_names_go_out() {
        for name in [
            "1.1.1.1.in-addr.arpa",
            "1.2.15.172.in-addr.arpa",
            "1.2.32.172.in-addr.arpa",
            "1.0.63.100.in-addr.arpa",
            "1.0.128.100.in-addr.arpa",
            "9.9.9.9.in-addr.arpa",
            // Shallower than the private zone: the parent is public.
            "172.in-addr.arpa",
            "192.in-addr.arpa",
            "in-addr.arpa",
            // Not a number: no decision, out it goes.
            "x.y.172.in-addr.arpa",
            "256.in-addr.arpa",
        ] {
            assert_eq!(answer(name), None, "{name}");
        }
    }

    #[test]
    fn private_ipv6_reverse_names_are_answered_locally() {
        let loopback = format!("1.{}ip6.arpa", "0.".repeat(31));
        let unspecified = format!("{}ip6.arpa", "0.".repeat(32));
        assert_eq!(answer(&loopback), Some(LocalAnswer::NoData));
        assert_eq!(answer(&unspecified), Some(LocalAnswer::NoData));
        assert_eq!(answer("1.0.0.0.d.f.ip6.arpa"), Some(LocalAnswer::NxDomain));
        assert_eq!(answer("d.f.ip6.arpa"), Some(LocalAnswer::NoData));
        assert_eq!(answer("0.8.e.f.ip6.arpa"), Some(LocalAnswer::NxDomain));
        assert_eq!(answer("b.e.f.ip6.arpa"), Some(LocalAnswer::NoData));
        assert_eq!(
            answer("1.8.b.d.0.1.0.0.2.ip6.arpa"),
            Some(LocalAnswer::NxDomain)
        );
    }

    #[test]
    fn public_ipv6_reverse_names_go_out() {
        let two = format!("2.{}ip6.arpa", "0.".repeat(31));
        for name in [
            "1.1.1.1.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa",
            "c.f.ip6.arpa", // fc00::/8 is not in RFC 6303's list
            "0.c.e.f.ip6.arpa",
            "f.ip6.arpa",
            two.as_str(),
        ] {
            assert_eq!(answer(name), None, "{name}");
        }
    }

    #[test]
    fn a_single_label_address_query_is_nxdomain_unless_it_is_a_tld() {
        for qtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::SVCB,
        ] {
            assert_eq!(
                local_answer("printer", qtype).map(|r| r.answer),
                Some(LocalAnswer::NxDomain),
                "{qtype}"
            );
            assert_eq!(local_answer("com", qtype), None, "{qtype}");
            assert_eq!(local_answer("UA.", qtype), None, "{qtype}");
        }
        // A TLD listed only by a wildcard rule, and an IDN TLD in ASCII.
        assert_eq!(local_answer("ck", RecordType::A), None);
        assert_eq!(local_answer("xn--p1ai", RecordType::A), None);
        // Other types go out: a single-label MX/TXT/DS can be real.
        assert_eq!(local_answer("printer", RecordType::MX), None);
        assert_eq!(local_answer("com", RecordType::DS), None);
    }

    #[test]
    fn the_root_and_an_empty_name_go_out() {
        assert_eq!(local_answer(".", RecordType::NS), None);
        assert_eq!(local_answer("", RecordType::A), None);
        assert_eq!(local_answer(".", RecordType::DNSKEY), None);
    }
}
