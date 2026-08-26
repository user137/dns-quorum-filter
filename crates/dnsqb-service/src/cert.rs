//! Self-signed leaf certificate generation for the local `DoH` listener
//! (SPEC.md §2, T-48) — **generation only**. This module deliberately does
//! not: write the cert/key to disk (T-50 — private-key file permissions is
//! its own tracked technical debt), install the cert into an OS trust store
//! (T-49 — a manual, human step at this phase), or wire a real `hyper` + TLS
//! listener (later `main.rs` work, unblocked by this module but not done by
//! it). Same "backend primitive ready, wiring later" pattern as every prior
//! module in this crate.
//!
//! **Leaf, never a CA** (SPEC.md §2's largest stated attack-surface
//! decision): a compromised private key for this cert can only spoof
//! `127.0.0.1`, not arbitrary domains, precisely because it is not a CA that
//! could sign other certificates. Uses `IsCa::ExplicitNoCa`, not the plain
//! `IsCa::NoCa` default — confirmed empirically that `NoCa` omits the
//! `BasicConstraints` extension entirely rather than encoding `CA:FALSE`, so
//! a test asserting "not a CA" against a `NoCa`-generated cert would pass
//! against *any* certificate lacking the extension, not specifically against
//! this one's actual encoded bytes. `ExplicitNoCa` makes the property
//! verifiable from the DER itself.
//!
//! **Validity window is a stated, provisional decision, not a library
//! default.** `rcgen`'s own unexamined default (`1975-01-01`..`4096-01-01`,
//! confirmed empirically, not assumed from docs) is not used. This module
//! instead sets an explicit 100-year window (`2020-01-01`..`2120-01-01`) —
//! long-lived per SPEC.md §2, without reproducing rcgen's own odd `4096`
//! upper bound. The window is **absolute dates, not generation-time-relative
//! (`now()` + N years)**, even though `std::time::SystemTime::now().into()`
//! would work without any new dependency (confirmed empirically) — chosen
//! instead so this module's own tests can assert an exact expected
//! timestamp rather than a fuzzy "far enough in the future" range. **T-51**'s
//! empirical Chrome/Firefox CT-policy check may still force a different
//! window; **T-69** (certificate rotation) is where switching to a
//! generation-relative window would become worth it, since each rotation
//! calls this function fresh.

use rcgen::{CertificateParams, CertifiedKey, DistinguishedName, DnType, IsCa, KeyPair};

/// Errors generating the self-signed leaf certificate.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// Underlying `rcgen` failure (key generation or certificate signing).
    #[error("failed to generate self-signed certificate: {0}")]
    Generation(#[from] rcgen::Error),
}

/// Generate the local `DoH` listener's self-signed leaf certificate
/// (SPEC.md §2): SAN `IP:127.0.0.1`, `IP:::1`, `DNS:localhost`, not a CA,
/// long-lived (see this module's doc comment for the validity-window
/// reasoning). Takes no parameters — SPEC.md hardcodes the SAN list, so
/// there is nothing for a caller to configure.
///
/// # Errors
///
/// Returns [`CertError::Generation`] if key generation or self-signing
/// fails at the `rcgen`/crypto-backend level.
pub fn generate_self_signed_cert() -> Result<CertifiedKey<KeyPair>, CertError> {
    let mut params = CertificateParams::new(vec![
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "localhost".to_string(),
    ])?;
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2120, 1, 1);
    params.is_ca = IsCa::ExplicitNoCa;

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "dns-quorum-filter local DoH");
    params.distinguished_name = distinguished_name;

    let signing_key = KeyPair::generate()?;
    let cert = params.self_signed(&signing_key)?;
    Ok(CertifiedKey { cert, signing_key })
}

#[cfg(test)]
mod tests {
    use super::generate_self_signed_cert;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::{FromDer, X509Certificate};

    /// Generates a cert and hands back its owned DER bytes — callers parse
    /// from that owned buffer themselves, so the parsed `X509Certificate<'_>`
    /// can borrow from a value that outlives the calling test function.
    fn generate_der() -> Vec<u8> {
        match generate_self_signed_cert() {
            Ok(ck) => ck.cert.der().to_vec(),
            Err(err) => panic!("generation must succeed: {err}"),
        }
    }

    fn parse(der: &[u8]) -> X509Certificate<'_> {
        match X509Certificate::from_der(der) {
            Ok((_, cert)) => cert,
            Err(err) => panic!("generated DER must parse as a valid X.509 certificate: {err}"),
        }
    }

    #[test]
    fn generated_cert_has_exactly_the_san_entries_spec_requires() {
        let der = generate_der();
        let cert = parse(&der);

        let san_ext = cert
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => Some(san),
                _ => None,
            })
            .unwrap_or_else(|| panic!("certificate must carry a SubjectAlternativeName extension"));

        assert_eq!(
            san_ext.general_names.len(),
            3,
            "expected exactly 3 SAN entries, got {:?}",
            san_ext.general_names
        );

        match &san_ext.general_names[0] {
            GeneralName::IPAddress(bytes) => assert_eq!(*bytes, [127, 0, 0, 1]),
            other => {
                panic!("first SAN entry must be the typed IPv4 address 127.0.0.1, got {other:?}")
            }
        }
        match &san_ext.general_names[1] {
            GeneralName::IPAddress(bytes) => {
                assert_eq!(*bytes, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            }
            other => panic!("second SAN entry must be the typed IPv6 address ::1, got {other:?}"),
        }
        match &san_ext.general_names[2] {
            GeneralName::DNSName(name) => assert_eq!(*name, "localhost"),
            other => panic!("third SAN entry must be the typed DNS name localhost, got {other:?}"),
        }
    }

    #[test]
    fn generated_cert_is_a_leaf_never_a_ca() {
        let der = generate_der();
        let cert = parse(&der);

        // `ExplicitNoCa` (not the plain `NoCa` default) makes rcgen encode the
        // `BasicConstraints` extension with `cA=FALSE` explicitly, so this
        // asserts the actual encoded bytes rather than merely the absence of
        // an extension — see this module's doc comment for why that
        // distinction matters.
        let basic_constraints = cert
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::BasicConstraints(bc) => Some(bc),
                _ => None,
            })
            .unwrap_or_else(|| {
                panic!("certificate must explicitly carry a BasicConstraints extension")
            });
        assert!(
            !basic_constraints.ca,
            "SPEC.md §2: this cert must never be a CA"
        );
        assert!(!cert.is_ca(), "SPEC.md §2: this cert must never be a CA");

        let carries_key_cert_sign = cert.extensions().iter().any(|ext| {
            matches!(
                ext.parsed_extension(),
                ParsedExtension::KeyUsage(usage) if usage.key_cert_sign()
            )
        });
        assert!(
            !carries_key_cert_sign,
            "a leaf cert must never carry the keyCertSign KeyUsage bit"
        );
    }

    #[test]
    fn generated_cert_carries_an_identifying_subject_not_rcgens_placeholder_cn() {
        let der = generate_der();
        let cert = parse(&der);

        // T-49's manual trust-store install and T-69/T-70's rotation/removal
        // all depend on a human (or a future automated uninstaller) being
        // able to recognize this cert in the OS store — rcgen's own
        // placeholder CN ("rcgen self signed cert") would not identify it as
        // belonging to this project.
        let subject = cert.subject().to_string();
        assert!(
            subject.contains("dns-quorum-filter"),
            "subject must identify this project, got {subject:?}"
        );
    }

    #[test]
    fn generated_cert_uses_the_stated_hundred_year_validity_window_not_rcgens_raw_default() {
        let der = generate_der();
        let cert = parse(&der);

        let validity = cert.validity();
        assert_eq!(
            validity.not_before.timestamp(),
            rcgen::date_time_ymd(2020, 1, 1).unix_timestamp(),
            "not_before must be the stated 2020-01-01 anchor, not rcgen's raw 1975 default"
        );
        assert_eq!(
            validity.not_after.timestamp(),
            rcgen::date_time_ymd(2120, 1, 1).unix_timestamp(),
            "not_after must be the stated 2120-01-01 anchor, not rcgen's raw 4096 default"
        );
    }
}
