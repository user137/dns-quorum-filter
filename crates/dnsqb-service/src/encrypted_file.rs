//! T-146: authenticated encryption for this crate's opt-in on-disk
//! persistence (SPEC.md §6 — the query log; §4 — the quorum-verdict cache,
//! T-97). The symmetric key comes from the OS secret store
//! ([`crate::key_store`]), never the disk; this module is the pure codec
//! around it.
//!
//! `XChaCha20Poly1305` — the 192-bit random nonce retires the birthday-bound
//! reuse question the 96-bit variant would raise for a file rewritten on
//! every flush. AEAD, so a truncated or bit-flipped file fails [`open`]
//! loudly rather than yielding partial plaintext.
//!
//! File layout — a 6-byte cleartext header, validated *before* the AEAD open
//! so a future format bump is a named [`EncryptedFileError::UnsupportedVersion`],
//! not an authentication failure indistinguishable from tampering (the same
//! "loud hard cutover" discipline as T-144 / T-145 / T-148):
//!
//! ```text
//! offset 0   magic    b"DQF1"                       4 bytes
//! offset 4   kind     0x01 query-log / 0x02 cache   1 byte
//! offset 5   version  0x01                          1 byte
//! offset 6   nonce    XChaCha20Poly1305             24 bytes
//! offset 30  ct       seal(key, nonce, plaintext, aad = header[0..6])
//! ```
//!
//! The 6-byte header is the AEAD associated data, so `magic` / `kind` /
//! `version` are also cryptographically bound: a cache file cannot be
//! replayed as a log file, and a version downgrade stays rejected even if the
//! explicit pre-check above were ever removed.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// File-format identifier, byte 0..4 of every container.
const MAGIC: [u8; 4] = *b"DQF1";
/// Current on-disk format version (byte 5). A hard cutover on bump — see the
/// module docs and [`EncryptedFileError::UnsupportedVersion`].
const VERSION: u8 = 1;
/// Cleartext header length: `magic` (4) + `kind` (1) + `version` (1).
const HEADER_LEN: usize = 6;
/// `XChaCha20Poly1305` nonce length.
const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length, always appended by the AEAD.
const TAG_LEN: usize = 16;
/// Smallest possible valid container: header + nonce + the tag over an empty
/// plaintext. `open` rejects anything shorter before it indexes past it, so
/// the two `split_at` calls below are provably in bounds from this constant
/// alone.
const MIN_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// Which persisted store a container holds — bound into the AEAD header so
/// one kind's file can never be opened as the other's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// `query-log.enc` (SPEC.md §6, T-146).
    QueryLog,
    /// `cache.enc` (SPEC.md §4, T-97).
    Cache,
}

impl FileKind {
    /// The `kind` header byte for this store.
    const fn tag(self) -> u8 {
        match self {
            FileKind::QueryLog => 0x01,
            FileKind::Cache => 0x02,
        }
    }
}

/// Failure modes of [`seal`] / [`open`]. Deliberately payload-free (no
/// plaintext, no key bytes, no domain names) — safe to `tracing::warn!` in a
/// diagnostic-log context, unlike the data these containers hold.
#[derive(Debug, thiserror::Error)]
pub enum EncryptedFileError {
    /// The OS RNG failed while producing a nonce. The write is aborted rather
    /// than risk a reused or predictable nonce — nonce reuse under a fixed
    /// key breaks Poly1305 authentication outright and leaks the XOR of the
    /// plaintexts.
    #[error("the OS random number generator failed while producing a nonce")]
    Rng,
    /// The plaintext is too large for the AEAD to encrypt (a `usize`-overflow
    /// bound, ~256 GiB) — unreachable for this crate's bounded ring
    /// buffer / cache, but `encrypt` returns a real `Result`.
    #[error("plaintext is too large to encrypt")]
    Encrypt,
    /// The container is shorter than [`MIN_LEN`], or its cleartext header
    /// (`magic` / `kind`) is not what was expected.
    #[error("persisted file is truncated or has an unrecognized header")]
    Malformed,
    /// The header names a format version this build does not understand — a
    /// forward-incompatible file, distinct from tampering.
    #[error("persisted file format version {found} is not supported (this build reads {VERSION})")]
    UnsupportedVersion {
        /// The version byte found in the header.
        found: u8,
    },
    /// AEAD authentication failed: wrong key, corrupted or truncated
    /// ciphertext, or deliberate tampering. Deliberately does not distinguish
    /// which.
    #[error("persisted file failed authentication (wrong key or corrupted data)")]
    Decrypt,
}

/// Encrypts `plaintext` into a self-describing container (see the module
/// docs) for the store identified by `kind`, under the 32-byte `key`.
///
/// # Errors
///
/// [`EncryptedFileError::Rng`] if the OS RNG fails (the write must then be
/// abandoned, never retried with a fallback nonce); [`EncryptedFileError::Encrypt`]
/// if `plaintext` exceeds the AEAD's length bound.
pub fn seal(
    key: &[u8; 32],
    kind: FileKind,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptedFileError> {
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(&MAGIC);
    header[4] = kind.tag();
    header[5] = VERSION;

    let mut nonce = [0u8; NONCE_LEN];
    // A failing OS RNG aborts the write - never a zero or predictable nonce.
    getrandom::fill(&mut nonce).map_err(|_| EncryptedFileError::Rng)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncryptedFileError::Encrypt)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| EncryptedFileError::Encrypt)?;

    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts a container produced by [`seal`], checking that it is well-formed,
/// of a supported version, and of the expected `kind`, before authenticating
/// and returning the plaintext.
///
/// # Errors
///
/// [`EncryptedFileError::Malformed`] if `bytes` is too short or its header
/// `magic` / `kind` is wrong; [`EncryptedFileError::UnsupportedVersion`] if
/// the version byte is not [`VERSION`]; [`EncryptedFileError::Decrypt`] if
/// authentication fails (wrong key or corrupted data).
pub fn open(
    key: &[u8; 32],
    expected_kind: FileKind,
    bytes: &[u8],
) -> Result<Vec<u8>, EncryptedFileError> {
    if bytes.len() < MIN_LEN {
        return Err(EncryptedFileError::Malformed);
    }
    let (header, rest) = bytes.split_at(HEADER_LEN);
    if header[0..4] != MAGIC || header[4] != expected_kind.tag() {
        return Err(EncryptedFileError::Malformed);
    }
    if header[5] != VERSION {
        return Err(EncryptedFileError::UnsupportedVersion { found: header[5] });
    }
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    // `nonce` is exactly `NONCE_LEN` (the `split_at` above), so this
    // conversion never actually fails; map it rather than unwrap.
    let nonce = XNonce::try_from(nonce).map_err(|_| EncryptedFileError::Decrypt)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncryptedFileError::Decrypt)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| EncryptedFileError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::{open, seal, EncryptedFileError, FileKind, HEADER_LEN, MIN_LEN};

    const KEY: [u8; 32] = [7u8; 32];

    /// `seal` in a test context - `#![deny(clippy::expect_used)]` applies to
    /// inline test modules in this crate, so this is the panic-on-`Err`
    /// helper the suite uses instead of `.expect(...)`.
    fn seal_ok(kind: FileKind, plaintext: &[u8]) -> Vec<u8> {
        match seal(&KEY, kind, plaintext) {
            Ok(bytes) => bytes,
            Err(err) => panic!("seal must succeed: {err}"),
        }
    }

    #[test]
    fn seal_then_open_round_trips_the_plaintext_and_kind() {
        let plaintext = b"example.com decision=ALLOWED source=QUORUM";
        let sealed = seal_ok(FileKind::QueryLog, plaintext);
        match open(&KEY, FileKind::QueryLog, &sealed) {
            Ok(got) => assert_eq!(got, plaintext),
            Err(err) => panic!("open must return the sealed plaintext: {err}"),
        }
    }

    #[test]
    fn sealed_bytes_do_not_contain_the_plaintext() {
        // Discriminating test: `seal` returning `Ok` proves nothing about
        // confidentiality. Same shape as
        // `overrides::tests::invalid_entry_debug_output_never_contains_the_raw_pattern_text`.
        let sentinel = "super-secret-internal-hostname.example";
        let sealed = seal_ok(FileKind::QueryLog, sentinel.as_bytes());
        let needle = sentinel.as_bytes();
        assert!(
            !sealed.windows(needle.len()).any(|w| w == needle),
            "the sealed container must not contain the plaintext in the clear"
        );
    }

    #[test]
    fn two_seals_of_the_same_plaintext_differ_by_nonce() {
        let plaintext = b"same input twice";
        let a = seal_ok(FileKind::Cache, plaintext);
        let b = seal_ok(FileKind::Cache, plaintext);
        assert_ne!(a, b, "each seal draws a fresh random nonce");
        match (
            open(&KEY, FileKind::Cache, &a),
            open(&KEY, FileKind::Cache, &b),
        ) {
            (Ok(pa), Ok(pb)) => {
                assert_eq!(pa, plaintext);
                assert_eq!(pb, plaintext);
            }
            other => panic!("both must still decrypt to the same plaintext, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_a_container_shorter_than_the_minimum() {
        let short = vec![0u8; MIN_LEN - 1];
        assert!(matches!(
            open(&KEY, FileKind::QueryLog, &short),
            Err(EncryptedFileError::Malformed)
        ));
        assert!(matches!(
            open(&KEY, FileKind::QueryLog, &[]),
            Err(EncryptedFileError::Malformed)
        ));
    }

    #[test]
    fn open_rejects_a_wrong_magic() {
        let mut sealed = seal_ok(FileKind::QueryLog, b"payload");
        sealed[0] ^= 0xff;
        assert!(matches!(
            open(&KEY, FileKind::QueryLog, &sealed),
            Err(EncryptedFileError::Malformed)
        ));
    }

    #[test]
    fn open_rejects_the_wrong_file_kind() {
        let sealed = seal_ok(FileKind::QueryLog, b"payload");
        assert!(
            matches!(
                open(&KEY, FileKind::Cache, &sealed),
                Err(EncryptedFileError::Malformed)
            ),
            "a query-log container must not open as a cache container"
        );
    }

    #[test]
    fn open_reports_an_unsupported_version_distinctly_from_tampering() {
        let mut sealed = seal_ok(FileKind::QueryLog, b"payload");
        sealed[5] = 2;
        match open(&KEY, FileKind::QueryLog, &sealed) {
            Err(EncryptedFileError::UnsupportedVersion { found: 2 }) => {}
            other => panic!("expected UnsupportedVersion {{ found: 2 }}, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_a_bit_flip_in_the_ciphertext() {
        let mut sealed = seal_ok(FileKind::QueryLog, b"a longer payload here");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(
            open(&KEY, FileKind::QueryLog, &sealed),
            Err(EncryptedFileError::Decrypt)
        ));
    }

    #[test]
    fn open_rejects_a_bit_flip_in_the_nonce() {
        let mut sealed = seal_ok(FileKind::QueryLog, b"payload");
        sealed[HEADER_LEN] ^= 0x01;
        assert!(matches!(
            open(&KEY, FileKind::QueryLog, &sealed),
            Err(EncryptedFileError::Decrypt)
        ));
    }

    #[test]
    fn open_rejects_truncation_of_the_ciphertext_tail() {
        let sealed = seal_ok(FileKind::QueryLog, b"a payload long enough to cut");
        let cut = &sealed[..sealed.len() - 1];
        assert!(matches!(
            open(&KEY, FileKind::QueryLog, cut),
            Err(EncryptedFileError::Decrypt)
        ));
    }

    #[test]
    fn open_with_the_wrong_key_fails_authentication() {
        let sealed = seal_ok(FileKind::QueryLog, b"payload");
        let wrong = [8u8; 32];
        assert!(matches!(
            open(&wrong, FileKind::QueryLog, &sealed),
            Err(EncryptedFileError::Decrypt)
        ));
    }

    #[test]
    fn round_trips_an_empty_plaintext() {
        let sealed = seal_ok(FileKind::Cache, b"");
        assert_eq!(sealed.len(), MIN_LEN, "header + nonce + tag, no body");
        match open(&KEY, FileKind::Cache, &sealed) {
            Ok(got) => assert!(got.is_empty()),
            Err(err) => panic!("open of an empty-body container must succeed: {err}"),
        }
    }

    #[test]
    fn the_header_is_bound_as_associated_data() {
        // Rewrite the kind byte to a value that matches a different
        // expected_kind. The cleartext pre-check now passes, but the
        // ciphertext was sealed under the original header - so authentication
        // must still fail (the header is the AEAD's associated data).
        let mut sealed = seal_ok(FileKind::QueryLog, b"payload");
        sealed[4] = FileKind::Cache.tag();
        assert!(
            matches!(
                open(&KEY, FileKind::Cache, &sealed),
                Err(EncryptedFileError::Decrypt)
            ),
            "rewriting the kind byte to match a different expected_kind must not authenticate"
        );
    }
}
