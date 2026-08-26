//! Override lists: allowlist/blocklist, suffix wildcard match (SPEC.md §5,
//! T-37). `Allowlist` always wins over `Blocklist` on conflict (§5). Not yet
//! wired to `resolve()`/the request pipeline (T-39), and has no `save()` —
//! SPEC.md §5 describes the file as "редагований і вручну" (manually edited)
//! and no writer exists yet (T-46/T-47); adding one now would be speculative.
//!
//! On-disk format is TOML (T-145, superseding T-37's JSON) — same
//! `ssh_config`/`my.cnf`-style hand-editability motivation as `config.rs`.
//! **Unlike `config.rs`'s `ConfigError::Toml`, this module's parse-error
//! variant carries no payload at all.** `overrides.toml` is nothing but
//! domain names, and `toml::de::Error`'s `Display`/`Debug` both render an
//! annotated snippet of the offending input line (confirmed empirically via
//! a scratch probe, not assumed) — wrapping it here would newly leak a
//! domain into the service diagnostic log the moment a caller logs the
//! error, the exact failure class `InvalidReason` already exists to prevent
//! (see that type's own doc comment). A fixed, payload-free message is
//! structurally incapable of carrying a domain, the same reasoning, applied
//! one layer up.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use hickory_proto::ProtoError;
use serde::Deserialize;

use crate::normalize_domain;

/// Which override list an entry belongs to (SPEC.md §5, `diagrams/ui-dto-model.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    /// Domain is always allowed, regardless of the quorum verdict.
    Allowlist,
    /// Domain is always blocked, even if no upstream provider blocks it.
    Blocklist,
}

/// One normalized override-list entry (SPEC.md §5, `diagrams/ui-dto-model.md`'s
/// `OverrideEntry` DTO — field names match that diagram literally).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideEntry {
    /// Normalized domain (T-38), never carries a `*.` prefix.
    pub domain: String,
    /// `true` if this entry also matches subdomains (suffix match, not regex,
    /// not substring — SPEC.md §5).
    pub is_wildcard: bool,
    /// Which list this entry belongs to.
    pub list: ListKind,
}

/// Coarse reason a pattern line failed to parse (SPEC.md "Наскрізні вимоги":
/// service diagnostic logs never contain domain names).
///
/// Deliberately carries **no** pattern/domain text at all — not
/// `hickory-proto`'s own `ProtoError`, not a formatted message. A first
/// attempt at this type stored `reason: ProtoError` and hand-redacted
/// [`InvalidEntry`]'s `Debug` impl to hide `raw` — but `ProtoError`'s own
/// `Debug`/`Display` still printed the domain (both this module's own error
/// messages and, more insidiously, `hickory-proto`'s `Label::from_ascii`
/// itself formats a decode failure as `"Malformed label: {s}"`, embedding
/// the label text) — the leak just moved to the next field over (caught by
/// advisor review before commit, not by a lint). A coarse, closed enum with
/// fixed per-variant messages is structurally incapable of carrying a
/// domain, rather than relying on every field of the type being individually
/// audited for what it might print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidReason {
    /// Pattern had `*` somewhere other than a single leading `"*."`.
    #[error("pattern contains '*' other than a single leading \"*.\"")]
    UnexpectedWildcard,
    /// Pattern normalized to an empty domain (e.g. a bare `"*."` or `""`).
    #[error("pattern normalizes to an empty domain")]
    EmptyDomain,
    /// The domain itself is not syntactically valid.
    #[error("domain is not syntactically valid")]
    InvalidDomain,
}

/// One override-list file line that failed to parse as a valid domain
/// pattern, returned by [`OverrideLists::load`] alongside the entries that
/// did parse (design decision 9, plan) — one typo in a manually edited file
/// must not silently empty the whole list.
///
/// Deliberately has no `Display`/`#[error]` impl, **and its `Debug` impl is
/// hand-written to redact `raw`**, rather than derived: SPEC.md "Наскрізні
/// вимоги" says service diagnostic logs never contain domain names, with no
/// carve-out for a user-authored config-file domain, and in a `tracing`
/// codebase the accidental leak path is `Debug` (`tracing::warn!(?entry)` or
/// `"{entry:?}"`), not just `Display` — a derived `Debug` would print `raw`
/// and defeat the guard as surely as a `Display` impl would. `reason` is
/// [`InvalidReason`], which structurally cannot carry a domain either way,
/// so redacting only `raw` here is sufficient. The `raw` field is still
/// public for a caller that surfaces it directly to the user without going
/// through `tracing` — e.g. a future override-list editor (T-47) — but
/// reaching it requires deliberate field access, not an accidental log/debug
/// print (same shape as `upstream::UpstreamError`/`error_kind()`, CLAUDE.md
/// gotchas).
pub struct InvalidEntry {
    /// The raw, unparsed line from the file.
    pub raw: String,
    /// Which list this line came from.
    pub list: ListKind,
    /// Why it failed to parse.
    pub reason: InvalidReason,
}

impl fmt::Debug for InvalidEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvalidEntry")
            .field("raw", &"<redacted>")
            .field("list", &self.list)
            .field("reason", &self.reason)
            .finish()
    }
}

/// Errors loading the override-list file itself (not a single bad entry —
/// see [`InvalidEntry`] for that).
#[derive(Debug, thiserror::Error)]
pub enum OverrideError {
    /// Failed to read the file (anything other than "file does not exist" —
    /// a missing file is `Ok`, see [`OverrideLists::load`]).
    #[error("failed to read override list file: {0}")]
    Io(#[source] io::Error),
    /// The file's contents are not valid TOML in the expected shape.
    ///
    /// Deliberately carries **no** payload — `toml::de::Error`'s own
    /// `Display`/`Debug` render an annotated snippet of the offending input
    /// line, and this file is nothing but domain names (see this module's
    /// own doc comment for the empirical confirmation and the full
    /// reasoning, same shape as [`InvalidReason`]).
    #[error("failed to parse override list TOML")]
    Parse,
}

/// On-disk shape (SPEC.md §5: "простий текстовий/TOML-файл", "редагований і
/// вручну") — two plain string arrays, not a literal `Vec<OverrideEntry>`.
/// A wildcard entry is written as `*.example.com` (UI-SPEC.md §3.3's own
/// user-facing convention), not as a separate `is_wildcard` field — simpler
/// for a human to hand-edit. This shape is a translation layer, not the
/// in-memory `OverrideEntry`/`OverrideLists` model (same separation as
/// `CacheEntry` never being serialized directly).
///
/// `deny_unknown_fields`: a misspelled key (`"blockList"`, `"block_list"`,
/// ...) must fail the whole load loudly (`OverrideError::Parse`), not parse
/// as `Ok` with the misspelled list silently defaulted to empty via
/// `#[serde(default)]` — that would be silent total loss of a list, a worse
/// outcome than the single-bad-domain case design decision 9 guards against,
/// and undetectable by the caller (caught by advisor review before commit).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverrideListsFile {
    #[serde(default)]
    allowlist: Vec<String>,
    #[serde(default)]
    blocklist: Vec<String>,
}

/// Allowlist/blocklist, held in memory (SPEC.md §5).
#[derive(Debug)]
pub struct OverrideLists {
    entries: Vec<OverrideEntry>,
}

/// Splits a raw pattern line into `(normalized_domain, is_wildcard)`.
///
/// A single leading `"*."` marks the pattern as matching subdomains (SPEC.md
/// §5); any other occurrence of `*` — a bare leading `*` not followed by `.`,
/// or a second `*` after the leading one is stripped — is rejected outright,
/// **before** the remainder ever reaches `normalize_domain`. This is a
/// deliberately stricter check than relying on `hickory-proto`'s own IDNA
/// path: `hickory-proto`'s `Label::from_utf8` (`label.rs`, vendored 0.26.1)
/// treats a label equal to exactly `"*"` as the legal RFC 1034 wildcard-RR
/// label and accepts it silently — passing an unstripped `"*.*.example.com"`
/// through would "normalize" into a string that still contains a literal
/// `*`, which can never match a real query domain (a silent, unnoticed
/// no-op rule). Guarding on `body.contains('*')` here makes the rejection
/// provable from this line alone, independent of that IDNA-path behavior.
///
/// Returns a coarse [`InvalidReason`] rather than propagating
/// `normalize_domain`'s `ProtoError` directly — that error's own message can
/// embed the invalid text (`hickory-proto`'s `Label::from_ascii` formats a
/// decode failure as `"Malformed label: {s}"`), so it is deliberately
/// discarded here rather than threaded through to a caller that might log it
/// (see [`InvalidReason`]'s doc comment).
///
/// # Errors
///
/// Returns `Err` if the pattern contains `*` anywhere other than a single
/// leading `"*."`, if the remaining domain is not syntactically valid, or if
/// it normalizes to an empty string.
fn parse_pattern(raw: &str) -> Result<(String, bool), InvalidReason> {
    let (body, is_wildcard) = match raw.strip_prefix("*.") {
        Some(rest) => (rest, true),
        None => (raw, false),
    };
    if body.contains('*') {
        return Err(InvalidReason::UnexpectedWildcard);
    }
    let domain = normalize_domain(body).map_err(|_| InvalidReason::InvalidDomain)?;
    if domain.is_empty() {
        // `Name::from_utf8("")` normalizes to the DNS root, not an error —
        // empirically confirmed while writing this function's tests. Left
        // unguarded, a bare `"*."` (or `""`) line would "succeed" into an
        // entry that can never match a real query domain: the same silent
        // no-op-rule risk the leading-`body.contains('*')` guard above
        // exists to prevent, just via a different malformed input shape.
        return Err(InvalidReason::EmptyDomain);
    }
    Ok((domain, is_wildcard))
}

/// Suffix-label match (SPEC.md §5) — not regex, not substring. A wildcard
/// entry also matches its own apex domain (`*.example.com` matches
/// `example.com` itself, not only subdomains) — SPEC.md only specifies the
/// negative example (`evil-example.com` must not match `*.example.com`),
/// this is the industry-convention choice for the unstated apex case (see
/// plan decision 7), not RFC 1034 §4.3.3 wildcard-RR semantics, which don't
/// apply to override lists.
fn rule_matches(query: &str, entry: &OverrideEntry) -> bool {
    query == entry.domain || (entry.is_wildcard && query.ends_with(&format!(".{}", entry.domain)))
}

impl OverrideLists {
    /// No entries in either list.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Test-only constructor from already-built entries (T-39's
    /// `pipeline.rs` tests need fixtures with specific entries, but
    /// `entries` is otherwise private by design — no production code
    /// constructs an `OverrideLists` any way other than `empty()`/`load()`).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_entries_for_test(entries: Vec<OverrideEntry>) -> Self {
        Self { entries }
    }

    /// SPEC.md §5 steps 1-2, combined: `Allowlist` is checked first (and, on
    /// conflict, wins), then `Blocklist`. `domain` is normalized internally —
    /// callers pass a raw query domain, not a pre-normalized one.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `domain` is not a syntactically valid domain name.
    pub fn decision(&self, domain: &str) -> Result<Option<ListKind>, ProtoError> {
        let normalized = normalize_domain(domain)?;
        let matches = |kind: ListKind| {
            self.entries
                .iter()
                .any(|e| e.list == kind && rule_matches(&normalized, e))
        };
        if matches(ListKind::Allowlist) {
            return Ok(Some(ListKind::Allowlist));
        }
        if matches(ListKind::Blocklist) {
            return Ok(Some(ListKind::Blocklist));
        }
        Ok(None)
    }

    /// Domains present as a literal entry in both lists (SPEC.md §5,
    /// UI-SPEC.md §3.3's conflict-highlight requirement) — exact string
    /// match on `domain`, not suffix-overlap semantics (e.g. an exact entry
    /// `sub.example.com` in one list and a wildcard entry `*.example.com` in
    /// the other are not reported here, even though they'd behaviorally
    /// overlap). The UI highlight itself is T-47's job; this is the pure
    /// detector it will call.
    #[must_use]
    pub fn conflicts(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.list == ListKind::Allowlist)
            .filter(|allow| {
                self.entries
                    .iter()
                    .any(|e| e.list == ListKind::Blocklist && e.domain == allow.domain)
            })
            .map(|e| e.domain.as_str())
            .collect()
    }

    /// Loads override lists from `path` (SPEC.md §5's app-data JSON file — the
    /// path itself is a parameter, not resolved here, same as
    /// `listener::bind_listener`'s port parameter; the OS-specific app-data
    /// directory is a wiring concern for whoever calls this).
    ///
    /// A missing file is **not** an error — it means no lists exist yet
    /// (first run) — `load` returns empty lists instead (design decision 5,
    /// plan). A single line that fails to parse as a valid domain pattern is
    /// also not fatal to the whole load — it's skipped and returned in the
    /// second element of the tuple as an [`InvalidEntry`] (design decision 9)
    /// — one typo in a hand-edited blocklist must not silently empty the
    /// entire blocklist. Only I/O failures other than "not found", or a file
    /// whose TOML isn't even shaped like `allowlist = [...]` /
    /// `blocklist = [...]`, fail the whole load.
    ///
    /// This does blocking file I/O — call at startup or on a
    /// list-changed event, not from a per-query hot path.
    ///
    /// # Errors
    ///
    /// Returns [`OverrideError::Io`] for a read failure other than "file not
    /// found", or [`OverrideError::Parse`] if the file's top-level TOML shape
    /// doesn't match `allowlist = [...]` / `blocklist = [...]`.
    pub fn load(path: &Path) -> Result<(Self, Vec<InvalidEntry>), OverrideError> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok((Self::empty(), Vec::new()));
            }
            Err(err) => return Err(OverrideError::Io(err)),
        };
        let file: OverrideListsFile = toml::from_str(&raw).map_err(|_| OverrideError::Parse)?;

        let mut entries = Vec::new();
        let mut invalid = Vec::new();
        for (patterns, kind) in [
            (file.allowlist, ListKind::Allowlist),
            (file.blocklist, ListKind::Blocklist),
        ] {
            for raw_pattern in patterns {
                match parse_pattern(&raw_pattern) {
                    Ok((domain, is_wildcard)) => entries.push(OverrideEntry {
                        domain,
                        is_wildcard,
                        list: kind,
                    }),
                    Err(reason) => invalid.push(InvalidEntry {
                        raw: raw_pattern,
                        list: kind,
                        reason,
                    }),
                }
            }
        }
        Ok((Self { entries }, invalid))
    }
}

/// SPEC.md §5 (T-40): entries whose presence differs between `before` and
/// `after` — added by a reload, removed by one, or moved between lists
/// (`OverrideEntry`'s own `Eq` includes `list`, so a move shows up as one
/// entry removed from its old list's set and a different-but-equal-looking
/// one added to the new list's set). Both directions are returned, not only
/// newly-added entries — see `pipeline::invalidate_changed`'s doc comment
/// for why.
///
/// `pub(crate)`, not `pub`: its only caller is `pipeline::invalidate_changed`
/// in this same crate — no reason to widen the public surface for a reader
/// that doesn't exist yet (same restraint as `QuorumOutcome` omitting
/// `incomplete` in T-39, and the two over-exposure corrections in T-37).
pub(crate) fn changed_entries<'a>(
    before: &'a OverrideLists,
    after: &'a OverrideLists,
) -> Vec<&'a OverrideEntry> {
    before
        .entries
        .iter()
        .filter(|e| !after.entries.contains(e))
        .chain(after.entries.iter().filter(|e| !before.entries.contains(e)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        changed_entries, parse_pattern, rule_matches, InvalidEntry, InvalidReason, ListKind,
        OverrideEntry, OverrideError, OverrideLists,
    };
    use std::io::Write as _;

    fn entry(domain: &str, is_wildcard: bool, list: ListKind) -> OverrideEntry {
        OverrideEntry {
            domain: domain.to_string(),
            is_wildcard,
            list,
        }
    }

    #[test]
    fn parse_pattern_exact_domain_is_not_wildcard() {
        let (domain, is_wildcard) = match parse_pattern("Example.COM.") {
            Ok(result) => result,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(domain, "example.com");
        assert!(!is_wildcard);
    }

    #[test]
    fn parse_pattern_wildcard_prefix_is_stripped_and_normalized() {
        let (domain, is_wildcard) = match parse_pattern("*.Example.COM.") {
            Ok(result) => result,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(domain, "example.com");
        assert!(is_wildcard);
    }

    #[test]
    fn parse_pattern_rejects_bare_leading_star_without_dot() {
        assert!(parse_pattern("*example.com").is_err());
    }

    #[test]
    fn parse_pattern_rejects_a_second_star_after_the_leading_wildcard() {
        assert!(parse_pattern("*.*.example.com").is_err());
    }

    #[test]
    fn parse_pattern_rejects_invalid_domain_after_stripping_prefix() {
        assert!(parse_pattern("*.").is_err());
    }

    #[test]
    fn rule_matches_wildcard_matches_apex_and_subdomain_not_lookalike() {
        let wildcard = entry("example.com", true, ListKind::Blocklist);
        assert!(rule_matches("example.com", &wildcard));
        assert!(rule_matches("sub.example.com", &wildcard));
        assert!(!rule_matches("evil-example.com", &wildcard));
    }

    #[test]
    fn rule_matches_exact_entry_does_not_match_subdomain() {
        let exact = entry("example.com", false, ListKind::Blocklist);
        assert!(rule_matches("example.com", &exact));
        assert!(!rule_matches("sub.example.com", &exact));
    }

    #[test]
    fn decision_allowlist_wins_on_conflict() {
        let lists = OverrideLists {
            entries: vec![
                entry("example.com", false, ListKind::Allowlist),
                entry("example.com", false, ListKind::Blocklist),
            ],
        };
        let decision = match lists.decision("example.com") {
            Ok(decision) => decision,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(decision, Some(ListKind::Allowlist));
    }

    #[test]
    fn decision_is_none_when_no_rule_matches() {
        let lists = OverrideLists {
            entries: vec![entry("example.com", false, ListKind::Blocklist)],
        };
        let decision = match lists.decision("other.com") {
            Ok(decision) => decision,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(decision, None);
    }

    #[test]
    fn conflicts_reports_identical_domain_string_in_both_lists() {
        let lists = OverrideLists {
            entries: vec![
                entry("example.com", false, ListKind::Allowlist),
                entry("example.com", true, ListKind::Blocklist),
            ],
        };
        assert_eq!(lists.conflicts(), vec!["example.com"]);
    }

    #[test]
    fn conflicts_ignores_a_suffix_only_overlap() {
        // Allowlist has the apex, blocklist has a different literal string
        // (a subdomain) — behaviorally these might overlap under wildcard
        // semantics, but conflicts() only reports identical domain strings.
        let lists = OverrideLists {
            entries: vec![
                entry("example.com", true, ListKind::Allowlist),
                entry("sub.example.com", false, ListKind::Blocklist),
            ],
        };
        assert!(lists.conflicts().is_empty());
    }

    #[test]
    fn load_of_missing_file_returns_empty_lists_not_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "dnsqb-overrides-test-missing-{}",
            std::process::id()
        ));
        let path = dir.join("does-not-exist.json");
        let (lists, invalid) = match OverrideLists::load(&path) {
            Ok(result) => result,
            Err(err) => panic!("expected Ok: {err}"),
        };
        let decision = match lists.decision("example.com") {
            Ok(decision) => decision,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(decision, None);
        assert!(invalid.is_empty());
    }

    #[test]
    fn load_rejects_structurally_invalid_toml() {
        let mut file = match tempfile_with_contents("not valid toml ===") {
            Ok(file) => file,
            Err(err) => panic!("failed to create temp file: {err}"),
        };
        let path = file.path().to_path_buf();
        if let Err(err) = file.flush() {
            panic!("failed to flush temp file: {err}");
        }
        match OverrideLists::load(&path) {
            Err(OverrideError::Parse) => {}
            other => panic!("expected OverrideError::Parse, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_a_misspelled_top_level_key_instead_of_silently_dropping_that_list() {
        let toml = "allowlist = [\"example.com\"]\nblockList = [\"bad.example.com\"]\n";
        let file = match tempfile_with_contents(toml) {
            Ok(file) => file,
            Err(err) => panic!("failed to create temp file: {err}"),
        };
        match OverrideLists::load(file.path()) {
            Err(OverrideError::Parse) => {}
            other => panic!("expected OverrideError::Parse, got {other:?}"),
        }
    }

    #[test]
    fn load_error_display_never_contains_the_raw_toml_input() {
        // Empirical proof that OverrideError::Parse's payload-free design
        // (this module's own doc comment) actually holds: a scratch probe
        // confirmed toml::de::Error's own Display/Debug render an annotated
        // snippet of the offending input line, so a domain in a malformed
        // overrides.toml must never survive into OverrideError's own Display.
        let telltale = "sentinel-marker.broken.example";
        let toml = format!("blocklist = [\"{telltale}\n");
        let file = match tempfile_with_contents(&toml) {
            Ok(file) => file,
            Err(err) => panic!("failed to create temp file: {err}"),
        };
        let Err(err) = OverrideLists::load(file.path()) else {
            panic!("expected the malformed TOML to fail to load")
        };
        let display_output = format!("{err}");
        assert!(
            !display_output.contains(telltale),
            "error Display must not contain the raw TOML input: {display_output}"
        );
        // Display alone isn't enough — in a tracing codebase the accidental
        // leak path is Debug (`tracing::warn!(?err)`/`"{err:?}"`), not just
        // Display (same reasoning as InvalidEntry's own Debug guard above).
        // This also catches a future regression the Display assertion alone
        // would miss: `#[source]` isn't rendered by thiserror's `#[error]`
        // message, so adding a `toml::de::Error` payload back to this
        // variant while keeping the same `#[error("...")]` text would pass
        // the Display assertion and still leak via Debug.
        let debug_output = format!("{err:?}");
        assert!(
            !debug_output.contains(telltale),
            "error Debug must not contain the raw TOML input: {debug_output}"
        );
    }

    #[test]
    fn load_of_empty_file_and_single_key_file_still_succeeds() {
        for toml in ["", "allowlist = [\"example.com\"]\n"] {
            let file = match tempfile_with_contents(toml) {
                Ok(file) => file,
                Err(err) => panic!("failed to create temp file for {toml:?}: {err}"),
            };
            if let Err(err) = OverrideLists::load(file.path()) {
                panic!("expected Ok for {toml:?}: {err}");
            }
        }
    }

    #[test]
    fn load_normalizes_and_splits_mixed_exact_and_wildcard_entries() {
        let toml = "allowlist = [\"Example.COM.\"]\nblocklist = [\"*.bad.example.net\"]\n";
        let file = match tempfile_with_contents(toml) {
            Ok(file) => file,
            Err(err) => panic!("failed to create temp file: {err}"),
        };
        let (lists, invalid) = match OverrideLists::load(file.path()) {
            Ok(result) => result,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert!(invalid.is_empty());
        let allow_decision = match lists.decision("example.com") {
            Ok(decision) => decision,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(allow_decision, Some(ListKind::Allowlist));
        let block_decision = match lists.decision("sub.bad.example.net") {
            Ok(decision) => decision,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(block_decision, Some(ListKind::Blocklist));
    }

    #[test]
    fn load_skips_one_invalid_domain_without_dropping_the_rest_of_the_list() {
        let toml = "allowlist = []\nblocklist = [\"good.example.com\", \"*.*.broken.example\"]\n";
        let file = match tempfile_with_contents(toml) {
            Ok(file) => file,
            Err(err) => panic!("failed to create temp file: {err}"),
        };
        let (lists, invalid) = match OverrideLists::load(file.path()) {
            Ok(result) => result,
            Err(err) => panic!("expected Ok: {err}"),
        };
        let decision = match lists.decision("good.example.com") {
            Ok(decision) => decision,
            Err(err) => panic!("expected Ok: {err}"),
        };
        assert_eq!(decision, Some(ListKind::Blocklist));
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0].raw, "*.*.broken.example");
        assert_eq!(invalid[0].list, ListKind::Blocklist);
    }

    #[test]
    fn invalid_entry_debug_output_never_contains_the_raw_pattern_text() {
        // Empirical proof the redaction actually holds through both fields
        // that could carry the pattern — `raw` itself and `reason` (an
        // earlier `reason: ProtoError` design leaked the pattern back in
        // through this second field; caught by advisor review, not by a
        // lint — this test is what would have caught it directly).
        let telltale = "sentinel-marker.broken.example";
        let entry = InvalidEntry {
            raw: format!("*.*.{telltale}"),
            list: ListKind::Blocklist,
            reason: InvalidReason::UnexpectedWildcard,
        };
        let debug_output = format!("{entry:?}");
        assert!(
            !debug_output.contains(telltale),
            "Debug output must not contain the raw pattern text: {debug_output}"
        );
    }

    #[test]
    fn changed_entries_of_identical_lists_is_empty() {
        let lists = OverrideLists {
            entries: vec![entry("example.com", false, ListKind::Blocklist)],
        };
        assert!(changed_entries(&lists, &lists).is_empty());
    }

    #[test]
    fn changed_entries_detects_a_newly_added_entry() {
        let before = OverrideLists { entries: vec![] };
        let added = entry("example.com", false, ListKind::Blocklist);
        let after = OverrideLists {
            entries: vec![added.clone()],
        };
        assert_eq!(changed_entries(&before, &after), vec![&added]);
    }

    #[test]
    fn changed_entries_detects_a_removed_entry() {
        let removed = entry("example.com", false, ListKind::Blocklist);
        let before = OverrideLists {
            entries: vec![removed.clone()],
        };
        let after = OverrideLists { entries: vec![] };
        assert_eq!(changed_entries(&before, &after), vec![&removed]);
    }

    #[test]
    fn changed_entries_detects_an_entry_moved_between_lists() {
        let before_entry = entry("example.com", false, ListKind::Blocklist);
        let after_entry = entry("example.com", false, ListKind::Allowlist);
        let before = OverrideLists {
            entries: vec![before_entry.clone()],
        };
        let after = OverrideLists {
            entries: vec![after_entry.clone()],
        };
        let mut result = changed_entries(&before, &after);
        result.sort_by_key(|e| e.list == ListKind::Allowlist);
        assert_eq!(result, vec![&before_entry, &after_entry]);
    }

    #[test]
    fn changed_entries_ignores_entries_present_in_both() {
        let kept = entry("kept.example.com", false, ListKind::Blocklist);
        let removed = entry("removed.example.com", false, ListKind::Blocklist);
        let added = entry("added.example.com", false, ListKind::Blocklist);
        let before = OverrideLists {
            entries: vec![kept.clone(), removed.clone()],
        };
        let after = OverrideLists {
            entries: vec![kept, added.clone()],
        };
        assert_eq!(changed_entries(&before, &after), vec![&removed, &added]);
    }

    fn tempfile_with_contents(contents: &str) -> std::io::Result<tempfile::NamedTempFile> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(contents.as_bytes())?;
        Ok(file)
    }
}
