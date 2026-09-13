//! T-227 — a **suggested** rating-filter «bubble» list, derived from the
//! machine's own system region, not a downloaded/curated list of its own
//! (SPEC.md §5.3's zone lists stay the T-105 distribution contract; see
//! [`crate::topn_download::AVAILABLE_TOPN_LISTS`]). Pure core here, one
//! `#[cfg(windows)]` impure shell — the standing "pure core / thin impure
//! shell" split this project uses throughout (`paths::resolve_app_data_dir`,
//! `self_uninstall::resolve_target`, …), so the pure half stays unit-testable
//! with plain strings and the OS read stays isolated and swappable per the
//! "Current phase boundaries" `#[cfg(target_os)]` seam requirement.
//!
//! This is a hint only: `rating_filter_status_view` only ever *suggests*
//! through `RatingFilterStatusView::suggested_list` — never writes into
//! `[rating_filter].lists` on its own. The user's own save action is still
//! required.

/// Normalizes a raw region string to this project's list-code shape: exactly
/// two ASCII letters, lowercased. Rejects anything else — a language-only
/// BCP-47 tag, a 3+-letter/numeric UN M.49 region code, empty input — since
/// this project's zone lists are ISO 3166-1 alpha-2 only
/// (`AVAILABLE_TOPN_LISTS`). `install_region` is a private module (not part
/// of the `lib.rs` re-export surface), so its examples live as `#[cfg(test)]`
/// unit tests below rather than a runnable doctest — `"UA"`/`"ua"` → `"ua"`,
/// `"241"`/`""` → `None`.
pub fn normalize_region_code(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() == 2 && trimmed.bytes().all(|b| b.is_ascii_alphabetic()) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}

/// Whether `region` (already [`normalize_region_code`]-normalized) is a real,
/// selectable list code — pure membership check against the caller's
/// `available` snapshot (`RatingFilterStatusView::available_lists`). A region
/// outside the curated set (no matching country list yet), or a malformed
/// value, suggests nothing rather than a list the user can't actually pick.
#[must_use]
pub fn suggested_list(region: Option<&str>, available: &[String]) -> Option<String> {
    let region = region?;
    available
        .iter()
        .find(|code| code.as_str() == region)
        .cloned()
}

/// Reads the machine's own system region — `HKCU\Control Panel\International\
/// Geo`'s `Name` string value, the same setting Settings → Region → "Country
/// or region" writes (confirmed on this dev box: `Name = "UA"`, alongside the
/// older numeric `Nation`). Deliberately **not** the UI language/locale
/// (`GetUserPreferredUILanguages` / `sys-locale`'s signal) — a user running
/// Windows in a non-native display language would get the wrong country from
/// that signal; region is what SPEC.md's "по регіону в системі" decision
/// asked for. Registry read only, no `unsafe` in this crate — `winreg`
/// encapsulates the FFI (SECURITY.md). Returns `None` on any failure (key or
/// value absent, wrong type, non-2-letter content) — this is a UX nicety, not
/// a required signal, so no error path is worth surfacing.
#[cfg(windows)]
#[must_use]
pub fn detect_system_region() -> Option<String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Control Panel\International\Geo")
        .ok()?;
    let raw: String = key.get_value("Name").ok()?;
    normalize_region_code(&raw)
}

/// Non-Windows builds have no equivalent registry to read — the seam this
/// project's Фаза 6 port needs stays visible here rather than inlined
/// (`CLAUDE.md`'s "Current phase boundaries").
#[cfg(not(windows))]
#[must_use]
pub fn detect_system_region() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Happy path.
    #[test]
    fn normalize_region_code_accepts_uppercase() {
        assert_eq!(normalize_region_code("UA"), Some("ua".to_string()));
    }

    #[test]
    fn normalize_region_code_accepts_lowercase() {
        assert_eq!(normalize_region_code("de"), Some("de".to_string()));
    }

    // Boundary.
    #[test]
    fn normalize_region_code_trims_whitespace() {
        assert_eq!(normalize_region_code("  gb  "), Some("gb".to_string()));
    }

    #[test]
    fn normalize_region_code_mixed_case() {
        assert_eq!(normalize_region_code("Us"), Some("us".to_string()));
    }

    // Misuse / fool.
    #[test]
    fn normalize_region_code_rejects_numeric_m49() {
        assert_eq!(normalize_region_code("241"), None);
    }

    #[test]
    fn normalize_region_code_rejects_three_letters() {
        assert_eq!(normalize_region_code("UKR"), None);
    }

    #[test]
    fn normalize_region_code_rejects_single_letter() {
        assert_eq!(normalize_region_code("u"), None);
    }

    // Error path (empty/garbage).
    #[test]
    fn normalize_region_code_rejects_empty() {
        assert_eq!(normalize_region_code(""), None);
    }

    #[test]
    fn normalize_region_code_rejects_garbage() {
        assert_eq!(normalize_region_code("uk-UA"), None);
    }

    fn available() -> Vec<String> {
        vec![
            "ua".to_string(),
            "us".to_string(),
            "de".to_string(),
            "pl".to_string(),
            "gb".to_string(),
            "global".to_string(),
            "gov-ua".to_string(),
        ]
    }

    // Happy path.
    #[test]
    fn suggested_list_matches_available_region() {
        assert_eq!(
            suggested_list(Some("ua"), &available()),
            Some("ua".to_string())
        );
    }

    // Boundary / misuse.
    #[test]
    fn suggested_list_none_when_region_absent() {
        assert_eq!(suggested_list(None, &available()), None);
    }

    #[test]
    fn suggested_list_none_when_region_not_available() {
        assert_eq!(suggested_list(Some("fr"), &available()), None);
    }

    #[test]
    fn normalize_region_code_rejects_global_shaped_input() {
        // "global"/"gov-ua" are list codes, not regions — `normalize_region_code`
        // rejects them by shape (not exactly 2 ASCII letters) alone, so
        // `suggested_list` (a plain membership check) never has to special-case
        // them: nothing that reaches it as `region` can ever equal one.
        assert_eq!(normalize_region_code("global"), None);
        assert_eq!(normalize_region_code("gov-ua"), None);
    }
}
