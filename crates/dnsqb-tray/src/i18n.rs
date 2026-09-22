//! T-151 Батч 5.5 — the tray's own translation dictionary. Mirrors
//! `dnsqb-service`'s `admin_ui.rs`/`ui/i18n/*.json` (T-236) in format and
//! locale-code list, but deliberately lives in its own file tree
//! (`crates/dnsqb-tray/i18n/`) rather than sharing `dnsqb-service`'s
//! `ui/i18n/*.json`: this tray's strings (native `rfd` dialogs) are a
//! different domain from that crate's embedded web UI, and the two macro
//! invocations staying independently typed (rather than importing one list)
//! mirrors `admin_ui.rs`'s own stated reasoning for not sharing its list with
//! `dispatch.rs` either — drift is caught by tests, not prevented by sharing.
//!
//! **Locale is always an explicit parameter, never read from ambient global
//! state** — [`t`]/[`t_args`] take `locale: &str`, and so does every caller
//! (`TrayStatus::tooltip`, `compose_tooltip`, …). This is deliberate: reading
//! a process-global "current locale" here would make every existing
//! Ukrainian-substring test in `status.rs` depend on the OS locale of
//! whatever machine runs the test suite - green on a Ukrainian dev box, red
//! on `windows-latest` CI, exactly the "local-green is not CI-green" class
//! this project has already been bitten by (T-50, T-241). Tests pin `"uk"`
//! explicitly instead. Same injected-ambient-value idiom as
//! `read_watchdog_view(paths, now)` / `cache_persist_dto::to_json(snapshot,
//! now_wall, now_mono)` in `dnsqb-service`.
//!
//! **No plural system** - Rust has no `Intl.PluralRules` equivalent, and
//! pulling in a full CLDR-plural crate for the tray's handful of
//! count-carrying tooltip fragments would be disproportionate (this
//! project's own dependency-minimization stance). The few strings that used
//! to hand-roll a Ukrainian-only "N запит(ів)" grammar hack are reworded as
//! a plain "label: N" readout instead (`tooltip.*Template` keys) - a count
//! that never needs its neighbouring word to inflect, in every language this
//! dictionary covers.

/// One `macro_rules!` invocation building the whole dictionary table from a
/// literal locale-code list - same code-generation shape as `admin_ui.rs`'s
/// own `i18n_dicts!`. **Batch 1 of Батч 5.5: `uk`/`en` only** (mirrors T-151's
/// own two-stage rollout, Батч 5.2 before T-236's 37-locale expansion) - the
/// remaining 35 locale files land in a later commit of this same batch, at
/// which point this list grows to match.
macro_rules! i18n_dicts {
    ($($code:literal),+ $(,)?) => {
        pub(crate) const I18N_DICTS: &[(&str, &str)] = &[
            $(($code, include_str!(concat!("../i18n/", $code, ".json")))),+
        ];
    };
}
i18n_dicts!("en", "uk");

/// Looks up one locale's raw dictionary JSON — `None` for an unregistered
/// code (never happens for the output of [`detect_locale`], but callers of
/// [`t`] can be handed an arbitrary string in a test).
fn dict(locale: &str) -> Option<&'static str> {
    I18N_DICTS
        .iter()
        .find(|(code, _)| *code == locale)
        .map(|&(_, json)| json)
}

/// Parses `locale`'s dictionary and looks up one key. Re-parses on every
/// call rather than caching — tray dialogs/tooltip renders are a handful of
/// user-paced events, not a hot path, and a few microseconds of JSON parsing
/// is not worth a cache invalidation story for zero measured benefit (this
/// project's own "no speculative features" stance).
fn lookup(locale: &str, key: &str) -> Option<String> {
    let json = dict(locale)?;
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    value.get(key)?.as_str().map(str::to_string)
}

/// Translates `key` into `locale`'s text. Falls back to `en`, then to the
/// bare key itself, so a missing translation degrades to something visibly
/// wrong rather than a panic or a blank dialog — the same "never go blank"
/// discipline `main.js`'s own `t()` documents (Три Б: a live, ugly string
/// beats no string at all).
#[must_use]
pub(crate) fn t(locale: &str, key: &str) -> String {
    lookup(locale, key)
        .or_else(|| lookup("en", key))
        .unwrap_or_else(|| key.to_string())
}

/// [`t`], with every `{name}` placeholder in the translated string replaced
/// by its value from `args` — mirrors `main.js`'s own `t(key, vars)`. Every
/// placeholder used by this dictionary's templates appears exactly once, so
/// `str::replace`'s replace-all semantics never differs from a
/// replace-first here.
#[must_use]
pub(crate) fn t_args(locale: &str, key: &str, args: &[(&str, &str)]) -> String {
    let mut text = t(locale, key);
    for (name, value) in args {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    text
}

/// Auto-detects the tray's display language from the OS (T-151 - no manual
/// switcher in the tray itself, unlike `/admin/ui`'s `<select>`; this project
/// has no settings surface of its own to host one). Mirrors `main.js`'s own
/// `resolveLocale`/`detectLocale`: split on `-`, lowercase, exact match
/// against the registered codes, else `"en"`. `sys-locale` may return a
/// tag like `"uk-UA"` or, on Windows, occasionally a script-qualified tag
/// (`"sr-Latn-RS"`) - the latter's primary subtag alone (`"sr"`) still won't
/// match this dictionary's `"sr-Latn"` entry once one exists, same
/// known/documented limitation `ui/i18n/GLOSSARY.md` already states for the
/// web UI (a Serbian-Latin user has to be reachable some other way; this
/// dictionary doesn't have one yet either).
#[must_use]
pub(crate) fn detect_locale() -> &'static str {
    let raw = sys_locale::get_locale().unwrap_or_else(|| "en".to_string());
    let primary = raw.split('-').next().unwrap_or("en").to_lowercase();
    I18N_DICTS
        .iter()
        .find(|(code, _)| *code == primary)
        .map_or("en", |&(code, _)| code)
}

#[cfg(test)]
mod tests {
    use super::{detect_locale, dict, t, t_args, I18N_DICTS};

    #[test]
    fn every_locale_dictionary_is_valid_json() {
        for &(code, json) in I18N_DICTS {
            assert!(
                serde_json::from_str::<serde_json::Value>(json).is_ok(),
                "{code}.json must be valid JSON"
            );
        }
    }

    #[test]
    fn every_locale_has_the_same_top_level_key_set_as_en() {
        let Some(en_json) = dict("en") else {
            panic!("en.json must be registered in I18N_DICTS");
        };
        let Ok(en_value) = serde_json::from_str::<serde_json::Value>(en_json) else {
            panic!("en.json must be valid JSON");
        };
        let Some(en_object) = en_value.as_object() else {
            panic!("en.json must be a flat JSON object");
        };
        for &(code, json) in I18N_DICTS {
            if code == "en" {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
                panic!("{code}.json must be valid JSON");
            };
            let Some(object) = value.as_object() else {
                panic!("{code}.json must be a flat JSON object");
            };
            let missing: Vec<&String> = en_object
                .keys()
                .filter(|k| !object.contains_key(*k))
                .collect();
            assert!(
                missing.is_empty(),
                "{code}.json is missing keys: {missing:?}"
            );
            let extra: Vec<&String> = object
                .keys()
                .filter(|k| !en_object.contains_key(*k))
                .collect();
            assert!(
                extra.is_empty(),
                "{code}.json has extra keys not in en.json: {extra:?}"
            );
        }
    }

    #[test]
    fn t_looks_up_a_known_key_in_the_requested_locale() {
        assert_eq!(t("uk", "menu.about"), "Про програму");
        assert_eq!(t("en", "menu.about"), "About");
    }

    #[test]
    fn t_falls_back_to_en_then_to_the_bare_key_on_a_miss() {
        // A locale that isn't registered at all falls back to en's value.
        assert_eq!(t("xx", "menu.about"), "About");
        // A key that exists in neither falls back to the key itself, never panics.
        assert_eq!(t("uk", "no.such.key"), "no.such.key");
    }

    #[test]
    fn t_args_substitutes_every_named_placeholder() {
        let text = t_args(
            "uk",
            "dialog.successTemplate",
            &[("outcome", "сертифікат встановлено")],
        );
        assert_eq!(text, "Успішно: сертифікат встановлено");
    }

    #[test]
    fn detect_locale_never_panics_on_an_unusual_os_tag() {
        // Not a live env-var override (sys_locale reads real OS state we
        // can't fake portably in a unit test) - this only proves the pure
        // post-processing (split/lowercase/lookup) can't panic, which is the
        // part this module actually owns.
        for raw in ["", "-", "SR-LATN-RS", "uk-UA", "zzzz"] {
            let primary = raw.split('-').next().unwrap_or("en").to_lowercase();
            let _ = I18N_DICTS.iter().find(|(code, _)| *code == primary);
        }
        // A real call must return one of the registered codes.
        let locale = detect_locale();
        assert!(I18N_DICTS.iter().any(|(code, _)| *code == locale));
    }
}
