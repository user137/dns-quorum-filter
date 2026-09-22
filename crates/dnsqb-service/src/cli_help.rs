//! T-235 Батч 5.6 — `--help` text shared by all three binaries
//! (`dnsqb-service`/`dnsqb-tray`/`dnsqb-watcher`). Deliberately lives here,
//! not as three separate per-binary copies the way `dnsqb-tray`'s own i18n
//! (Батч 5.5, `crates/dnsqb-tray/src/i18n.rs`) chose a private file tree
//! over sharing with the web UI's `ui/i18n/*.json` — that decision was about
//! two genuinely different domains (native dialogs vs. a web page); CLI
//! `--help` output for this project's three binaries **is** one domain (the
//! same short text-envelope shape, differing only by which binary's
//! description slots in), so sharing the mechanism and the dictionary here
//! is the right call, not drift from that precedent.
//!
//! [`help_text`] is a pure string-formatting function — it does not touch
//! `orchestrate::run` or anything else gated by the §7.1 #7 boundary
//! (`dnsqb-watcher` links this lib but must never call `run()`); adding this
//! module does not widen that boundary.
//!
//! **No `AttachConsole`/`MessageBoxW`, no `unsafe` code at all.** Confirmed
//! empirically before writing this (not assumed): a `windows_subsystem =
//! "windows"` binary's `println!`/`eprintln!` (1) print correctly when the
//! process is launched from an existing console (inherited handles) and (2)
//! neither panic nor error when launched with no console at all - verified
//! via a real `ShellExecute` launch (`UseShellExecute=true`, the exact
//! mechanism a Windows Explorer double-click uses), `panic::catch_unwind`
//! around the print calls, result written to a file: no panic, exit 0. A
//! `--help` invocation only makes sense from an existing terminal anyway
//! (that is the only way to type the flag), so the double-click case - which
//! silently prints nothing - is not a regression from today's behaviour.

macro_rules! i18n_dicts {
    ($($code:literal),+ $(,)?) => {
        const I18N_DICTS: &[(&str, &str)] = &[
            $(($code, include_str!(concat!("../cli-help-i18n/", $code, ".json")))),+
        ];
    };
}
i18n_dicts!(
    "ar", "bg", "cs", "da", "de", "el", "en", "es", "et", "fi", "fr", "he", "hi", "hr", "hu", "id",
    "it", "ja", "ko", "lt", "lv", "nb", "nl", "pl", "pt", "ro", "sk", "sl", "sr-Latn", "sv", "sw",
    "th", "tr", "uk", "ur", "vi", "zh",
);

fn dict(locale: &str) -> Option<&'static str> {
    I18N_DICTS
        .iter()
        .find(|(code, _)| *code == locale)
        .map(|&(_, json)| json)
}

fn lookup(locale: &str, key: &str) -> Option<String> {
    let json = dict(locale)?;
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    value.get(key)?.as_str().map(str::to_string)
}

/// Same "never go blank" fallback discipline as `dnsqb-tray/src/i18n.rs`'s
/// own `t()` - falls back to `en`, then to the bare key, so a missing
/// translation degrades visibly rather than panicking.
fn t(locale: &str, key: &str) -> String {
    lookup(locale, key)
        .or_else(|| lookup("en", key))
        .unwrap_or_else(|| key.to_string())
}

fn t_args(locale: &str, key: &str, args: &[(&str, &str)]) -> String {
    let mut text = t(locale, key);
    for (name, value) in args {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    text
}

/// Mirrors `dnsqb-tray`'s own `detect_locale` exactly (split on `-`,
/// lowercase, exact match, else `"en"`) - no manual switcher for a CLI flag,
/// OS auto-detect only.
fn detect_locale() -> &'static str {
    let raw = sys_locale::get_locale().unwrap_or_else(|| "en".to_string());
    let primary = raw.split('-').next().unwrap_or("en").to_lowercase();
    I18N_DICTS
        .iter()
        .find(|(code, _)| *code == primary)
        .map_or("en", |&(code, _)| code)
}

/// The one binary-specific piece: which description sentence to show.
/// Exhaustive on purpose (rust.md's own "make illegal states unrepresentable"):
/// a typo'd binary-name string can't silently fall through to a wrong or
/// blank description the way a `&str` lookup key could.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary {
    /// `dnsqb-service` — the `DoH` quorum resolver.
    Service,
    /// `dnsqb-tray` — the tray icon.
    Tray,
    /// `dnsqb-watcher` — the watchdog / autostart entry point.
    Watcher,
}

impl Binary {
    const fn name(self) -> &'static str {
        match self {
            Self::Service => "dnsqb-service",
            Self::Tray => "dnsqb-tray",
            Self::Watcher => "dnsqb-watcher",
        }
    }

    const fn description_key(self) -> &'static str {
        match self {
            Self::Service => "cliHelp.description.service",
            Self::Tray => "cliHelp.description.tray",
            Self::Watcher => "cliHelp.description.watcher",
        }
    }
}

/// The full `--help` body for `binary`, in the OS-detected language. Pure
/// (aside from the one OS-locale read) - no I/O, no process exit, callers
/// decide how to print it and when to exit.
#[must_use]
pub fn help_text(binary: Binary) -> String {
    let locale = detect_locale();
    let description = t(locale, binary.description_key());
    let usage = t(locale, "cliHelp.usage");
    t_args(
        locale,
        "cliHelp.bodyTemplate",
        &[
            ("binary", binary.name()),
            ("version", env!("CARGO_PKG_VERSION")),
            ("description", &description),
            ("usage", &usage),
        ],
    )
}

/// Whether an argument list asked for help - the exact set every GNU-style
/// and Windows-style tool recognizes, so whichever convention a user reaches
/// for works. Pure and total, checked by the caller before doing anything
/// else (no `app_data_dir`, no logging, no single-instance lock - a `--help`
/// that took the lock would make the flag unusable exactly when someone is
/// most likely to reach for it, while the app is already running).
#[must_use]
pub fn wants_help<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .any(|arg| matches!(arg.as_ref(), "--help" | "-h" | "/?"))
}

#[cfg(test)]
mod tests {
    use super::{dict, help_text, wants_help, Binary, I18N_DICTS};

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
    fn wants_help_recognizes_every_documented_spelling() {
        for flag in ["--help", "-h", "/?"] {
            assert!(wants_help(["dnsqb-service", flag]), "flag {flag:?}");
        }
    }

    #[test]
    fn wants_help_is_false_for_no_args_or_unrelated_args() {
        assert!(!wants_help(Vec::<&str>::new()));
        assert!(!wants_help(["dnsqb-service"]));
        assert!(!wants_help(["dnsqb-service", "--version"]));
    }

    #[test]
    fn help_text_names_the_right_binary_and_carries_the_version() {
        for binary in [Binary::Service, Binary::Tray, Binary::Watcher] {
            let text = help_text(binary);
            assert!(text.contains(binary.name()), "{binary:?}: {text:?}");
            assert!(
                text.contains(env!("CARGO_PKG_VERSION")),
                "{binary:?}: {text:?}"
            );
        }
    }

    #[test]
    fn help_text_is_never_empty_and_never_panics_for_any_binary() {
        for binary in [Binary::Service, Binary::Tray, Binary::Watcher] {
            assert!(!help_text(binary).is_empty());
        }
    }
}
