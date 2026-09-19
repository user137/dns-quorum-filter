# i18n glossary and translation rules (T-236)

Governs the pilot key set shipped in `ui/i18n/*.json` (`localeSwitcher.label`, `fieldHelp.*`,
`hero.*`, `zoneDomainCount`) — the *rule*, not a duplicate of the translated strings themselves
(those live in the JSON files, one source of truth per Documentation map convention). Expanding
the *key set* (the rest of `main.js`'s hardcoded text) is Батч 5.4, out of scope here.

## Terms that stay untranslated

Config-mode identifiers are code literals quoted inside the sentence, not prose — translate the
sentence around them, never the identifiers: `fail_open`, `fail_closed`, `degraded`. This was
already the convention in the original `uk.json`/`en.json` (`fieldHelp.timeoutMode`); T-236 keeps
it for all 37 locales for consistency.

Technical abbreviations also stay as-is across every locale: `DNS`, `DoH`, `ccTLD`, `GeoIP`, `TTL`.

## Terms with a per-locale rendering

- **quorum** — has a direct cognate in most European languages (кворум/quorum/quórum/kworum/…),
  used as-is. Non-cognate locales (ja/ko/zh/th/vi/ar/he/hi/ur/sw) use a native descriptive term
  for "the collective decision among providers" rather than a transliteration.
- **allowlist / blocklist** — translated as "the list that always allows / always blocks" in each
  locale's own idiom, not treated as fixed English product names (unlike `fail_open` etc., these
  aren't config-file identifiers the user would ever type back in).

## Plural categories — measured, not recalled

`tPlural()` (`main.js`) calls `Intl.PluralRules(locale).select(n)` at runtime and looks up the
matching key in `zoneDomainCount`, falling back to `other` if the exact category is missing. The
JSON shape for each locale therefore has to match what that locale's *real* `Intl.PluralRules`
implementation returns — not a remembered CLDR rule, which is easy to get wrong for the less common
categories (e.g. Spanish/French/Italian/Portuguese's `many`, Hebrew's `two`, Arabic's full 6-way
split). Measured directly in a real Chrome instance before writing any translation:

```js
Object.fromEntries(
  CODES.map((c) => [c, new Intl.PluralRules(c).resolvedOptions().pluralCategories])
);
```

Result (`CODES` = the 37 `SUPPORTED_LOCALES`), mirrored exactly in
`admin_ui::tests::EXPECTED_PLURAL_CATEGORIES`:

| Locale | Categories |
|---|---|
| ar | zero, one, two, few, many, other |
| bg | one, other |
| cs | one, few, many, other |
| da | one, other |
| de | one, other |
| el | one, other |
| en | one, other |
| es | one, many, other |
| et | one, other |
| fi | one, other |
| fr | one, many, other |
| he | one, two, other |
| hi | one, other |
| hr | one, few, other |
| hu | one, other |
| id | other |
| it | one, many, other |
| ja | other |
| ko | other |
| lt | one, few, many, other |
| lv | zero, one, other |
| nb | one, other |
| nl | one, other |
| pl | one, few, many, other |
| pt | one, many, other |
| ro | one, few, other |
| sk | one, few, many, other |
| sl | one, two, few, other |
| sr-Latn | one, few, other |
| sv | one, other |
| sw | one, other |
| th | other |
| tr | one, other |
| uk | one, few, many, other |
| ur | one, other |
| vi | other |
| zh | other |

`other` is a mandatory fallback in every file regardless of the table above — `tPlural()` already
degrades to it on a missing category, so it must always resolve to a real string.

## `sr` is `sr-Latn`, not bare `sr`

Source list (`windows-archiver-wrapper`'s `PasswordMessages.sr-Latn-RS.resx`) is Latin-script
Serbian. `Intl.DisplayNames(['sr'])`/`Intl.PluralRules('sr')` default to Cyrillic when given the
bare macrolanguage code — truncating to `sr` would silently mismatch the script of the actual
translated content. `sr-Latn` is kept as the full locale code (a valid literal path segment,
`/admin/ui/i18n/sr-Latn.json`), not auto-detected via `navigator.language.split('-')[0]` (a
Serbian user has to pick it manually from the `<select>` — `detectLocale()`'s fallback to `en` on
a miss is the same graceful behavior every unmatched locale already gets).

## Locale-switcher entries are not part of this dictionary

`#locale-select`'s own `<option>` labels (`populateLocaleSelect()`, `main.js`) are deliberately
**not** translated keys in `ui/i18n/*.json` and never go through `CURRENT_LOCALE` at all — each
language names itself (`Intl.DisplayNames([code], { type: "language" }).of(code)`, e.g. `de` →
"Deutsch", `ja` → "日本語"), the same principle Wikipedia's own interlanguage picker uses.
2026-09-19, direct user request. This is the one deliberate exception to "everything on the page
follows `CURRENT_LOCALE`": an admin stuck on a locale they don't read still has to recognise their
own language's name in this specific list to get back, which only works if that name was never
translated away from itself. **Scoped narrowly** — GeoIP/ccTLD country-name pickers
(`regionLabel()`/`cctldLabel()`) stay `CURRENT_LOCALE`-translated as before; the user confirmed
this rule does not extend to them (DECISIONS.md 2026-09-19).

## Known limitation — machine translation, not native review

All 35 non-uk/en dictionaries (uk and en predate T-236 and were already reviewed in Батч 5.2) were
translated by Claude, not a native speaker. The self-review pass covered structural correctness —
glossary-term consistency, valid JSON, the plural-category table above matching each file's
`zoneDomainCount` shape — not idiomatic/register quality, which only a native reviewer can confirm.
Flagged in `KNOWN-LIMITATIONS.md`; treat any specific locale's prose as a starting point for human
QA, not a finished translation.
