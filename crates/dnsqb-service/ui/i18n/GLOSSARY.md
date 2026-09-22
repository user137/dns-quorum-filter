# i18n glossary and translation rules (T-236, extended by Батч 5.4/T-151)

Governs every key shipped in `ui/i18n/*.json` — the *rule*, not a duplicate of the translated
strings themselves (those live in the JSON files, one source of truth per Documentation map
convention). Originally scoped to the T-236 pilot key set (`localeSwitcher.label`, `fieldHelp.*`,
`hero.*`, `zoneDomainCount`); Батч 5.4 (2026-09-20-, one card/section per commit) extends the key
set to the rest of `main.js` and `index.html` under the same rules, plus the additions below.

## Батч 5.4 additions to the rules above

- **Every new key ships translated into all 37 locales in the same commit that adds it** — not
  uk+en first with the rest backfilled later (a deliberate user choice, since the latter would
  make untouched cards show raw key names in 35 locales until the whole batch finishes; see
  TASKS-DONE.md's Батч 5.4 entries for the discussion).
- **Static HTML vs. JS-rendered text**: if a DOM node is overwritten synchronously during
  bootstrap (before a user could read the hardcoded-Ukrainian placeholder), the HTML placeholder
  stays hardcoded and only the JS-rendered replacement gets a `t()` key. A node JS never touches
  (long-form prose: browser-setup instructions, the danger-zone warning, the footer attributions)
  is translated via `data-i18n="<key>"` (`textContent`) or `data-i18n-html="<key>"` (`innerHTML`,
  for a string whose translated value legitimately contains inline markup like `<a>`/`<strong>` —
  first-party `include_str!` dictionaries are not an injection surface here), applied by
  `applyStaticTranslations()` and re-applied by `renderTranslatedCards()` on a live locale switch.
- **Shared keys over duplicated ones**: several patterns repeat verbatim (or near-verbatim, with
  the inconsistencies fixed as part of adopting the shared key) across many render functions —
  `error.generic` (`` `Помилка: ${msg}` ``, ~15 sites), `warning.notPersisted` (the "not saved to
  disk" notice, ~9 sites), a shared delete-button label, a shared offline-network message. The
  first commit that touches each pattern defines the key; later commits reuse it rather than
  minting a second key for the same sentence.
- **Two hand-rolled Ukrainian-only pluralizers** (`pluralUk()`, `blocklistRelativeTime()`) are
  being retired in favor of `tPlural()` with dedicated keys, one `{n}` slot per key (`tPlural()`
  substitutes only the first occurrence — `.replace`, not `.replaceAll`). Any new plural-shaped
  key must be added to `admin_ui.rs`'s plural-shape test alongside the measured category table
  above (that test originally checked only `zoneDomainCount` by name and was generalized to walk
  every object-valued top-level key once Батч 5.4 introduced a second one).
- **Browser-setup instructions (`browserSetup.*`) quote the browser's own menu labels in their English
  originals in every non-uk locale** (`"Use secure DNS" → "Custom"`, `"DNS over HTTPS" → "Max
  Protection" → ...`) - the operator's browser may run in a different UI language than this page, and
  the English label is the one a search engine or the vendor docs will find. Only the surrounding prose
  is translated. The README section the verify paragraph points at (`README "Перевірка: браузер →
  локальний DoH"`) is quoted verbatim in Ukrainian in every locale, including `en` - the README itself
  is Ukrainian-only.
- **Licence/attribution links are never part of a translation** (footer, `footer.*Attribution`):
  their `href`s and anchor texts (including DB-IP's mandated "IP Geolocation by DB-IP") are
  constants in `main.js` (`FOOTER_LINK_VARS`) and reach the sentence through `{sapics}`/`{dbip}`/
  `{ccby}`/... tokens - a translation may reorder or reword around a token but must keep every
  token (`admin_ui::tests::every_locale_footer_attribution_keeps_every_required_link_token`).
- **Brand/product names and technical scheme identifiers stay untranslated**, same principle as
  `fail_open`/`DNS`/`ccTLD` above: `Quad9`, `AdGuard`, `DB-IP Lite`, `MaxMind GeoLite2`, blocklist
  source names (HaGeZi, 1Hosts, …), and `chrome://`/`edge://`/`brave://`/`opera://` URL schemes.

## Terms that stay untranslated

Config-mode identifiers are code literals quoted inside the sentence, not prose — translate the
sentence around them, never the identifiers: `fail_open`, `fail_closed`, `degraded`. This was
already the convention in the original `uk.json`/`en.json` (`fieldHelp.timeoutMode`); T-236 keeps
it for all 37 locales for consistency.

Found in live smoke-testing (2026-09-22): the timeout-mode *radio labels*
(`timeoutConfig.mode.failOpen`/`failClosed`/`degraded`) used to render the bare identifier alone,
with no surrounding sentence at all — technically consistent with "never translate the
identifier," but useless to a user who doesn't already know the config format. Fixed by giving
each radio label a real translated word (reusing that locale's own `overrides.allowOption`/
`blockOption` for the first two, a locale-appropriate "incomplete" for `degraded` — matching
`fieldHelp.timeoutMode`'s own English/Ukrainian wording, not a new "degraded" jargon term) with
the untranslated identifier kept in parens: `"Дозволити (fail_open)"`. The identifier itself is
still never translated — this only added the sentence around it, which had been missing entirely.

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
