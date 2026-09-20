// T-149: ported from the deleted dnsqb-ui/ui/main.js (Tauri) - no local
// optimistic state, every action re-fetches/returns the live status from
// dnsqb-service, and every render below comes straight from that response.
// If the service isn't reachable, the error panel renders instead of the
// controls - never a fake 0/0 stat (Три Б). `window.__TAURI__.core.invoke`
// calls became same-origin `fetch()` calls - no CORS needed, the existing
// `content_type_is_json` CSRF gate on `/admin/config` still applies.

const appBody = document.getElementById("app-body");
const providersBody = document.getElementById("providers-body");
const overridesBody = document.getElementById("overrides-body");
const cacheConfigBody = document.getElementById("cache-config-body");
const geoipBody = document.getElementById("geoip-body");
const geoipMaxmindBody = document.getElementById("geoip-maxmind-body");
const logBody = document.getElementById("log-body");
// T-176:
const protectionHero = document.getElementById("protection-hero");
const filterControlsBody = document.getElementById("filter-controls-body");
const timeoutConfigBody = document.getElementById("timeout-config-body");
// T-127/T-128: the rating-filter «bubble» card + its always-visible badge.
const ratingFilterBody = document.getElementById("rating-filter-body");
const ratingFilterBadge = document.getElementById("rating-filter-badge");
// T-218 Фаза 7, Батч 7.4 частина 3: the public blocklist-bundles card.
const blocklistBundlesBody = document.getElementById("blocklist-bundles-body");
// Фаза 5, Батч 5.3: the ccTLD-block card (T-118).
const cctldBlockBody = document.getElementById("cctld-block-body");
// T-151 Батч 5.2: static, never rewritten by render()/renderProtectionHero() -
// see the comment on #locale-switcher in index.html.
const localeSelect = document.getElementById("locale-select");
const localeSwitcherLabel = document.getElementById("locale-switcher-label");

// T-151 Батч 5.2: i18n infra. Flat per-locale JSON (crates/dnsqb-service/ui/i18n/<code>.json),
// two value shapes - plain string, or a pluralized object (keys per Intl.PluralRules
// .resolvedOptions().pluralCategories, see ui/i18n/GLOSSARY.md's measured table) selected via
// Intl.PluralRules for a count-dependent string. Only FIELD_HELP + HERO_PRESENTATION + one plural
// key (zoneDomainCount) are migrated - pilot scope, DECISIONS.md; the rest of the page's text is
// Батч 5.4 (a different axis - more keys within these locales, not more locales for these keys).
// T-236: grown from ["uk", "en"] to the full 36-culture set windows-archiver-wrapper's own
// PasswordMessages.*.resx ships (+ en, the neutral default) - see DECISIONS.md and
// ui/i18n/GLOSSARY.md for the sr-Latn-not-bare-sr rationale.
const SUPPORTED_LOCALES = [
  "ar", "bg", "cs", "da", "de", "el", "en", "es", "et", "fi", "fr", "he", "hi", "hr", "hu", "id",
  "it", "ja", "ko", "lt", "lv", "nb", "nl", "pl", "pt", "ro", "sk", "sl", "sr-Latn", "sv", "sw",
  "th", "tr", "uk", "ur", "vi", "zh",
];
const LOCALE_STORAGE_KEY = "dqf-locale";
// T-236: the only three RTL scripts in SUPPORTED_LOCALES. document.dir is set from this in
// setLocale()/bootstrap - correct text direction/alignment, but NOT a mirrored flex/grid layout
// (KNOWN-LIMITATIONS.md: that's a separate, much larger CSS-logical-properties effort).
const RTL_LOCALES = ["ar", "he", "ur"];

function resolveLocale(code) {
  return SUPPORTED_LOCALES.includes(code) ? code : "en";
}

function detectLocale() {
  try {
    const stored = localStorage.getItem(LOCALE_STORAGE_KEY);
    if (stored) {
      return resolveLocale(stored);
    }
  } catch {
    // localStorage unavailable (private mode etc.) - fall through to navigator.language
  }
  return resolveLocale((navigator.language || "en").split("-")[0].toLowerCase());
}

let CURRENT_LOCALE = detectLocale();
let DICT = {};

// Kicked off at parse time so every top-level render kickoff below (refresh(),
// refreshRatingFilter(), refreshBlocklistBundles()) can await the same promise
// instead of racing it. On failure DICT stays {} - t()/tPlural() then degrade
// visibly (return the key / the raw number) instead of the page staying blank
// forever (Три Б: a live, ugly page beats a silently empty one).
const DICTIONARY_READY = loadDictionary(CURRENT_LOCALE).catch(() => {});

async function loadDictionary(locale) {
  const response = await fetch(`/admin/ui/i18n/${locale}.json`);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  DICT = await response.json();
}

// Missing key returns the key itself, never silently blank - a visible seam
// beats a silently absent label (Три Б).
function t(key, vars) {
  let value = DICT[key];
  if (value === undefined) {
    return key;
  }
  if (vars) {
    for (const [name, replacement] of Object.entries(vars)) {
      value = value.replaceAll(`{${name}}`, replacement);
    }
  }
  return value;
}

function tPlural(key, n) {
  const entry = DICT[key];
  if (entry === undefined) {
    return String(n);
  }
  const category = new Intl.PluralRules(CURRENT_LOCALE).select(n);
  const template = entry[category] ?? entry.other;
  return template.replace("{n}", n);
}

// Lists only SUPPORTED_LOCALES - deliberately not a broader "every language"
// list: a selector entry for a locale with no dictionary would silently snap
// back to English the moment it's picked (Три Б - never offer a choice that
// isn't real). 2026-09-19, direct user request: every entry names itself in
// its OWN language (autonym) - Intl.DisplayNames([code]), never
// CURRENT_LOCALE - the same principle Wikipedia's own interlanguage picker
// uses ("Deutsch", "日本語", never translated into the reader's current
// language). This is deliberately the ONE picker in this file that works
// this way - GeoIP/ccTLD country names stay CURRENT_LOCALE-translated
// (user confirmed 2026-09-19, DECISIONS.md) - because translating this
// specific list defeats its own purpose: an admin stuck on a locale they
// can't read must still recognise their own language's name to click their
// way back, which only works if it was never translated away from itself.
// Sorted by the autonym text but WITHOUT a locale argument to
// localeCompare() - that uses the host's own default-locale collation, not
// CLDR root and not CURRENT_LOCALE; once every entry can be in a different
// script, the admin's own CURRENT_LOCALE has no more claim to ordering them
// than any other. In practice this groups scripts into stable, predictable
// clusters (Latin/Cyrillic/Greek/Hebrew/Arabic/Indic/Thai/Korean/Chinese/
// Japanese, verified empirically for all 37 codes, both in Node and live in
// Chrome) that - unlike a CURRENT_LOCALE-keyed sort - don't reshuffle every
// time the admin switches locale.
function populateLocaleSelect() {
  // The switcher's own label/aria-label are translated here too, not left
  // hardcoded - this is the one control an English-speaking user must be
  // able to find before anything else on the page is readable to them.
  localeSwitcherLabel.textContent = t("localeSwitcher.label");
  const entries = SUPPORTED_LOCALES.map((code) => ({
    code,
    name: new Intl.DisplayNames([code], { type: "language" }).of(code),
  }));
  entries.sort((a, b) => a.name.localeCompare(b.name));
  localeSelect.textContent = "";
  for (const { code, name } of entries) {
    const option = document.createElement("option");
    option.value = code;
    // The document's own <html lang> can be a different language entirely
    // (applyDocumentLanguage() below sets it to CURRENT_LOCALE) - without
    // this, a CJK autonym rendered inside e.g. lang="ja" picks up the wrong
    // Han glyph variants for its own script (the same class of bug T-236's
    // own <html lang> fix, right below, already exists to prevent - here
    // per-option, not just once for the whole page).
    option.lang = code;
    option.textContent = name;
    option.selected = code === CURRENT_LOCALE;
    localeSelect.appendChild(option);
  }
}

// T-236: sets both <html lang> and dir, not just dir (advisor-catch on
// closing review) - index.html never had a lang attribute at all, so
// leaving it unset would keep every locale (including CJK, where lang
// drives glyph-variant selection) rendering under the browser's default
// language for screen readers/spellcheck/font shaping. RTL - see
// RTL_LOCALES's own comment. Called from both the bootstrap IIFE and
// setLocale(), same "one place, not duplicated at each call site"
// reasoning as renderTranslatedCards().
function applyDocumentLanguage() {
  document.documentElement.lang = CURRENT_LOCALE;
  document.documentElement.dir = RTL_LOCALES.includes(CURRENT_LOCALE) ? "rtl" : "ltr";
}

// Every card whose render path calls t()/tPlural() through a FIELD_HELP-key
// cardHeading() or HERO_PRESENTATION, OR (Батч 5.3) whose render path calls
// regionLabel()/Intl.DisplayNames and so also depends on CURRENT_LOCALE -
// listed once so the initial-load bootstrap and setLocale() below can't
// drift apart on which cards actually need re-rendering after DICT/locale
// changes. #overrides-body/#cache-config-body/#providers-body/#log-body's
// filter row are each their own fetch/render cycle, off the 2s poll, same
// reasoning as #rating-filter-body (CLAUDE.md) - none of them are otherwise
// reachable from refresh(). #geoip-maxmind-body is the same shape (own
// fetch/render cycle, T-228) and was missing from this list before Батч 5.4
// gave its render path t() calls too (advisor-caught while planning that
// batch: the card would have stayed in the previous language after a live
// locale switch). refreshLog()/initBrowserSetup() still render no
// FIELD_HELP/HERO/region-name/t() text and are deliberately left out.
function renderTranslatedCards() {
  refresh();
  refreshRatingFilter();
  refreshBlocklistBundles();
  refreshOverrides();
  refreshCacheConfig();
  refreshMaxmind();
  refreshProviders();
  refreshGeoip();
  refreshCctldBlock();
  buildLogFilterRow();
  refreshLog(); // must come after buildLogFilterRow() - see its own comment
}

async function setLocale(requested) {
  const next = resolveLocale(requested);
  try {
    await loadDictionary(next);
  } catch {
    // the fetch failed (service down between page load and this click) -
    // CURRENT_LOCALE/localStorage are deliberately left untouched, so DICT
    // and CURRENT_LOCALE never end up pointing at different locales (the
    // same DICTIONARY_READY.catch() reasoning as bootstrap, applied here).
    // Snap the <select> back to the locale that's actually still loaded.
    populateLocaleSelect();
    return;
  }
  CURRENT_LOCALE = next;
  try {
    localStorage.setItem(LOCALE_STORAGE_KEY, CURRENT_LOCALE);
  } catch {
    // per-viewer convenience only, safe to lose (same precedent as
    // BROWSER_SETUP_SEEN_KEY below)
  }
  applyDocumentLanguage();
  populateLocaleSelect();
  renderTranslatedCards();
}

// Native <details><summary> - zero JS beyond construction, keyboard-
// accessible (Enter/Space) out of the box, works on touch where a
// hover-only tooltip wouldn't (T-159's own two options, this is #1).
// Help text is authored in UI-SPEC.md §3.8 and shipped as ui/i18n/{uk,en}.json's
// `fieldHelp.*` keys - this function is a lookup, not a second source of truth.
function helpDetails(key) {
  const details = document.createElement("details");
  details.className = "field-help";
  const summary = document.createElement("summary");
  summary.textContent = "?";
  summary.setAttribute("aria-label", t("common.helpAriaLabel"));
  const text = document.createElement("p");
  text.textContent = t(`fieldHelp.${key}`);
  details.appendChild(summary);
  details.appendChild(text);
  return details;
}

// `<h3>` only permits phrasing content - nesting a `<details>` (flow
// content) inside one is invalid HTML; browsers silently recover (verified
// in Chrome) but that's "true by observed behavior," not provable from the
// markup, and Firefox is a first-class target here (scenario 12). Returns
// a flex row with the heading and the help toggle as siblings instead.
function cardHeading(text, helpKey) {
  const row = document.createElement("div");
  row.className = "card-heading-row";
  const heading = document.createElement("h3");
  heading.textContent = text;
  row.appendChild(heading);
  row.appendChild(helpDetails(helpKey));
  return row;
}

// T-176 / T-204: the basic view's one large element. The decisive priority
// ladder (watchdog > offline > paused > 0-voters > cert) moved to the server
// (admin.rs::compute_hero_state, finding 3-B) and arrives as
// `status.hero_state`; this file only maps that enum to presentation. The one
// case the server can't report is its own unreachability - when the
// /admin/status fetch itself fails, renderError() renders SERVICE_UNREACHABLE
// directly.
// T-151 Батч 5.2: `state`/`detail` text now lives in ui/i18n/{uk,en}.json under
// `hero.<KEY>.state`/`hero.<KEY>.detail` - this object keeps only the structural,
// non-textual fields (`cls`, `action`), looked up by heroPresentation() below.
const HERO_PRESENTATION = {
  SERVICE_UNREACHABLE: { cls: "is-bad" },
  WATCHDOG_GAVE_UP: { cls: "is-bad" },
  WATCHDOG_RESTARTING: { cls: "is-warn" },
  OFFLINE: { cls: "is-warn" },
  PAUSED: { cls: "is-warn" },
  NO_PROVIDERS: { cls: "is-bad" },
  CERT_NOT_TRUSTED: { cls: "is-bad", action: "install-cert" },
  CERT_UNKNOWN: { cls: "is-warn" },
  PROTECTED: { cls: "is-ok" },
};

// Map `status.hero_state` to {cls,state,detail,action?}. The only
// presentation logic left here: the PROTECTED detail gains the blocked count
// (a number the server already sends in `stats`, formatted client-side).
function heroPresentation(heroState, stats) {
  const key = HERO_PRESENTATION[heroState] ? heroState : "SERVICE_UNREACHABLE";
  const base = HERO_PRESENTATION[key];
  const blocked = stats ? stats.blocked : 0;
  const detail =
    key === "PROTECTED" && blocked > 0
      ? t("hero.PROTECTED.detailWithBlocked", { blocked })
      : t(`hero.${key}.detail`);
  return { ...base, state: t(`hero.${key}.state`), detail };
}

const HERO_MARK = { "is-ok": "✓", "is-bad": "✕", "is-warn": "↺" };

function renderProtectionHero(state) {
  protectionHero.textContent = "";
  const box = document.createElement("div");
  box.className = `hero ${state.cls}`;
  const head = document.createElement("div");
  head.className = "hero-headline";
  const mark = document.createElement("span");
  mark.className = "hero-mark";
  mark.setAttribute("aria-hidden", "true");
  mark.textContent = HERO_MARK[state.cls] || "";
  const label = document.createElement("span");
  label.className = "hero-state";
  label.textContent = state.state;
  head.appendChild(mark);
  head.appendChild(label);
  box.appendChild(head);
  const detail = document.createElement("p");
  detail.className = "hero-detail";
  detail.textContent = state.detail;
  box.appendChild(detail);
  // T-188: the "install the local cert" hero carries its own action button
  // (same-origin POST, no CSP change). Built via DOM methods, like the
  // override editor below.
  if (state.action === "install-cert") {
    const action = document.createElement("button");
    action.type = "button";
    action.className = "hero-action";
    action.textContent = t("hero.installCertButton");
    action.addEventListener("click", () => installCertFromHero(action));
    box.appendChild(action);
  }
  protectionHero.appendChild(box);
}

// T-188: POST /admin/install-cert, then re-render. On failure, point the user
// at the tray item (which surfaces the certutil error in a dialog) rather than
// trying to show it here. T-204/T-211: the route pokes the server's cert-trust
// cache synchronously, so the very next refresh() (2s poll or the one below)
// shows the flipped hero - no separate cert fetch needed.
async function installCertFromHero(button) {
  button.disabled = true;
  const original = button.textContent;
  button.textContent = t("hero.installingLabel");
  try {
    const response = await fetch("/admin/install-cert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    await refresh();
  } catch (_err) {
    button.disabled = false;
    button.textContent = t("hero.installFailedLabel");
    setTimeout(() => {
      button.textContent = original;
    }, 4000);
  }
}

async function getStatus() {
  const response = await fetch("/admin/status");
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

/// Sends a full `AdminConfigUpdate`. The DTO is a full replace (no partial
/// patch), so every field it carries -- `timeout_mode` and, since T-155,
/// `serve_baseline_when_filters_unreachable` -- must be present. Both config
/// controls live in the same card and are read straight off the DOM here.
async function applyCurrentConfig() {
  const selectedMode = document.querySelector(
    'input[name="timeout-mode"]:checked',
  );
  const baselineFallback = document.getElementById("baseline-fallback-toggle");
  const body = {
    timeout_mode: selectedMode ? selectedMode.value : "fail_open",
    serve_baseline_when_filters_unreachable: baselineFallback
      ? baselineFallback.checked
      : false,
  };
  const response = await fetch("/admin/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

// T-155 / T-47: a config change that live-applies but fails to persist to
// resolver_config.toml must stay visible, not be wiped by the next 2s status
// poll (whose `persisted` is always true). Latched here, cleared on the next
// successful apply.
let configPersistFailed = false;

// T-228: a read-only cache of status.network for the two cards that fetch
// their own data off the 2s poll (#rating-filter-body, #geoip-maxmind-body)
// and so never see it directly - updated by render() on every poll tick.
// Used only to disable/explain controls that need a live network fetch to
// do anything (a fresh bubble zone, the MaxMind save-time probe), never to
// gate anything that only reads/writes local config.
let lastNetworkStatus = "ONLINE";

// T-139: percentage is derived here, not stored server-side - `total`/`blocked`
// are already the source of truth (`admin::compute_stats`), a third persisted
// field would just be able to drift from them. `total === 0` (log window empty,
// e.g. right after a restart) must render as "no data" rather than a NaN/0%
// that would misleadingly claim zero blocking is happening. A rounded 0%/100%
// has the same falseness one level down: a real DNS filter's steady-state
// block rate over a full log window is often well under 1% (most queries
// aren't blocked), so plain Math.round would silently read "0% blocked" while
// blocking is actively happening - and the mirror case (a handful of allowed
// queries rounding away to "100% blocked") is the same lie in the other
// direction. Both edges are called out explicitly instead of rounded through.
function blockedPercentLabel(stats) {
  if (stats.total === 0) {
    return "—";
  }
  const pct = (stats.blocked / stats.total) * 100;
  if (stats.blocked > 0 && pct < 1) {
    return "<1%";
  }
  if (stats.blocked < stats.total && pct > 99) {
    return ">99%";
  }
  return `${Math.round(pct)}%`;
}

// T-176: the timeout-mode radios + baseline-fallback checkbox. Moved out of
// #app-body into its own card inside the advanced disclosure. Still driven by
// the 2s status poll (click-only, no free-text), same as the stats below.
function renderTimeoutConfig(status) {
  const configWarning =
    configPersistFailed || status.persisted === false
      ? `<div class="notice warn">${t("warning.notPersisted")}</div>`
      : "";
  timeoutConfigBody.innerHTML = `
    <div class="card-heading-row"><h3>${t("timeoutConfig.heading")}</h3><details class="field-help"><summary aria-label="${t("common.helpAriaLabel")}">?</summary><p>${t("fieldHelp.timeoutMode")}</p></details></div>
    ${configWarning}
    <div class="radio-group">
      ${["fail_open", "fail_closed", "degraded"]
        .map(
          (mode) => `
        <label class="radio-opt">
          <input type="radio" name="timeout-mode" value="${mode}" ${status.timeout_mode === mode ? "checked" : ""} />
          <span>${mode}</span>
        </label>`
        )
        .join("")}
    </div>
    <label class="radio-opt baseline-fallback-opt">
      <input type="checkbox" id="baseline-fallback-toggle" ${status.serve_baseline_when_filters_unreachable ? "checked" : ""} />
      <span>${t("timeoutConfig.baselineFallbackLabel")}</span>
    </label>
  `;
  document
    .querySelectorAll('input[name="timeout-mode"]')
    .forEach((el) => el.addEventListener("change", onConfigChanged));
  const baselineFallback = document.getElementById("baseline-fallback-toggle");
  if (baselineFallback) {
    baselineFallback.addEventListener("change", onConfigChanged);
  }
}

function render(status) {
  // `|| "ONLINE"` makes the fail-open default provable from this line alone
  // (not just true by the server's own NetworkStatusView::#[default] Online)
  // - an older/malformed response missing `network` must not read as offline
  // and lock out the two guarded controls below.
  lastNetworkStatus = status.network || "ONLINE";
  renderProtectionHero(heroPresentation(status.hero_state, status.stats));
  // T-128: the always-visible rating-filter «bubble» badge. On the 2s poll
  // path (unlike the #rating-filter-body card) so it can't go stale; a
  // no-op empty div whenever the bubble is off, which is the common case.
  renderRatingFilterBadge(status.rating_filter);
  renderTimeoutConfig(status);
  syncDohUrl(status);
  // T-96: passive indicator that the query log (i.e. browsing history) is
  // being written to disk. Enabling this is a hand-edit of resolver_config.toml
  // by design (no toggle here), so this is a plain always-visible line, not a
  // per-event confirm.
  const persistWarning = status.encrypted_persistence.query_log
    ? `<div class="notice warn">${t("app.queryLogPersistWarning")}</div>`
    : "";
  // T-97: the same kind of passive, hand-edit-only indicator for the
  // quorum-verdict cache. Independent flag, its own file, its own line.
  const cachePersistWarning = status.encrypted_persistence.cache
    ? `<div class="notice warn">${t("app.cachePersistWarning")}</div>`
    : "";
  // T-138 (Батч 4.5): same passive, hand-edit-only indicator for the
  // personal learned rating-filter zone — a higher privacy tier than
  // either of the two above (it learns which sites *you specifically*
  // visit often/regularly), so it gets the same always-visible treatment,
  // not buried inside the collapsed #rating-filter-body card.
  const personalZoneWarning = status.rating_filter.personal_zone_enabled
    ? `<div class="notice warn">${t("app.personalZonePersistWarning")}</div>`
    : "";
  appBody.innerHTML = `
    ${persistWarning}
    ${cachePersistWarning}
    ${personalZoneWarning}
    <div class="card">
      <h3>${t("app.statsHeading")}</h3>
      <div class="stat-row">
        <div>
          <div class="stat">${status.stats.blocked}</div>
          <div class="stat-sub">${t("app.statBlocked")}</div>
        </div>
        <div>
          <div class="stat">${status.stats.total}</div>
          <div class="stat-sub">${t("app.statTotal")}</div>
        </div>
        <div>
          <div class="stat">${status.stats.in_flight}</div>
          <div class="stat-sub">${t("app.statInFlight")}</div>
        </div>
        <div>
          <div class="stat">${blockedPercentLabel(status.stats)}</div>
          <div class="stat-sub">${t("app.statBlockedPercent")}</div>
        </div>
      </div>
    </div>
  `;
}

function renderError(err) {
  // The /admin/status fetch failed - the one hero state the server can't
  // report about itself (T-204). Route through heroPresentation() (not the
  // bare HERO_PRESENTATION.SERVICE_UNREACHABLE object) so state/detail are
  // actually populated - that object only carries `cls`/`action` since
  // Батч 5.2 moved the text into i18n. Batch 5.4 fix: the bare-object call
  // shipped with Батч 5.2 rendered a blank hero headline/detail on a fetch
  // failure.
  renderProtectionHero(heroPresentation("SERVICE_UNREACHABLE"));
  appBody.textContent = "";
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = t("error.generic", {
    message: (err && err.message) || String(err),
  });
  appBody.appendChild(panel);
}

async function onConfigChanged() {
  try {
    const status = await applyCurrentConfig();
    configPersistFailed = status.persisted === false;
    render(status);
  } catch (err) {
    renderError(err);
  }
}

async function refresh() {
  try {
    render(await getStatus());
  } catch (err) {
    renderError(err);
  }
}

// T-151 Батч 5.2: wait for DICTIONARY_READY first - every card in
// renderTranslatedCards() calls t()/tPlural(), so the first paint must not
// race the dictionary fetch. This is now the single top-level kickoff for
// all of them (the standalone refreshOverrides()/refreshCacheConfig()/
// refreshProviders()/buildLogFilterRow() calls further down were folded in
// here - grep for "renderTranslatedCards()" if one of those cards looks
// like it isn't loading on its own any more, it's on purpose). The <select>
// listener is attached exactly once here, never inside a render function
// (see the comment on #locale-switcher in index.html).
(async () => {
  await DICTIONARY_READY;
  applyDocumentLanguage();
  populateLocaleSelect();
  localeSelect.addEventListener("change", (event) => setLocale(event.target.value));
  renderTranslatedCards();
  // T-204: cert-trust used to be its own GET here (+ a visibilitychange
  // re-fetch). It is now a field of `status.hero_state`, computed server-side
  // from a cache the background `cert_watch` poll keeps warm (T-211), so the
  // 2s poll below picks up a tray-side "Видалити сертифікат" on its own.
  // `in_flight` (a live count of requests being resolved right now) is
  // otherwise only ever sampled at the instant of a toggle click - a page
  // that only re-renders on user action would show it near-permanently 0,
  // reading as "the resolver is idle" even while it's busy (the same
  // honesty failure this project already corrected twice: T-66's cold/warm
  // relabel, T-52's "never a fake 0/0 stat"). Polling every 2s keeps every
  // rendered value the server's actual live response, same "no local
  // optimistic state" philosophy as every other render() call here.
  setInterval(refresh, 2000);
})();

// T-47: the override-list editor. Deliberately NOT part of refresh()/render()
// above and NOT on the 2s poll - #overrides-body is a separate DOM subtree
// from #app-body specifically so a free-text "add domain" input in progress
// never gets wiped by an unrelated timer tick (index.html's own comment on
// the container explains this). Fetches once on load, and again after every
// add/remove action - not on a timer, since nothing else changes this list.

async function getOverrides() {
  const response = await fetch("/admin/overrides");
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function addOverride(pattern, list) {
  const response = await fetch("/admin/overrides/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pattern, list }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function removeOverride(domain, isWildcard, list) {
  const response = await fetch("/admin/overrides/remove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, is_wildcard: isWildcard, list }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

// Built via DOM methods (createElement/textContent), not the string-
// interpolated innerHTML pattern render() uses above - admin_ui.rs's own
// module doc comment flags exactly this gap for a future screen that
// renders a domain into innerHTML (this page's CSP doesn't set Trusted
// Types, so string interpolation here would need manual escaping instead
// of construction-time safety). This is that screen.
function overrideListItem(entry, list, conflicts) {
  const li = document.createElement("li");
  li.className = "override-item";
  const label = document.createElement("span");
  label.textContent = entry.is_wildcard ? `*.${entry.domain}` : entry.domain;
  li.appendChild(label);
  if (conflicts.includes(entry.domain)) {
    li.classList.add("conflict");
    const note = document.createElement("span");
    note.className = "conflict-note";
    // SPEC.md §5: allowlist wins on conflict - the UI must show this, not
    // silently apply it. Shown on both the allowlist and blocklist entry
    // for the same domain, not just one side.
    note.textContent = t("overrides.conflictNote");
    li.appendChild(note);
  }
  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "override-remove";
  removeBtn.textContent = t("common.delete");
  removeBtn.addEventListener("click", async () => {
    try {
      await removeOverride(entry.domain, entry.is_wildcard, list);
      await refreshOverrides();
      // T-224: without this, a log-row "В allowlist"/"В blocklist" button
      // that was disabled+"✓ Додано" for this exact domain stays stuck that
      // way after the override is removed here - refreshLog() rebuilds
      // #log-results (safe per its own comment below), giving that row a
      // fresh, re-clickable button. Same trade-off the log-row add handler
      // above already accepts for refreshOverrides(): this applies whatever
      // filter is currently sitting in #log-search/#log-decision/#log-voter,
      // even if the user hasn't pressed "Пошук" yet.
      await refreshLog();
    } catch (err) {
      renderOverridesError(err);
    }
  });
  li.appendChild(removeBtn);
  return li;
}

function renderOverrides(data) {
  overridesBody.textContent = "";

  overridesBody.appendChild(cardHeading(t("overrides.heading"), "overrides"));

  // T-47, advisor-caught: an add/remove that live-applies but fails to
  // persist must be visible, not just silently reflected in the response -
  // otherwise a restart could silently drop a filtering rule the user
  // thinks they already saved (the same failure class AdminStatusResponse's
  // own `persisted` field exists to prevent for resolver_config.toml).
  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent = t("warning.notPersisted");
    overridesBody.appendChild(notPersisted);
  }

  const addRow = document.createElement("div");
  addRow.className = "override-add-row";
  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = t("overrides.inputPlaceholder");
  const select = document.createElement("select");
  const allowOpt = document.createElement("option");
  allowOpt.value = "allowlist";
  allowOpt.textContent = t("overrides.allowOption");
  const blockOpt = document.createElement("option");
  blockOpt.value = "blocklist";
  blockOpt.textContent = t("overrides.blockOption");
  select.appendChild(allowOpt);
  select.appendChild(blockOpt);
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.textContent = t("overrides.addButton");
  const errorLine = document.createElement("div");
  errorLine.className = "override-error";

  async function submitAdd() {
    const pattern = input.value.trim();
    if (!pattern) {
      return;
    }
    try {
      errorLine.textContent = "";
      await addOverride(pattern, select.value);
      await refreshOverrides();
    } catch (err) {
      errorLine.textContent = t("overrides.addFailedTemplate", {
        pattern,
        message: (err && err.message) || String(err),
      });
    }
  }
  addBtn.addEventListener("click", submitAdd);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      submitAdd();
    }
  });

  addRow.appendChild(input);
  addRow.appendChild(select);
  addRow.appendChild(addBtn);
  overridesBody.appendChild(addRow);
  overridesBody.appendChild(errorLine);

  const allowHeading = document.createElement("h4");
  allowHeading.textContent = t("overrides.allowlistHeading");
  overridesBody.appendChild(allowHeading);
  const allowList = document.createElement("ul");
  allowList.className = "override-list";
  data.allowlist.forEach((entry) =>
    allowList.appendChild(overrideListItem(entry, "allowlist", data.conflicts))
  );
  overridesBody.appendChild(allowList);

  const blockHeading = document.createElement("h4");
  blockHeading.textContent = t("overrides.blocklistHeading");
  overridesBody.appendChild(blockHeading);
  const blockList = document.createElement("ul");
  blockList.className = "override-list";
  data.blocklist.forEach((entry) =>
    blockList.appendChild(overrideListItem(entry, "blocklist", data.conflicts))
  );
  overridesBody.appendChild(blockList);
}

function renderOverridesError(err) {
  overridesBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = t("overrides.heading");
  overridesBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = t("error.generic", {
    message: (err && err.message) || String(err),
  });
  overridesBody.appendChild(panel);
}

async function refreshOverrides() {
  try {
    renderOverrides(await getOverrides());
  } catch (err) {
    renderOverridesError(err);
  }
}

// T-151 Батч 5.2: kicked off from renderTranslatedCards() (bootstrap, near
// the top of this file) instead of a bare top-level call here - its
// cardHeading() reads t("fieldHelp.overrides"), so it must not race
// DICTIONARY_READY.

// T-153: cache TTL/capacity editor. Same reasoning as the overrides section
// above - a separate #cache-config-body DOM subtree, not part of
// refresh()/render(), not on the 2s poll, own fetch/render cycle - number
// inputs the user is actively editing must not lose their value to an
// unrelated timer tick.

async function getCacheConfig() {
  const response = await fetch("/admin/cache-config");
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function applyCacheConfig(update) {
  const response = await fetch("/admin/cache-config/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(update),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

const CACHE_CONFIG_FIELDS = [
  { key: "clamp_min_secs", labelKey: "cacheConfig.field.clampMin" },
  { key: "clamp_max_secs", labelKey: "cacheConfig.field.clampMax" },
  { key: "block_verdict_ttl_secs", labelKey: "cacheConfig.field.blockVerdictTtl" },
  { key: "stale_grace_secs", labelKey: "cacheConfig.field.staleGrace" },
  { key: "max_capacity", labelKey: "cacheConfig.field.maxCapacity" },
];

function renderCacheConfig(data) {
  cacheConfigBody.textContent = "";

  cacheConfigBody.appendChild(cardHeading(t("cacheConfig.heading"), "cache"));

  // Same "silent data loss" concern as #overrides-body's own persisted
  // warning (T-47) - a live-applied change that failed to persist must be
  // visible, not just silently reflected in the response.
  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent = t("warning.notPersisted");
    cacheConfigBody.appendChild(notPersisted);
  }

  // T-153: a config change rebuilds the whole cache (moka has no live
  // setter for max_capacity/its expiry policy - see CONFIGURATION.md's own
  // explanation of why) - shown here so "Застосувати" isn't a surprise.
  const flushNotice = document.createElement("p");
  flushNotice.className = "cache-config-flush-notice";
  flushNotice.textContent = t("cacheConfig.flushNotice");
  cacheConfigBody.appendChild(flushNotice);

  const inputs = {};
  const form = document.createElement("div");
  form.className = "cache-config-form";
  CACHE_CONFIG_FIELDS.forEach(({ key, labelKey }) => {
    const row = document.createElement("label");
    row.className = "cache-config-row";
    const span = document.createElement("span");
    span.textContent = t(labelKey);
    const input = document.createElement("input");
    input.type = "number";
    input.min = "0";
    input.step = "1";
    input.value = String(data[key]);
    inputs[key] = input;
    row.appendChild(span);
    row.appendChild(input);
    form.appendChild(row);
  });
  cacheConfigBody.appendChild(form);

  const errorLine = document.createElement("div");
  errorLine.className = "override-error";

  const applyBtn = document.createElement("button");
  applyBtn.type = "button";
  applyBtn.className = "cache-config-apply";
  applyBtn.textContent = t("cacheConfig.applyButton");
  applyBtn.addEventListener("click", async () => {
    const update = {};
    CACHE_CONFIG_FIELDS.forEach(({ key }) => {
      update[key] = Number(inputs[key].value);
    });
    // Client-side mirror of the server's own from_secs() check - belt and
    // suspenders, not a replacement for it (the server still rejects an
    // inverted range independently).
    if (update.clamp_min_secs > update.clamp_max_secs) {
      errorLine.textContent = t("cacheConfig.minMaxError");
      return;
    }
    try {
      errorLine.textContent = "";
      renderCacheConfig(await applyCacheConfig(update));
    } catch (err) {
      errorLine.textContent = t("cacheConfig.applyFailedTemplate", {
        message: (err && err.message) || String(err),
      });
    }
  });
  cacheConfigBody.appendChild(applyBtn);
  cacheConfigBody.appendChild(errorLine);
}

function renderCacheConfigError(err) {
  cacheConfigBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = t("cacheConfig.heading");
  cacheConfigBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = t("error.generic", {
    message: (err && err.message) || String(err),
  });
  cacheConfigBody.appendChild(panel);
}

async function refreshCacheConfig() {
  try {
    renderCacheConfig(await getCacheConfig());
  } catch (err) {
    renderCacheConfigError(err);
  }
}

// T-151 Батч 5.2: kicked off from renderTranslatedCards() - see the comment
// by refreshOverrides() above.

// T-226(а)/Батч 5.3: ISO 3166-1 alpha-2 codes for the GeoIP country-add
// datalist below, generated via `pycountry` (canonical iso-codes data, not
// hand-typed - same "script, not manual retyping" rule this project applies
// to any large data block). T-151/Батч 5.3: this used to also carry an
// English display name per code (a static `{code: name}` object) - that
// half is gone now, replaced by `regionLabel()` below, which asks the
// browser's own `Intl.DisplayNames` for a name in whatever locale is
// active, instead of shipping (and never localising) 249 hardcoded English
// strings.
const GEOIP_COUNTRY_CODES = [
  "AF", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW",
  "AU", "AT", "AZ", "BS", "BH", "BD", "BB", "BY", "BE", "BZ", "BJ", "BM",
  "BT", "BO", "BQ", "BA", "BW", "BV", "BR", "IO", "BN", "BG", "BF", "BI",
  "CV", "KH", "CM", "CA", "KY", "CF", "TD", "CL", "CN", "CX", "CC", "CO",
  "KM", "CG", "CD", "CK", "CR", "HR", "CU", "CW", "CY", "CZ", "CI", "DK",
  "DJ", "DM", "DO", "EC", "EG", "SV", "GQ", "ER", "EE", "SZ", "ET", "FK",
  "FO", "FJ", "FI", "FR", "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH",
  "GI", "GR", "GL", "GD", "GP", "GU", "GT", "GG", "GN", "GW", "GY", "HT",
  "HM", "VA", "HN", "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IM",
  "IL", "IT", "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KW", "KG", "LA",
  "LV", "LB", "LS", "LR", "LY", "LI", "LT", "LU", "MO", "MG", "MW", "MY",
  "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT", "MX", "FM", "MD", "MC",
  "MN", "ME", "MS", "MA", "MZ", "MM", "NA", "NR", "NP", "NL", "NC", "NZ",
  "NI", "NE", "NG", "NU", "NF", "KP", "MK", "MP", "NO", "OM", "PK", "PW",
  "PS", "PA", "PG", "PY", "PE", "PH", "PN", "PL", "PT", "PR", "QA", "RO",
  "RU", "RW", "RE", "BL", "SH", "KN", "LC", "MF", "PM", "VC", "WS", "SM",
  "ST", "SA", "SN", "RS", "SC", "SL", "SG", "SX", "SK", "SI", "SB", "SO",
  "ZA", "GS", "KR", "SS", "ES", "LK", "SD", "SR", "SJ", "SE", "CH", "SY",
  "TW", "TJ", "TZ", "TH", "TL", "TG", "TK", "TO", "TT", "TN", "TM", "TC",
  "TV", "TR", "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU", "VE",
  "VN", "VG", "VI", "WF", "EH", "YE", "ZM", "ZW", "AX"
];

// Локалізована назва регіону за ISO/CLDR-кодом (Батч 5.3) - ділиться між
// GeoIP-датаlist'ом і cctldLabel() нижче. Кешується по CURRENT_LOCALE, не
// захоплюється один раз при завантаженні модуля: setLocale() присвоює
// CURRENT_LOCALE до виклику renderTranslatedCards(), тож кеш інвалідується
// сам, без окремого "скинути" кроку. Жодного try/catch - кожен код, що сюди
// доходить, уже або сервер-валідований, або regex-звужений на вході
// (`/^[A-Z]{2}$/`); Intl.DisplayNames кидає RangeError лише на синтаксично
// невалідний субтег (цифри тощо), а для невідомого, але валідного коду тихо
// повертає сам код назад - той самий fallback, що раніше давав `|| code`.
let regionNamesCache = null;
let regionNamesCacheLocale = null;
function regionLabel(code) {
  if (regionNamesCacheLocale !== CURRENT_LOCALE) {
    regionNamesCache = new Intl.DisplayNames([CURRENT_LOCALE], { type: "region" });
    regionNamesCacheLocale = CURRENT_LOCALE;
  }
  return regionNamesCache.of(code.toUpperCase());
}

// Фаза 5, Батч 5.3: ccTLD-block editor (T-118, SPEC.md §5.2). Same isolation
// reasoning as #overrides-body/#geoip-body below - a free-text combobox
// input being typed into must not be wiped by the unrelated 2s status poll,
// so this has its own fetch/render cycle off GET /admin/status (once on
// load) + the POST /admin/cctld-block response, same shape as
// #rating-filter-body. `[cctld_block]` has no `enabled` flag - an empty
// list already means "off" (CctldBlockStatusView's own doc comment), so
// unlike rating-filter there's no on/off switch or arm-on-enable step here.

// SPEC.md §5.2's own bluntness, translated - analogous to
// GEOIP_OVER_BLOCKING_WARNING below but about a different risk: a ccTLD
// match blocks by domain suffix alone, catching every legitimate site
// registered under that TLD regardless of who actually runs it or where its
// content is hosted (a `.io`/`.co`-registered business with nothing to do
// with the sponsoring territory, for instance) - not a GeoIP-style anycast
// routing quirk, but the same class of "the signal is real but coarse"
// warning T-118 asked for alongside the picker itself.
function cctldOverBlockingWarning() {
  return t("cctldBlock.overBlockingWarning");
}

// ccTLD codes that aren't ISO 3166-1 alpha-2 (so aren't in
// GEOIP_COUNTRY_CODES) but are real, delegated ccTLDs - the three TASKS.md
// itself named as the reconciliation to do before reusing GeoIP's code set:
// `.uk` (the UK's actual ccTLD - its ISO code is GB, there is no `.gb`),
// `.eu` (European Union, a valid CLDR region despite not being a country),
// `.su` (the Soviet Union's ccTLD - still delegated and in use today, a
// genuinely separate namespace from `.ru`, not a historical alias of it).
// `.tp` (East Timor's old ccTLD, superseded by `.tl`, already in
// GEOIP_COUNTRY_CODES) is deliberately left out of this suggestion
// catalogue - IANA retired it, no live reason to suggest blocking it. This
// catalogue is discoverability only, same as GEOIP_COUNTRY_CODES's datalist
// - `validate_cctld_code` accepts any syntactically valid 2-letter code,
// and the combobox below has its own typed-code fallback for anything not
// listed here (so a code missing from this catalogue is a worse search
// experience, never a capability gap).
// Lowercased, unlike GEOIP_COUNTRY_CODES itself (which stays uppercase for
// the GeoIP card's own display convention) - a ccTLD suffix is
// conventionally written lowercase (`.ru`, not `.RU`), and the server
// always echoes `blocked_codes` lowercase (`validate_cctld_code`), so
// showing `RU` here would be a visible, un-caught-by-any-test inconsistency
// against the three hand-typed additions below, which were already
// lowercase (caught live in Chrome under a Japanese locale, not by a test -
// admin_ui.rs only asserts substrings, never renders the actual menu).
const CCTLD_CODES = GEOIP_COUNTRY_CODES.map((code) => code.toLowerCase()).concat([
  "uk",
  "eu",
  "su",
]);

// `Intl.DisplayNames`'s own CLDR data maps `SU` to "Russia" (SU is treated
// as a historical alias of RU) - misleading here, where an operator is
// choosing what to block and `.su` is a genuinely separate, still-live
// namespace from `.ru`. One explicit override, not a general exceptions
// map - `uk`/`eu`/`tp` were all checked and already resolve sensibly
// through regionLabel() alone.
//
// Side effect, not a bug: this override text itself contains ".ru", so
// visibleCodes()'s label-substring search surfaces `su` as a match on the
// query "ru" too (confirmed live) - a coincidence of this override's own
// wording, not a code/label mismatch to "fix" later.
function cctldLabel(code) {
  if (code.toLowerCase() === "su") {
    return t("cctldBlock.sovietUnionLabel");
  }
  return regionLabel(code);
}

async function setCctldBlock(blockedCodes) {
  const response = await fetch("/admin/cctld-block", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ blocked_codes: blockedCodes }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

function renderCctldBlock(status) {
  const cc = status.cctld_block;
  cctldBlockBody.textContent = "";

  const heading = document.createElement("h3");
  heading.textContent = t("cctldBlock.heading");
  cctldBlockBody.appendChild(heading);

  const desc = document.createElement("p");
  desc.className = "rf-desc";
  desc.textContent = t("cctldBlock.description");
  cctldBlockBody.appendChild(desc);

  // Same "silent data loss" concern as #overrides-body/#geoip-body/
  // #rating-filter-body (T-47/T-57/T-77/T-127 - CLAUDE.md's own recurring
  // pattern, "a failed disk save must surface persisted: false"). Not on
  // the 2s poll, so this stays on screen until the next action, same as
  // #rating-filter-body.
  if (status.persisted === false) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent = t("warning.notPersisted");
    cctldBlockBody.appendChild(notPersisted);
  }

  const card = document.createElement("div");
  card.className = "rf-card";

  // Save-time arm-confirm block, hidden until a save adds at least one new
  // code (Три Б: "an always-on warning ≡ no warning", T-77's own
  // arm-on-add precedent) - a save that only removes codes de-risks and
  // commits immediately below, no arming.
  const confirmNotice = document.createElement("div");
  confirmNotice.className = "notice warn";
  confirmNotice.hidden = true;
  confirmNotice.textContent = cctldOverBlockingWarning();
  card.appendChild(confirmNotice);

  const confirmRow = document.createElement("div");
  confirmRow.className = "rf-confirm-row cc-confirm-row";
  confirmRow.hidden = true;
  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.textContent = t("common.cancel");
  const confirmBtn = document.createElement("button");
  confirmBtn.type = "button";
  confirmBtn.className = "rf-confirm cc-confirm";
  confirmBtn.textContent = t("cctldBlock.confirmBlockButton");
  confirmRow.appendChild(cancelBtn);
  confirmRow.appendChild(confirmBtn);
  card.appendChild(confirmRow);

  const errorLine = document.createElement("div");
  errorLine.className = "override-error";
  card.appendChild(errorLine);

  // Same "no local optimistic state" rule as #rating-filter-body - picked
  // codes are re-seeded from the server's own echo on every render.
  const savedCodes = cc.blocked_codes.slice();
  const picked = new Set(savedCodes);

  const combo = document.createElement("div");
  combo.className = "rf-combo cc-combo";
  const input = document.createElement("input");
  input.type = "text";
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-expanded", "false");
  input.setAttribute("aria-controls", "cc-code-menu");
  input.setAttribute("aria-autocomplete", "list");
  input.setAttribute("aria-label", t("cctldBlock.searchAriaLabel"));
  input.placeholder = t("cctldBlock.inputPlaceholder");
  const menu = document.createElement("ul");
  menu.className = "rf-menu cc-menu";
  menu.id = "cc-code-menu";
  menu.setAttribute("role", "listbox");
  menu.hidden = true;
  combo.appendChild(input);
  combo.appendChild(menu);
  card.appendChild(combo);

  const pickedList = document.createElement("ul");
  pickedList.className = "rf-picked cc-picked";
  card.appendChild(pickedList);

  const emptyLine = document.createElement("p");
  emptyLine.className = "rf-empty cc-empty";
  emptyLine.textContent = t("cctldBlock.emptyLine");
  card.appendChild(emptyLine);

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "rf-save cc-save";
  saveBtn.textContent = t("common.save");
  saveBtn.hidden = true;
  card.appendChild(saveBtn);

  let activeIndex = -1;

  function pickedMatchesSaved() {
    if (picked.size !== savedCodes.length) {
      return false;
    }
    return savedCodes.every((code) => picked.has(code));
  }

  function syncSaveBtn() {
    saveBtn.hidden = pickedMatchesSaved();
  }

  function hasAdditions() {
    return [...picked].some((code) => !savedCodes.includes(code));
  }

  // Never hide a code the server actually has (or the user just picked)
  // just because it's outside CCTLD_CODES's suggestion catalogue - same
  // "never a silently hidden zone" rule as rating-filter's displayCodes()
  // (main.js's own precedent for this exact shape, T-108).
  function displayCodes() {
    const extra = [...picked].filter((code) => !CCTLD_CODES.includes(code));
    return CCTLD_CODES.concat(extra);
  }

  function renderPicked() {
    pickedList.textContent = "";
    const codes = displayCodes().filter((code) => picked.has(code));
    emptyLine.hidden = codes.length > 0;
    codes.forEach((code) => {
      const li = document.createElement("li");
      const nm = document.createElement("span");
      nm.className = "rf-nm cc-nm";
      nm.textContent = `${code} — ${cctldLabel(code)}`;
      li.appendChild(nm);
      const removeBtn = document.createElement("button");
      removeBtn.type = "button";
      removeBtn.className = "rf-x cc-x";
      removeBtn.textContent = "×";
      removeBtn.setAttribute("aria-label", t("common.removeAriaLabelTemplate", { code }));
      removeBtn.addEventListener("click", () => {
        picked.delete(code);
        renderPicked();
        renderMenu();
        resetArming();
      });
      li.appendChild(removeBtn);
      pickedList.appendChild(li);
    });
  }

  function visibleCodes() {
    const query = input.value.trim().toLowerCase();
    return displayCodes().filter((code) => {
      if (!query) {
        return true;
      }
      return (
        code.toLowerCase().includes(query) ||
        cctldLabel(code).toLowerCase().includes(query)
      );
    });
  }

  function renderMenu() {
    menu.textContent = "";
    const codes = visibleCodes();
    if (activeIndex >= codes.length) {
      activeIndex = codes.length - 1;
    }
    codes.forEach((code, index) => {
      const li = document.createElement("li");
      li.className = "rf-opt cc-opt";
      li.id = `cc-opt-${code}`;
      li.setAttribute("role", "option");
      const isPicked = picked.has(code);
      li.setAttribute("aria-selected", isPicked ? "true" : "false");
      if (isPicked) {
        li.classList.add("picked");
      }
      if (index === activeIndex) {
        li.classList.add("active");
      }
      const box = document.createElement("span");
      box.className = "rf-box cc-box";
      box.textContent = isPicked ? "✓" : "";
      li.appendChild(box);
      const nm = document.createElement("span");
      nm.className = "rf-nm cc-nm";
      nm.textContent = `${code} — ${cctldLabel(code)}`;
      li.appendChild(nm);
      // mousedown, not click: it fires before the input's blur handler
      // closes the menu.
      li.addEventListener("mousedown", (event) => {
        event.preventDefault();
        toggleCode(code);
      });
      menu.appendChild(li);
    });
    if (codes.length > 0 && activeIndex >= 0) {
      input.setAttribute("aria-activedescendant", `cc-opt-${codes[activeIndex]}`);
    } else {
      input.removeAttribute("aria-activedescendant");
    }
  }

  function toggleCode(code) {
    if (picked.has(code)) {
      picked.delete(code);
    } else {
      picked.add(code);
    }
    renderPicked();
    renderMenu();
    resetArming();
  }

  function openMenu() {
    if (!menu.hidden) {
      return;
    }
    menu.hidden = false;
    input.setAttribute("aria-expanded", "true");
    activeIndex = -1;
    renderMenu();
  }

  function closeMenu() {
    menu.hidden = true;
    input.setAttribute("aria-expanded", "false");
    activeIndex = -1;
    input.removeAttribute("aria-activedescendant");
  }

  input.addEventListener("focus", openMenu);
  input.addEventListener("input", () => {
    openMenu();
    activeIndex = -1;
    renderMenu();
  });
  input.addEventListener("blur", () => {
    // Delay so a mousedown on an option runs first.
    setTimeout(closeMenu, 120);
  });
  input.addEventListener("keydown", (event) => {
    const codes = visibleCodes();
    if (event.key === "ArrowDown") {
      event.preventDefault();
      openMenu();
      activeIndex = Math.min(activeIndex + 1, codes.length - 1);
      renderMenu();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      openMenu();
      activeIndex = Math.max(activeIndex - 1, 0);
      renderMenu();
    } else if (event.key === "Enter") {
      event.preventDefault();
      if (!menu.hidden && activeIndex >= 0 && activeIndex < codes.length) {
        toggleCode(codes[activeIndex]);
        return;
      }
      // Typed-code fallback (Батч 5.3): the combobox catalogue
      // (CCTLD_CODES) is discoverability only, not the source of truth -
      // validate_cctld_code accepts any syntactically valid 2-letter code
      // server-side, so a code the menu has no entry for must still be
      // addable. Lowercased before toggling (the server always echoes
      // lowercase - "RU" and "ru" must never become two separate chips),
      // and the input is cleared BEFORE toggleCode() so the renderMenu()
      // inside it re-filters against an empty query in the same pass.
      const typed = input.value.trim().toLowerCase();
      if (/^[a-z]{2}$/.test(typed)) {
        input.value = "";
        toggleCode(typed);
      }
    } else if (event.key === "Escape") {
      closeMenu();
    }
  });

  // Resets the save-arm state on any edit to `picked` - GeoIP's own
  // resetArming precedent (input.addEventListener("input", resetArming)),
  // applied here to every mutation of `picked` (toggleCode/×), not just
  // Скасувати: without this, removing the just-added code that triggered
  // the arm would leave Підтвердити wired to a warning describing a state
  // that no longer exists.
  function resetArming() {
    confirmNotice.hidden = true;
    confirmRow.hidden = true;
    syncSaveBtn();
  }

  saveBtn.addEventListener("click", async () => {
    errorLine.textContent = "";
    if (hasAdditions()) {
      confirmNotice.hidden = false;
      confirmRow.hidden = false;
      saveBtn.hidden = true;
      return;
    }
    try {
      renderCctldBlock(await setCctldBlock([...picked]));
    } catch (err) {
      errorLine.textContent = t("cctldBlock.saveFailedTemplate", {
        message: (err && err.message) || String(err),
      });
    }
  });
  cancelBtn.addEventListener("click", resetArming);
  confirmBtn.addEventListener("click", async () => {
    try {
      renderCctldBlock(await setCctldBlock([...picked]));
    } catch (err) {
      errorLine.textContent = t("cctldBlock.saveFailedTemplate", {
        message: (err && err.message) || String(err),
      });
    }
  });

  renderPicked();
  syncSaveBtn();
  cctldBlockBody.appendChild(card);
}

function renderCctldBlockError(err) {
  cctldBlockBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = t("cctldBlock.heading");
  cctldBlockBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = t("error.generic", {
    message: (err && err.message) || String(err),
  });
  cctldBlockBody.appendChild(panel);
}

async function refreshCctldBlock() {
  try {
    renderCctldBlock(await getStatus());
  } catch (err) {
    renderCctldBlockError(err);
  }
}

// Батч 5.3: kicked off from renderTranslatedCards() only (see the comment by
// refreshOverrides() above) - no eager module-scope call, same reasoning as
// refreshGeoip() right below.

// T-77: GeoIP blocked-country list editor. Same isolation reasoning as the
// overrides/cache-config sections above - a country-code input the user is
// actively typing into must not lose its value to the unrelated 2s poll.
// SPEC.md §3.5's own explicit requirement is that the CDN over-blocking
// warning must appear on every addition, not sit as a permanent fixture (a
// permanent banner is functionally identical to no banner - the same trap
// this project's own T-56 status-indicator design and the now-reversed T-57
// notice already document, DECISIONS.md). So "Додати" arms a confirm step
// inline instead of adding immediately - the warning becomes visible only
// as part of that interaction, and a second click on the same code (or
// "Підтвердити додавання") is what actually sends the request.

async function getGeoip() {
  const response = await fetch("/admin/geoip");
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function addGeoipCountry(country) {
  const response = await fetch("/admin/geoip/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ country }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function removeGeoipCountry(country) {
  const response = await fetch("/admin/geoip/remove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ country }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

// T-162/T-226(б): `DatabaseSource` wire strings → human labels. DB-IP Lite
// and MaxMind GeoLite2 are brand names, kept as-is in every locale; the
// other two are plain prose, resolved through t() at call time (not a
// module-level const - see cctldOverBlockingWarning()'s own comment on why).
function databaseSourceLabel(source) {
  switch (source) {
    case "DB_IP_LITE":
      return "DB-IP Lite";
    case "USER_COUNTRY":
      return t("geoip.sourceLabel.userCountry");
    case "GEO_LITE2":
      return "MaxMind GeoLite2";
    case "OTHER":
      return t("geoip.sourceLabel.other");
    default:
      return source;
  }
}


// One <datalist>, shared by every renderGeoip() call - native browser
// autocomplete on the free-text code input below (T-226(a)), never a
// replacement for validate_country_code's own server-side check. The node
// itself is built once (renderGeoip() re-appends the same node every call,
// it doesn't need a fresh one); its <option>s are rebuilt on every
// renderGeoip() call instead of once at module load (Батч 5.3) - unlike the
// old static per-code English-name map this replaced, a name from
// Intl.DisplayNames depends on CURRENT_LOCALE, so a locale switch must be
// able to change it.
const geoipCountryDatalist = document.createElement("datalist");
geoipCountryDatalist.id = "geoip-country-list";
function populateGeoipCountryDatalist() {
  geoipCountryDatalist.textContent = "";
  [...GEOIP_COUNTRY_CODES]
    .sort((a, b) => regionLabel(a).localeCompare(regionLabel(b), CURRENT_LOCALE))
    .forEach((code) => {
      const option = document.createElement("option");
      option.value = code;
      option.textContent = `${code} — ${regionLabel(code)}`;
      geoipCountryDatalist.appendChild(option);
    });
}

function geoipListItem(code) {
  const li = document.createElement("li");
  li.className = "override-item";
  const label = document.createElement("span");
  label.textContent = code;
  li.appendChild(label);
  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "override-remove";
  removeBtn.textContent = t("common.delete");
  removeBtn.addEventListener("click", async () => {
    try {
      // Renders the POST response directly (same as renderCacheConfig
      // below), not add-then-refetch - a re-GET always reports the live
      // state's own persisted:true and would silently hide a failed save
      // (advisor-caught during this task's own closing review).
      renderGeoip(await removeGeoipCountry(code));
    } catch (err) {
      renderGeoipError(err);
    }
  });
  li.appendChild(removeBtn);
  return li;
}

function renderGeoip(data) {
  geoipBody.textContent = "";
  populateGeoipCountryDatalist();

  const heading = document.createElement("h3");
  heading.textContent = t("geoip.heading");
  geoipBody.appendChild(heading);

  // T-78: three distinct, always-visible lines - not a banner - for three
  // states that must not collapse into one another (advisor-caught while
  // planning this task): no database at all (filtering isn't happening,
  // regardless of blocked_countries below), a loaded database with a known
  // build date, and a loaded database whose own metadata has no build
  // date. `database_built_at_ms` is the publisher's own build time, not a
  // refresh-poll timestamp - see CLAUDE.md's T-75 note on why "last
  // updated" would be a misleading label here.
  const databaseStatus = document.createElement("p");
  databaseStatus.className = "geoip-database-status";
  if (!data.database_loaded) {
    databaseStatus.textContent = t("geoip.noDatabaseStatus");
  } else if (data.database_built_at_ms == null) {
    databaseStatus.textContent = t("geoip.unknownBuildDateStatus");
  } else {
    // Source-neutral date line - `database_source` (below) carries which
    // publisher's database this actually is (T-162); before that field
    // existed a hardcoded "(DB-IP)" here was wrong once T-80 landed.
    databaseStatus.textContent = t("geoip.buildDateTemplate", {
      date: new Date(data.database_built_at_ms).toLocaleString(),
    });
  }
  geoipBody.appendChild(databaseStatus);

  // T-162: which publisher's database is *actually* loaded right now,
  // classified server-side from the file's own metadata (not from which
  // source is configured - those diverge when MaxMind creds are set but
  // rejected). Omitted entirely when no database is loaded (the line above
  // already says so).
  if (data.database_source) {
    const sourceLine = document.createElement("p");
    sourceLine.className = "geoip-database-status";
    sourceLine.textContent = t("geoip.activeSourceTemplate", {
      source: databaseSourceLabel(data.database_source),
    });
    geoipBody.appendChild(sourceLine);
  }

  // Same "silent data loss" concern as #overrides-body's own persisted
  // warning (T-47).
  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent = t("warning.notPersisted");
    geoipBody.appendChild(notPersisted);
  }

  const addRow = document.createElement("div");
  addRow.className = "override-add-row";
  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = "SE";
  // T-226(a): name-assisted autocomplete via the shared datalist above -
  // typing a country NAME (e.g. "Ukraine") needs more than 2 characters,
  // so the old maxLength=2 (back when only a bare code could be typed) is
  // now too short and would silently truncate the name before the browser
  // ever matches it against the datalist. Submission still only accepts a
  // 2-letter code (submitAdd's own regex below); selecting a datalist
  // <option> sets the input back to its 2-letter `value` automatically -
  // this is discoverability only, `validate_country_code` server-side is
  // still the real gate.
  input.maxLength = 64;
  input.setAttribute("list", geoipCountryDatalist.id);
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.textContent = t("overrides.addButton");
  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.textContent = t("common.cancel");
  cancelBtn.hidden = true;
  const errorLine = document.createElement("div");
  errorLine.className = "override-error";
  const warningLine = document.createElement("div");
  warningLine.className = "notice warn";
  warningLine.hidden = true;
  warningLine.textContent = t("geoip.overBlockingWarning");

  // Local to this one render's closure, not module state - a fresh
  // renderGeoip() call (after a successful add/remove) always starts
  // un-armed, and nothing else re-renders #geoip-body mid-interaction (this
  // section isn't touched by the unrelated 2s status poll, same as
  // overrides/cache-config above).
  let armedCode = null;

  function resetArming() {
    armedCode = null;
    warningLine.hidden = true;
    cancelBtn.hidden = true;
    addBtn.textContent = t("overrides.addButton");
  }
  cancelBtn.addEventListener("click", resetArming);
  input.addEventListener("input", resetArming);

  async function submitAdd() {
    const code = input.value.trim().toUpperCase();
    if (!code) {
      return;
    }
    // Client-side mirror of the server's own validate_country_code check -
    // belt and suspenders, not a replacement (the server still rejects an
    // invalid code independently).
    if (!/^[A-Z]{2}$/.test(code)) {
      errorLine.textContent = t("geoip.invalidCodeTemplate", { code });
      return;
    }
    errorLine.textContent = "";
    if (armedCode !== code) {
      armedCode = code;
      warningLine.hidden = false;
      cancelBtn.hidden = false;
      addBtn.textContent = t("geoip.confirmAddButton");
      return;
    }
    try {
      // Renders the POST response directly - see the remove handler's own
      // comment above for why add-then-refresh would silently hide a
      // failed save.
      renderGeoip(await addGeoipCountry(code));
    } catch (err) {
      errorLine.textContent = t("geoip.addFailedTemplate", {
        code,
        message: (err && err.message) || String(err),
      });
    }
  }
  addBtn.addEventListener("click", submitAdd);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      submitAdd();
    }
  });

  addRow.appendChild(input);
  addRow.appendChild(addBtn);
  addRow.appendChild(cancelBtn);
  addRow.appendChild(geoipCountryDatalist);
  geoipBody.appendChild(addRow);
  geoipBody.appendChild(warningLine);
  geoipBody.appendChild(errorLine);

  const list = document.createElement("ul");
  list.className = "override-list";
  data.blocked_countries.forEach((code) => list.appendChild(geoipListItem(code)));
  geoipBody.appendChild(list);
}

function renderGeoipError(err) {
  geoipBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = t("geoip.heading");
  geoipBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = t("error.generic", {
    message: (err && err.message) || String(err),
  });
  geoipBody.appendChild(panel);
}

async function refreshGeoip() {
  try {
    renderGeoip(await getGeoip());
  } catch (err) {
    renderGeoipError(err);
  }
}

// Батч 5.3: no eager module-scope call here any more (there used to be one,
// unconditional, independent of DICTIONARY_READY) - the datalist's option
// labels now depend on CURRENT_LOCALE via regionLabel(), so this card joined
// renderTranslatedCards() below instead, the same "only reachable from
// renderTranslatedCards()" shape every other locale-dependent card already
// has. Calling both would double-fetch on first load.

// T-162/T-163: MaxMind GeoLite2 credentials card. Own fetch/render cycle (a
// license-key field the operator is typing must not be wiped by the 2s
// status poll), same pattern as the GeoIP card above. The POST response
// carries a `check` field - the result of one authenticated probe the
// service runs against MaxMind right after saving - so the operator learns
// immediately whether the credentials were accepted (Три Б: hand-editing the
// file gave no such signal). `refresh_health` is the complementary signal:
// whether the *stored* credentials are still being accepted at the scheduled
// 24h background refresh (a key can be revoked after it was accepted). A
// credentials change takes effect immediately - no dnsqb-service restart.

// Structural (cls) vs. textual (t() key) split - same reasoning as
// HERO_PRESENTATION (Батч 5.2): the object stays a plain lookup, the text
// itself is resolved fresh from the dictionary at call time.
const MAXMIND_CHECK_MESSAGES = {
  VERIFIED: { cls: "notice ok", key: "maxmind.check.verified" },
  REJECTED: { cls: "notice warn", key: "maxmind.check.rejected" },
  UNVERIFIED: { cls: "notice warn", key: "maxmind.check.unverified" },
};

async function getMaxmind() {
  const response = await fetch("/admin/geoip/maxmind");
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function setMaxmind(accountId, licenseKey) {
  const response = await fetch("/admin/geoip/maxmind", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ account_id: accountId, license_key: licenseKey }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function clearMaxmind() {
  const response = await fetch("/admin/geoip/maxmind/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

function renderMaxmind(data) {
  geoipMaxmindBody.textContent = "";

  const heading = document.createElement("h3");
  heading.textContent = t("maxmind.heading");
  geoipMaxmindBody.appendChild(heading);

  const state = document.createElement("p");
  state.className = "geoip-database-status";
  state.textContent = data.configured
    ? t("maxmind.configuredStatusTemplate", { accountId: data.account_id })
    : t("maxmind.notConfiguredStatus");
  geoipMaxmindBody.appendChild(state);

  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    // Батч 5.4: this card used to have its own, slightly different "not
    // persisted" wording (missing "застосовано") - reconciled onto the
    // shared key like every other card, not kept as a second source of
    // truth for the same notice.
    notPersisted.textContent = t("warning.notPersisted");
    geoipMaxmindBody.appendChild(notPersisted);
  }

  if (data.refresh_health === "AUTH_REJECTED") {
    const brokenLater = document.createElement("div");
    brokenLater.className = "notice warn";
    brokenLater.textContent = t("maxmind.authRejectedWarning");
    geoipMaxmindBody.appendChild(brokenLater);
  }

  const check = MAXMIND_CHECK_MESSAGES[data.check];
  if (check) {
    const line = document.createElement("div");
    line.className = check.cls;
    line.textContent = t(check.key);
    geoipMaxmindBody.appendChild(line);
  }

  const errorLine = document.createElement("div");
  errorLine.className = "override-error";

  const accountInput = document.createElement("input");
  accountInput.type = "text";
  // Not translated (Батч 5.4): "account ID" is MaxMind's own dashboard field
  // name, in English on every locale of their own site - matching it here
  // is more useful to the operator than a translated paraphrase.
  accountInput.placeholder = "account ID";
  const keyInput = document.createElement("input");
  keyInput.type = "password";
  keyInput.placeholder = t("maxmind.licenseKeyPlaceholder");
  keyInput.autocomplete = "off";

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.textContent = t("common.save");
  // T-228: saving runs a save-time probe against MaxMind (SERVICES.md/
  // dispatch.rs's own doc: "POST stores then runs a save-time probe -
  // check") - offline, that probe just times out and the existing
  // MAXMIND_CHECK_MESSAGES.FAILED text ("MaxMind відхилив креденшели
  // (401/403)") would misleadingly read as a bad key rather than no
  // network. Block before the request, name the real reason, instead of
  // showing a wrong diagnosis after a doomed fetch.
  if (lastNetworkStatus === "OFFLINE") {
    saveBtn.disabled = true;
    saveBtn.title = t("maxmind.offlineMessage");
  }
  saveBtn.addEventListener("click", async () => {
    if (lastNetworkStatus === "OFFLINE") {
      errorLine.textContent = t("maxmind.offlineMessage");
      return;
    }
    const accountId = accountInput.value.trim();
    const licenseKey = keyInput.value.trim();
    if (!accountId || !licenseKey) {
      errorLine.textContent = t("maxmind.bothFieldsRequired");
      return;
    }
    errorLine.textContent = "";
    try {
      renderMaxmind(await setMaxmind(accountId, licenseKey));
    } catch (err) {
      errorLine.textContent = t("maxmind.saveFailedTemplate", {
        message: (err && err.message) || String(err),
      });
    }
  });

  const addRow = document.createElement("div");
  addRow.className = "override-add-row";
  addRow.appendChild(accountInput);
  addRow.appendChild(keyInput);
  addRow.appendChild(saveBtn);

  if (data.configured) {
    let armed = false;
    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.textContent = t("maxmind.clearButton");
    clearBtn.addEventListener("click", async () => {
      if (!armed) {
        armed = true;
        clearBtn.textContent = t("maxmind.confirmClearButton");
        return;
      }
      try {
        renderMaxmind(await clearMaxmind());
      } catch (err) {
        errorLine.textContent = t("maxmind.clearFailedTemplate", {
          message: (err && err.message) || String(err),
        });
      }
    });
    addRow.appendChild(clearBtn);
  }

  geoipMaxmindBody.appendChild(addRow);
  geoipMaxmindBody.appendChild(errorLine);
}

function renderMaxmindError(err) {
  geoipMaxmindBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = t("maxmind.heading");
  geoipMaxmindBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = t("error.generic", {
    message: (err && err.message) || String(err),
  });
  geoipMaxmindBody.appendChild(panel);
}

async function refreshMaxmind() {
  try {
    renderMaxmind(await getMaxmind());
  } catch (err) {
    renderMaxmindError(err);
  }
}

// Батч 5.4: no eager module-scope call here any more (there used to be
// one) - renderMaxmind() now calls t(), so this card joined
// renderTranslatedCards() above instead, same "only reachable from
// renderTranslatedCards()" shape Батч 5.3 already established for
// refreshGeoip()/refreshCctldBlock(). Calling both would double-fetch.

// T-46/T-54: query log screen. Same isolation reasoning as the two sections
// above (#log-body, own fetch/render cycle, not on the 2s poll) - but unlike
// them, this one also has no timer of its own: a log table re-rendering
// under a reader every couple seconds (losing scroll position, wiping an
// expanded voter-detail row) would be actively worse than a stale view with
// a manual "Оновити" button. Driven by an explicit call at the bottom, plus
// re-fetches after a filter change or a successful "очистити лог".

async function getLog(params) {
  const response = await fetch(`/admin/log?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function clearLog() {
  const response = await fetch("/admin/log/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
}

const DECISION_LABELS = {
  ALLOWED: { text: "Дозволено", cls: "good" },
  BLOCKED: { text: "Заблоковано", cls: "bad" },
  FAILED: { text: "Не вдалося", cls: "warn" },
};
const DECISION_SOURCE_LABELS = {
  ALLOWLIST: "Allowlist",
  BLOCKLIST: "Blocklist",
  BLOCKLIST_BUNDLE: "Блок-лист-бандл",
  CACHE: "Кеш",
  QUORUM: "Quorum",
  CCTLD_BLOCK: "ccTLD-блок",
  RATING_FILTER: "Рейтинговий фільтр",
  GEOIP: "GeoIP",
};
const QTYPE_LABELS = { A: "A", AAAA: "AAAA", HTTPS_SVCB: "HTTPS/SVCB", OTHER: "Інше" };
// VoterVerdictView's seven wire values (admin.rs) - PENDING is declared on
// the DTO but structurally never produced by this read-only route (reserved
// for a future live-updating log view that doesn't exist yet), kept here
// anyway so an unrecognized status never renders as literally nothing.
const VOTER_STATUS_LABELS = {
  PENDING: "очікується",
  BLOCK: "заблокував",
  ALLOW: "дозволив",
  TIMEOUT: "не відповів",
  ERROR: "помилка",
  CANCELED: "скасовано",
  DISABLED: "вимкнено",
};
// Pretty names for the two Phase-1 provider ids; any other id (a preset
// toggled on, or a custom entry) falls through to its raw wire id, which is
// already human-readable enough (e.g. "cloudflare-family").
const PROVIDER_LABELS = { quad9: "Quad9", adguard: "AdGuard" };

// Built via DOM methods only, same discipline as overrideListItem above -
// `domain`/`voter.status.message` are both untrusted (a domain from live DNS
// traffic; `message` is currently always a fixed coarse error-kind label
// server-side, but nothing about this DTO's shape guarantees that stays
// true) and admin_ui.rs's own module doc comment names exactly this screen
// as the one that must not relax into innerHTML string interpolation.
function voterDetailList(voters) {
  const ul = document.createElement("ul");
  ul.className = "log-voter-list";
  voters.forEach((voter) => {
    const li = document.createElement("li");
    const provider = document.createElement("span");
    provider.className = "log-voter-provider";
    provider.textContent = PROVIDER_LABELS[voter.provider_name] || voter.provider_name;
    li.appendChild(provider);
    const status = document.createElement("span");
    let text = VOTER_STATUS_LABELS[voter.status.status] || voter.status.status;
    if (voter.status.status === "ALLOW") {
      text += ` (${voter.status.ip_count} IP)`;
    } else if (voter.status.status === "ERROR") {
      text += `: ${voter.status.message}`;
    }
    status.textContent = text;
    li.appendChild(status);
    ul.appendChild(li);
  });
  return ul;
}

function logItem(entry) {
  const li = document.createElement("li");
  li.className = "log-item";

  const row = document.createElement("div");
  row.className = "log-item-row";

  const time = document.createElement("span");
  time.className = "log-item-time";
  time.textContent = new Date(entry.timestamp_ms).toLocaleString();
  row.appendChild(time);

  const domain = document.createElement("span");
  domain.className = "log-item-domain";
  domain.textContent = entry.domain;
  row.appendChild(domain);

  const qtype = document.createElement("span");
  qtype.className = "log-item-badge";
  qtype.textContent = QTYPE_LABELS[entry.qtype] || entry.qtype;
  row.appendChild(qtype);

  // T-161: informational country of the first resolved IP - deliberately
  // suppressed on a GEOIP-decision row, where entry.geoip_country (the IP
  // that actually matched the blocked-country list, not necessarily the
  // first one) is the meaningful value; showing this badge there would read
  // as the block reason when it might not be. geoip_country itself still has
  // no UI consumer (a pre-existing gap since T-79, named not fixed here).
  if (entry.resolved_ip_country != null && entry.decision_source !== "GEOIP") {
    const geoBadge = document.createElement("span");
    geoBadge.className = "log-item-badge";
    geoBadge.title = "Країна першої резолвленої IP-адреси";
    geoBadge.textContent = entry.resolved_ip_country;
    row.appendChild(geoBadge);
  }

  const decision = DECISION_LABELS[entry.decision] || { text: entry.decision, cls: "" };
  const decisionBadge = document.createElement("span");
  decisionBadge.className = `log-item-badge log-item-decision ${decision.cls}`;
  decisionBadge.textContent = decision.text;
  row.appendChild(decisionBadge);

  const source = document.createElement("span");
  source.className = "log-item-source";
  source.textContent = DECISION_SOURCE_LABELS[entry.decision_source] || entry.decision_source;
  row.appendChild(source);

  const latency = document.createElement("span");
  latency.className = "log-item-latency";
  latency.textContent = `${entry.latency_ms} мс`;
  row.appendChild(latency);

  li.appendChild(row);

  const actions = document.createElement("div");
  actions.className = "log-item-actions";

  // Row-level "add in one click" (T-46) - reuses the already-established
  // addOverride() from the T-47 section above rather than a second copy of
  // the same POST /admin/overrides/add call.
  ["allowlist", "blocklist"].forEach((list) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = list === "allowlist" ? "В allowlist" : "В blocklist";
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        await addOverride(entry.domain, list);
        btn.textContent = "✓ Додано";
        // Deliberately re-renders #overrides-body (unlike the unrelated 2s
        // status poll T-47's own comment guards against) - the user just
        // caused this exact mutation from this row, so showing the new
        // entry/conflict highlight immediately is the point. If they have
        // in-progress text in the override "add domain" input, it's lost;
        // accepted as a reasonable trade for the immediate feedback.
        await refreshOverrides();
      } catch (err) {
        btn.disabled = false;
        btn.textContent = `Помилка: ${(err && err.message) || String(err)}`;
      }
    });
    actions.appendChild(btn);
  });

  if (entry.voters.length > 0) {
    const detailBtn = document.createElement("button");
    detailBtn.type = "button";
    detailBtn.textContent = "Деталі";
    const detail = voterDetailList(entry.voters);
    detail.hidden = true;
    detailBtn.addEventListener("click", () => {
      detail.hidden = !detail.hidden;
      detailBtn.textContent = detail.hidden ? "Деталі" : "Сховати деталі";
    });
    actions.appendChild(detailBtn);
    li.appendChild(actions);
    li.appendChild(detail);
  } else {
    li.appendChild(actions);
  }

  return li;
}

function currentLogQuery() {
  const params = new URLSearchParams();
  const domain = document.getElementById("log-search").value.trim();
  if (domain) {
    params.set("domain_contains", domain);
  }
  const decision = document.getElementById("log-decision").value;
  if (decision) {
    params.set("decision", decision);
  }
  const voter = document.getElementById("log-voter").value;
  if (voter) {
    params.set("voter", voter);
  }
  return params;
}

// The filter row (search box, two selects, buttons) is built exactly once,
// not rebuilt on every refresh - live-verified via Chrome that the naive
// "rebuild everything from the fetch response" approach the sibling
// sections (overrides/cache-config) use has two real bugs here that it
// doesn't have there: (1) the very first refreshLog() call runs before any
// data-driven render has ever happened, so currentLogQuery() would read
// from elements that don't exist yet (`#log-search` etc.) - a null-deref,
// not a hypothetical; (2) even past the first call, wiping and recreating
// `<input id="log-search">` on every refresh would reset the user's
// in-progress search text/dropdown selection right after they triggered the
// very refresh that's supposed to show its result. Only `#log-results`
// (entries/empty-state/truncated-notice/error) is data-dependent and gets
// rebuilt; the filter chrome around it is permanent.
const logResults = document.createElement("div");

function buildLogFilterRow() {
  logBody.textContent = "";

  logBody.appendChild(cardHeading("Лог запитів", "logFilters"));

  const filterRow = document.createElement("div");
  filterRow.className = "log-filter-row";

  const search = document.createElement("input");
  search.type = "text";
  search.id = "log-search";
  search.placeholder = "Пошук за доменом";
  search.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      refreshLog();
    }
  });
  filterRow.appendChild(search);

  const decisionSelect = document.createElement("select");
  decisionSelect.id = "log-decision";
  [
    ["", "Усі рішення"],
    ["ALLOWED", "Дозволено"],
    ["BLOCKED", "Заблоковано"],
    ["FAILED", "Не вдалося"],
  ].forEach(([value, text]) => {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = text;
    decisionSelect.appendChild(opt);
  });
  decisionSelect.addEventListener("change", refreshLog);
  filterRow.appendChild(decisionSelect);

  const voterSelect = document.createElement("select");
  voterSelect.id = "log-voter";
  // T-72/T-73: options are filled in by syncLogVoterOptions() from the live
  // /admin/providers response (every built-in preset + any active custom
  // entry), not hardcoded - the provider list is now runtime state. Starts
  // with just the "all" option so the element exists for currentLogQuery()
  // even before the providers fetch resolves.
  const allVoters = document.createElement("option");
  allVoters.value = "";
  allVoters.textContent = "Усі voter'и";
  voterSelect.appendChild(allVoters);
  voterSelect.addEventListener("change", refreshLog);
  filterRow.appendChild(voterSelect);

  const searchBtn = document.createElement("button");
  searchBtn.type = "button";
  searchBtn.textContent = "Пошук";
  searchBtn.addEventListener("click", refreshLog);
  filterRow.appendChild(searchBtn);

  const refreshBtn = document.createElement("button");
  refreshBtn.type = "button";
  refreshBtn.textContent = "Оновити";
  refreshBtn.addEventListener("click", refreshLog);
  filterRow.appendChild(refreshBtn);

  // Two-step confirm instead of a blocking window.confirm() (no precedent
  // for one anywhere else on this page, and a native dialog can't be styled
  // to explain the consequence the way this project's other destructive
  // actions - dnsqb-tray's "Зупинити фільтрацію" - already do).
  const clearBtn = document.createElement("button");
  clearBtn.type = "button";
  clearBtn.textContent = "Очистити лог";
  let confirming = false;
  clearBtn.addEventListener("click", async () => {
    if (!confirming) {
      confirming = true;
      clearBtn.textContent = "Точно очистити?";
      setTimeout(() => {
        if (confirming) {
          confirming = false;
          clearBtn.textContent = "Очистити лог";
        }
      }, 4000);
      return;
    }
    confirming = false;
    try {
      await clearLog();
      await refreshLog();
    } catch (err) {
      renderLogError(err);
    } finally {
      // Live-verified gap: without this, a successful clear left the button
      // permanently reading "Точно очистити?" - misleadingly implying a
      // confirmation was still pending even though the action already
      // completed.
      clearBtn.textContent = "Очистити лог";
    }
  });
  filterRow.appendChild(clearBtn);

  logBody.appendChild(filterRow);
  logBody.appendChild(logResults);
}

function renderLog(data) {
  logResults.textContent = "";

  if (data.entries.length === 0) {
    const empty = document.createElement("p");
    empty.className = "log-empty";
    empty.textContent = "Записів не знайдено.";
    logResults.appendChild(empty);
    return;
  }

  if (data.truncated) {
    const truncatedNotice = document.createElement("div");
    truncatedNotice.className = "notice warn";
    truncatedNotice.textContent =
      "Показано лише найновіші записи, що відповідають фільтру - звузьте пошук, щоб побачити решту.";
    logResults.appendChild(truncatedNotice);
  }

  const list = document.createElement("ul");
  list.className = "log-list";
  // Newest first for reading, even though the backend returns oldest-first
  // within the kept window (dispatch::serve_admin_log's own doc comment).
  [...data.entries].reverse().forEach((entry) => list.appendChild(logItem(entry)));
  logResults.appendChild(list);
}

function renderLogError(err) {
  logResults.textContent = "";
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  logResults.appendChild(panel);
}

async function refreshLog() {
  try {
    renderLog(await getLog(currentLogQuery()));
  } catch (err) {
    renderLogError(err);
  }
}

// Order matters: buildLogFilterRow() must run first - refreshLog() calls
// currentLogQuery(), which reads #log-search/#log-decision/#log-voter, and
// those elements don't exist until buildLogFilterRow() creates them (see its
// own comment above for the null-deref this fixed). T-151 Батч 5.2:
// buildLogFilterRow() moved into renderTranslatedCards() (its cardHeading()
// reads t("fieldHelp.logFilters")) - refreshLog() moved there too, right
// after it, so this order requirement survives the move intact.

// T-72/T-73: the voter (provider) list editor. Same isolation reasoning as
// the overrides/geoip sections - #providers-body is its own DOM subtree with
// its own fetch/render cycle, not on the 2s status poll, so the free-text
// inputs in the "add custom provider" sub-form aren't wiped mid-typing.
// Fetches once on load, then re-renders straight from each mutating route's
// echoed ProvidersResponse (add/remove/set-enabled) - the same
// render-the-POST-response, never re-GET pattern the geoip card uses, so a
// failed disk save shows up as persisted:false instead of being hidden by a
// fresh GET's always-true value.

const PROVIDER_CATEGORY_LABELS = {
  SECURITY: "Безпека (шкідливе, фішинг)",
  ADS_TRACKERS: "Реклама і трекери",
  ADULT_CONTENT: "Дорослий контент",
};
const PROVIDER_CATEGORY_ORDER = ["SECURITY", "ADS_TRACKERS", "ADULT_CONTENT"];
const BLOCK_SIGNATURE_LABELS = {
  NULL_IP: "0.0.0.0 у відповіді",
  NXDOMAIN_VS_BASELINE: "NXDOMAIN проти baseline",
  NULL_IP_OR_NXDOMAIN: "0.0.0.0 або NXDOMAIN",
};

async function getProviders() {
  const response = await fetch("/admin/providers");
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function setProviderEnabled(id, enabled) {
  const response = await fetch("/admin/providers/set-enabled", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, enabled }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function addProvider(spec) {
  const response = await fetch("/admin/providers/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(spec),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function removeProvider(id) {
  const response = await fetch("/admin/providers/remove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

// Rebuilds #log-voter's options from the live provider list - every built-in
// preset plus any active custom entry, keyed by id. Runs on every
// renderProviders() (add/remove/toggle). Preserves the current selection;
// if it named an entry that no longer exists the browser drops it back to
// "" (all voters), which is also what the backend's ?voter= validation
// would 400 anyway.
function syncLogVoterOptions(data) {
  const select = document.getElementById("log-voter");
  if (!select) {
    return;
  }
  const previous = select.value;
  select.textContent = "";
  const all = document.createElement("option");
  all.value = "";
  all.textContent = "Усі voter'и";
  select.appendChild(all);

  const seen = new Set();
  const pairs = [];
  data.available_presets.concat(data.active).forEach((entry) => {
    if (!seen.has(entry.id)) {
      seen.add(entry.id);
      pairs.push([entry.id, entry.display_name]);
    }
  });
  pairs.forEach(([value, text]) => {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = text;
    select.appendChild(opt);
  });
  // Only restore the prior selection if it still names a real option -
  // assigning a missing value sets selectedIndex to -1, which renders the
  // dropdown blank (currentLogQuery() would still read "", so the filter is
  // correct, but it looks broken).
  const stillPresent = Array.from(select.options).some((opt) => opt.value === previous);
  select.value = stillPresent ? previous : "";
}

// Built via DOM methods only (createElement / textContent) - a custom
// entry's display_name is operator-supplied and reaches the DOM here;
// admin_ui.rs's own module doc flags that this page's CSP does not restrain
// innerHTML, so every renderer that shows user text constructs nodes
// instead of interpolating strings (same discipline as overrideListItem).
function providerRow(entry) {
  const li = document.createElement("li");
  li.className = "override-item";

  const label = document.createElement("span");
  label.textContent = entry.display_name;
  li.appendChild(label);

  const sig = document.createElement("span");
  sig.className = "log-item-badge";
  sig.title = "Як quorum читає блок-відповідь цього провайдера";
  sig.textContent = BLOCK_SIGNATURE_LABELS[entry.block_signature] || entry.block_signature;
  li.appendChild(sig);

  if (!entry.is_builtin) {
    const custom = document.createElement("span");
    custom.className = "log-item-badge";
    custom.textContent = "власний";
    li.appendChild(custom);
  }

  const sw = document.createElement("label");
  sw.className = "switch";
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.checked = entry.enabled;
  cb.addEventListener("change", async () => {
    try {
      renderProviders(await setProviderEnabled(entry.id, cb.checked));
    } catch (err) {
      cb.checked = entry.enabled;
      renderProvidersError(err);
    }
  });
  const track = document.createElement("span");
  track.className = "track";
  const thumb = document.createElement("span");
  thumb.className = "thumb";
  sw.appendChild(cb);
  sw.appendChild(track);
  sw.appendChild(thumb);
  li.appendChild(sw);

  if (!entry.is_builtin) {
    let armed = false;
    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "override-remove";
    removeBtn.textContent = "Видалити";
    removeBtn.addEventListener("click", async () => {
      if (!armed) {
        armed = true;
        removeBtn.textContent = "Підтвердити видалення";
        return;
      }
      try {
        renderProviders(await removeProvider(entry.id));
      } catch (err) {
        renderProvidersError(err);
      }
    });
    li.appendChild(removeBtn);
  }

  return li;
}

// Ukrainian count agreement: 1 / 2-4 / everything else (0, 5-20, then by the
// last digit). Used for the fan-out privacy line, which CLAUDE.md requires
// stay prominent and in the user's language.
function pluralUk(n, one, few, many) {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) {
    return one;
  }
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) {
    return few;
  }
  return many;
}

// Built exactly once and re-appended (not rebuilt) on every renderProviders()
// - a toggle/add/remove elsewhere in the card must not wipe a half-typed
// custom endpoint URL + token out of these five fields. Same reasoning and
// pattern as buildLogFilterRow()'s once-built filter chrome above; the
// weaker "accept the wipe" trade logItem() makes for the single overrides
// input doesn't carry to a five-field form sitting right below the toggles.
let customFormNode = null;

function customProviderForm() {
  if (customFormNode) {
    return customFormNode;
  }
  const wrap = document.createElement("div");

  const heading = document.createElement("h4");
  heading.textContent = "Додати власний DoH-провайдер";
  wrap.appendChild(heading);

  const row = document.createElement("div");
  row.className = "override-add-row";

  const idInput = document.createElement("input");
  idInput.type = "text";
  idInput.placeholder = "ідентифікатор (a-z, 0-9, -)";
  idInput.maxLength = 64;

  const urlInput = document.createElement("input");
  urlInput.type = "text";
  urlInput.placeholder = "https://xxxx.dns.nextdns.io/dns-query";

  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.placeholder = "показова назва";

  const catSelect = document.createElement("select");
  PROVIDER_CATEGORY_ORDER.forEach((cat) => {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = PROVIDER_CATEGORY_LABELS[cat];
    catSelect.appendChild(opt);
  });

  const sigSelect = document.createElement("select");
  // NULL_IP_OR_NXDOMAIN first: the permissive default for an endpoint whose
  // block behaviour hasn't been live-verified - matches resolve_providers'
  // own default on the backend.
  ["NULL_IP_OR_NXDOMAIN", "NULL_IP", "NXDOMAIN_VS_BASELINE"].forEach((sigValue) => {
    const opt = document.createElement("option");
    opt.value = sigValue;
    opt.textContent = BLOCK_SIGNATURE_LABELS[sigValue];
    sigSelect.appendChild(opt);
  });

  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.textContent = "Додати";

  const errorLine = document.createElement("div");
  errorLine.className = "override-error";

  addBtn.addEventListener("click", async () => {
    const id = idInput.value.trim();
    const url = urlInput.value.trim();
    const displayName = nameInput.value.trim();
    errorLine.textContent = "";
    // Client-side mirror of the backend's is_valid_provider_id /
    // validate_provider_url checks - belt and suspenders, the server still
    // rejects independently and stays payload-free.
    if (!/^[a-z0-9-]{1,64}$/.test(id)) {
      errorLine.textContent =
        "Ідентифікатор: лише малі латинські літери, цифри та дефіс (1-64 символи).";
      return;
    }
    if (!/^https:\/\//i.test(url)) {
      errorLine.textContent = "URL має починатися з https://";
      return;
    }
    if (!displayName) {
      errorLine.textContent = "Вкажіть показову назву.";
      return;
    }
    try {
      renderProviders(
        await addProvider({
          id,
          url,
          display_name: displayName,
          category: catSelect.value,
          block_signature: sigSelect.value,
        }),
      );
    } catch (err) {
      errorLine.textContent = `Не вдалося додати: ${(err && err.message) || String(err)}`;
    }
  });

  row.appendChild(idInput);
  row.appendChild(urlInput);
  row.appendChild(nameInput);
  row.appendChild(catSelect);
  row.appendChild(sigSelect);
  row.appendChild(addBtn);
  wrap.appendChild(row);
  wrap.appendChild(errorLine);
  customFormNode = wrap;
  return wrap;
}

function renderProviders(data) {
  providersBody.textContent = "";

  providersBody.appendChild(cardHeading("Провайдери-voter'и", "providers"));

  // T-176: this same ProvidersResponse also drives the basic-view master +
  // category toggles, the fan-out privacy line and the pass-through warning
  // (which moved up into the basic view - CLAUDE.md "not buried" / SPEC.md
  // §8.1). One fetch, both views stay in sync.
  renderFilterControls(data);

  // Same "silent data loss" concern as #overrides-body / #geoip-body (T-47).
  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent =
      "Зміну застосовано, але НЕ збережено на диск - вона не переживе перезапуск сервісу.";
    providersBody.appendChild(notPersisted);
  }

  PROVIDER_CATEGORY_ORDER.forEach((cat) => {
    const inCategory = data.active.filter((entry) => entry.category === cat);
    if (inCategory.length === 0) {
      return;
    }
    const catHeading = document.createElement("h4");
    catHeading.textContent = PROVIDER_CATEGORY_LABELS[cat] || cat;
    providersBody.appendChild(catHeading);
    const list = document.createElement("ul");
    list.className = "override-list";
    inCategory.forEach((entry) => list.appendChild(providerRow(entry)));
    providersBody.appendChild(list);
  });

  const activeIds = new Set(data.active.map((entry) => entry.id));
  const addable = data.available_presets.filter((preset) => !activeIds.has(preset.id));
  if (addable.length > 0) {
    const addHeading = document.createElement("h4");
    addHeading.textContent = "Додати пресет";
    providersBody.appendChild(addHeading);
    const list = document.createElement("ul");
    list.className = "override-list";
    addable.forEach((preset) => {
      const li = document.createElement("li");
      li.className = "override-item";
      const label = document.createElement("span");
      label.textContent = preset.display_name;
      li.appendChild(label);
      const catBadge = document.createElement("span");
      catBadge.className = "log-item-badge";
      catBadge.textContent = PROVIDER_CATEGORY_LABELS[preset.category] || preset.category;
      li.appendChild(catBadge);
      const addBtn = document.createElement("button");
      addBtn.type = "button";
      addBtn.className = "override-remove";
      addBtn.textContent = "Додати";
      addBtn.addEventListener("click", async () => {
        try {
          renderProviders(await addProvider({ id: preset.id }));
        } catch (err) {
          renderProvidersError(err);
        }
      });
      li.appendChild(addBtn);
      list.appendChild(li);
    });
    providersBody.appendChild(list);
  }

  providersBody.appendChild(customProviderForm());

  syncLogVoterOptions(data);
}

function renderProvidersError(err) {
  const message = `Помилка: ${(err && err.message) || String(err)}`;
  providersBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = "Провайдери-voter'и";
  providersBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = message;
  providersBody.appendChild(panel);
  // T-176: the basic-view toggles ride on this same fetch - if it failed,
  // don't leave stale switches sitting there implying a known state.
  filterControlsBody.textContent = "";
  const basicPanel = document.createElement("div");
  basicPanel.className = "error-panel";
  basicPanel.textContent = message;
  filterControlsBody.appendChild(basicPanel);
}

async function refreshProviders() {
  try {
    renderProviders(await getProviders());
  } catch (err) {
    renderProvidersError(err);
  }
}

// T-151 Батч 5.2: kicked off from renderTranslatedCards() - see the comment
// by refreshOverrides() above.

// ===================================================================
// T-176: basic-view filter controls (master + category toggles) and the
// browser-setup card. The toggles ride on the same GET /admin/providers
// fetch as #providers-body (renderProviders calls renderFilterControls),
// so a click never races the 2s status poll - same isolation reasoning as
// every other card that owns its own cycle.
// ===================================================================

const CATEGORY_META = [
  {
    key: "SECURITY",
    name: "Захист від шкідливого",
    sub: "Віруси, фішинг, шахрайські сайти",
  },
  {
    key: "ADS_TRACKERS",
    name: "Блокування реклами",
    sub: "Рекламні й стежні домени",
  },
  {
    key: "ADULT_CONTENT",
    name: "Дорослий вміст",
    sub: "Порнографія та подібні сайти",
  },
];

async function setCategoryEnabled(category, enabled) {
  const response = await fetch("/admin/providers/set-category-enabled", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ category, enabled }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

// "on" | "off" | "partial" for one category. T-204: the fold moved to the
// server (admin.rs::category_filter_views); this reads `data.category_states`
// (CategoryToggleState, SCREAMING_SNAKE) and lowercases it for the render
// helpers below. A category the server didn't list ⇒ "off".
function categoryStateFrom(data, key) {
  const row = (data.category_states || []).find((entry) => entry.category === key);
  return row ? row.state.toLowerCase() : "off";
}

// Built via DOM methods, no user text - but kept construction-style for
// consistency with the rest of this file (admin_ui.rs's module doc). A
// "partial" state is a non-interactive visual whose click/Enter turns the
// whole category on; "on"/"off" is a real checkbox.
function toggleControl(checked, partial, onFlip, ariaLabel) {
  if (partial) {
    const span = document.createElement("span");
    span.className = "switch is-partial";
    // role="checkbox" (not "switch") - only checkbox accepts aria-checked="mixed".
    span.setAttribute("role", "checkbox");
    span.setAttribute("aria-checked", "mixed");
    span.setAttribute("aria-label", ariaLabel);
    span.tabIndex = 0;
    const track = document.createElement("span");
    track.className = "track";
    const thumb = document.createElement("span");
    thumb.className = "thumb";
    span.appendChild(track);
    span.appendChild(thumb);
    const activate = () => onFlip(true);
    span.addEventListener("click", activate);
    span.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        activate();
      }
    });
    return span;
  }
  const label = document.createElement("label");
  label.className = "switch";
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.checked = checked;
  cb.setAttribute("aria-label", ariaLabel);
  cb.addEventListener("change", () => onFlip(cb.checked));
  const track = document.createElement("span");
  track.className = "track";
  const thumb = document.createElement("span");
  thumb.className = "thumb";
  label.appendChild(cb);
  label.appendChild(track);
  label.appendChild(thumb);
  return label;
}

function toggleRow(name, sub, control, isMaster) {
  const row = document.createElement("div");
  row.className = isMaster ? "toggle-row is-master" : "toggle-row";
  const meta = document.createElement("div");
  meta.className = "toggle-meta";
  const nameEl = document.createElement("div");
  nameEl.className = "toggle-name";
  nameEl.textContent = name;
  const subEl = document.createElement("div");
  subEl.className = "toggle-sub";
  subEl.textContent = sub;
  meta.appendChild(nameEl);
  meta.appendChild(subEl);
  row.appendChild(meta);
  row.appendChild(control);
  return row;
}

function showFilterControlsError(message) {
  const el = document.getElementById("filter-controls-error");
  if (el) {
    el.textContent = message;
  }
}

async function flipCategory(category, enabled) {
  try {
    renderProviders(await setCategoryEnabled(category, enabled));
  } catch (err) {
    // refreshProviders() rebuilds #filter-controls-error empty, so the message
    // must be shown after it, not before (same order as flipAllCategories).
    await refreshProviders();
    showFilterControlsError(
      `Не вдалося змінити категорію: ${(err && err.message) || String(err)}`,
    );
  }
}

// The master switch flips every allowed category to the same target.
// Sequential (not Promise.all): each POST rewrites resolver_config.toml under
// persist_lock, and a partial failure must be reported, not swallowed.
//
// T-204: `targets` is `status.master_switch_targets` - the categories with a
// configured voter, computed server-side (admin.rs::master_switch_targets).
// The guard that keeps the master switch from opting a user into adult
// filtering with a preset they never chose (T-170 / DECISIONS.md 2026-09-06)
// now lives there, Rust-tested, instead of being re-derived here.
async function flipAllCategories(enabled, targets) {
  const failed = [];
  for (const key of targets || []) {
    try {
      await setCategoryEnabled(key, enabled);
    } catch (_err) {
      const meta = CATEGORY_META.find((cat) => cat.key === key);
      failed.push(meta ? meta.name : key);
    }
  }
  await refreshProviders();
  if (failed.length > 0) {
    showFilterControlsError(
      `Не перемкнулись: ${failed.join(", ")}. Спробуйте ще раз.`,
    );
  }
}

function renderFilterControls(data) {
  filterControlsBody.textContent = "";
  const providers = data.active || [];
  const anyOn = providers.some((entry) => entry.enabled);

  filterControlsBody.appendChild(
    toggleRow(
      "Фільтрація",
      "Головний вимикач — вмикає й вимикає всі перевірки",
      toggleControl(
        anyOn,
        false,
        (want) => flipAllCategories(want, data.master_switch_targets),
        "Фільтрація",
      ),
      true,
    ),
  );

  CATEGORY_META.forEach((cat) => {
    const state = categoryStateFrom(data, cat.key);
    const sub =
      state === "partial"
        ? `${cat.sub}. Увімкнено частково — натисніть, щоб увімкнути всі`
        : cat.sub;
    filterControlsBody.appendChild(
      toggleRow(
        cat.name,
        sub,
        toggleControl(
          state === "on",
          state === "partial",
          (want) => flipCategory(cat.key, want),
          cat.name,
        ),
        false,
      ),
    );
  });

  // T-72/T-73 closing review: the all-disabled pass-through is a legitimate
  // user choice, but it must be shown - and in the BASIC view (T-176), since
  // that is exactly when the user is least likely to open "Розширені".
  if (!data.filtering_active) {
    const off = document.createElement("div");
    off.className = "notice warn";
    off.textContent =
      "Жоден фільтр не активний. Запити все одно бачить резервний резолвер — " +
      "він знає кожен домен, який ви відвідуєте.";
    filterControlsBody.appendChild(off);
  }

  // Same "silent data loss" concern as every other card (T-47) - a category
  // toggle that live-applied but failed to persist must be visible here too.
  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent =
      "Зміну застосовано, але НЕ збережено на диск — вона не переживе перезапуск сервісу.";
    filterControlsBody.appendChild(notPersisted);
  }

  // SPEC.md / CLAUDE.md: the fan-out privacy tradeoff must stay user-visible,
  // not buried - so it lives in the basic view now, not the providers card.
  const parties = data.third_party_count;
  const voterCount = parties - 1;
  const fanout = document.createElement("p");
  fanout.className = "fanout-note";
  fanout.textContent =
    `Кожен запит поза кешем ${pluralUk(parties, "бачить", "бачать", "бачать")} ${parties} ` +
    `${pluralUk(parties, "сторону", "сторони", "сторін")}: ` +
    `${voterCount} ${pluralUk(voterCount, "увімкнена перевірка", "увімкнені перевірки", "увімкнених перевірок")} ` +
    `+ резервний резолвер.`;
  filterControlsBody.appendChild(fanout);

  const errLine = document.createElement("div");
  errLine.className = "override-error";
  errLine.id = "filter-controls-error";
  filterControlsBody.appendChild(errLine);
}

// --- browser DoH setup / onboarding (#browser-setup-body) ---
// Wired once at load: the buttons, and the first-visit auto-open of the
// steps, must not be re-run by the 2s status poll. The #doh-url value is
// refreshed from status.port on every render() call (harmless - readonly).

const BROWSER_SETUP_SEEN_KEY = "dnsqb-browser-setup-seen";

function syncDohUrl(status) {
  const field = document.getElementById("doh-url");
  if (field && status && status.port) {
    field.value = `https://127.0.0.1:${status.port}/dns-query`;
  }
}

// T-189: wire one "copy this string to the clipboard" button. `getText`
// returns the current string (the DoH URL is refreshed by the status poll,
// the browser settings-URL is set by the detector below). Feedback goes to
// the shared #browser-setup-result line.
function wireCopyButton(button, getText) {
  const result = document.getElementById("browser-setup-result");
  if (!button) {
    return;
  }
  button.addEventListener("click", async () => {
    const text = getText();
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        throw new Error("no clipboard API");
      }
      if (result) {
        result.textContent = "Скопійовано.";
        setTimeout(() => {
          if (result) {
            result.textContent = "";
          }
        }, 2000);
      }
    } catch (_err) {
      if (result) {
        result.textContent = `Скопіюйте вручну: ${text}`;
      }
    }
  });
}

// T-189: browser family from the UA string of the browser rendering THIS page
// - which is exactly the one the user needs to configure (better than the
// registry default: /admin/ui may have opened in a non-default browser).
function detectBrowserFamily() {
  const ua = navigator.userAgent;
  if (/Firefox\//.test(ua)) return "firefox";
  if (/Edg\//.test(ua)) return "edge";
  if (/OPR\//.test(ua)) return "opera";
  if (/Chrome\//.test(ua)) return "chrome";
  return "other";
}

const CHROMIUM_SETTINGS_URL = {
  chrome: "chrome://settings/security",
  edge: "edge://settings/privacy",
  brave: "brave://settings/security",
  opera: "opera://settings",
};

// T-189: unhide the one static step block for `family`, hide the rest, set the
// Chromium settings-URL. Synchronous - so a block is visible at every point.
function applyBrowserFamily(family) {
  const chromium = document.getElementById("browser-steps-chromium");
  const firefox = document.getElementById("browser-steps-firefox");
  const other = document.getElementById("browser-steps-other");
  const urlCode = document.getElementById("chromium-settings-url");
  [chromium, firefox, other].forEach((el) => {
    if (el) el.hidden = true;
  });
  if (family === "firefox") {
    if (firefox) firefox.hidden = false;
  } else if (CHROMIUM_SETTINGS_URL[family]) {
    if (urlCode) urlCode.textContent = CHROMIUM_SETTINGS_URL[family];
    if (chromium) chromium.hidden = false;
  } else if (other) {
    other.hidden = false;
  }
}

// Apply the UA-detected family synchronously first (so the first-visit
// auto-open never shows an opened container with every block hidden), then
// refine to Brave, which reports as Chrome in the UA and can only be told
// apart via an async call.
async function revealBrowserSteps() {
  const family = detectBrowserFamily();
  applyBrowserFamily(family);
  if (
    family === "chrome" &&
    navigator.brave &&
    typeof navigator.brave.isBrave === "function"
  ) {
    try {
      if (await navigator.brave.isBrave()) {
        applyBrowserFamily("brave");
      }
    } catch (_err) {
      /* stay on "chrome" */
    }
  }
}

function initBrowserSetup() {
  const steps = document.getElementById("browser-setup-steps");
  const toggle = document.getElementById("browser-setup-toggle");
  const field = document.getElementById("doh-url");
  const chromiumUrl = document.getElementById("chromium-settings-url");
  const firefoxUrl = document.getElementById("firefox-settings-url");

  if (toggle && steps) {
    toggle.addEventListener("click", () => {
      steps.hidden = !steps.hidden;
      toggle.setAttribute("aria-expanded", String(!steps.hidden));
      toggle.textContent = steps.hidden
        ? "Показати покрокову інструкцію"
        : "Сховати інструкцію";
    });
  }

  wireCopyButton(document.getElementById("doh-url-copy"), () =>
    field ? field.value : "",
  );
  wireCopyButton(document.getElementById("chromium-settings-copy"), () =>
    chromiumUrl ? chromiumUrl.textContent : "",
  );
  wireCopyButton(document.getElementById("firefox-settings-copy"), () =>
    firefoxUrl ? firefoxUrl.textContent : "",
  );
  revealBrowserSteps();

  // First visit: open the steps so a new user is walked through setup. The
  // flag is per-viewer convenience only (localStorage), never anything the
  // service needs back - and every read/write is guarded (private windows,
  // blocked site data).
  let seen = false;
  try {
    seen = localStorage.getItem(BROWSER_SETUP_SEEN_KEY) === "1";
  } catch (_err) {
    seen = false;
  }
  if (!seen && steps && toggle) {
    steps.hidden = false;
    toggle.setAttribute("aria-expanded", "true");
    toggle.textContent = "Сховати інструкцію";
    try {
      localStorage.setItem(BROWSER_SETUP_SEEN_KEY, "1");
    } catch (_err) {
      /* best-effort: the steps just stay open again next visit */
    }
  }
}

initBrowserSetup();

// T-70: "Повністю видалити" - no fetch/render cycle, no 2s poll (there is
// nothing persisted to show, only the one-shot result of the last click).
// Two-step confirm, same established convention as #log-body's "Очистити
// лог" above - this is a strictly higher-blast-radius action (trust store +
// three Credential Manager secrets), so it gets the same in-page pattern,
// not a native window.confirm() this page has no other precedent for.

const OUTCOME_LABELS = {
  REMOVED: "видалено",
  NOT_PRESENT: "не було встановлено",
  FAILED: "НЕ ВДАЛОСЯ видалити",
};

async function uninstallLocalState() {
  const response = await fetch("/admin/uninstall-local-state", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

function renderUninstallResult(result) {
  const box = document.getElementById("uninstall-local-state-result");
  box.textContent = "";
  const rows = [
    ["Сертифікат", result.cert],
    ["TLS-ключ", result.tls_key],
    ["Ключ шифрування", result.persistence_key],
    ["Креденшели MaxMind", result.maxmind_creds],
    ["Ключ особистої зони", result.personal_zone_key],
  ];
  const anyFailed = rows.some(([, outcome]) => outcome === "FAILED");
  const panel = document.createElement("p");
  panel.className = anyFailed ? "notice warn" : "notice ok";
  panel.textContent = rows
    .map(([label, outcome]) => `${label}: ${OUTCOME_LABELS[outcome] || outcome}`)
    .join(" · ");
  box.appendChild(panel);
}

function renderUninstallError(err) {
  const box = document.getElementById("uninstall-local-state-result");
  box.textContent = "";
  const panel = document.createElement("p");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  box.appendChild(panel);
}

const uninstallBtn = document.getElementById("uninstall-local-state-btn");
let confirmingUninstall = false;
uninstallBtn.addEventListener("click", async () => {
  if (!confirmingUninstall) {
    confirmingUninstall = true;
    uninstallBtn.textContent = "Точно видалити все?";
    setTimeout(() => {
      if (confirmingUninstall) {
        confirmingUninstall = false;
        uninstallBtn.textContent = "Повністю видалити";
      }
    }, 4000);
    return;
  }
  confirmingUninstall = false;
  try {
    renderUninstallResult(await uninstallLocalState());
  } catch (err) {
    renderUninstallError(err);
  } finally {
    // Same live-verified fix as #log-body's clearBtn - without it a
    // successful click leaves the button permanently reading "Точно
    // видалити все?" even though the action already completed.
    uninstallBtn.textContent = "Повністю видалити";
  }
});

// T-127/T-111: the rating-filter «bubble» zone-config card
// (#rating-filter-body). SPEC.md §5.3. Its data is a field on
// AdminStatusResponse (status.rating_filter: RatingFilterStatusView), not
// its own GET route - the card fetches /admin/status once on load and
// re-renders from the POST /admin/rating-filter response after every
// action. Deliberately NOT on the 2s poll: the zone combobox is a
// free-text input in progress, same reasoning as #overrides-body /
// #geoip-body. Built via DOM methods, not innerHTML (the CSP sets no
// Trusted Types - same house rule as the overrides/geoip editors).
// (ratingFilterBody / ratingFilterBadge are declared with the other
// element handles at the top of this file.)

// The curated availability zones ship as bare codes in
// status.rating_filter.available_lists (the T-105 distribution contract);
// the Ukrainian names are a client-side presentation concern - the server
// has no basis to localise "ua" (i18n is T-151 / Фаза 5). An unknown code
// (a future dataset the client has no label for) falls back to the code.
const RATING_FILTER_ZONE_LABELS = {
  ua: "Україна",
  us: "США",
  de: "Німеччина",
  pl: "Польща",
  gb: "Велика Британія",
  global: "Глобальний топ",
  // T-122/T-123 (Батч 4.2) — hand-curated, not CrUX popularity lists.
  "gov-ua": "Україна (державні)",
  "gov-us": "США (державні)",
  "gov-pl": "Польща (державні)",
  "gov-gb": "Велика Британія (державні)",
  edu: "Наука/освіта",
};

function ratingFilterZoneLabel(code) {
  return RATING_FILTER_ZONE_LABELS[code] || code;
}

async function setRatingFilter(enabled, lists) {
  const response = await fetch("/admin/rating-filter", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled, lists }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

function ratingFilterCountByList(loaded) {
  const map = {};
  (loaded || []).forEach((entry) => {
    map[entry.list] = entry.domains;
  });
  return map;
}

// T-128: the always-visible activity indicator (#rating-filter-badge),
// rendered from status.rating_filter on every 2s poll via render(). Nothing
// is shown while the bubble is off (an empty div, no layout); "active" vs
// "enabled, lists loading" (Fork B) are the two visible states, matching the
// mockup's Артборд E and the tray tooltip suffix.
function renderRatingFilterBadge(rf) {
  ratingFilterBadge.textContent = "";
  if (!rf || !rf.enabled) {
    return;
  }
  const badge = document.createElement("span");
  badge.className = rf.active ? "rf-badge on" : "rf-badge pending";
  const dot = document.createElement("span");
  dot.className = "rf-dot";
  badge.appendChild(dot);
  badge.appendChild(
    document.createTextNode(
      rf.active
        ? "Рейтинговий фільтр «бульбашка» активний"
        : "Рейтинговий фільтр увімкнено — списки завантажуються",
    ),
  );
  ratingFilterBadge.appendChild(badge);
}

function renderRatingFilter(status) {
  const rf = status.rating_filter;
  ratingFilterBody.textContent = "";

  const heading = document.createElement("h3");
  heading.textContent = "Рейтинговий фільтр «бульбашка»";
  ratingFilterBody.appendChild(heading);

  // Same silent-data-loss concern as #overrides-body / #geoip-body (T-47).
  // No module flag needed here (unlike renderTimeoutConfig's
  // configPersistFailed): this card isn't re-rendered by the 2s poll, so a
  // `persisted: false` render stays on screen until the next action.
  if (status.persisted === false) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent =
      "Зміну застосовано, але НЕ збережено на диск — вона не переживе перезапуск сервісу.";
    ratingFilterBody.appendChild(notPersisted);
  }

  const card = document.createElement("div");
  card.className = "rf-card";

  const head = document.createElement("div");
  head.className = "rf-head";
  const title = document.createElement("span");
  title.className = "rf-title";
  title.textContent = "Обмежити інтернет обраними зонами";
  head.appendChild(title);

  const switchLabel = document.createElement("label");
  switchLabel.className = "switch rating-filter-switch";
  const switchInput = document.createElement("input");
  switchInput.type = "checkbox";
  switchInput.checked = rf.enabled;
  switchInput.setAttribute("aria-label", "Рейтинговий фільтр «бульбашка»");
  const track = document.createElement("span");
  track.className = "track";
  const thumb = document.createElement("span");
  thumb.className = "thumb";
  switchLabel.appendChild(switchInput);
  switchLabel.appendChild(track);
  switchLabel.appendChild(thumb);
  head.appendChild(switchLabel);
  card.appendChild(head);

  const desc = document.createElement("p");
  desc.className = "rf-desc";
  if (rf.active) {
    desc.textContent =
      "Активний. Поза обраними зонами → блок, кворум не опитується.";
  } else if (rf.enabled) {
    desc.textContent =
      "Дозволяє резолвити лише сайти з курованих списків популярних доменів. Усе інше → блок.";
  } else {
    desc.textContent =
      "Дозволяє резолвити лише сайти з курованих списків популярних доменів. " +
      "Усе інше → блок. Опційно, дефолт вимкнено. Оберіть зони заздалегідь — " +
      "вони застосуються, щойно ввімкнете.";
  }
  card.appendChild(desc);

  // Fork B: enabled, but run_topn_updater hasn't landed a list yet - step 5
  // is inert. A distinct, un-missable warning, not a permanent banner.
  if (rf.enabled && !rf.active) {
    const forkB = document.createElement("div");
    forkB.className = "notice warn";
    forkB.textContent =
      "Фільтр увімкнено, але жоден список ще не завантажено — фільтрація поки не діє. " +
      "Оновиться автоматично за кілька секунд.";
    card.appendChild(forkB);
  }

  // OFF→ON arm-confirm block, hidden until the switch is clicked on
  // (mirrors #geoip-body's add-arming: "an always-on warning is
  // functionally identical to no warning", SPEC.md §8.1).
  const confirmNotice = document.createElement("div");
  confirmNotice.className = "notice warn";
  confirmNotice.hidden = true;
  confirmNotice.textContent =
    "Увімкнення заблокує переважну більшість інтернету — доступними лишаться " +
    "лише сайти з обраних зон нижче. Дефолт — вимкнено.";
  card.appendChild(confirmNotice);

  const confirmRow = document.createElement("div");
  confirmRow.className = "rf-confirm-row";
  confirmRow.hidden = true;
  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.textContent = "Скасувати";
  const confirmBtn = document.createElement("button");
  confirmBtn.type = "button";
  confirmBtn.className = "rf-confirm";
  confirmBtn.textContent = "Підтвердити ввімкнення";
  // T-228: enabling wakes run_topn_updater (SPEC.md §5.3 / dispatch.rs), which
  // fetches any picked zone that isn't already cached on disk - offline, that
  // fetch just fails in the background with no feedback here beyond the
  // existing "завантажується…" placeholder staying stuck forever. Block
  // before the request instead of leaving that silent.
  if (lastNetworkStatus === "OFFLINE") {
    confirmBtn.disabled = true;
    confirmBtn.title =
      "Немає з'єднання з інтернетом - завантаження списків зон неможливе.";
  }
  confirmRow.appendChild(cancelBtn);
  confirmRow.appendChild(confirmBtn);
  card.appendChild(confirmRow);

  const errorLine = document.createElement("div");
  errorLine.className = "override-error";
  card.appendChild(errorLine);

  const sub = document.createElement("div");
  sub.className = "rf-sub";
  sub.textContent = "Зони доступності";
  card.appendChild(sub);

  // T-227: a suggested zone matching the machine's own system region — a
  // hint only, shown while nothing is picked yet. Never pre-picks on its
  // own (SPEC.md §8.1 "an always-on warning ≡ no warning" cuts both ways —
  // a silent pre-check the user didn't click is the same failure via a
  // different path); adding it still requires this explicit button, and the
  // usual "Зберегти зони" step still applies after that.
  const suggestionNotice = document.createElement("div");
  suggestionNotice.className = "notice rf-suggestion";
  suggestionNotice.hidden = true;
  const suggestionText = document.createElement("span");
  suggestionNotice.appendChild(suggestionText);
  const suggestionBtn = document.createElement("button");
  suggestionBtn.type = "button";
  suggestionBtn.className = "rf-suggestion-add";
  suggestionBtn.textContent = "Додати";
  suggestionNotice.appendChild(suggestionBtn);
  card.appendChild(suggestionNotice);

  function syncSuggestion() {
    suggestionNotice.hidden = !rf.suggested_list || picked.size > 0;
    if (!suggestionNotice.hidden) {
      suggestionText.textContent =
        `Рекомендовано для вашого регіону: ${ratingFilterZoneLabel(rf.suggested_list)}. `;
    }
  }

  suggestionBtn.addEventListener("click", () => {
    toggleCode(rf.suggested_list);
  });

  // Picked codes are re-seeded from the server's normalised echo on every
  // render (this file's "no local optimistic state" rule). User edits
  // mutate this render-scoped Set; the "Зберегти зони" button appears when
  // it diverges from what the server already has.
  const savedCodes = rf.lists.slice();
  const picked = new Set(savedCodes);
  const counts = ratingFilterCountByList(rf.loaded);

  const combo = document.createElement("div");
  combo.className = "rf-combo";
  const input = document.createElement("input");
  input.type = "text";
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-expanded", "false");
  input.setAttribute("aria-controls", "rf-zone-menu");
  input.setAttribute("aria-autocomplete", "list");
  input.setAttribute("aria-label", "Пошук зони");
  input.placeholder = "Додати зону — країна або «глобальний топ»…";
  const menu = document.createElement("ul");
  menu.className = "rf-menu";
  menu.id = "rf-zone-menu";
  menu.setAttribute("role", "listbox");
  menu.hidden = true;
  combo.appendChild(input);
  combo.appendChild(menu);
  card.appendChild(combo);

  const pickedList = document.createElement("ul");
  pickedList.className = "rf-picked";
  card.appendChild(pickedList);

  const emptyLine = document.createElement("p");
  emptyLine.className = "rf-empty";
  emptyLine.textContent = "Ще нічого не обрано.";
  card.appendChild(emptyLine);

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "rf-save";
  saveBtn.textContent = "Зберегти зони";
  saveBtn.hidden = true;
  // T-228: same reasoning as confirmBtn above - saving a changed zone set
  // wakes the same updater for whichever picked zone isn't cached yet.
  if (lastNetworkStatus === "OFFLINE") {
    saveBtn.disabled = true;
    saveBtn.title = "Немає з'єднання з інтернетом - завантаження списків зон неможливе.";
  }
  card.appendChild(saveBtn);

  let activeIndex = -1;

  function pickedMatchesSaved() {
    if (picked.size !== savedCodes.length) {
      return false;
    }
    return savedCodes.every((code) => picked.has(code));
  }

  function syncSaveBtn() {
    saveBtn.hidden = pickedMatchesSaved();
  }

  function zoneMeta(code) {
    // T-122 (Батч 4.2): a gov-* list is one blanket suffix covering an
    // entire domain space, not a popularity count - showing "1 дом." would
    // read as broken (T-66 "never a fake count" discipline). `edu` keeps
    // the real count: it's a genuine curated list, not a single suffix.
    const isBlanketGovZone = code.startsWith("gov-");
    if (Object.prototype.hasOwnProperty.call(counts, code)) {
      return isBlanketGovZone
        ? { text: "весь простір", loading: false }
        : { text: tPlural("zoneDomainCount", counts[code]), loading: false };
    }
    if (rf.enabled) {
      return { text: "завантажується…", loading: true };
    }
    return { text: "—", loading: false };
  }

  // Codes to display: the server's available set in its canonical order,
  // plus any already-picked code the client has no catalogue entry for.
  // Since T-127 validate_rating_filter_lists rejects a code outside
  // AVAILABLE_TOPN_LISTS, so status.rating_filter.lists is normally a
  // subset of available_lists - but a resolver_config.toml written before
  // that check can still carry one, and it must show as a removable row,
  // never a silently hidden zone ("never a fake 0/0", Три Б).
  function displayCodes() {
    const extra = [...picked].filter(
      (code) => !rf.available_lists.includes(code),
    );
    return rf.available_lists.concat(extra);
  }

  function renderPicked() {
    pickedList.textContent = "";
    const codes = displayCodes().filter((code) => picked.has(code));
    emptyLine.hidden = codes.length > 0;
    codes.forEach((code) => {
      const li = document.createElement("li");
      const nm = document.createElement("span");
      nm.className = "rf-nm";
      nm.textContent = ratingFilterZoneLabel(code);
      li.appendChild(nm);
      const meta = document.createElement("span");
      const info = zoneMeta(code);
      meta.className = info.loading ? "rf-meta loading" : "rf-meta";
      meta.textContent = info.text;
      li.appendChild(meta);
      const removeBtn = document.createElement("button");
      removeBtn.type = "button";
      removeBtn.className = "rf-x";
      removeBtn.textContent = "×";
      removeBtn.setAttribute(
        "aria-label",
        `Прибрати: ${ratingFilterZoneLabel(code)}`,
      );
      removeBtn.addEventListener("click", () => {
        picked.delete(code);
        renderPicked();
        renderMenu();
        syncSaveBtn();
        syncSuggestion();
      });
      li.appendChild(removeBtn);
      pickedList.appendChild(li);
    });
  }

  function visibleCodes() {
    const query = input.value.trim().toLowerCase();
    return displayCodes().filter((code) => {
      if (!query) {
        return true;
      }
      return (
        code.toLowerCase().includes(query) ||
        ratingFilterZoneLabel(code).toLowerCase().includes(query)
      );
    });
  }

  function renderMenu() {
    menu.textContent = "";
    const codes = visibleCodes();
    if (activeIndex >= codes.length) {
      activeIndex = codes.length - 1;
    }
    codes.forEach((code, index) => {
      const li = document.createElement("li");
      li.className = "rf-opt";
      li.id = `rf-opt-${code}`;
      li.setAttribute("role", "option");
      const isPicked = picked.has(code);
      li.setAttribute("aria-selected", isPicked ? "true" : "false");
      if (isPicked) {
        li.classList.add("picked");
      }
      if (index === activeIndex) {
        li.classList.add("active");
      }
      const box = document.createElement("span");
      box.className = "rf-box";
      box.textContent = isPicked ? "✓" : "";
      li.appendChild(box);
      const nm = document.createElement("span");
      nm.className = "rf-nm";
      nm.textContent = ratingFilterZoneLabel(code);
      li.appendChild(nm);
      const ct = document.createElement("span");
      ct.className = "rf-ct";
      ct.textContent = Object.prototype.hasOwnProperty.call(counts, code)
        ? String(counts[code])
        : "—";
      li.appendChild(ct);
      // mousedown, not click: it fires before the input's blur handler
      // closes the menu.
      li.addEventListener("mousedown", (event) => {
        event.preventDefault();
        toggleCode(code);
      });
      menu.appendChild(li);
    });
    if (codes.length > 0 && activeIndex >= 0) {
      input.setAttribute(
        "aria-activedescendant",
        `rf-opt-${codes[activeIndex]}`,
      );
    } else {
      input.removeAttribute("aria-activedescendant");
    }
  }

  function toggleCode(code) {
    if (picked.has(code)) {
      picked.delete(code);
    } else {
      picked.add(code);
    }
    renderPicked();
    renderMenu();
    syncSaveBtn();
    syncSuggestion();
  }

  function openMenu() {
    if (!menu.hidden) {
      return;
    }
    menu.hidden = false;
    input.setAttribute("aria-expanded", "true");
    activeIndex = -1;
    renderMenu();
  }

  function closeMenu() {
    menu.hidden = true;
    input.setAttribute("aria-expanded", "false");
    activeIndex = -1;
    input.removeAttribute("aria-activedescendant");
  }

  input.addEventListener("focus", openMenu);
  input.addEventListener("input", () => {
    openMenu();
    activeIndex = -1;
    renderMenu();
  });
  input.addEventListener("blur", () => {
    // Delay so a mousedown on an option runs first.
    setTimeout(closeMenu, 120);
  });
  input.addEventListener("keydown", (event) => {
    const codes = visibleCodes();
    if (event.key === "ArrowDown") {
      event.preventDefault();
      openMenu();
      activeIndex = Math.min(activeIndex + 1, codes.length - 1);
      renderMenu();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      openMenu();
      activeIndex = Math.max(activeIndex - 1, 0);
      renderMenu();
    } else if (event.key === "Enter") {
      event.preventDefault();
      if (!menu.hidden && activeIndex >= 0 && activeIndex < codes.length) {
        toggleCode(codes[activeIndex]);
      }
    } else if (event.key === "Escape") {
      closeMenu();
    }
  });

  function clearArm() {
    confirmNotice.hidden = true;
    confirmRow.hidden = true;
  }

  switchInput.addEventListener("change", async () => {
    errorLine.textContent = "";
    if (switchInput.checked) {
      // OFF→ON: don't POST yet - revert the visual toggle and show the
      // confirm step. The confirm submits the local picked set, so a user
      // who queued zones while off gets them applied on enable (the
      // mockup's own OFF-panel copy: "застосуються, щойно ввімкнете").
      switchInput.checked = false;
      confirmNotice.hidden = false;
      confirmRow.hidden = false;
    } else {
      try {
        renderRatingFilter(await setRatingFilter(false, [...picked]));
      } catch (err) {
        switchInput.checked = true;
        errorLine.textContent = `Не вдалося вимкнути: ${(err && err.message) || String(err)}`;
      }
    }
  });
  cancelBtn.addEventListener("click", clearArm);
  confirmBtn.addEventListener("click", async () => {
    if (lastNetworkStatus === "OFFLINE") {
      errorLine.textContent =
        "Немає з'єднання з інтернетом - завантаження списків зон неможливе.";
      return;
    }
    try {
      renderRatingFilter(await setRatingFilter(true, [...picked]));
    } catch (err) {
      errorLine.textContent = `Не вдалося ввімкнути: ${(err && err.message) || String(err)}`;
    }
  });
  saveBtn.addEventListener("click", async () => {
    if (lastNetworkStatus === "OFFLINE") {
      errorLine.textContent =
        "Немає з'єднання з інтернетом - завантаження списків зон неможливе.";
      return;
    }
    try {
      renderRatingFilter(await setRatingFilter(rf.enabled, [...picked]));
    } catch (err) {
      errorLine.textContent = `Не вдалося зберегти зони: ${(err && err.message) || String(err)}`;
    }
  });

  renderPicked();
  syncSaveBtn();
  syncSuggestion();
  ratingFilterBody.appendChild(card);
}

function renderRatingFilterError(err) {
  ratingFilterBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = "Рейтинговий фільтр «бульбашка»";
  ratingFilterBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  ratingFilterBody.appendChild(panel);
}

async function refreshRatingFilter() {
  try {
    renderRatingFilter(await getStatus());
  } catch (err) {
    renderRatingFilterError(err);
  }
}

// T-218 Фаза 7, Батч 7.4 частина 3: the public blocklist-bundles card
// (#blocklist-bundles-body). Its data is a field on AdminStatusResponse
// (status.blocklist_bundles: BlocklistBundlesStatusView, added Батч 7.4
// частина 2), not its own GET route - same shape as #rating-filter-body
// above: fetch /admin/status once on load, re-render from the
// POST /admin/blocklist-bundles response after every action. Own
// fetch/render cycle, deliberately off the 2s poll - see the doc comment
// over #blocklist-bundles-body in index.html.

// Static client-side catalogue for the 8 BLOCKLIST_SOURCES ids
// (crates/dnsqb-service/src/blocklist_download.rs) - the server has no
// basis to localise/describe these (same "distribution contract" reasoning
// as RATING_FILTER_ZONE_LABELS above). Keyed by id, not group: hagezi-nrd/
// hagezi-dga are two independently-toggleable ids that share one display
// group and are folded into a single checkbox row below.
const BLOCKLIST_SOURCE_META = {
  "hagezi-multi-pro": {
    group: "hagezi-multi-pro",
    cluster: "ads",
    name: "HaGeZi Multi PRO",
    desc: "Реклама, трекери, шкідливе ПЗ — основний набір",
  },
  "adguard-dns-filter": {
    group: "adguard-dns-filter",
    cluster: "ads",
    name: "AdGuard DNS filter",
    desc: "Той самий клас, окреме джерело — ширше покриття",
  },
  "1hosts-lite": {
    group: "1hosts-lite",
    cluster: "ads",
    name: "1Hosts Lite",
    desc: "Те саме, легший список — менше хибних блокувань",
  },
  "hagezi-tif": {
    group: "hagezi-tif",
    cluster: "security",
    name: "HaGeZi Threat Intelligence Feeds",
    desc: "Індикатори компрометації, фішинг",
  },
  "hagezi-nrd": {
    group: "hagezi-nrd-dga",
    cluster: "security",
    name: "HaGeZi NRD / DGA",
    desc: "Щойно зареєстровані й алгоритмічно згенеровані домени (malware C2)",
  },
  "hagezi-dga": {
    group: "hagezi-nrd-dga",
    cluster: "security",
    name: "HaGeZi NRD / DGA",
    desc: "Щойно зареєстровані й алгоритмічно згенеровані домени (malware C2)",
  },
  "hagezi-dyndns": {
    group: "hagezi-dyndns",
    cluster: "security",
    name: "HaGeZi Dynamic DNS",
    desc: "Динамічні DNS-хостнейми, часто зловживані",
  },
  "hagezi-hoster": {
    group: "hagezi-hoster",
    cluster: "security",
    name: "HaGeZi Badware Hoster",
    desc: "Хостери, відомі розповсюдженням шкідливого ПЗ",
  },
};

const BLOCKLIST_CLUSTER_LABELS = {
  ads: "Реклама й трекери",
  security: "Безпека й загрози",
};
const BLOCKLIST_CLUSTER_ORDER = ["ads", "security"];

async function setBlocklistBundles(enabled, sources) {
  const response = await fetch("/admin/blocklist-bundles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled, sources }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

// "N год/дн тому" - a first-pass relative-time label, same precision level
// the mockup itself shows ("оновлено 3 год тому"), not a claim of
// second-accuracy.
function blocklistRelativeTime(unixMillis) {
  const deltaMs = Date.now() - unixMillis;
  const hours = Math.floor(deltaMs / 3600000);
  if (hours < 1) {
    return "оновлено щойно";
  }
  if (hours < 24) {
    return `оновлено ${hours} год тому`;
  }
  return `оновлено ${Math.floor(hours / 24)} дн тому`;
}

function renderBlocklistBundles(status) {
  const bb = status.blocklist_bundles;
  blocklistBundlesBody.textContent = "";

  const heading = document.createElement("h3");
  heading.textContent = "Блок-лист-бандли";
  blocklistBundlesBody.appendChild(heading);

  if (status.persisted === false) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent =
      "Зміну застосовано, але НЕ збережено на диск — вона не переживе перезапуск сервісу.";
    blocklistBundlesBody.appendChild(notPersisted);
  }

  const card = document.createElement("div");
  card.className = "rf-card";

  const head = document.createElement("div");
  head.className = "rf-head";
  const title = document.createElement("span");
  title.className = "rf-title";
  title.textContent = "Блокувати за публічними бандл-списками";
  head.appendChild(title);

  const switchLabel = document.createElement("label");
  switchLabel.className = "switch";
  const switchInput = document.createElement("input");
  switchInput.type = "checkbox";
  switchInput.checked = bb.enabled;
  switchInput.setAttribute("aria-label", "Блок-лист-бандли");
  const track = document.createElement("span");
  track.className = "track";
  const thumb = document.createElement("span");
  thumb.className = "thumb";
  switchLabel.appendChild(switchInput);
  switchLabel.appendChild(track);
  switchLabel.appendChild(thumb);
  head.appendChild(switchLabel);
  card.appendChild(head);

  // `sources === null` ⇒ "track every currently published source" - shown
  // as every id checked, never resolved into a concrete list here (the same
  // invariant BlocklistBundlesStatusView.sources's own doc states: a client
  // must never echo `None` back as a snapshot). Only an explicit checkbox
  // click below turns this into a concrete Set.
  const trackedSet = new Set(bb.sources === null ? bb.available_sources : bb.sources);

  // Rows come from the union of three id sources, not the bare
  // available_sources list - an id already in `sources`/`loaded` that has
  // dropped out of BLOCKLIST_SOURCE_META (a shipped source removed from a
  // future build) must still show as a removable row, never silently
  // vanish (same reasoning as renderRatingFilter's displayCodes() above).
  const knownIds = new Set(Object.keys(BLOCKLIST_SOURCE_META));
  const orphanIds = new Set();
  (bb.sources || []).forEach((id) => {
    if (!knownIds.has(id)) {
      orphanIds.add(id);
    }
  });
  bb.loaded.forEach((entry) => {
    if (!knownIds.has(entry.id)) {
      orphanIds.add(entry.id);
    }
  });

  const loadedById = new Map(bb.loaded.map((entry) => [entry.id, entry]));

  function rowStatus(ids) {
    const tracked = ids.some((id) => trackedSet.has(id));
    const loaded = ids.map((id) => loadedById.get(id)).filter(Boolean);
    if (!tracked) {
      // A fully-empty selection never gets a "cleared on the next cycle"
      // promise - refresh_all_sources returns before touching the bundle
      // when `sources` is an explicit empty list, so no next cycle ever
      // comes (KNOWN-LIMITATIONS.md). That case is covered by the
      // card-level notice below instead; a per-row promise here would
      // contradict it.
      if (trackedSet.size === 0) {
        return { text: "не відстежується", cls: "" };
      }
      return loaded.length > 0
        ? { text: "знято — лишається чинним до наступного оновлення", cls: "stale" }
        : { text: "не відстежується", cls: "" };
    }
    if (loaded.length === 0) {
      return { text: "завантажується…", cls: "loading" };
    }
    const failed = loaded.find((entry) => entry.last_error);
    if (failed) {
      return { text: "збій оновлення — попередня версія", cls: "stale" };
    }
    // last_updated is None only alongside last_error (refresh_all_sources'
    // Ok branch always sets Some(now); its Err branch always sets
    // last_error) - `failed` above already catches that case, so Infinity
    // never reaches the ?? below in practice. The guard stays because
    // that's another module's invariant, not something provable from this
    // line alone.
    const oldest = Math.min(...loaded.map((entry) => entry.last_updated ?? Infinity));
    return Number.isFinite(oldest)
      ? { text: blocklistRelativeTime(oldest), cls: "" }
      : { text: "—", cls: "" };
  }

  async function toggleIds(ids) {
    const newSet = new Set(trackedSet);
    const allTracked = ids.every((id) => newSet.has(id));
    ids.forEach((id) => {
      if (allTracked) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
    });
    // Re-checking every row yields Some([...8 ids]), not None - a
    // deliberately explicit subset, not an automatic return to "track
    // every future source" (that would silently resurrect the exact
    // freeze-on-echo footgun `sources: Option<Vec<String>>` exists to
    // avoid). There is no UI affordance in this batch to go back to `null`.
    return setBlocklistBundles(bb.enabled, [...newSet]);
  }

  const trackedEmpty = trackedSet.size === 0;
  const desc = document.createElement("p");
  desc.className = "rf-desc";
  // Catalogue size (total rows this card can show) - used for the
  // <summary> count below, which counts what EXISTS, not what's selected.
  const knownRowCount =
    new Set(
      [...knownIds].map((id) => BLOCKLIST_SOURCE_META[id].group),
    ).size + orphanIds.size;
  // What's actually selected right now (advisor-catch: "Активно, N джерел"
  // must move when a source is unchecked, or it's the same fake-count class
  // zoneMeta() already refused for gov-* zones, T-66) - count of *rows*
  // (grouped ids + orphans) with at least one tracked id, not the raw
  // trackedSet.size (which would double-count the merged nrd/dga row).
  const groupedKnownIds = new Map();
  Object.keys(BLOCKLIST_SOURCE_META).forEach((id) => {
    const group = BLOCKLIST_SOURCE_META[id].group;
    if (!groupedKnownIds.has(group)) {
      groupedKnownIds.set(group, []);
    }
    groupedKnownIds.get(group).push(id);
  });
  const trackedRowCount =
    [...groupedKnownIds.values()].filter((ids) => ids.some((id) => trackedSet.has(id))).length +
    [...orphanIds].filter((id) => trackedSet.has(id)).length;

  if (!bb.enabled) {
    desc.textContent =
      "Доповнює кворум статичними публічними списками (реклама/трекери/шкідливе/DGA). " +
      "Опційно, дефолт вимкнено. Той самий пайплайн, лише крок 2 (Blocklist).";
    card.appendChild(desc);
  } else if (trackedEmpty) {
    desc.textContent = "Той самий пайплайн, лише крок 2 (Blocklist).";
    card.appendChild(desc);
    const emptyNotice = document.createElement("div");
    emptyNotice.className = "notice warn";
    emptyNotice.textContent = bb.active
      ? "Увімкнено, але жодного джерела не обрано — блокування й далі діє на раніше " +
        "завантаженому наборі (він не очищується автоматично, поки не оберете джерело)."
      : "Увімкнено, але жодного джерела не обрано — фільтрація не діє. Позначте " +
        "принаймні одне джерело нижче.";
    card.appendChild(emptyNotice);
  } else if (bb.active) {
    desc.textContent = `Активно, ${trackedRowCount} джерел. Той самий пайплайн, лише крок 2 (Blocklist).`;
    card.appendChild(desc);
  } else {
    desc.textContent = "Той самий пайплайн, лише крок 2 (Blocklist).";
    card.appendChild(desc);
    const forkB = document.createElement("div");
    forkB.className = "notice warn";
    forkB.textContent =
      "Увімкнено, перше завантаження триває у фоні — попередня (порожня) версія лишається " +
      "чинною. Оновіть сторінку, щоб побачити результат, коли воно завершиться.";
    card.appendChild(forkB);
  }

  const errorLine = document.createElement("div");
  errorLine.className = "override-error";
  card.appendChild(errorLine);

  const sourcesDetails = document.createElement("details");
  sourcesDetails.className = "bl-sources";
  const summary = document.createElement("summary");
  const summaryLabel = document.createElement("span");
  summaryLabel.textContent = `Джерела (${knownRowCount})`;
  const chev = document.createElement("span");
  chev.className = "chev";
  chev.textContent = "›";
  summary.appendChild(summaryLabel);
  summary.appendChild(chev);
  sourcesDetails.appendChild(summary);

  function buildCheckboxRow(ids, name, rowDesc) {
    const li = document.createElement("li");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = ids.some((id) => trackedSet.has(id));
    checkbox.setAttribute("aria-label", name);
    checkbox.addEventListener("change", async () => {
      errorLine.textContent = "";
      // Disabled for the round trip (advisor-catch: a slow/failed POST left
      // the row showing a selection the server hadn't confirmed, with no
      // in-flight signal - same reasoning as the master switch below) and
      // reverted on failure, mirroring switchInput's own revert (a rejected
      // POST - e.g. an orphan id still in `sources` - must not leave the
      // checkbox showing a selection the server never accepted).
      checkbox.disabled = true;
      try {
        renderBlocklistBundles(await toggleIds(ids));
      } catch (err) {
        checkbox.checked = !checkbox.checked;
        checkbox.disabled = false;
        errorLine.textContent = `Помилка: ${(err && err.message) || String(err)}`;
      }
    });
    li.appendChild(checkbox);
    const row = document.createElement("div");
    row.className = "bl-row";
    const top = document.createElement("div");
    top.className = "bl-row-top";
    const nm = document.createElement("span");
    nm.className = "nm";
    nm.textContent = name;
    top.appendChild(nm);
    const status = rowStatus(ids);
    const meta = document.createElement("span");
    meta.className = status.cls ? `meta ${status.cls}` : "meta";
    meta.textContent = status.text;
    top.appendChild(meta);
    row.appendChild(top);
    const descLine = document.createElement("p");
    descLine.className = "desc";
    descLine.textContent = rowDesc;
    row.appendChild(descLine);
    li.appendChild(row);
    return li;
  }

  BLOCKLIST_CLUSTER_ORDER.forEach((cluster) => {
    const groupsInCluster = new Map();
    Object.keys(BLOCKLIST_SOURCE_META).forEach((id) => {
      const meta = BLOCKLIST_SOURCE_META[id];
      if (meta.cluster !== cluster) {
        return;
      }
      if (!groupsInCluster.has(meta.group)) {
        groupsInCluster.set(meta.group, []);
      }
      groupsInCluster.get(meta.group).push(id);
    });
    if (groupsInCluster.size === 0) {
      return;
    }
    const sub = document.createElement("div");
    sub.className = "rf-sub";
    sub.textContent = BLOCKLIST_CLUSTER_LABELS[cluster];
    sourcesDetails.appendChild(sub);
    const list = document.createElement("ul");
    list.className = "bl-list";
    groupsInCluster.forEach((ids) => {
      const meta = BLOCKLIST_SOURCE_META[ids[0]];
      const rowDesc = ids.length > 1 ? `${meta.desc} — 2 джерела` : meta.desc;
      list.appendChild(buildCheckboxRow(ids, meta.name, rowDesc));
    });
    sourcesDetails.appendChild(list);
  });

  if (orphanIds.size > 0) {
    const sub = document.createElement("div");
    sub.className = "rf-sub";
    sub.textContent = "Інше";
    sourcesDetails.appendChild(sub);
    const list = document.createElement("ul");
    list.className = "bl-list";
    orphanIds.forEach((id) => {
      list.appendChild(
        buildCheckboxRow(
          [id],
          id,
          "невідоме джерело (більше не публікується) — зніміть позначку, щоб зберегти інші зміни",
        ),
      );
    });
    sourcesDetails.appendChild(list);
  }

  card.appendChild(sourcesDetails);

  switchInput.addEventListener("change", async () => {
    errorLine.textContent = "";
    try {
      renderBlocklistBundles(await setBlocklistBundles(switchInput.checked, bb.sources));
    } catch (err) {
      switchInput.checked = !switchInput.checked;
      errorLine.textContent = `Помилка: ${(err && err.message) || String(err)}`;
    }
  });

  blocklistBundlesBody.appendChild(card);
}

function renderBlocklistBundlesError(err) {
  blocklistBundlesBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = "Блок-лист-бандли";
  blocklistBundlesBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  blocklistBundlesBody.appendChild(panel);
}

async function refreshBlocklistBundles() {
  try {
    renderBlocklistBundles(await getStatus());
  } catch (err) {
    renderBlocklistBundlesError(err);
  }
}

// T-151 Батч 5.2: kicked off from renderTranslatedCards() - see the comment
// by refreshOverrides() above (own fetch/render cycle, off the 2s poll, same
// reasoning as the doc comment above refreshBlocklistBundles itself).
