// Behavioural smoke for /admin/ui i18n (Батч 5.4, T-151) - run manually:
//   node crates/dnsqb-service/ui/smoke.js        (exit 0 = clean)
// Executes main.js in a node `vm` against a Proxy DOM stub, once per locale
// dictionary, and calls every render function on sample data. It collects every
// string assigned to the stub (textContent/innerHTML/title/placeholder/attributes)
// and fails on (a) a raw dictionary key echoed back (t() echoes a missing key),
// (b) an unsubstituted {token}, (c) any exception, (d) a footer whose mandated
// licence anchors were not substituted in. Control: with an empty dictionary it
// must fail (~228 findings) - if it ever passes there, the stub stopped observing.
//
// NOT covered, on purpose: the async bootstrap IIFE and setLocale() (fetch is
// stubbed to fail everything except the dictionaries), real layout/CSS, real
// Intl.PluralRules values for n, and event handlers. It is not a substitute for
// a live browser check - that gap is recorded in KNOWN-LIMITATIONS.md.
// Manual-only by decision (2026-09-22): not wired into ci.yml (changing the
// pipeline is the maintainer's call); node is preinstalled on windows-latest,
// so `node crates/dnsqb-service/ui/smoke.js` is a one-line CI step if wanted.
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const UI = __dirname;
const assigned = [];
function stub(name) {
  const store = {};
  const target = function () {};
  return new Proxy(target, {
    get(_t, p) {
      if (p === Symbol.toPrimitive) return () => "";
      if (p === "then") return undefined;
      if (p === "dataset") return {};
      if (p === "length") return 0;
      if (p === Symbol.iterator) return function* () {};
      if (p in store) return store[p];
      return (store[p] = stub(name + "." + String(p)));
    },
    set(_t, p, v) {
      store[p] = v;
      if (typeof v === "string") assigned.push([name + "." + String(p), v]);
      return true;
    },
    apply(_t, _this, args) {
      for (const a of args) if (typeof a === "string") assigned.push([name + "()", a]);
      return stub(name + "()");
    },
    construct() { return stub(name + "#new"); },
  });
}
const dicts = {};
for (const f of fs.readdirSync(path.join(UI, "i18n"))) {
  if (f.endsWith(".json")) dicts[f.slice(0, -5)] = JSON.parse(fs.readFileSync(path.join(UI, "i18n", f), "utf8"));
}
const doc = stub("document");
const ctx = {
  document: doc, console: { log() {}, error() {}, warn() {} },
  navigator: { language: "en", userAgent: "Chrome/1 Test", clipboard: null },
  localStorage: { getItem: () => null, setItem() {} },
  setTimeout: () => 0, setInterval: () => 0, clearTimeout() {},
  fetch: async (url) => {
    const m = /\/admin\/ui\/i18n\/(.+)\.json$/.exec(url);
    if (m) return { ok: true, json: async () => dicts[m[1]] };
    return { ok: false, status: 599, json: async () => ({}) };
  },
  URLSearchParams, Intl, Date, Math, JSON, Object, Array, Set, Map, Number, String, Promise, Error, RegExp, Infinity, isFinite,
};
ctx.window = ctx;
const html = fs.readFileSync(path.join(UI, "index.html"), "utf8");
const staticEls = [];
function fakeEl(kind, value) {
  const el = { dataset: {}, _kind: kind, _value: value };
  const dsKey = { i18n: "i18n", html: "i18nHtml", attr: "i18nAttr" }[kind];
  el.dataset[dsKey] = value;
  ["textContent", "innerHTML"].forEach((prop) => {
    let cur = "";
    Object.defineProperty(el, prop, { get: () => cur, set: (v) => { cur = v; assigned.push([`static[${kind}:${value}].${prop}`, v]); } });
  });
  el.setAttribute = (a, v) => assigned.push([`static[${kind}:${value}].attr(${a})`, v]);
  el.hidden = false;
  staticEls.push(el);
  return el;
}
const byAttr = { "[data-i18n]": [], "[data-i18n-html]": [], "[data-i18n-attr]": [] };
for (const m of html.matchAll(/data-i18n="([^"]+)"/g)) byAttr["[data-i18n]"].push(fakeEl("i18n", m[1]));
for (const m of html.matchAll(/data-i18n-html="([^"]+)"/g)) byAttr["[data-i18n-html]"].push(fakeEl("html", m[1]));
for (const m of html.matchAll(/data-i18n-attr="([^"]+)"/g)) byAttr["[data-i18n-attr]"].push(fakeEl("attr", m[1]));
doc.querySelectorAll = (sel) => byAttr[sel] || [];
vm.createContext(ctx);
const src = fs.readFileSync(path.join(UI, "main.js"), "utf8");
vm.runInContext(src, ctx, { filename: "main.js" });

const status = (over) => Object.assign({ persisted: false }, over);
const providersData = {
  active: [
    { id: "x", display_name: "X", category: "SECURITY", block_signature: "NULL_IP", enabled: true, is_builtin: false },
    { id: "q", display_name: "Q", category: "ADULT_CONTENT", block_signature: "NXDOMAIN_VS_BASELINE", enabled: false, is_builtin: true },
  ],
  available_presets: [{ id: "y", display_name: "Y", category: "ADS_TRACKERS" }, { id: "x", display_name: "X", category: "SECURITY" }],
  persisted: false, filtering_active: false, third_party_count: 3,
  category_states: [{ category: "SECURITY", state: "PARTIAL" }], master_switch_targets: [],
};
const logData = {
  entries: [{ timestamp_ms: 0, domain: "a.com", qtype: "A", decision: "BLOCKED", decision_source: "CCTLD_BLOCK", latency_ms: 5,
    voters: [{ provider_name: "quad9", status: { status: "ERROR", message: "x" } }, { provider_name: "z", status: { status: "ALLOW", ip_count: 2 } }],
    resolved_ip_country: "SE" }], truncated: true,
};
const calls = [
  ["renderProtectionHero", `renderProtectionHero(heroPresentation("PROTECTED", {blocked: 3}))`],
  ["renderProtectionHeroCert", `renderProtectionHero(heroPresentation("CERT_NOT_TRUSTED", {blocked: 0}))`],
  ["renderTimeoutConfig", `renderTimeoutConfig(${JSON.stringify(status({ timeout_mode: "fail_open", serve_baseline_when_filters_unreachable: false }))})`],
  ["renderOverrides", `renderOverrides(${JSON.stringify({ allowlist: [{ domain: "a.com", is_wildcard: false }], blocklist: [{ domain: "a.com", is_wildcard: true }], conflicts: ["a.com"], persisted: false })})`],
  ["renderCacheConfig", `renderCacheConfig(${JSON.stringify({ clamp_min_secs: 1, clamp_max_secs: 2, block_verdict_ttl_secs: 3, stale_grace_secs: 4, max_capacity: 5, persisted: false })})`],
  ["renderCctldBlock", `renderCctldBlock(${JSON.stringify(status({ cctld_block: { blocked_codes: ["ru", "su", "zz"] } }))})`],
  ["renderGeoip", `renderGeoip(${JSON.stringify({ database_loaded: true, database_built_at_ms: 1700000000000, database_source: "USER_COUNTRY", blocked_countries: ["SE"], persisted: false })})`],
  ["renderGeoipNoDb", `renderGeoip(${JSON.stringify({ database_loaded: false, blocked_countries: [], persisted: true })})`],
  ["renderMaxmind", `renderMaxmind(${JSON.stringify({ configured: true, account_id: "1", persisted: false, refresh_health: "AUTH_REJECTED", check: "REJECTED" })})`],
  ["renderProviders", `renderProviders(${JSON.stringify(providersData)})`],
  ["buildLogFilterRow+renderLog", `buildLogFilterRow(); renderLog(${JSON.stringify(logData)})`],
  ["renderRatingFilterOff", `renderRatingFilter(${JSON.stringify(status({ rating_filter: { enabled: false, active: false, lists: ["ua", "gov-pl", "xx"], available_lists: ["ua", "us", "de", "pl", "gb", "global", "gov-ua", "gov-us", "gov-pl", "gov-gb", "edu"], loaded: [{ list: "ua", domains: 5 }, { list: "gov-pl", domains: 1 }], suggested_list: "gb", personal_zone_enabled: false } }))})`],
  ["renderRatingFilterOn", `renderRatingFilter(${JSON.stringify(status({ rating_filter: { enabled: true, active: false, lists: ["ua"], available_lists: ["ua", "global", "edu"], loaded: [], suggested_list: null, personal_zone_enabled: false } }))})`],
  ["renderRatingFilterBadge", `renderRatingFilterBadge({enabled: true, active: false})`],
  ["renderBlocklistBundles", `renderBlocklistBundles(${JSON.stringify(status({ blocklist_bundles: { enabled: true, active: true, sources: null, available_sources: ["hagezi-multi-pro", "hagezi-nrd", "hagezi-dga", "old-x"], loaded: [{ id: "hagezi-multi-pro", last_updated: Date.now() - 5 * 3600e3, last_error: null }, { id: "old-x", last_updated: Date.now() - 50 * 3600e3, last_error: null }] } }))})`],
  ["renderBlocklistBundlesInactive", `renderBlocklistBundles(${JSON.stringify(status({ blocklist_bundles: { enabled: true, active: false, sources: ["hagezi-tif"], available_sources: ["hagezi-tif"], loaded: [] } }))})`],
  ["renderUninstallResult", `renderUninstallResult(${JSON.stringify({ cert: "REMOVED", tls_key: "NOT_PRESENT", persistence_key: "FAILED", maxmind_creds: "REMOVED", personal_zone_key: "REMOVED" })})`],
  ["errors", `renderError(new Error("boom")); renderOverridesError(new Error("boom")); renderCacheConfigError(new Error("boom")); renderCctldBlockError(new Error("boom")); renderGeoipError(new Error("boom")); renderMaxmindError(new Error("boom")); renderLogError(new Error("boom")); renderProvidersError(new Error("boom")); renderRatingFilterError(new Error("boom")); renderBlocklistBundlesError(new Error("boom")); renderUninstallError(new Error("boom"));`],
  ["plurals", `[0,1,2,3,5,11,21,100].forEach((n) => { tPlural("filterControls.fanoutPartiesClause", n); tPlural("filterControls.fanoutChecksClause", n); tPlural("blocklist.activeCount", n); tPlural("blocklist.updated.hours", n); tPlural("blocklist.updated.days", n); tPlural("zoneDomainCount", n); })`],
  ["applyStatic", `applyStaticTranslations()`],
  ["relTime", `blocklistRelativeTime(Date.now()); blocklistRelativeTime(Date.now()-3*3600e3); blocklistRelativeTime(Date.now()-72*3600e3)`],
  ["zones", `["ua","us","global","edu","gov-ua","gov-gb","zz","weird-x","gov-abc","gov-","gov-1","ABC","gov-UA"].forEach(ratingFilterZoneLabel)`],
  ["cctldSu", `cctldLabel("su"); cctldLabel("ru")`],
];

const RAW_KEY = /^(hero|error|app|warning|common|timeoutConfig|overrides|cacheConfig|cctldBlock|geoip|maxmind|log|providers|filterControls|browserSetup|advanced|danger|rating|blocklist|footer|fieldHelp|localeSwitcher)\.[A-Za-z0-9.]+$/;
const TOKEN = /\{[A-Za-z_][A-Za-z0-9_]*\}/;
let failures = 0;
for (const loc of Object.keys(dicts).sort()) {
  vm.runInContext(`DICT = __dict; CURRENT_LOCALE = ${JSON.stringify(loc)}; regionNamesCacheLocale = null;`, Object.assign(ctx, { __dict: dicts[loc] }));
  for (const [name, code] of calls) {
    assigned.length = 0;
    try {
      const r = vm.runInContext(code, ctx);
      if (r && typeof r.then === "function") { /* not awaited: sync smoke only */ }
    } catch (e) {
      failures++;
      console.log(`[${loc}] ${name}: THREW ${e && e.message}`);
      continue;
    }
    if (name === "applyStatic") {
      const geo = assigned.find(([w]) => w.includes("footer.geoipAttribution"));
      const crux = assigned.find(([w]) => w.includes("footer.cruxAttribution"));
      const need = [[geo, ['href="https://db-ip.com"', ">IP Geolocation by DB-IP</a>", 'https://creativecommons.org/licenses/by/4.0/', "https://github.com/sapics/ip-location-db", "https://www.maxmind.com"]],
        [crux, ['https://developer.chrome.com/docs/crux/', "https://publicsuffix.org/", "https://mozilla.org/MPL/2.0/", "https://creativecommons.org/licenses/by/4.0/"]]];
      for (const [hit, needles] of need) {
        if (!hit) { failures++; console.log(`[${loc}] applyStatic: footer element never assigned`); continue; }
        for (const n of needles) if (!hit[1].includes(n)) { failures++; console.log(`[${loc}] applyStatic: footer missing ${n}`); }
      }
      if (assigned.length < 20) { failures++; console.log(`[${loc}] applyStatic assigned only ${assigned.length} static nodes`); }
    }
    for (const [where, val] of assigned) {
      const v = val.trim();
      if (RAW_KEY.test(v)) { failures++; console.log(`[${loc}] ${name}: raw key echoed at ${where}: ${v}`); }
      else if (TOKEN.test(v) && !/^\{n\}$/.test(v)) { failures++; console.log(`[${loc}] ${name}: unsubstituted token at ${where}: ${v.slice(0, 90)}`); }
    }
  }
}
console.log(`locales=${Object.keys(dicts).length} calls=${calls.length} failures=${failures}`);
process.exit(failures ? 1 : 0);
