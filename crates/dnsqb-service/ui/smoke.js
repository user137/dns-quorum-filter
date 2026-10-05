// Behavioural smoke for /admin/ui i18n (Батч 5.4, T-151); exit 0 = clean.
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
// Runs in CI as the `ui-smoke` job in .github/workflows/ci.yml; locally: node crates/dnsqb-service/ui/smoke.js
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
// T-249: createElement is tracked per element, so the a11y check below can ask
// every JS-built form field for an id/name and an accessible name.
const created = [];
const recOf = new WeakMap();
function elStub(rec) {
  const store = {};
  rec.dataset = {};
  const proxy = new Proxy(function () {}, {
    get(_t, p) {
      if (p === Symbol.toPrimitive) return () => "";
      if (p === "then") return undefined;
      if (p === "dataset") return rec.dataset;
      if (p === "length") return 0;
      if (p === Symbol.iterator) return function* () {};
      if (p in store) return store[p];
      if (p === "setAttribute") return (a, v) => { rec.attrs[a] = String(v); if (typeof v === "string") assigned.push([`<${rec.tag}>.attr(${a})`, v]); };
      if (["appendChild", "append", "prepend", "insertBefore", "replaceChildren"].includes(p)) {
        return (...kids) => { for (const k of kids) { const r = recOf.get(k); if (r) r.parent = rec; } return kids[0]; };
      }
      return (store[p] = stub(`<${rec.tag}>.${String(p)}`));
    },
    set(_t, p, v) {
      store[p] = v;
      rec.props[p] = v;
      if (typeof v === "string") assigned.push([`<${rec.tag}>.${String(p)}`, v]);
      return true;
    },
    apply() { return stub(`<${rec.tag}>()`); },
  });
  recOf.set(proxy, rec);
  return proxy;
}
doc.createElement = (tag) => {
  const rec = { tag: String(tag).toLowerCase(), props: {}, attrs: {}, parent: null };
  created.push(rec);
  return elStub(rec);
};
function fieldA11yProblems(rec) {
  if (!["input", "select", "textarea"].includes(rec.tag) || rec.props.type === "hidden") return [];
  const id = rec.props.id || rec.attrs.id;
  const out = [];
  if (!id && !(rec.props.name || rec.attrs.name)) out.push("no id/name");
  // A wrapping <label> names the field only if some node inside it carries text
  // (a switch label holding just the track/thumb spans names nothing).
  const within = (r, anc) => { for (let p = r; p; p = p.parent) if (p === anc) return true; return false; };
  const hasText = (r) => typeof r.props.textContent === "string" && r.props.textContent.trim() !== "";
  let inLabel = false;
  for (let p = rec.parent; p; p = p.parent) {
    if (p.tag === "label" && created.some((r) => within(r, p) && hasText(r))) inLabel = true;
  }
  const forLabel = id && created.some((r) => r.tag === "label" && (r.props.htmlFor === id || r.attrs.for === id));
  if (!(rec.attrs["aria-label"] || rec.props.ariaLabel || rec.attrs["aria-labelledby"] || rec.props.title || rec.attrs.title || inLabel || forLabel)) {
    out.push("no accessible name");
  }
  return out;
}
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
    resolved_ip_country: "SE", geoip_country: "RU" }], truncated: true,
};
// T-279: 120 entries = 3 pages of LOG_PAGE_SIZE 50.
const bigLogData = { entries: Array.from({ length: 120 }, (_, i) => Object.assign({}, logData.entries[0], { domain: `d${i}.com`, timestamp_ms: i })), truncated: false };
const calls = [
  ["renderProtectionHero", `renderProtectionHero(heroPresentation("PROTECTED", {blocked: 3}))`],
  ["renderProtectionHeroCert", `renderProtectionHero(heroPresentation("CERT_NOT_TRUSTED", {blocked: 0}))`],
  ["renderProtectionHeroDegraded", `renderProtectionHero(heroPresentation("FILTERS_DEGRADED", {blocked: 0}))`],
  ["renderLastQuery", `renderLastQuery(null); renderLastQuery(Date.now() - 20e3); renderLastQuery(Date.now() - 7 * 60e3); renderLastQuery(Date.now() - 5 * 3600e3); renderLastQuery(Date.now() - 3 * 86400e3)`],
  ["renderStartupTask", `renderStartupTask("DISABLED"); renderStartupTask("DISABLED_BY_POLICY"); renderStartupTask("ENABLED")`],
  ["renderTimeoutConfig", `renderTimeoutConfig(${JSON.stringify(status({ timeout_mode: "fail_open", serve_baseline_when_filters_unreachable: false }))})`],
  ["renderOverrides", `renderOverrides(${JSON.stringify({ allowlist: [{ domain: "a.com", is_wildcard: false }], blocklist: [{ domain: "a.com", is_wildcard: true }], conflicts: ["a.com"], persisted: false })})`],
  ["renderCacheConfig", `renderCacheConfig(${JSON.stringify({ clamp_min_secs: 1, clamp_max_secs: 2, block_verdict_ttl_secs: 3, stale_grace_secs: 4, max_capacity: 5, persisted: false })})`],
  ["renderCctldBlock", `renderCctldBlock(${JSON.stringify(status({ cctld_block: { blocked_codes: ["ru", "su", "zz"] } }))})`],
  ["renderGeoip", `renderGeoip(${JSON.stringify({ database_loaded: true, database_built_at_ms: 1700000000000, database_source: "USER_COUNTRY", blocked_countries: ["SE"], persisted: false })})`],
  ["renderGeoipNoDb", `renderGeoip(${JSON.stringify({ database_loaded: false, blocked_countries: [], persisted: true })})`],
  ["renderMaxmind", `renderMaxmind(${JSON.stringify({ configured: true, account_id: "1", persisted: false, refresh_health: "AUTH_REJECTED", check: "REJECTED" })})`],
  ["renderProviders", `renderProviders(${JSON.stringify(providersData)})`],
  ["buildLogFilterRow+renderLog", `buildLogFilterRow(); renderLog(${JSON.stringify(logData)})`],
  ["logPagerAndLiveMarker", `pushLive = true; renderLogLiveMarker(); logPage = 1; renderLog(${JSON.stringify(bigLogData)}); pushLive = false; logPage = 0; renderLogLiveMarker()`],
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

const RAW_KEY = /^(hero|startupTask|error|app|warning|common|timeoutConfig|overrides|cacheConfig|cctldBlock|geoip|maxmind|log|providers|filterControls|browserSetup|advanced|danger|rating|blocklist|footer|fieldHelp|localeSwitcher)\.[A-Za-z0-9.]+$/;
const TOKEN = /\{[A-Za-z_][A-Za-z0-9_]*\}/;
let failures = 0;
for (const loc of Object.keys(dicts).sort()) {
  vm.runInContext(`DICT = __dict; CURRENT_LOCALE = ${JSON.stringify(loc)}; regionNamesCacheLocale = null;`, Object.assign(ctx, { __dict: dicts[loc] }));
  for (const [name, code] of calls) {
    assigned.length = 0;
    created.length = 0;
    try {
      const r = vm.runInContext(code, ctx);
      if (r && typeof r.then === "function") { /* not awaited: sync smoke only */ }
    } catch (e) {
      failures++;
      console.log(`[${loc}] ${name}: THREW ${e && e.message}`);
      continue;
    }
    if (loc === "en") {
      for (const rec of created) {
        for (const problem of fieldA11yProblems(rec)) {
          failures++;
          console.log(`[a11y] ${name}: <${rec.tag}${rec.props.type ? ` type=${rec.props.type}` : ""}> ${problem}`);
        }
      }
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
// QA pass (rows B-*-SB): every server-supplied string carries an HTML payload;
// it may reach the DOM only as text, never through an HTML-parsing sink.
// renderCctldBlock is left out: its only server strings are validated 2-letter
// codes (validate_cctld_codes), fed to Intl.DisplayNames, which rejects anything else.
const XSS = `<img src=x onerror=qaXss()>`;
const xssDeep = (v) => typeof v === "string" ? v + XSS
  : Array.isArray(v) ? v.map(xssDeep)
  : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, xssDeep(x)])) : v;
const HTML_SINK = /\.(innerHTML|outerHTML)$|\.insertAdjacentHTML\(\)$|\.write\(\)$/;
const xssCalls = [
  ["renderOverrides", { allowlist: [{ domain: "a.com", is_wildcard: false }], blocklist: [{ domain: "b.com", is_wildcard: true }], conflicts: ["a.com"], persisted: false }],
  ["renderProviders", providersData],
  ["renderLog", logData],
  ["renderMaxmind", { configured: true, account_id: "1", persisted: false, refresh_health: "OK", check: "OK" }],
  ["renderGeoip", { database_loaded: true, database_built_at_ms: 1700000000000, database_source: "USER_COUNTRY", blocked_countries: ["SE"], persisted: false }],
  ["renderRatingFilter", status({ rating_filter: { enabled: true, active: true, lists: ["ua"], available_lists: ["ua"], loaded: [{ list: "ua", domains: 5 }], suggested_list: "ua", personal_zone_enabled: false } })],
  ["renderBlocklistBundles", status({ blocklist_bundles: { enabled: true, active: true, sources: null, available_sources: ["hagezi-tif"], loaded: [{ id: "hagezi-tif", last_updated: Date.now(), last_error: "e" }] } })],
  ["renderTimeoutConfig", status({ timeout_mode: "fail_open", serve_baseline_when_filters_unreachable: false })],
];
vm.runInContext(`DICT = __dict; CURRENT_LOCALE = "uk";`, Object.assign(ctx, { __dict: dicts.uk }));
for (const [fn, data] of xssCalls) {
  assigned.length = 0;
  try {
    vm.runInContext(`${fn}(${JSON.stringify(xssDeep(data))})`, ctx);
  } catch (e) {
    failures++;
    console.log(`[xss] ${fn}: THREW ${e && e.message}`);
    continue;
  }
  for (const [where, val] of assigned) {
    if (HTML_SINK.test(where) && val.includes(XSS)) { failures++; console.log(`[xss] ${fn}: payload reached ${where}`); }
  }
  if (!assigned.some(([, val]) => val.includes(XSS)) && fn !== "renderTimeoutConfig") {
    failures++;
    console.log(`[xss] ${fn}: payload never rendered at all - the probe stopped observing`);
  }
}
// T-258/T-260: the picker shows exactly one browser's steps plus the matching
// verify paragraph, and a manual pick survives the async Brave refinement.
(async () => {
  const byId = {};
  doc.getElementById = (id) => (byId[id] = byId[id] || { id, hidden: true, textContent: "" });
  const pickers = ["chrome", "edge", "firefox", "brave", "opera", "vivaldi"].map((b) => ({ dataset: { browser: b }, attrs: {}, setAttribute(a, v) { this.attrs[a] = v; } }));
  doc.querySelectorAll = (sel) => (sel === "[data-browser]" ? pickers : byAttr[sel] || []);
  const families = ["chrome", "edge", "brave", "opera", "vivaldi", "firefox", "other"];
  const check = (want, label) => {
    const shown = families.filter((f) => byId[`browser-steps-${f}`] && !byId[`browser-steps-${f}`].hidden);
    if (shown.join() !== want) { failures++; console.log(`[browser] ${label}: shown [${shown}] want [${want}]`); }
    const ff = want === "firefox";
    if (byId["browser-verify-firefox"].hidden === ff || byId["browser-verify-chromium"].hidden !== ff) { failures++; console.log(`[browser] ${label}: wrong verify paragraph`); }
    const pressed = pickers.filter((p) => p.attrs["aria-pressed"] === "true").map((p) => p.dataset.browser);
    if (pressed.join() !== (want === "other" ? "" : want)) { failures++; console.log(`[browser] ${label}: aria-pressed [${pressed}]`); }
    const text = byId["browser-detected"].textContent;
    if (!text || RAW_KEY.test(text) || TOKEN.test(text)) { failures++; console.log(`[browser] ${label}: bad label ${text}`); }
  };
  vm.runInContext(`DICT = __dict; CURRENT_LOCALE = "en";`, Object.assign(ctx, { __dict: dicts.en }));
  for (const f of families) { vm.runInContext(`applyBrowserFamily(${JSON.stringify(f)})`, ctx); check(f, `apply ${f}`); }
  let release;
  ctx.navigator.brave = { isBrave: () => new Promise((r) => { release = r; }) };
  const pending = vm.runInContext(`revealBrowserSteps()`, ctx);
  check("chrome", "UA chrome before isBrave resolves");
  vm.runInContext(`pickBrowserFamily("vivaldi")`, ctx);
  release(true);
  await pending;
  check("vivaldi", "manual pick vs late isBrave");

  // T-277 / T-248: a background re-render (locale switch, server push) keeps
  // what the user typed and opened, and waits while the card is in use. A
  // user-action render (any mode other than BACKGROUND) is never held back.
  const FIELDS = ["input", "select", "textarea"];
  const fel = (tag, props) => Object.assign({ tag, dataset: {}, hidden: false, value: "", open: false, matches(sel) { return sel.split(",").map((s) => s.trim()).includes(this.tag); } }, props);
  const card = (kids) => ({
    kids, listeners: {},
    contains(el) { return this.kids.includes(el); },
    querySelectorAll(sel) {
      if (sel === "[data-pending]") return this.kids.filter((k) => "pending" in k.dataset);
      if (sel === "details[data-state-key]") return this.kids.filter((k) => k.tag === "details" && k.dataset.stateKey);
      if (sel === "input, select, textarea") return this.kids.filter((k) => FIELDS.includes(k.tag));
      throw new Error(`fake card: unexpected selector ${sel}`);
    },
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
    fire(type, event) { (this.listeners[type] || []).forEach((fn) => fn(event || {})); },
  });
  const guard = (label, ok) => { if (!ok) { failures++; console.log(`[guard] ${label}`); } };
  ctx.setTimeout = (fn) => { fn(); return 0; };
  let focused = true;
  doc.hasFocus = () => focused;
  doc.activeElement = null;
  const freshOverrides = () => [fel("input", { name: "override-pattern" }), fel("select", { name: "override-list", value: "allowlist", options: [{ value: "allowlist" }, { value: "blocklist" }] }), fel("details", { dataset: { stateKey: "help:overrides" } })];

  // Happy: typed text, a changed select and an open "?" survive a re-render.
  let c = card([fel("input", { name: "override-pattern", value: "foo.com" }), fel("select", { name: "override-list", value: "blocklist" }), fel("details", { open: true, dataset: { stateKey: "help:overrides" } })]);
  vm.runInContext("watchCard", ctx)(c);
  c.fire("input", { target: c.kids[0] });
  c.fire("input", { target: c.kids[1] });
  vm.runInContext("renderInBackground", ctx)(c, () => { c.kids = freshOverrides(); }, () => {});
  guard("typed text lost on background render", c.kids[0].value === "foo.com");
  guard("changed select lost on background render", c.kids[1].value === "blocklist");
  guard("open help closed by background render", c.kids[2].open === true);

  // Misuse: a field the user never touched takes the new server value, a
  // carried select value that no longer exists as an option is not forced in.
  c = card([fel("input", { name: "max-capacity", value: "5" }), fel("select", { name: "override-list", value: "gone", dataset: { edited: "1" } })]);
  vm.runInContext("renderInBackground", ctx)(c, () => { c.kids = [fel("input", { name: "max-capacity", value: "7" }), fel("select", { name: "override-list", value: "allowlist", options: [{ value: "allowlist" }] })]; }, () => {});
  guard("untouched field resurrected a stale value", c.kids[0].value === "7");
  guard("carried a select value with no matching option", c.kids[1].value === "allowlist");

  // Busy by focus: held back, then run once focus leaves the card.
  let renders = 0;
  let refetches = 0;
  c = card(freshOverrides());
  vm.runInContext("watchCard", ctx)(c);
  doc.activeElement = c.kids[0];
  vm.runInContext("renderInBackground", ctx)(c, () => { renders++; }, () => { refetches++; });
  guard("rendered under a focused field", renders === 0);
  c.fire("focusout");
  guard("deferred render ran while focus was still in the card", refetches === 0);
  doc.activeElement = null;
  c.fire("focusout");
  guard("deferred render never ran after focus left", refetches === 1);
  c.fire("focusout");
  guard("deferred render ran twice", refetches === 1);

  // Focus left on a checkbox (it saves on change) is not editing.
  const box = fel("input", { type: "checkbox", name: "provider-x" });
  c = card([box]);
  doc.activeElement = box;
  vm.runInContext("renderInBackground", ctx)(c, () => { renders++; }, () => {});
  guard("held back by focus on a checkbox", renders === 1);
  renders = 0;

  // A window in the background does not count as editing.
  focused = false;
  doc.activeElement = c.kids[0];
  vm.runInContext("renderInBackground", ctx)(c, () => { renders++; }, () => {});
  guard("held back while the window had no focus", renders === 1);
  focused = true;
  doc.activeElement = null;

  // Busy by visible unsaved state ([data-pending]): released by a click that hides it.
  const save = fel("button", { dataset: { pending: "" } });
  c = card([save]);
  vm.runInContext("watchCard", ctx)(c);
  refetches = 0;
  vm.runInContext("renderInBackground", ctx)(c, () => { renders++; }, () => { refetches++; });
  guard("rendered over unsaved picks", renders === 1);
  save.hidden = true;
  c.fire("click");
  guard("unsaved-state deferral never released", refetches === 1);

  // A user action (refreshX called from a click handler gets an Event) always renders.
  c = card(freshOverrides());
  doc.activeElement = c.kids[0];
  vm.runInContext("paint", ctx)(c, { type: "click" }, () => { renders++; }, () => {});
  guard("user-action render was held back", renders === 2);
  doc.activeElement = null;

  // Selected text inside the card holds a background render back too.
  c = card([fel("input", { name: "x" })]);
  const selected = { isCollapsed: false, anchorNode: c.kids[0] };
  doc.getSelection = () => selected;
  renders = 0;
  vm.runInContext("renderInBackground", ctx)(c, () => { renders++; }, () => {});
  guard("rendered over a text selection in the card", renders === 0);
  selected.isCollapsed = true;
  vm.runInContext("renderInBackground", ctx)(c, () => { renders++; }, () => {});
  guard("collapsed selection still held the render back", renders === 1);
  doc.getSelection = () => null;

  // T-279: pager - 50 rows per page, newest first, page clamped to the data.
  const logRows = () => created.filter((r) => r.tag === "li" && r.props.className === "log-item");
  const pagerText = () => assigned.filter(([w]) => w === "<span>.textContent").map(([, v]) => v);
  const run = (code) => vm.runInContext(code, ctx);
  created.length = 0; assigned.length = 0;
  run(`logPage = 0; renderLog(${JSON.stringify(bigLogData)})`);
  guard(`page 1 shows ${logRows().length} rows, want 50`, logRows().length === 50);
  guard("page 1 is not newest-first", logRows()[0] && created.some((r) => r.props.textContent === "d119.com"));
  guard("pager status missing on page 1", pagerText().some((v) => v.includes("1") && v.includes("3")));
  created.length = 0; assigned.length = 0;
  run(`logPage = 2; renderLogPage(document.createElement("div"))`);
  guard(`last page shows ${logRows().length} rows, want 20`, logRows().length === 20);
  created.length = 0;
  run(`logPage = 2; renderLog(${JSON.stringify(logData)})`);
  guard("page not clamped when the data shrank", run("logPage") === 0 && logRows().length === 1);
  run("logPage = 0");

  // ARCH-12: an expanded voter-detail row marks the log card busy, so the
  // pushed log refresh waits instead of collapsing it.
  created.length = 0;
  run(`renderLog(${JSON.stringify(logData)})`);
  const detail = created.find((r) => r.parent && r.parent.tag === "li" && "pending" in r.dataset);
  guard("log voter detail is not marked [data-pending]", detail && detail.props.hidden === true);

  // T-277: the push-stream client.
  const timers = [];
  let timerId = 1;
  ctx.setTimeout = (fn, ms) => { const id = timerId++; timers.push({ id, fn, ms }); return id; };
  ctx.clearTimeout = (id) => { const i = timers.findIndex((tm) => tm.id === id); if (i >= 0) timers.splice(i, 1); };
  const intervals = new Map();
  ctx.setInterval = (fn, ms) => { const id = timerId++; intervals.set(id, { fn, ms }); return id; };
  ctx.clearInterval = (id) => intervals.delete(id);
  const fire = (ms) => { const due = timers.filter((tm) => tm.ms === ms); due.forEach((tm) => { ctx.clearTimeout(tm.id); tm.fn(); }); return due.length; };
  const sources = [];
  class FakeEventSource {
    constructor(url) { this.url = url; this.readyState = 0; this.listeners = {}; sources.push(this); }
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
    emit(type, data) { (this.listeners[type] || []).forEach((fn) => fn({ data })); }
    close() { this.readyState = 2; }
  }
  FakeEventSource.CONNECTING = 0; FakeEventSource.OPEN = 1; FakeEventSource.CLOSED = 2;
  ctx.EventSource = FakeEventSource;
  const spied = ["render", "renderProtectionHero", "refresh", "refreshOverrides", "refreshProviders", "refreshCacheConfig", "refreshGeoip", "refreshMaxmind", "refreshCctldBlock", "refreshRatingFilter", "refreshBlocklistBundles", "refreshLog"];
  const spy = {};
  for (const name of spied) { spy[name] = []; ctx[name] = (...args) => { spy[name].push(args); }; }
  const BG = run("BACKGROUND");
  const unreachableCls = run(`heroPresentation("SERVICE_UNREACHABLE").cls`);
  const heroDown = () => spy.renderProtectionHero.filter(([p]) => p && p.cls === unreachableCls).length;
  const topicCards = { overrides: "refreshOverrides", providers: "refreshProviders", "cache-config": "refreshCacheConfig", geoip: "refreshGeoip", maxmind: "refreshMaxmind", cctld: "refreshCctldBlock", "rating-filter": "refreshRatingFilter", "blocklist-bundles": "refreshBlocklistBundles" };

  run("startLiveUpdates()");
  let es = sources[0];
  guard("stream not opened at /admin/events", es && es.url === "/admin/events");
  es.readyState = 1; es.emit("open");
  guard("first open re-fetched every card (bootstrap already did)", spy.refreshOverrides.length === 0);
  guard("polling running while the stream is open", intervals.size === 0);
  es.emit("status", JSON.stringify({ marker: 7 }));
  guard("status event not rendered", spy.render.length === 1 && spy.render[0][0].marker === 7);
  for (const [topic, fn] of Object.entries(topicCards)) {
    es.emit(topic, "1");
    guard(`event ${topic} did not re-fetch its card in BACKGROUND mode`, spy[fn].length === 1 && spy[fn][0][0] === BG);
  }
  es.emit("log", "1"); es.emit("log", "2"); es.emit("log", "3");
  guard("log refreshed before the throttle window", spy.refreshLog.length === 0);
  fire(1000);
  guard("three log events must give one log re-fetch", spy.refreshLog.length === 1 && spy.refreshLog[0][0] === BG);
  run("logPage = 1");
  es.emit("log", "4");
  guard("a log event re-fetched while reading an older page", fire(1000) === 0 && spy.refreshLog.length === 1);
  run("logPage = 0");
  // A list scrolled down is held the same way (a re-render would reset its
  // scroll), and scrolling back to the top catches up once.
  const scrolledList = { scrollTop: 300 };
  vm.runInContext("currentLogList = __list", Object.assign(ctx, { __list: scrolledList }));
  es.emit("log", "5");
  guard("a log event re-fetched while the list was scrolled down", fire(1000) === 0 && spy.refreshLog.length === 1);
  guard("scrolled list not reported as paused", run("logLiveText()") === run(`t("log.livePaused")`));
  run("currentLogList = null; logUpdateMissed = false");

  // Silence: hero says unreachable at once, the poll takes over, a reconnect is scheduled.
  es.emit("ping", "");
  guard("silence fired too early", fire(25000) === 1);
  guard("silent stream not closed", es.readyState === 2);
  guard("silence did not show SERVICE_UNREACHABLE", heroDown() === 1);
  guard("silence did not start the poll", intervals.size === 1 && spy.refresh.length === 1);
  guard("no reconnect after silence", fire(5000) === 1 && sources.length === 2);

  // Reconnect: poll stops, every card catches up on what it missed.
  es = sources[1];
  es.readyState = 1; es.emit("open");
  guard("poll kept running after reconnect", intervals.size === 0);
  guard("reconnect did not re-fetch every card", Object.values(topicCards).every((fn) => spy[fn].length === 2));

  // A non-200 answer (503) closes the stream without calling the service down.
  es.readyState = 2; es.emit("error");
  guard("503 shown as SERVICE_UNREACHABLE", heroDown() === 1);
  guard("503 did not fall back to polling", intervals.size === 1);
  guard("503: no reconnect scheduled", fire(5000) === 1 && sources.length === 3);

  // A dropped connection (browser retrying) is the service being gone.
  es = sources[2];
  es.readyState = 0; es.emit("error");
  guard("dropped connection not shown as SERVICE_UNREACHABLE", heroDown() === 2);
  guard("events from a stream already given up on still act", (() => { const before = spy.render.length; es.emit("status", "{}"); return spy.render.length === before; })());
  guard("backoff did not grow", fire(10000) === 1);
  run("pushLost(false); stopPolling()");
  timers.length = 0;

  // No EventSource at all: the old poll.
  delete ctx.EventSource;
  run("eventSource = null; pollTimer = null; startLiveUpdates()");
  guard("no EventSource: poll not started", intervals.size >= 1);
  console.log(`locales=${Object.keys(dicts).length} calls=${calls.length} xss=${xssCalls.length} failures=${failures}`);
  process.exit(failures ? 1 : 0);
})();
