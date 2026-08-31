// T-149: ported from the deleted dnsqb-ui/ui/main.js (Tauri) - no local
// optimistic state, every action re-fetches/returns the live status from
// dnsqb-service, and every render below comes straight from that response.
// If the service isn't reachable, the error panel renders instead of the
// controls - never a fake 0/0 stat (Три Б). `window.__TAURI__.core.invoke`
// calls became same-origin `fetch()` calls - no CORS needed, the existing
// `content_type_is_json` CSRF gate on `/admin/config` still applies.

const statusPill = document.getElementById("status-pill");
const statusText = document.getElementById("status-text");
const appBody = document.getElementById("app-body");
const providersBody = document.getElementById("providers-body");
const overridesBody = document.getElementById("overrides-body");
const cacheConfigBody = document.getElementById("cache-config-body");
const geoipBody = document.getElementById("geoip-body");
const geoipMaxmindBody = document.getElementById("geoip-maxmind-body");
const logBody = document.getElementById("log-body");

function setPill(ok, text) {
  statusPill.classList.toggle("is-bad", !ok);
  statusText.textContent = text;
}

async function getStatus() {
  const response = await fetch("/admin/status");
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

/// Sends an `AdminConfigUpdate`. Since T-72/T-73 that DTO carries only
/// `timeout_mode` (the voter list moved to its own `/admin/providers/*`
/// routes), so `applyConfig` is only ever called with `{ timeout_mode }` -
/// the pre-fetch of the current status is gone with the `providers` field
/// it used to carry forward.
async function applyConfig(overrides) {
  const response = await fetch("/admin/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(overrides),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

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

function render(status) {
  setPill(true, "Сервіс доступний");
  // The voter (provider) list moved to its own #providers-body card
  // (T-72/T-73) - it is no longer part of the 2s status poll's DOM.
  appBody.innerHTML = `
    <div class="card">
      <h3>Режим таймауту</h3>
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
    </div>
    <div class="card">
      <h3>Статистика (у поточному вікні логу)</h3>
      <div class="stat-row">
        <div>
          <div class="stat">${status.stats.blocked}</div>
          <div class="stat-sub">заблоковано</div>
        </div>
        <div>
          <div class="stat">${status.stats.total}</div>
          <div class="stat-sub">усього оброблено</div>
        </div>
        <div>
          <div class="stat">${status.stats.in_flight}</div>
          <div class="stat-sub">зараз обробляється</div>
        </div>
        <div>
          <div class="stat">${blockedPercentLabel(status.stats)}</div>
          <div class="stat-sub">частка заблокованих</div>
        </div>
      </div>
    </div>
  `;

  document
    .querySelectorAll('input[name="timeout-mode"]')
    .forEach((el) => el.addEventListener("change", onTimeoutModeChanged));
}

function renderError(err) {
  setPill(false, "Сервіс недоступний");
  appBody.textContent = "";
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  appBody.appendChild(panel);
}

async function onTimeoutModeChanged(event) {
  try {
    render(await applyConfig({ timeout_mode: event.target.value }));
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

refresh();
// `in_flight` (a live count of requests being resolved right now) is
// otherwise only ever sampled at the instant of a toggle click - a page
// that only re-renders on user action would show it near-permanently 0,
// reading as "the resolver is idle" even while it's busy (the same
// honesty failure this project already corrected twice: T-66's cold/warm
// relabel, T-52's "never a fake 0/0 stat"). Polling every 2s keeps every
// rendered value the server's actual live response, same "no local
// optimistic state" philosophy as every other render() call here.
setInterval(refresh, 2000);

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
    note.textContent = "конфлікт: домен є і в allowlist, і в blocklist — allowlist має пріоритет";
    li.appendChild(note);
  }
  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "override-remove";
  removeBtn.textContent = "Видалити";
  removeBtn.addEventListener("click", async () => {
    try {
      await removeOverride(entry.domain, entry.is_wildcard, list);
      await refreshOverrides();
    } catch (err) {
      renderOverridesError(err);
    }
  });
  li.appendChild(removeBtn);
  return li;
}

function renderOverrides(data) {
  overridesBody.textContent = "";

  const heading = document.createElement("h3");
  heading.textContent = "Списки виключень";
  overridesBody.appendChild(heading);

  // T-47, advisor-caught: an add/remove that live-applies but fails to
  // persist must be visible, not just silently reflected in the response -
  // otherwise a restart could silently drop a filtering rule the user
  // thinks they already saved (the same failure class AdminStatusResponse's
  // own `persisted` field exists to prevent for resolver_config.toml).
  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent =
      "Зміну застосовано, але НЕ збережено на диск - вона не переживе перезапуск сервісу.";
    overridesBody.appendChild(notPersisted);
  }

  const addRow = document.createElement("div");
  addRow.className = "override-add-row";
  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = "example.com або *.example.com";
  const select = document.createElement("select");
  const allowOpt = document.createElement("option");
  allowOpt.value = "allowlist";
  allowOpt.textContent = "Дозволити";
  const blockOpt = document.createElement("option");
  blockOpt.value = "blocklist";
  blockOpt.textContent = "Блокувати";
  select.appendChild(allowOpt);
  select.appendChild(blockOpt);
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.textContent = "Додати";
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
      errorLine.textContent = `Не вдалося додати "${pattern}": ${(err && err.message) || String(err)}`;
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
  allowHeading.textContent = "Allowlist";
  overridesBody.appendChild(allowHeading);
  const allowList = document.createElement("ul");
  allowList.className = "override-list";
  data.allowlist.forEach((entry) =>
    allowList.appendChild(overrideListItem(entry, "allowlist", data.conflicts))
  );
  overridesBody.appendChild(allowList);

  const blockHeading = document.createElement("h4");
  blockHeading.textContent = "Blocklist";
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
  heading.textContent = "Списки виключень";
  overridesBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  overridesBody.appendChild(panel);
}

async function refreshOverrides() {
  try {
    renderOverrides(await getOverrides());
  } catch (err) {
    renderOverridesError(err);
  }
}

refreshOverrides();

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
  { key: "clamp_min_secs", label: "Мін. TTL апстріму (с)" },
  { key: "clamp_max_secs", label: "Макс. TTL апстріму (с)" },
  { key: "block_verdict_ttl_secs", label: "TTL для BLOCK-вердикту (с)" },
  { key: "stale_grace_secs", label: "Вікно stale-if-error (с)" },
  { key: "max_capacity", label: "Максимум записів у кеші" },
];

function renderCacheConfig(data) {
  cacheConfigBody.textContent = "";

  const heading = document.createElement("h3");
  heading.textContent = "Кеш";
  cacheConfigBody.appendChild(heading);

  // Same "silent data loss" concern as #overrides-body's own persisted
  // warning (T-47) - a live-applied change that failed to persist must be
  // visible, not just silently reflected in the response.
  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent =
      "Зміну застосовано, але НЕ збережено на диск - вона не переживе перезапуск сервісу.";
    cacheConfigBody.appendChild(notPersisted);
  }

  // T-153: a config change rebuilds the whole cache (moka has no live
  // setter for max_capacity/its expiry policy - see CONFIGURATION.md's own
  // explanation of why) - shown here so "Застосувати" isn't a surprise.
  const flushNotice = document.createElement("p");
  flushNotice.className = "cache-config-flush-notice";
  flushNotice.textContent =
    "Застосування цих значень повністю скидає поточний кеш вердиктів.";
  cacheConfigBody.appendChild(flushNotice);

  const inputs = {};
  const form = document.createElement("div");
  form.className = "cache-config-form";
  CACHE_CONFIG_FIELDS.forEach(({ key, label }) => {
    const row = document.createElement("label");
    row.className = "cache-config-row";
    const span = document.createElement("span");
    span.textContent = label;
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
  applyBtn.textContent = "Застосувати";
  applyBtn.addEventListener("click", async () => {
    const update = {};
    CACHE_CONFIG_FIELDS.forEach(({ key }) => {
      update[key] = Number(inputs[key].value);
    });
    // Client-side mirror of the server's own from_secs() check - belt and
    // suspenders, not a replacement for it (the server still rejects an
    // inverted range independently).
    if (update.clamp_min_secs > update.clamp_max_secs) {
      errorLine.textContent =
        "Мін. TTL апстріму не може перевищувати макс. TTL апстріму.";
      return;
    }
    try {
      errorLine.textContent = "";
      renderCacheConfig(await applyCacheConfig(update));
    } catch (err) {
      errorLine.textContent = `Не вдалося застосувати: ${(err && err.message) || String(err)}`;
    }
  });
  cacheConfigBody.appendChild(applyBtn);
  cacheConfigBody.appendChild(errorLine);
}

function renderCacheConfigError(err) {
  cacheConfigBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = "Кеш";
  cacheConfigBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  cacheConfigBody.appendChild(panel);
}

async function refreshCacheConfig() {
  try {
    renderCacheConfig(await getCacheConfig());
  } catch (err) {
    renderCacheConfigError(err);
  }
}

refreshCacheConfig();

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

// T-162: `DatabaseSource` wire strings → human labels.
const DATABASE_SOURCE_LABELS = {
  DB_IP_LITE: "DB-IP Lite",
  GEO_LITE2: "MaxMind GeoLite2",
  OTHER: "інше джерело",
};

// SPEC.md §3.5's own wording, translated - large CDNs hand out anycast IPs
// whose apparent country changes between requests/points of presence, so
// blocking a country is expected, typical over-blocking risk for any site
// behind one, not a hypothetical edge case.
const GEOIP_OVER_BLOCKING_WARNING =
  "Великі CDN (Cloudflare, Google, Amazon) роздають anycast-адреси, чия " +
  "географія змінюється між запитами - блокування країни ризикує " +
  "заблокувати легітимні сайти, які просто фізично проходять через " +
  "дата-центр у цій країні, не маючи стосунку до її юрисдикції.";

function geoipListItem(code) {
  const li = document.createElement("li");
  li.className = "override-item";
  const label = document.createElement("span");
  label.textContent = code;
  li.appendChild(label);
  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "override-remove";
  removeBtn.textContent = "Видалити";
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

  const heading = document.createElement("h3");
  heading.textContent = "GeoIP-блокування";
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
    databaseStatus.textContent =
      "База GeoIP ще не завантажена - фільтрація за країною зараз не діє, незалежно від списку нижче.";
  } else if (data.database_built_at_ms == null) {
    databaseStatus.textContent = "База GeoIP завантажена, дата збірки невідома.";
  } else {
    // Source-neutral date line - `database_source` (below) carries which
    // publisher's database this actually is (T-162); before that field
    // existed a hardcoded "(DB-IP)" here was wrong once T-80 landed.
    databaseStatus.textContent = `Дата збірки бази GeoIP: ${new Date(
      data.database_built_at_ms,
    ).toLocaleString()}`;
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
    sourceLine.textContent = `Активне джерело: ${
      DATABASE_SOURCE_LABELS[data.database_source] || data.database_source
    }`;
    geoipBody.appendChild(sourceLine);
  }

  // Same "silent data loss" concern as #overrides-body's own persisted
  // warning (T-47).
  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent =
      "Зміну застосовано, але НЕ збережено на диск - вона не переживе перезапуск сервісу.";
    geoipBody.appendChild(notPersisted);
  }

  const addRow = document.createElement("div");
  addRow.className = "override-add-row";
  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = "SE";
  input.maxLength = 2;
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.textContent = "Додати";
  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.textContent = "Скасувати";
  cancelBtn.hidden = true;
  const errorLine = document.createElement("div");
  errorLine.className = "override-error";
  const warningLine = document.createElement("div");
  warningLine.className = "notice warn";
  warningLine.hidden = true;
  warningLine.textContent = GEOIP_OVER_BLOCKING_WARNING;

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
    addBtn.textContent = "Додати";
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
      errorLine.textContent = `"${code}" не є дійсним дволітерним кодом країни (ISO 3166-1 alpha-2).`;
      return;
    }
    errorLine.textContent = "";
    if (armedCode !== code) {
      armedCode = code;
      warningLine.hidden = false;
      cancelBtn.hidden = false;
      addBtn.textContent = "Підтвердити додавання";
      return;
    }
    try {
      // Renders the POST response directly - see the remove handler's own
      // comment above for why add-then-refresh would silently hide a
      // failed save.
      renderGeoip(await addGeoipCountry(code));
    } catch (err) {
      errorLine.textContent = `Не вдалося додати "${code}": ${(err && err.message) || String(err)}`;
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
  heading.textContent = "GeoIP-блокування";
  geoipBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  geoipBody.appendChild(panel);
}

async function refreshGeoip() {
  try {
    renderGeoip(await getGeoip());
  } catch (err) {
    renderGeoipError(err);
  }
}

refreshGeoip();

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

const MAXMIND_CHECK_MESSAGES = {
  VERIFIED: { cls: "notice ok", text: "MaxMind підтвердив ці креденшели." },
  REJECTED: {
    cls: "notice warn",
    text: "MaxMind відхилив креденшели (401/403) - перевірте account ID та ліцензійний ключ.",
  },
  UNVERIFIED: {
    cls: "notice warn",
    text: "Не вдалося перевірити креденшели зараз (мережа?) - креденшели збережено, перевірка відбудеться при наступному оновленні бази.",
  },
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
  heading.textContent = "Джерело GeoIP: MaxMind GeoLite2";
  geoipMaxmindBody.appendChild(heading);

  const state = document.createElement("p");
  state.className = "geoip-database-status";
  state.textContent = data.configured
    ? `Налаштовано. Account ID: ${data.account_id}. Діє одразу.`
    : "Не налаштовано - використовується DB-IP Lite (за замовчуванням).";
  geoipMaxmindBody.appendChild(state);

  if (!data.persisted) {
    const notPersisted = document.createElement("div");
    notPersisted.className = "notice warn";
    notPersisted.textContent =
      "Зміну НЕ збережено - вона не переживе перезапуск сервісу.";
    geoipMaxmindBody.appendChild(notPersisted);
  }

  if (data.refresh_health === "AUTH_REJECTED") {
    const brokenLater = document.createElement("div");
    brokenLater.className = "notice warn";
    brokenLater.textContent =
      "MaxMind більше не приймає збережені креденшели на плановому оновленні бази - перезбережіть account ID та ліцензійний ключ.";
    geoipMaxmindBody.appendChild(brokenLater);
  }

  const check = MAXMIND_CHECK_MESSAGES[data.check];
  if (check) {
    const line = document.createElement("div");
    line.className = check.cls;
    line.textContent = check.text;
    geoipMaxmindBody.appendChild(line);
  }

  const errorLine = document.createElement("div");
  errorLine.className = "override-error";

  const accountInput = document.createElement("input");
  accountInput.type = "text";
  accountInput.placeholder = "account ID";
  const keyInput = document.createElement("input");
  keyInput.type = "password";
  keyInput.placeholder = "ліцензійний ключ";
  keyInput.autocomplete = "off";

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.textContent = "Зберегти";
  saveBtn.addEventListener("click", async () => {
    const accountId = accountInput.value.trim();
    const licenseKey = keyInput.value.trim();
    if (!accountId || !licenseKey) {
      errorLine.textContent = "Обидва поля обов'язкові.";
      return;
    }
    errorLine.textContent = "";
    try {
      renderMaxmind(await setMaxmind(accountId, licenseKey));
    } catch (err) {
      errorLine.textContent = `Не вдалося зберегти: ${(err && err.message) || String(err)}`;
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
    clearBtn.textContent = "Очистити";
    clearBtn.addEventListener("click", async () => {
      if (!armed) {
        armed = true;
        clearBtn.textContent = "Підтвердити очищення";
        return;
      }
      try {
        renderMaxmind(await clearMaxmind());
      } catch (err) {
        errorLine.textContent = `Не вдалося очистити: ${(err && err.message) || String(err)}`;
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
  heading.textContent = "Джерело GeoIP: MaxMind GeoLite2";
  geoipMaxmindBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  geoipMaxmindBody.appendChild(panel);
}

async function refreshMaxmind() {
  try {
    renderMaxmind(await getMaxmind());
  } catch (err) {
    renderMaxmindError(err);
  }
}

refreshMaxmind();

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

  const heading = document.createElement("h3");
  heading.textContent = "Лог запитів";
  logBody.appendChild(heading);

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
// own comment above for the null-deref this fixed).
buildLogFilterRow();
refreshLog();

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

  const heading = document.createElement("h3");
  heading.textContent = "Провайдери-voter'и";
  providersBody.appendChild(heading);

  // SPEC.md / CLAUDE.md: the fan-out privacy tradeoff (more third parties
  // see uncached browsing history) must stay user-visible, not buried.
  const fanout = document.createElement("p");
  fanout.className = "geoip-database-status";
  const parties = data.third_party_count;
  const voterCount = parties - 1;
  fanout.textContent =
    `Кожен запит поза кешем ${pluralUk(parties, "бачить", "бачать", "бачать")} ${parties} ` +
    `${pluralUk(parties, "третю сторону", "треті сторони", "третіх сторін")}: ` +
    `${voterCount} ${pluralUk(voterCount, "увімкнений voter", "увімкнені voter'и", "увімкнених voter'ів")} ` +
    `+ baseline-резолвер.`;
  providersBody.appendChild(fanout);

  // T-72/T-73 closing review: the all-disabled state is a legitimate
  // user choice (SPEC.md §3/§8.1 pass-through), but it must be shown, not
  // silently in effect - filtering_active is the backend's explicit signal.
  if (!data.filtering_active) {
    const off = document.createElement("div");
    off.className = "notice warn";
    off.textContent =
      "Жоден voter не увімкнено - фільтрація не активна. Запити йдуть напряму через " +
      "baseline-резолвер, який усе одно бачить кожен домен, який ви відвідуєте.";
    providersBody.appendChild(off);
  }

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
  providersBody.textContent = "";
  const heading = document.createElement("h3");
  heading.textContent = "Провайдери-voter'и";
  providersBody.appendChild(heading);
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = `Помилка: ${(err && err.message) || String(err)}`;
  providersBody.appendChild(panel);
}

async function refreshProviders() {
  try {
    renderProviders(await getProviders());
  } catch (err) {
    renderProvidersError(err);
  }
}

refreshProviders();
