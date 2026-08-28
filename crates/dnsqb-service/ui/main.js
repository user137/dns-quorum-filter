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
const overridesBody = document.getElementById("overrides-body");

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

/// Sends a full `AdminConfigUpdate` (always both fields together - see the
/// backend's own `AdminConfigUpdate` doc comment for why the wire format is
/// a full replace, not a per-field patch). Fetches the current status first
/// so the caller only has to override the one field it actually changed -
/// the same pattern the deleted Tauri commands used.
async function applyConfig(overrides) {
  const current = await getStatus();
  const response = await fetch("/admin/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      providers: current.providers,
      timeout_mode: current.timeout_mode,
      ...overrides,
    }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

// SPEC.md "Відкриті питання" п.4 / §8: quorum privacy is a real tradeoff
// (N third parties see a new, uncached domain instead of one) that must be
// communicated explicitly, not buried. The baseline resolver
// (`upstream::BASELINE_DOH_URL`, hardcoded to Cloudflare - not yet
// admin-configurable) is queried unconditionally for every quorum-
// applicable, uncached lookup regardless of which filtering providers are
// toggled on - `quorum::resolve` always pushes a `Slot::Baseline` future,
// even when both `quad9`/`adguard` are disabled (`quorum.rs`, the
// unconditional push right after the two `if enabled.*` blocks). So the
// true third-party count is always "enabled filtering providers + 1", never
// just the filtering providers themselves - a first draft of this notice
// undercounted by exactly that one party.
const PROVIDER_LABELS = { quad9: "Quad9", adguard: "AdGuard" };
const BASELINE_LABEL = "Cloudflare (baseline)";

function privacyNoticeHtml(providers) {
  const filtering = Object.keys(providers).filter((key) => providers[key]);
  if (filtering.length === 0) {
    // Both filtering providers are off - the "not filtered" warning below
    // already names the baseline resolver and its full visibility, so no
    // separate notice here (would be redundant, not a missing disclosure).
    return "";
  }
  const names = filtering.map((key) => PROVIDER_LABELS[key]).concat(BASELINE_LABEL).join(", ");
  const total = filtering.length + 1;
  return `<div class="notice info">Кожен новий (не кешований) домен, який ви відвідуєте, надсилається до ${total} сторонніх серверів (${names}) — свідомий компроміс приватності заради кращого покриття загроз: ваша нова історія браузингу видима одразу ${total} сторонам замість однієї.</div>`;
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
  const bothOff = !status.providers.quad9 && !status.providers.adguard;
  appBody.innerHTML = `
    ${bothOff ? `<div class="notice warn">Обидва провайдери вимкнено — фільтрація не активна, запити йдуть напряму через baseline-резолвер (Cloudflare), який усе одно бачить кожен новий домен, який ви відвідуєте.</div>` : privacyNoticeHtml(status.providers)}
    <div class="card">
      <h3>Провайдери</h3>
      <div class="toggle-row">
        <span>Quad9</span>
        <label class="switch">
          <input type="checkbox" id="toggle-quad9" ${status.providers.quad9 ? "checked" : ""} />
          <span class="track"></span><span class="thumb"></span>
        </label>
      </div>
      <div class="toggle-row">
        <span>AdGuard</span>
        <label class="switch">
          <input type="checkbox" id="toggle-adguard" ${status.providers.adguard ? "checked" : ""} />
          <span class="track"></span><span class="thumb"></span>
        </label>
      </div>
    </div>
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

  document.getElementById("toggle-quad9").addEventListener("change", onProvidersChanged);
  document.getElementById("toggle-adguard").addEventListener("change", onProvidersChanged);
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

async function onProvidersChanged() {
  const quad9 = document.getElementById("toggle-quad9").checked;
  const adguard = document.getElementById("toggle-adguard").checked;
  try {
    render(await applyConfig({ providers: { quad9, adguard } }));
  } catch (err) {
    renderError(err);
  }
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
