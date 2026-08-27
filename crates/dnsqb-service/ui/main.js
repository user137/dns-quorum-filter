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

function render(status) {
  setPill(true, "Сервіс доступний");
  const bothOff = !status.providers.quad9 && !status.providers.adguard;
  appBody.innerHTML = `
    ${bothOff ? `<div class="notice warn">Обидва провайдери вимкнено — фільтрація не активна, запити йдуть напряму через baseline-резолвер.</div>` : ""}
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
