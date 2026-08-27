// T-52: no local optimistic state - every command re-fetches/returns the
// live status from dnsqb-service, and every render below comes straight
// from that response. If the service isn't reachable, the error panel
// renders instead of the controls - never a fake 0/0 stat (Три Б).

const { invoke } = window.__TAURI__.core;

const statusPill = document.getElementById("status-pill");
const statusText = document.getElementById("status-text");
const appBody = document.getElementById("app-body");

function setPill(ok, text) {
  statusPill.classList.toggle("is-bad", !ok);
  statusText.textContent = text;
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
  const message =
    err && err.kind === "SERVICE_UNREACHABLE"
      ? "dnsqb-service не запущено або недоступний."
      : `Помилка: ${(err && err.message) || String(err)}`;
  setPill(false, "Сервіс недоступний");
  appBody.textContent = "";
  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.textContent = message;
  appBody.appendChild(panel);
}

async function onProvidersChanged() {
  const quad9 = document.getElementById("toggle-quad9").checked;
  const adguard = document.getElementById("toggle-adguard").checked;
  try {
    render(await invoke("set_providers", { quad9, adguard }));
  } catch (err) {
    renderError(err);
  }
}

async function onTimeoutModeChanged(event) {
  try {
    render(await invoke("set_timeout_mode", { mode: event.target.value }));
  } catch (err) {
    renderError(err);
  }
}

async function refresh() {
  try {
    render(await invoke("get_status"));
  } catch (err) {
    renderError(err);
  }
}

refresh();
