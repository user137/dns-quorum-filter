# QA-FIX-PLAN — план виправлень хвилями (QA-прохід 0.8.0, Фаза 4)

Складено 2026-10-04 за `review/QA-PROMPT.md` (Фаза 4). Лише план — жодного коду; виконання кожної
хвилі починається за окремим «так» користувача. Вхід: усі `FAIL` з `review/QA-MATRIX.md` + відкриті
задачі, заведені або зачеплені проходом (T-242…T-256, T-243 і відкладене з T-238).

**Стан входу:** Firefox-прохід виконано 2026-10-04 (рядки `I-firefox-*`, `B-firefox-*`,
`B-browser-setup-firefox-*`): дві нові знахідки — T-257 («спершу діагноз») і T-258 (хвиля 10).
Деструктивний блок (ребут T-243, «Вийти», `/admin/shutdown`, «Повністю видалити»,
деінсталяція+перевстановлення) теж ще попереду і може додати знахідки.

## Таблиця хвиль

| Хвиля | Назва | Задачі | Чому разом | Файли | Залежить від | plan+advisor | Регресійні тести | Як перевірити | Розмір | Блокує реліз |
|---|---|---|---|---|---|---|---|---|---|---|
| 0 | Аудит ін'єкцій у полях API | запит користувача 2026-10-04 (нова T-NNN) | Security: одна наскрізна таблиця «поле → sink → захист → тест», окремо від усього | `dispatch.rs`, `admin.rs`, `config.rs`, `overrides.rs`, `upstream.rs`, `geoip_credentials.rs`, `ui/main.js`, `self_uninstall.rs`, `trust_store.rs` | — | так | на кожне поле × sink без тесту — payload-тест (HTML/`"`/`'`/`
`/`
`/`]`/`=`/`;`/`&`/`\|`/`%`/NUL/RTL-override) | CI + `smoke-installed.ps1` + браузер | M | так |
| 1 | Межі `[cache]` | T-256 | Security-чутлива зміна формату конфігу — окремо за правилом | `cache.rs`, `config.rs`, `admin.rs`, `dispatch.rs`, `CONFIGURATION.md` | — | так | рядок `u64::MAX` у `every_config_field_rejects_…`; `CacheConfigUpdate` з `u64::MAX` → 400; `CacheEntry::new`/`expire_after_create` без паніки | CI + `smoke-installed.ps1` | M | так |
| 2 | Апгрейд MSIX | T-244 | Процесна модель (spawn-прапорці watchdog) — архітектурна, окремо | `watchdog/spawn.rs`, `dnsqb-watcher/src/main.rs`, `packaging/Trust-TestCert.ps1`, `packaging/README.md` | — | так | чисте ядро вибору прапорців spawn; поведінку апгрейду — лише наживо | артефакт GitHub: апгрейд 0.8.0 → нова версія руками користувача (UAC) | L | так |
| 3 | Hero при мертвих фільтрах | T-254 | Зміна DTO з бампом `schema_version` — окремо; **лише після рішення користувача** | `admin.rs` (`compute_hero_state`, `HeroStateView`), `ui/main.js`, `ui/i18n/*.json`, `UI-SPEC.md`, `diagrams/ui-status-indicator*` | рішення користувача | так | `admin::hero_and_category_tests` — новий вхід деградації; DTO-тест бампу | CI + наживо hosts-деградація (UAC) | M | на рішення користувача (false-safe — рекомендую так) |
| 4 | Стійкість CLI | T-246 (2), (4) | Ті самі три `main.rs` + `cli_help.rs`, одна перевірка | `dnsqb-service/src/main.rs:23`, `dnsqb-tray/src/main.rs:193`, `dnsqb-watcher/src/main.rs:61`, `cli_help.rs` | — | ні | `wants_help` над `OsString` з непарним сурогатом; друк довідки у writer, що повертає `BrokenPipe` → без паніки | CI + `smoke-installed.ps1` + ручний `--help \| Select -First 1` | S | ні |
| 5 | Tooltip трею (залежність) | T-253 | Оновлення/патч `tray-icon` — lower-layer, окремо | `crates/dnsqb-tray/Cargo.toml`, `Cargo.lock`, `SECURITY.md`, можливо `dnsqb-tray/src/main.rs` | — | так | `compose_tooltip` уже покрито; довжину нативного tooltip — лише наживо | `cargo deny`/`audit` у CI + наведення миші на іконку з артефакту GitHub | M | ні (рекомендую до релізу) |
| 6 | Дрібниці трею | T-255, T-251, T-263, T-264 | Обидва — `dnsqb-tray`, один артефакт для перевірки | `dnsqb-tray/src/status.rs` (`spawn_trust_watch`), `dnsqb-tray/src/main.rs:617-627` | хвиля 5 (той самий крейт) | ні | перехід cert `NOT_TRUSTED→TRUSTED` у `/admin/status` викликає recheck; рядок логу паузи | CI + наживо: install-cert з `/admin/ui` → трей зелений ≤ 5 с | S | ні |
| 7 | Приватність логу конфігу | T-252 | Точковий privacy-фікс | `config.rs` / `orchestrate.rs` (місце логування помилки `toml`) | хвиля 1 (спільний `config.rs`) | ні | помилка розбору → у тексті логу немає цитати рядка файлу | CI + наживо: битий `resolver_config.toml` + `/admin/reset` | S | ні |
| 8 | Помилки POST у `/admin/ui` | T-250 | Один клас бага: невдалий POST руйнує картку/hero | `ui/main.js` (`onConfigChanged` :654, `renderError`, картки категорій і провайдерів) | — | ні | `ui/smoke.js`: reject `fetch` → картка лишає контроли, видно рядок помилки, hero не `SERVICE_UNREACHABLE` | CI (`ui-smoke`) + chrome-devtools/Firefox на артефакті | M | ні |
| 9 | Перемальовування не стирає ввід | T-248 (+T-242 після рішення) | Один клас: ре-рендер скидає те, що користувач редагує; T-242 — нове опитування логу, яке не має скидати той самий стан | `ui/main.js` (`renderTranslatedCards`, `refreshLog`) | хвиля 8 (той самий `main.js`) | ні | `ui/smoke.js`: зміна локалі зберігає ввід overrides/пошуку й відкриті `?` | CI + браузер на артефакті | M | ні |
| 10 | i18n і доступність | T-247, T-249, T-258 | Один прохід по 37 словниках + `index.html` | `ui/i18n/*.json` (37), `ui/index.html`, `ui/main.js` | хвилі 8, 9 (`main.js`) | ні | `ui/smoke.js`: кожне поле форми має доступне ім'я; рядок MaxMind не згадує DB-IP | CI + Lighthouse/a11y у браузері | S | ні |
| 11 | Розбіжності документації | T-245, T-246 (1) як обмеження платформи, T-268 (якщо обрано перейменування) | Лише документи, без коду | `UI-SPEC.md`, `CLAUDE.md`, `KNOWN-LIMITATIONS.md`, `CONFIGURATION.md` | — (паралельно з усіма) | ні | — | перечитування + `qa-matrix-check.py`; CI для `.md` не запускається | S | ні |
| 12 | Тест-покриття без зміни поведінки | рядки `CODE-ONLY` «кандидат у Фазу 3», T-265 | Лише нові тести | `watchdog/*` (transition/loop_driver), `persist_dto`, `cache_persist_dto`, `personal_zone_stats`, `dnsqb-tray` nudge | після 1-10 | ні | — | CI | M | ні |

Порядок: хвиля 0 першою (security). Паралельність: 1, 2, 4, 11 не мають спільних файлів — можна паралельно. 5→6 послідовно (`dnsqb-tray`).
1→7 послідовно (`config.rs`). 8→9→10 послідовно (`main.js`). Хвиля 3 чіпає `main.js` і словники —
не паралельно з 8-10.

## Деталі хвиль

### Хвиля 0 — аудит ін'єкцій у полях API (запит користувача)
- Обсяг: **кожне** поле, яке приймає `/admin/*` або читається з `resolver_config.toml`/`overrides.toml`:
  domain/`is_wildcard`/`list` overrides, `id`/`url`/`display_name`/`category`/`block_signature`
  провайдера, коди GeoIP і ccTLD, `lists`/`sources`, MaxMind `account_id`/`license_key`, поля
  `/admin/config`/`cache-config`, параметри фільтра/пошуку логу, тіло `/dns-query`.
- Sink-и, які перевірити для кожного: HTML `/admin/ui` (DOM-методи, CSP); запис TOML (екранування
  крейтом `toml`, підміна ключа/секції через `]`/`
`); рядки логів (`
`-ін'єкція фальшивих записів,
  витік секретів/доменів); заголовок HTTP (MaxMind Basic auth — `
` у ключі); URL до upstream
  (SSRF — `validate_provider_url`); командні рядки (`certutil`, `rundll32`, PowerShell у
  `self_uninstall.rs:165`); шляхи файлів (path traversal через `id`); DNS wire (`hickory-proto`).
- Вже є: XSS-прогін `ui/smoke.js` (Фаза 3a, 8 карток), `.arg()` замість shell-рядка, екранування `'`
  у `self_uninstall.rs` з тестом, SSRF-валідатор, `is_valid_provider_id`, фазі `serve_never_panics_…`.
- Результат: таблиця в цьому файлі + payload-тест на кожну клітинку без покриття; знайдений пролом —
  окрема T-NNN з регресійним тестом першим. Перша звірка (2026-10-04): HTML-шаблони `main.js:528`,
  `:608` підставляють лише числа/enum/словник — пролому не знайдено, аудит не завершено.
- Коміти: тести окремо від фіксів. Re-test: усі `A-*-MF`, `A-*-SB`, `B-*-SB`, `H-cfg-*-SB`.

### Хвиля 1 — межі `[cache]` (T-256)
- **Форма фіксу (визначає тип хвилі):** верхня межа на поля `[cache]` у `config.rs` і в
  `CacheConfigUpdate::into_config` (`admin.rs:1036`) → раніше завантажуваний конфіг з величезним
  значенням стає помилкою завантаження (жорсткий cutover, патерн «Hard TOML cutovers») + насичувальна
  арифметика в `CacheEntry::new` (`cache.rs:84`) і `expire_after_create` (`cache.rs:303`) як
  другий рубіж. Саме через межу — окрема хвиля й оновлення `CONFIGURATION.md`.
- Тест першим: додати `u64::MAX` у таблицю `every_config_field_rejects_wrong_type_bad_case_negative_and_duplicate_key`
  (зараз для Unsigned там лише `-1`/`1.5`/рядок/bool) — тест падає, потім фікс.
- Коміти: 1 (тест+фікс), окремо docs. Артефакт GitHub: так (смоук після фіксу).
- Re-test: `A-admin-cache-config-apply-SB2`, `H-cfg-cache.*-SB`.
- Документи: `CONFIGURATION.md` (межі), `TASKS-DONE.md`.

### Хвиля 2 — апгрейд MSIX (T-244)
- **Крок 0 — підтвердити причину**, бо фікс від неї залежить: зараз «`0x80070020` через дітей поза
  job пакета» спирається лише на журнал подій. Експеримент на тестовому артефакті: watcher спавнить
  без `CREATE_BREAKAWAY_FROM_JOB` → апгрейд `-ForceTargetApplicationShutdown` закриває всіх? Якщо ні
  — хвиля повертається в «спершу діагноз».
- Далі: варіанти (без breakaway; або явне завершення дітей перед апгрейдом; або видимий сигнал
  «оновлення не завершено») — вибір через plan+advisor, з урахуванням T-182 (чому breakaway з'явився).
- Коміти: 2-3 (діагностичний, фікс, docs). Артефакт: так, кожен крок.
- Re-test: `G-upgrade`, `F-respawn*`, `F-launcher-order*`.
- Документи: `packaging/README.md`, `RUST-GOTCHAS.md` (якщо підтвердиться), `TASKS-DONE.md`.

### Хвиля 3 — hero при мертвих фільтрах (T-254)
- Гейт: рішення користувача, чи потрібен варіант hero для «усі фільтри мовчать» (зараз by design
  за діаграмою `ui-status-indicator`, умова 5 — лише суфікс/amber трею).
- Якщо так: новий `HeroStateView` + вхід у `compute_hero_state` + бамп `ADMIN_DTO_SCHEMA_VERSION` +
  `#[serde(default)]`; трей не чіпати (окремий авторитет, CLAUDE.md).
- Коміти: 1 код + 1 docs/діаграма. Артефакт: так. Re-test: `I-degraded`, `DIAG-status-S5`, `B-hero-*`.
- Документи: `UI-SPEC.md`, діаграма + ритуал ground-truth, `DECISIONS.md`.

### Хвиля 4 — стійкість CLI (T-246 пункти 2 і 4)
- `std::env::args()` → `args_os()` + `to_string_lossy()` у трьох `main.rs`; друк довідки через
  `writeln!` з явно проігнорованою (з коментарем) помилкою замість `println!`.
- Коміт: 1. Артефакт: так (`smoke-installed.ps1` + ручний закритий pipe).
- Re-test: `E-watcher-help-EP`, `E-locale-EP`, `E-watcher-args-SB`; `E-service-help-HP` і
  `E-tray-help-HP` — після діагнозу T-246 (1).
- Документи: модульний doc `cli_help.rs` (теза «`println!` безпечний» хибна для закритого pipe),
  нотатка T-235 у `TASKS-DONE.md`.

### Хвиля 5 — tooltip трею (T-253)
- Перевірити `tray-icon` 0.26.0 на `cbSize`; якщо виправлено — бамп (API-зміни в `main.rs`), інакше
  локальний патч/форк — рішення через plan+advisor.
- `SECURITY.md` рядок, `cargo deny check` / `cargo audit`.
- Коміт: 1-2. Артефакт: так — перевірка лише наведенням миші (CI нативний tooltip не бачить).
- Re-test: `D-tooltip-suffixes`, `D-icon-Filtering-cert-untrusted`, `D-icon-Filtering-cert-untrusted-SB`.

### Хвиля 6 — дрібниці трею (T-255, T-251, T-263, T-264)
- T-255: сигнал зі служби перетинає межу процесу — трей бачить зміну cert-стану в `/admin/status`
  (2 с опитування) і смикає `request_recheck()`; маршрут служби не змінюється.
- T-251: рядок `info` у `tray.log` при вдалій паузі.
- T-263: текст діалогу «Вийти» (37 локалей трею) — назвати обидва наслідки: тихий обхід фільтра в
  автоматичному режимі браузера і непрацюючі сайти в режимі secure.
- T-264: UIA-ім'я іконки — склейка зі стартовим «service unreachable»; спершу діагноз (`szTip` у
  `tray-icon`), потім фікс або обмеження.
- Коміти: 4 (по задачі). Артефакт: так. Re-test: `A-admin-install-cert-HP`, `C-PAUSE_RESUME_ID-SB`,
  `C-QUIT_APP_ID-HP`, `D-tooltip-suffixes`.

### Хвиля 7 — приватність логу конфігу (T-252)
- Логувати тип/рядок/колонку помилки `toml`, не цитату рядка файлу (як уже робить `overrides.toml`).
- Коміт: 1. Re-test: `H-logs-privacy`.

### Хвиля 8 — помилки POST у `/admin/ui` (T-250)
- Невдалий POST → рядок помилки в картці, контроли лишаються, значення відкочується з поясненням;
  `renderError()`/`SERVICE_UNREACHABLE` — лише для провалу самого опитування статусу.
- Коміт: 1. Re-test: `B-timeout-EP`, `B-filter-controls-EP`, `B-providers-EP`.

### Хвиля 9 — перемальовування не стирає ввід (T-248, T-242)
- T-248 — без рішень. T-242 (автооновлення логу) — нова поведінка, інтервал і пауза при відкритих
  деталях за рішенням користувача; хвиля відвантажується й без T-242.
- Коміти: по задачі. Re-test: `B-locale-MF`, `B-log-autorefresh-HP`.

### Хвиля 10 — i18n, доступність і інструкції браузерів (T-247, T-249, T-258, T-260)
- T-247: `maxmind.notConfiguredStatus` у 37 словниках → типове джерело `user-country`; граматика
  `en.json` `filterControls.fanoutSummary` («query see» → «sees»).
- T-258: `browserSetup.verify` розвести за браузером (UA-детекція T-189 уже є): для Firefox —
  очікувати «не вдається знайти сайт», плюс попередження про «Посилений захист» (T-257).
- T-260: інструкції картки «Підключення браузера» й README під кожен браузер (Chrome, Brave,
  Firefox, Edge, Vivaldi, Opera, LibreWolf) за знахідками проходу інших браузерів — повний перелік у
  задачі. Робиться разом із T-258 (та сама картка, ті самі 37 словників). Перед реалізацією —
  рішення користувача, чи додавати ручний вибір браузера (Vivaldi за UA не відрізнити від Chrome).
- T-249: доступне ім'я для `<select>`/input у `#overrides-body`, фокус після radio в
  `#timeout-config-body`, `<link rel="icon">`.
- Коміти: по задачі. Re-test: `B-maxmind-HP`, `B-overrides-SB`, `B-app-body-SB`, `C-menu-a11y`,
  `B-browser-setup-firefox-MF`, `B-firefox-render-HP`, `B-browser-setup-edge-MF`,
  `B-browser-setup-opera-MF`, `B-browser-setup-vivaldi-MF`.

### Хвиля 11 — документація (T-245; T-246 п. 1)
- Шість пунктів T-245 — як у задачі. T-246 (1) — записати в `KNOWN-LIMITATIONS.md` як обмеження
  платформи **лише після** підтвердження документацією Microsoft (див. «Спершу діагноз»).
- Коміт: 1 docs (CI не запускається). Re-test: `A-dto-doc-drift`, `KL-tls-key-uninstall`.

### Хвиля 12 — тест-покриття
- Рядки `CODE-ONLY` з «автотестів НЕМАЄ — кандидат у Фазу 3», де є чисте ядро: `F-state-*`
  (`watchdog::transition`, `loop_driver`), `F-start-flags-*`, `F-launcher-order-*` (`launcher::plan_launch`),
  `H-file-*` (формати `persist_dto`/`cache_persist_dto`), `D-browser-nudge-*`, `DIAG-rf-*`.
- T-265: тести, що пишуть у `keyring`, прибирають за собою через `Drop`-guard (у справжньому
  Credential Manager 7 записів `test:*` і десятки ключів скретч-тек); текст danger-zone і рядок
  `local_state` у CLAUDE.md — 4 секрети, не 3.
- Re-test: лише перегенерація матриці (`qa-matrix-gen.py` + `qa-matrix-check.py`); для T-265 —
  `cmdkey /list` до/після `cargo test`.

## Спершу діагноз (у хвилі не входять)

- **T-257 — Firefox TRR mode 2 обходить фільтр на кожному блокуванні (user safety).** Спостереження
  повне (`I-firefox-mode2-block`), механізм — ні: Firefox відкидає нульову адресу як
  `TRR_DECODE_FAILED`. Експеримент: чи приймає Firefox mode 2 без fallback іншу форму блок-відповіді
  (NXDOMAIN, NODATA, адреса не `0.0.0.0`) — і що це зламає в Chrome (SPEC §3.2 обрав `0.0.0.0` саме
  проти ретраїв). Рішення про форму відповіді — архітектурне, через plan+advisor і DECISIONS.md;
  до того — пом'якшення текстом у T-258.

- **T-261 — Edge з будь-якою політикою блокує Secure DNS.** Діагностовано (`I-edge-secure-dns`,
  2026-10-04): `edge://management` — «керує ваша організація», `edge://policy` — 15 політик
  приватності, `DnsOverHttpsMode` не задано. Не перевірено (зміна політик заборонена), чи знімає
  блок явна `DnsOverHttpsMode`. Результат іде в текст T-260; служба політики за користувача не міняє.

- **T-243 — автозапуск після ребуту. Блокер релізу (від нього залежить T-239).** Стан запису вже
  спостережено: `HKCU\…\AppModel\SystemAppData\<PFN>\DnsqbWatcherStartup` `State=2` (Enabled).
  Діагностовано 2026-10-04: ребут — автозапуск працює (~175 с); на свіжому інсталі ключа немає до
  першого запуску (`G-startup-state` FAIL) — задокументована поведінка Microsoft. Фікс — інструкція
  «запустіть один раз» і/або `ImmediateRegistration` для Store; потрібне рішення користувача.
- **T-266 — GaveUp без шляху ручного відновлення (user safety).** Спостережено наживо (`F-gaveup`):
  tooltip «open the app to restart it» не працює (другий watcher лише показує трей), а
  перезапущений watcher <90 с успадковує `GaveUp` при робочій службі; «Quit» + плитка через >90 с не перевірено. Спершу тест на «запуск плитки
  при GaveUp», потім рішення, що саме скидає бюджет. Ймовірно власна хвиля (watchdog — архітектурне).
- **T-268 — дві різні дії під назвою «Повністю видалити»** (`B-danger-HP`, `A-admin-uninstall-local-state-HP`).
  Потрібне рішення користувача, яку форму обрати (див. TASKS.md).
- **T-262 — систематичні `kind="http"` від Quad9** (`I-quad9-http-errors`) (7–67 на день, інші провайдери ~0). Спершу
  підтип помилки в лозі (без доменів), потім рішення.
- **T-246 (1) — «Access is denied» на `dnsqb-service.exe`/`dnsqb-tray.exe` поза пакетом.** Гіпотеза
  (не оголошені в маніфесті exe не запускаються ззовні) не підтверджена документацією. Знайти
  документ або експеримент → тоді або фікс маніфесту, або обмеження в хвилі 11.
- **T-246 (побічне) — другий екземпляр `dnsqb-service` логує `ERROR … not starting a second one`, але
  виходить з кодом 0.** Не досліджено: чи це задум (ідемпотентний запуск) чи має бути ненульовий код.
- **T-244 — причина `0x80070020`** — крок 0 хвилі 2; якщо експеримент не підтвердить, хвиля 2
  стає цим пунктом.

## Свідомо не плануються

- **LibreWolf — не підтримується (рішення користувача 2026-10-04).** `I-librewolf-cert` FAIL:
  не довіряє сертифікату з Windows Root, що відомо як T-132 (окрема NSS-база Firefox-родини, поза
  MVP). Решта рядків `I-librewolf-*`/`B-*-librewolf` заблоковані тим самим. У T-260 — лише чесне
  «не підтримується» в інструкції.
- **Already-filed у `KNOWN-LIMITATIONS.md`** (рядки `KL-*` з `CODE-ONLY`): `KL-geoip-voters-empty`,
  `KL-fuzz-scope`, `KL-rating-e`, `KL-rating-f`, `KL-maxmind-health-live`, `KL-status-indicator`,
  `KL-t160-geoip-startup`, `KL-enc-log`, `KL-markers-config`, `KL-t169-limits`, `KL-user-country-url`,
  `KL-blocklist-integrity`, `KL-fail-closed-cache`, `KL-baseline-geoip`, `KL-serve-stale`,
  `KL-resolve-precondition`, `KL-sinkhole-hardcoded` — живі обмеження з власними записами.
- **Свідомо без автотестів (CLAUDE.md):** `local_state::remove_all`/`remove_cert` (реальний
  `CurrentUser\Root`), живі маршрути з `FUZZ_EXCLUDED_ROUTES`, I/O-оболонки watchdog у `main.rs`,
  `G-direct-remove-*` (деінсталяція ОС) — у хвилю 12 не входять.
- **`D-icon-ServiceGaveUp*`, `F-gaveup*`, `F-state-GaveUp*`** — 2026-10-04 GaveUp досягнуто
  ненавмисно (6 рестартів через `/admin/shutdown`); колір і стан — PASS, відновлення — FAIL (T-266,
  «Спершу діагноз»). Решта шаблонних рядків — unit-тести `watchdog::budget`/`transition`.
- **T-239** (публікація в Store) — поза проходом, власний kickoff.

## Ще не пройдено (не вхід Фази 4, але має потрапити у фінальний звіт)

- Деструктивний блок, лише руками користувача (класифікатор режиму auto відхилив незворотне
  видалення): `A-admin-uninstall-local-state-*`, `B-danger-*`, `C-REMOVE_ALL_ID-*`, деінсталяція +
  перевстановлення + повтор `smoke-installed.ps1`. Firefox, інші браузери, ребут, «Вийти»,
  `/admin/shutdown` — пройдено.
- `B-hero-HP`, `I-*-SB` (automatic secure DNS при мертвому DoH), шаблонні cert MF/EP та решта
  рядків зі вердиктом `NOT RUN`/порожнім — перелік у фінальному звіті.
