# review/03-ARCH.md — Фаза 3: Архітектура і відповідність місії

> Це review-артефакт, не частина DOC MAP (`CLAUDE.md`). Джерело істини —
> `SPEC.md`/`DECISIONS.md`. Знахідки, що переживають ревʼю, переїжджають
> у `TASKS.md`. Прогони baseline позначено місцем (`gnu-local` / `CI`).
>
> Дата: 2026-09-10. HEAD `0ecab35`.

---

## Скоуп і структура фази

Наскрізна, не помодульна. Один прохід. Розглянуто:
структуру `dispatch.rs` (3253 прод / 8550 всього — межа на рядку 3254),
`AppState`, `resolve_doh_request`; контракти між 3 крейтами (13 каналів
з `00-MAP.md` §4); версіонування форматів (`encrypted_file` header,
`persist_dto::PersistedFileV1`, `watchdog::frame::Frame`,
`watchdog-state.json`); DTO-родину `admin.rs`; `logging.rs`; десктоп-
інтеграцію (MSIX / autostart / uninstall); conformance-сюїту проти
SPEC.md «Крок 0».

Плюс три перенесені питання Фази 1: **1.1-A** (cache stampede /
single-flight), **1.2-A** (клієнтська логіка в DTO чи JS), **1.4-C**
(conformance ↔ «Крок 0»).

---

## 1. Місія модулів — імʼя vs поведінка  ✅

Фази 1.1–1.4 пройшли помодульно; місії крейтів звірено в `00-MAP.md` §2
(збіг зі SPEC.md §0/§1/§3/§7, SERVICES.md). Тут — тільки транспорт-шар:

- **`resolve_doh_request`** (`dispatch.rs:492–619`) — **чистий
  composition root**, не «логіка в транспорті». Знімає снапшот кожного
  зрізу `AppState` (`Arc::clone` під власним lock'ом, **жодного** через
  `.await` — дисципліна R12), збирає context-структури, делегує в
  `pipeline::handle_query`, і робить рівно дві дії свого шару: push у
  `query_log` і `record_zone_removal` (lazy-hygiene) — обидві належать
  саме сюди за доком `pipeline::QueryLogMeta` (пайплайн не володіє
  логом). Уся резолв-логіка — в `pipeline`/`quorum`. Розбіжності
  «імʼя vs робить» немає.
- **`serve` + 18 `serve_admin_*`** — тонкі async-обгортки: parse body →
  виклик sync `apply_*` / `*_view` → format. Коректний поділ.

---

## 2. Зв'язність і зачеплення

### `dispatch.rs` — 3253 прод-LOC в одному файлі

Прод-портія містить: wire-хелпери (~60), 7 стан-структур + `AppState`
impl (~600, з них `AppState` сам ≈500), `resolve_doh_request` (~130),
18 route-хендлерів (тонкі), **8 `apply_*`-функцій** (мутація конфігу +
оркестрація персисту з cross-field read), 6 `*_view` (проєкція DTO),
`admin_status`/`live_stats`/`rating_filter_status_view` (збірка статусу).

**Спостереження (не знахідка):** `apply_admin_config` / `apply_admin_reset`
/ `apply_cache_config` / `apply_geoip_change` / `apply_rating_filter_change`
/ `apply_provider_change` / `apply_overrides_change` — це адмін-**бізнес-
логіка** (валідація → своп → персист), і живе вона в модулі
маршрутизації. Формально — низька когезія (кандидат на `admin_ops.rs`).
Фактично: усі вони нерозривно зчеплені з `AppState` і дисципліною
`persist_lock` (яка тут і має жити), і покриті (Фаза 1 1.2 — «еталон
§8.1», 5 concurrency-тестів). Виніс — **чиста косметика**.
Оцінка для PET-масштабу: **незручно навігувати, не дорого, не
блокує**; тести роблять майбутню екстракцію безпечною.

### `AppState` — god-object за дизайном

≈20 полів: `client`, `runtime` (`RwLock`), `overrides`/`cache`/`geoip`/
`geoip_countries`/`providers`/`baseline` (усі `RwLock<Arc<_>>`),
`rating_filter_*` (3 зрізи + `Notify`), `persist_lock`/
`overrides_persist_lock`/`geoip_source_lock`, `connection_gate`,
`in_flight`, `persist` (paths + read-only поля), `query_log`,
`reachability`/`filtering_paused` (`RwLock<bool>`).

Це **найбільша структурна вага проєкту** — будь-яка нова фіча чіпає
`AppState`. Але для HTTP-сервісу зі спільним станом це властива, не
випадкова складність: кожен зріз має задокументовану причину бути
окремим `RwLock` (див. їхні doc-коментарі), патерн `RwLock<Arc<T>>`
читача дотримано наскрізно (Фаза 2 §6). Не переписувати —
для PET-масштабу прийнятно; якщо колись розростеться — розбивати за
підсистемами (cache-стан, geoip-стан, rating-filter-стан у власні
under-структури), тести це витримають.

---

## 3. Контракти між крейтами — версіонування

**Ключове відкриття фази.** Кожен крос-процесний формат у репо
**явно версійований** — крім одного.

| Контракт | Версіонування | Поведінка при неспівпадінні |
|---|---|---|
| `encrypted_file` (`query-log.enc` / `cache.enc`) | `MAGIC b"DQF1"` + `kind` + `VERSION=1`, **6-байт header — AEAD AAD** | `UnsupportedVersion { found }`, окремо від `Decrypt`; hard cutover на bump. Downgrade заборонений криптографічно. ✅ |
| `persist_dto::PersistedFileV1` | struct-обгортка (additive) + `#[serde(default)]` на полях; «`V1` суфікс = *внутрішня* JSON-форма, container версіонує header `encrypted_file`» | новіша схема → additive-сумісна; несумісна → hard bump `V2`. ✅ |
| `watchdog::frame::Frame` (named pipe) | `FRAME_VERSION=1` байт; `FrameError::BadVersion` | parse fail → канал читається як **`NoSignal`** (тихо, не гучна помилка). 2-of-3 vote захищає від хибного респавну від одного темного каналу; **bump `FRAME_VERSION` мусить бути зміною в тому ж релізі для обох бінарників** — інакше один heartbeat-канал мовчки згасає. Задокументовано (`00-MAP.md` §4 рядок 1). ⚠️ але керовано |
| `watchdog-state.json` | `STATE_SCHEMA_VERSION=1`, `schema_version` штампується в кожен запис; `WATCHDOG_STATE_STALE_AFTER=15s` | watcher — єдиний писар (§7.1 #7); читачі (tray, `/admin/status`) на absent/stale/unparseable → `None` («watchdog не працює»), ніколи не фабрикований healthy. Schema-bump старий читач бачить як parse-fail → `None`. ✅ safe-by-default |
| **`AdminStatusResponse` + DTO-родина `admin.rs` (канал #8)** | **немає `schema_version`, немає `#[serde(default)]` на полях**, звичайний `#[derive(Deserialize)]` | **новий tray + старий service** → `serde_json` падає «missing field `rating_filter`». Старий tray + новий service → зайві поля ігноруються (ОК). → **Знахідка 3-A** |

---

## 4. Стан — власники, рестарт/краш  ✅

- **Single-writer наскрізно**: `watchdog-state.json` — лише watcher
  (§7.1 #7); `reachability` / `filtering_paused` / `baseline` — по
  одному писарю-таску кожен, публікують `Copy`/`Arc` в `AppState`;
  `rating_filter_zone` пише лише `run_topn_updater`,
  `rating_filter_removed` — лише `record_zone_removal`.
- **Рестарт/краш — задокументовано per-store**: budget у напрямку
  service→watcher **не durable** (§7.1 #7, скидається на кожен рестарт
  сервісу — вже зафіксовано); `fail_closed` timeout-`Block` у памʼяті
  переживає outage (вже зафіксовано); `cache.enc` персистить лише
  `Verdict::Allow`; `watchdog-state.json` `resume` <90с.
- `apply_admin_reset` — єдиний холдер >1 lock, порядок
  `geoip_source_lock → persist_lock → overrides_persist_lock`
  (Фаза 2 §6). Deadlock-цикл структурно неможливий.

---

## 5. Конфіг і секрети  ✅

- `resolver_config.toml` — per-field валідація, гучні помилки, `0`/
  надвеликі → fatal load error (`config.rs`, Фаза 1 1.2 «рівень
  еталона»). `overrides.toml` — payload-free parse-error (приватність).
- **Hard-cutover без dual-format shim** — зафіксований патерн (T-144/
  T-145/T-148): старий ключ/файл стає гучною parse-помилкою, лише
  legacy-sibling *presence* попереджає. Свідомо. Стосується `config` і
  `encrypted_file` (`UnsupportedVersion`).
- OS secret store — 3 записи (TLS-ключ, MaxMind-креди, `persistence-key`),
  імена деривуються з sha1(app-data dir)[..8] → scratch-інстанс не
  колідить. Інваріант «created exactly once» тримається на
  `instance::acquire`. `persistence-key` не видаляється на uninstall —
  вже зафіксовано (фолдиться в T-70).

---

## 6. Спостережуваність — `logging.rs`

Оцінка: **достатньо для PET-масштабу**, з двома застереженнями (не
знахідки, спостереження):

1. **Ротація — лише на старті.** `prepare_log_file` ротує `<role>.log`
   → `.log.old` тільки коли `init()` бачить розмір > 5 MiB **на старті
   процесу**. Watcher, що працює місяцями без рестарту, пише необмежений
   `.log` весь цей час. Практично обмежено рідкістю подій (heartbeat-
   цикл логує лише зміни стану / помилки, не кожен 5-с тік), не
   ротацією. Імʼя `MAX_LOG_BYTES` натякає на постійну межу, якої нема.
2. **Немає регульованої в полі детальності.** Фіксований INFO, без
   `env-filter`, релізний білд не має DEBUG/TRACE. Це **свідомий Три Б
   тредоф**: підняти детальність = ризик залогувати домен (уся
   приватнісна вимога). Діагностика per-query рішень — через `/admin/log`
   (in-memory, несе домени, лише оператор); `logs/<role>.log` —
   lifecycle/помилки. Поділ розумний.

Приватність файлу перевірена в Фазі 2 (модуль-док T-184 re-verify «no
domain names reach `tracing`»).

---

## 7. Десктопна інтеграція  ✅ (з lower-layer крихкістю)

MSIX не має uninstall-хука → in-app `local_state::remove_all` +
детачнутий `self_uninstall.rs` wipe; autostart через
`windows.startupTask` = `dnsqb-watcher.exe` (ідемпотентний лаунчер);
trust у `CurrentUser\Root` + `TrustedPeople` для MSIX-підпису.

Архітектурно **звучно**, але **навантажене на емпірично підтверджену
недокументовану поведінку** `Add-AppxPackage` (яка store перевіряє
підпис, CryptoAPI-ключ vs CNG, `0x800B010A`) — портовано з sister-
проєкту pakko. Це `lower-layer safety`: OS недовірена, інтеграція
покладається на поведінку, що може змінитись між версіями Windows.
Кожна окрема гоча задокументована в CLAUDE.md — **вже зафіксовано** як
клас; standing fragility, не нова знахідка.

---

## 8. Перенесені питання Фази 1

### 1.1-A — cache stampede / single-flight  →  **прийнятно для PET**

`moka` не робить single-flight; N одночасних промахів на один
`CacheKey` = N quorum-fan-out'ів. `moka` *має* `get_with`/`try_get_with`
(один обчислювач на ключ).

**Аналіз масштабу:** один локальний резолвер, 1 машина. Справді
однакові одночасні промахи (той самий домен + qtype у вікні fan-out
≈200мс): A+AAAA+HTTPS від браузера — це *різні* ключі (різний qtype),
не stampede. Реальний stampede — кілька браузерів / багато вкладок, що
прокидаються разом (resume ноутбука): N ≈ 2–5, транзиторно, на кілька
сотень мс. Приватнісна ціна: апстріми бачать запит 5× замість 1× у
межах секунди — не матеріально більше розкриття (вони й так бачать
його раз). Навантажувальна ціна: 5×(3–10) зайвих HTTP/2-запитів, один
раз, на resume. Незначна.

**Рекомендація:**
1. Додати характеризаційний тест (1.1-A Варіант 1 — `two_concurrent_
   misses_for_the_same_key_each_run_quorum`, `assert_eq!(client.calls(),
   2 * voters)`), щоб майбутній рефактор не зламав припущення тихо.
2. Один рядок у `PERFORMANCE.md` / SPEC.md §4: «свідомо без single-
   flight — на масштабі однієї машини множення несуттєве».
3. **НЕ** додавати `moka::get_with` зараз — новий coalesced-шлях у
   гарячому коді, cancellation-safety обчислювача треба доводити, заради
   вигоди, якої на цьому масштабі немає.
4. Переоткрити лише якщо зʼявиться multi-user сценарій.

Категорія: архітектурний борг, `nit`. → **Знахідка 3-C**.

### 1.2-A — клієнтська вирішальна логіка (`main.js`) у DTO чи JS  →  **реальний борг, є патерн**

hero-state (який із N станів показати), master-switch guard (чи можна
ввімкнути тумблер), стан-машина картки rating-filter — обчислюються
в `main.js`, тестуються лише `assert!(MAIN_JS.contains("…"))`.

**Проєкт уже має патерн для фіксу — двічі:**
- `rating_filter_is_active` (`dispatch.rs:1208`) обчислюється **на
  сервері**, віддається як `RatingFilterStatusView.active`, *саме щоб*
  «badge не міг розійтися з пайплайном» (`admin.rs:158–165`).
- `dnsqb-tray/status.rs` виокремлює чисті функції (`icon_colour`,
  `from_response`, `compose_tooltip`) — 20 поведінкових тестів.

**Рекомендація:** для справді *вирішальної* логіки (hero-state,
master-switch guard) — обчислювати на сервері в `admin.rs` як поля DTO
(`hero_state: HeroStateView`, `master_switch_allowed: bool`), дзеркалячи
`rating_filter_is_active`. `main.js` → чистий рендер. Чиста презентація
(форматування чисел, спінер) лишається в JS. Це **рефактор за наявним
патерном репо**, не нова архітектура. Зусилля ≈1–2 дні. Вигода: керівна
поверхня стає Rust-тестовною.

Категорія: архітектурний борг, **`major`** (Фаза 1 1.2-A так і
класифікувала — цей звіт лишає severity незмінним; downgrade не
обґрунтований). → **Знахідка 3-B**. Вищий важіль із двох перенесених
питань.

### 1.4-C — conformance ↔ SPEC.md «Крок 0»  →  **не прогалина**

«Крок 0» (SPEC.md:1755) — таблиця з **10 рядків RFC**. Conformance-
сюїта — **10 файлів, 1:1** з рядками:
`rfc_{1035,2181,2308,4033_4035,5891,6891,7871,8484,8767,9460}.rs`,
22 активні `#[test]` + `#[ignore]` (rfc_7871: 2 активні + 3 ignored —
ECS свідомо не-ціль, ignored-тести це документують). Тонкі файли
(`rfc_1035` — 1 тест) відповідають рядкам, явно делегованим
`hickory-dns` («фундамент, на якому стоїть `hickory-dns`» — сам текст
рядка) або non-target. Літера мандату («тест, що перевіряє
відповідність цій вимозі») виконана.

Єдиний реальний залишок: `rfc_8767` (stale-if-error) — 3 тести на
**предикат** `should_serve_stale`, не на вбудований у пайплайн шлях
(предикат не спожитий) — **вже зафіксовано** (CLAUDE.md «Known
limitations», `lib.rs` коментар).

`nit` знято; фіксую як звірено.

---

## ЗНАХІДКИ

```
[3-A] severity: minor
Файл: admin.rs:73 (`AdminStatusResponse`) + DTO-родина каналу #8
Категорія: архітектурний борг
Джерело: ПІДТВЕРДЖЕНО В КОДІ (grep admin.rs — 0 `schema_version`, 0
`#[serde(default)]` на полях status-DTO; порівняння з encrypted_file
VERSION / PersistedFileV1 / FRAME_VERSION / STATE_SCHEMA_VERSION)
Три Б: —
Що: адмін-DTO (`AdminStatusResponse` + вкладені `*View`) — єдиний
крос-процесний контракт у репо БЕЗ явного версіонування. Кожен інший
(`encrypted_file` header, `persist_dto::PersistedFileV1`,
`watchdog::frame::FRAME_VERSION`, `watchdog-state.json`
`STATE_SCHEMA_VERSION`) має або версійний байт/поле, або `#[serde(
default)]`-additive-дисципліну. Status-DTO — ні.
Чому важливо: новий `dnsqb-tray` проти старого `dnsqb-service` →
`serde_json::from_slice` падає «missing field» (напр. `rating_filter`,
додане в Батч 4.4). Старий tray + новий service — ОК (зайві поля
ігноруються). Вплив на практиці **низький**: MSIX пакує всі 3
бінарники разом, `pack-msix.ps1` кросс-звіряє версії (`throw` на
розбіжності), path-deps + `Cargo.lock` тримають `AdminClient` і
service на одній версії. Розбіжність можлива лише при dev-запуску
mismatched бінарників або транзиторно під час in-place MSIX-апдейту,
поки старі процеси ще живі.
Це **невідповідність власній дисципліні проєкту**, не активний баг.
Вже зафіксовано в: `00-MAP.md` §4 рядок 8 назвав це «зоною ризику
Фази 3»; більш ніде.
Варіанти:
  1. `#[serde(default)]` на всіх нових/additive полях status-DTO +
     `schema_version: u32` поле, `AdminClient` логує warning на
     розбіжність, але парсить. Дешево (derive-атрибути), робить
     new-tray-old-service graceful. Тредоф: `default` маскує справжній
     missing-field баг у тестах — пом'якшується `deny_unknown_fields`
     на *request*-DTO (не на response).
  2. Нічого не робити — покладатися на MSIX-атомарність + pack-time
     version-check. Тредоф: dev-mismatch і апдейт-вікно лишаються
     крихкими; невідповідність нормі репо лишається.
  3. Явний `GET /admin/version` + tray перевіряє сумісність до першого
     status-запиту. Дорожче, зайве для PET.
Рекомендація: Варіант 1, як `TASKS.md`-рядок (низький пріоритет).
Робить контракт консистентним із рештою репо за ~derive-атрибути.
Ревʼю коду не пише.
Тест, який би це зловив: `admin_status_response_deserializes_when_a_
future_field_is_absent` (десеріалізація JSON без `rating_filter` →
`Ok`, не `Err`).
```

```
[3-B] severity: major   (= 1.2-A з Фази 1; тут переформульовано як арх-рішення, severity незмінна)
Файл: admin_ui.rs (`MAIN_JS` `include_str!`) + ui/main.js
Категорія: архітектурний борг
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: user
Що: вирішальна логіка керівної поверхні — обчислення hero-state,
guard master-switch, стан-машина картки rating-filter — живе в
`main.js` і верифікується лише `assert!(MAIN_JS.contains("…"))` (22
тести `admin_ui`). Жоден рядок цієї логіки не виконується в тест-сюїті
(немає headless-раннера, немає шва). Форма «тест проходить, не доводячи
властивість» (T-59), масштабована на кількасот рядків JS, на поверхні,
що вмикає/вимикає фільтрацію.
Чому важливо: логічний баг у `main.js` (hero «захищено» під час паузи;
master-switch вмикає категорію без воутера) їде мовчки — єдиний гейт
ручний огляд мокапу.
Вже зафіксовано в: review 1.2-A (як тест-знахідка); тут — як
архітектурне рішення.
Варіанти:
  1. Перенести вирішальну логіку на сервер: `admin.rs` обчислює
     `hero_state: HeroStateView` / `master_switch_allowed: bool` як
     поля DTO, дзеркалячи наявний `rating_filter_is_active` («єдина
     влада, badge і пайплайн не розходяться»). `main.js` → чистий
     рендер. Зусилля ≈1–2 дні. Тредоф: DTO +2–3 поля, рендер
     переписати; чиста презентація лишається в JS.
  2. Виокремити чисті JS-функції + `node --test` без jsdom. Тредоф:
     додає JS-тулчейн, якого проєкт свідомо уникає («no bundler»).
  3. Не чіпати — прийняти ручний огляд мокапу як гейт, задокументувати
     непокриття.
Рекомендація: Варіант 1. Це **рефактор за патерном, який у репо вже
двічі застосовано** (`rating_filter_is_active` на сервері; `status.rs`
виокремлення чистих функцій), не нова архітектура. Найвищий важіль із
перенесених питань. → `TASKS.md`-рядок, середній пріоритет.
Тест, який би це зловив (за В.1): `#[test] fn hero_state_is_paused_
when_filtering_paused_even_if_providers_active` над чистою
`compute_hero_state(&AdminStatusResponse)` в `admin.rs`.
```

```
[3-C] severity: nit   (перенесено з 1.1-A, вирішено як арх-питання)
Файл: pipeline.rs (`handle_query`) + cache.rs (`moka` без single-flight)
Категорія: архітектурний борг
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: —
Що: N одночасних cache-miss на той самий ключ = N повних quorum-fan-
out'ів. Ніде не задокументовано як свідомий тредоф, ніде не перевірено.
Чому важливо: на масштабі однієї машини N ≈ 2–5, транзиторно, без
матеріальної приватнісної чи навантажувальної ціни (аналіз — §8 вище).
**Прийнятно для PET-масштабу.**
Вже зафіксовано в: частково — PERFORMANCE.md «Fan-out ceiling» (про
відсутність стелі на конкурентні резолви, не про дедуплікацію
однакових in-flight).
Варіанти:
  1. Характеризаційний тест поточної поведінки + рядок у PERFORMANCE.md
     / SPEC.md §4 «свідомо без single-flight». Дешево, чесно, нічого не
     змінює.
  2. `moka::get_with` single-flight. Прибирає множення. Тредоф: новий
     coalesced-шлях у гарячому коді, cancellation-safety обчислювача
     треба доводити — заради вигоди, якої на цьому масштабі немає.
  3. Не чіпати. Тредоф: множинність лишається неперевіреною, наступний
     рефактор `handle_query` може її зламати непомітно.
Рекомендація: Варіант 1. НЕ Варіант 2 зараз. Переоткрити лише для
multi-user. → `TASKS.md`-рядок (тест + доку), низький пріоритет.
Тест, який би це зловив: `two_concurrent_misses_for_the_same_key_each_
run_quorum` (спільний `AppState`, `MockClient` з `AtomicU32`,
`tokio::join!`, `assert_eq!(client.calls(), 2 * voters)`).
```

```
[3-D] severity: nit
Файл: logging.rs:22–24 (`MAX_LOG_BYTES` / `prepare_log_file`)
Категорія: спостережуваність
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: —
Що: ротація логу відбувається **лише на старті процесу**
(`prepare_log_file` викликається з `init()`), не під час роботи. Імʼя
`MAX_LOG_BYTES` і doc «bound a long-running watcher» натякають на
постійну межу, якої немає — довготривалий watcher пише необмежений
`<role>.log` до наступного рестарту.
Чому важливо: мінімально — heartbeat-цикл логує лише зміни стану /
помилки (рідко), тож зростання практично обмежене рідкістю подій, не
ротацією. Але поведінка сюрпризить проти назви.
Вже зафіксовано в: —
Варіанти: (1) уточнити doc-коментар — «rotated once per process start,
not continuously»; (2) додати перевірку розміру раз на N хвилин у
кожному loop-tick (складніше, «runtime machinery», якої модуль
свідомо уникає). Один розумний — (1).
Рекомендація: doc-фікс у Фазі 5.
Тест, який би це зловив: N/A (документаційна точність).
```

---

## Вже зафіксовано (Правило 0 — рядком)

- `Frame` version bump = тихе згасання каналу (`NoSignal`), не гучна
  помилка → мусить бути зміною в тому ж релізі для обох бінарників —
  `00-MAP.md` §4 рядок 1; керовано (coordinated-release only).
- budget у напрямку service→watcher не durable (скидається на рестарт
  сервісу) — CLAUDE.md / SPEC.md §7.1 #7.
- `dnsqb-tray` = UI-клієнт + актуатор, не «сервіс» — `00-MAP.md` §2
  (SPEC.md §0 / SERVICES.md уже кваліфікують правильно).
- MSIX trust-store / `self_uninstall` покладаються на емпірично
  підтверджену недокументовану поведінку `Add-AppxPackage` — CLAUDE.md
  gotchas (портовано з pakko); standing lower-layer fragility.
- hard-cutover без dual-format shim (`config`, `encrypted_file`) —
  CLAUDE.md recurring pattern; свідомо.
- `should_serve_stale` — неспожитий предикат, RFC 8767 не вбудований у
  пайплайн — CLAUDE.md «Known limitations» + `lib.rs` коментар.
- `fail_closed` timeout-`Block` у памʼяті переживає outage — CLAUDE.md.

---

## Позитив (Правило 5 — по одному реченню)

- **Кожен персистентний / IPC-формат версійований** (`encrypted_file`
  AAD-bound header, `PersistedFileV1` additive + container-версія,
  `FRAME_VERSION`, `STATE_SCHEMA_VERSION`) — консистентна дисципліна;
  адмін-DTO — єдиний виняток (3-A).
- **`resolve_doh_request` — чистий composition root**: снапшот кожного
  зрізу `AppState` під власним lock'ом, жодного через `.await`, уся
  резолв-логіка делегована в `pipeline`/`quorum` — на гарячому шляху
  бізнес-логіки в транспорті немає.
- **Власність стану — single-writer наскрізно**, семантика рестарту/
  крашу задокументована per-store; `apply_admin_reset` — єдиний
  мульти-lock холдер із фіксованим порядком.
- **Патерн «єдина влада»** (`rating_filter_is_active` — один предикат
  і для пайплайн-гейта, і для status-view) — готова модель, за якою
  має піти 3-B.

---

## Стан Фази 3: **ЗАВЕРШЕНА**

**Blocker — немає.** Архітектура **когерентна** і відповідає SPEC.md /
місіям крейтів. Основний борг:
- **3-B `major`** — вирішальна логіка UI поза тестовною поверхнею
  (керівна поверхня, логіка не виконується ніде в сюїті, рекурентний
  урок T-59); рефактор за наявним патерном, ~1–2 дні — **найвищий
  важіль**;
- **3-A `minor`** — адмін-DTO не версійований проти власної норми репо
  (низький вплив на MSIX-масштабі, ~derive-атрибути щоб виправити).

`dispatch.rs` розмір / `AppState` god-object — **прийнятно для PET-
масштабу**, тести де-ризикують майбутню екстракцію. 1.4-C звірено (не
прогалина). 1.1-A вирішено (single-flight не потрібен). `logging`
достатній.

Per протокол: `advisor()` між фазами — лише на `blocker`. Не піднято →
без виклику.
