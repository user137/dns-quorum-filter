# UI-SPEC — специфікація графічного інтерфейсу

**Що цей файл власне описує** (per таблицю "Документація map" у CLAUDE.md):
екранний inventory, таблиці полів/типів по кожному екрану, чернетка allowlist
Tauri-команд, посилання на мокап. **Дизайн-рішення й обґрунтування "чому саме
так" лишаються в SPEC.md** — цей файл їх не переказує, лише цитує номер
розділу. Якщо факт звідси розходиться з SPEC.md — SPEC.md головний (як і для
решти проєкту).

Мокап: [`mockups/gui-dashboard.html`](mockups/gui-dashboard.html) (локальний
файл — відкривається будь-яким браузером, без збірки).
Діаграми: [`diagrams/ui-navigation.md`](diagrams/ui-navigation.md),
[`diagrams/ui-dto-model.md`](diagrams/ui-dto-model.md),
[`diagrams/ui-status-indicator.md`](diagrams/ui-status-indicator.md).

---

## 1. Принцип фазування полів (важливо — читати перед рештою файлу)

**"Закладено з початку" (вимога користувача) означає: DTO й колонки логу
несуть ВСІ поля з дня нуль, навіть ті, що не можуть спрацювати до пізньої
фази.** Не додавати колонку/поле пізніше — тільки активувати його заповнення.
Конкретно:

- `LogEntry.geoip_country` — поле існує в Ф1 (nullable), завжди `null` до Ф2 (3.5).
- `LogEntry.decision_source` — enum уже включає `CCTLD_BLOCK` (Ф5) і `RATING_FILTER`
  (Ф4), хоча ці значення фізично не можуть з'явитися до відповідної фази.
- Аналогічно: `CctldBlockConfig`, `RatingFilterConfig`, `GeoIPConfig` — типи
  визначені зараз (розділ 4 нижче), відповідні маршрути й екранні поля — лише в
  тій фазі, де вони активуються (розділ 5).

**Прибрано T-179 (2026-09-07):** `LogEntry.voter_scope` / `VoterScopeView` /
`TopSiteExemptionConfig` — §5.1 (виключення топ-сайтів з Ads/Adult-voters)
знято, механізм злито в рейтинговий фільтр §5.3 (DECISIONS.md 2026-09-07);
нічого не звужує voter-набір, поле мертве.

Це узгоджено з T-43 у TASKS.md, який уже явно фіксує цей принцип для
структури логу.

---

## 2. Інвентар екранів

| Екран | Фаза | Пріоритет видимості | Що містить (короткий список — деталі в §3) |
|---|---|---|---|
| Dashboard / Статус | Ф1 | **Найвищий** — головний екран при запуску | категорійні тумблери, швидка статистика, прев'ю логу |
| Лог запитів | Ф1 | **Найвищий** — "основний UX-цикл продукту" (SPEC.md §6) | таблиця, пошук/фасети, дія allow/block в один клік |
| Списки виключень | Ф1 | Високий | редактор allow/blocklist, підсвітка конфліктів |
| Провайдери | Ф1 база / Ф2 розширення | Середній | таймаут-режим, presets, custom DoH URL (Ф2) |
| GeoIP | Ф2 | Низький | список країн, дата оновлення бази |
| Розширені | Ф4/Ф5 | Найнижчий — нішеве | рейтинговий фільтр «бульбашка» + зони (Ф4), ccTLD-блок (Ф5) |
| Про застосунок | Ф1 база / Ф2 доповнення | Низький, але юридично обов'язковий вміст | ліцензія, атрибуція DB-IP Lite |

Обґрунтування порядку — SPEC.md §6 прямо називає allow/block-з-логу основним
циклом продукту; §8 вимагає індикатор стану обов'язковим і не захованим;
§5.3 сама характеризує рейтинговий фільтр як нішевий. Порядок вкладок як
такий — інтерпретація, позначена як ⚠️ GAP у `diagrams/ui-navigation.md`.

### 2.1 Розкладка `/admin/ui` — basic / advanced (T-176)

Реальний `/admin/ui` — одна сторінка (T-149), не вкладки. **Після T-176** вона
поділена на два рівні (макет: `mockups/gui-dashboard.html`, затверджено
2026-09-06):

- **Базовий вигляд** (завжди видимий) — hero-статус «захищено / не захищено»,
  головний перемикач фільтрації, три категорійні перемикачі (шкідливе / реклама /
  дорослий вміст), рядок «N сторін бачать запити», попередження pass-through,
  компактна статистика, прев'ю логу, секція «Підключення браузера».
- **`<details>` «Розширені налаштування»** (згорнуто за замовчуванням, нативний
  елемент — без JS-стану, сумісний зі строгим CSP) — перелік провайдерів
  поштучно, режим таймауту, GeoIP + MaxMind, TTL кешу, персистентність,
  «Повне видалення». Це наявні картки (`#providers-body`, `#cache-config-body`,
  `#geoip-body`, `#geoip-maxmind-body`, `#danger-zone-body`) — ID збережено, їх
  просто загорнуто в розкриття.

Кожен рядок §3 нижче позначено **[basic]** / **[advanced]** де це стосується
`/admin/ui`. Футер `#credits` (T-81) — поза обома рівнями, на кожному рендері.

---

## 3. Поля по екрану

### 3.1 Dashboard / Статус (Ф1)

| Поле | Тип | Джерело (SPEC.md) | Контрол UI | Що приймає / валідація |
|---|---|---|---|---|
| **[basic]** Hero-статус захисту (T-176; T-188; **T-204**) | **`AdminStatusResponse.hero_state: HeroStateView`** (8 варіантів) — обчислюється **на сервері** `admin::compute_hero_state`, знахідка 3-B | §8, §3.3, §7, ВП№10; T-95/T-152/T-56 | єдиний великий блок угорі базового вигляду: колір (good/bad/warn) + слово («Захищено» / «Не захищено» / «Відновлення…» / «Немає інтернету» / «Служба зупинилась» / **«Сертифікат не встановлено»** [+ кнопка «Встановити сертифікат» → `POST /admin/install-cert`] / **«Сертифікат не перевірено»**) + один рядок пояснення | **T-204:** `main.js` лише мапить `hero_state` на презентацію (`HERO_PRESENTATION`); сходи пріоритету (watchdog > offline > paused > 0-voters > cert) — на сервері, Rust-тестовані (`admin::hero_and_category_tests`), не `MAIN_JS.contains`. `SERVICE_UNREACHABLE` синтезується клієнтом на невдалому fetch (єдиний стан, який сервер не бачить про себе). Cert-довіра — з кешу `AppState.cert_trust` (T-211, фоновий poll), `None` «ще не перевіряли» → `PROTECTED`. **Межа влади:** `hero_state` — тільки для hero; трей тримає власний ранкінг (`status.rs`, DECISIONS.md 2026-09-07/08) |
| **[basic]** Головний перемикач «Фільтрація» (T-176; **T-204**) | **`ProvidersResponse.master_switch_targets: Vec<Category>`** — категорії з ≥1 сконфіг. воутером, обчислює `admin::master_switch_targets` | §3, §8.1 | switch угорі картки контролів | **T-204:** `main.js` ітерує `master_switch_targets` (не re-derive) — guard проти opt-in дорослого без воутера (T-170) тепер на сервері, Rust-тестований; `POST /admin/providers/set-category-enabled` послідовно по кожній цілі (не `/admin/shutdown`); OFF = `filtering_active=false` pass-through |
| **[basic]** Категорійні перемикачі: шкідливе / реклама / дорослий вміст (T-176; **T-204**) | **`ProvidersResponse.category_states: Vec<CategoryFilterView>`** (`{category, state: OFF/PARTIAL/ON}`) — fold `admin::category_filter_views` | §3.4, T-176 | три switch'і з людськими підписами + рядок «що це» | `POST /admin/providers/set-category-enabled {category, enabled}` — атомарно; порожня `ADULT_CONTENT` при ON додає `opendns-familyshield` (DECISIONS.md 2026-09-06); стан `PARTIAL` → клік вмикає всіх. **T-204:** fold `on/off/partial` більше не в `main.js` (`categoryState()` прибрано) |
| **[basic]** Рядок «N сторін бачать запити» (T-176) | `ProvidersResponse.third_party_count` | §3.4, CLAUDE.md «не ховати» | текст у базовому вигляді, під перемикачами — **не** в розкритті | лише читання; увімкнені voter'и + baseline |
| **[basic]** Попередження pass-through (T-176) | `ProvidersResponse.filtering_active == false` | §3, §8.1 | `notice warn` у базовому вигляді, умовний | показується, коли жоден voter не активний — саме тоді, коли користувач найменш схильний відкрити «Розширені» |
| Індикатор стану | `StatusIndicatorState` (§4.6) | §8, §3.3, §7, ВП№10 | ⚠️ T-176: піднятий у hero-статус (рядок вище); окремого header-індикатора немає — hero і є ним | обчислюваний, не редагується користувачем |
| Мережевий стан | `NetworkStatusView` (`ONLINE`/`OFFLINE`) в `AdminStatusResponse.network` | §3.7, T-152 | внесок в індикатор — умова #3 (між watchdog і "0 voters", DECISIONS.md 2026-09-03) | обчислюваний; `OFFLINE` публікується лише після 3 поспіль невдалих проб-циклів |
| Активний baseline-endpoint | `BaselineEndpointView` (`PRIMARY`/`SECONDARY`/`TERTIARY`) в `AdminStatusResponse.baseline_endpoint` | §3.7, T-154 | діагностичний, лише читання | обчислюваний із `BaselineSelector.active_index` |
| **[basic]** Бейдж рейтингового фільтра (T-128) | `AdminStatusResponse.rating_filter` (`RatingFilterStatusView`) | §5.3, T-128 | ⚠️ реалізовано Батч 4.4 — окремий `<div id="rating-filter-badge">` одразу під hero, наповнюється `renderRatingFilterBadge` на 2-с status-поллі (не застаріває) | лише читання; **порожній `<div>`, коли `enabled = false`** (типовий випадок, без розкладки); `enabled && active` → «активний» (ok), `enabled && !active` (Fork B) → «увімкнено — списки завантажуються» (warn) |
| Тумблери провайдерів + попередження про порожній набір voters | — | §3.4 | — | ⚠️ T-72/T-73: перенесено на картку `#providers-body` (§3.4) — на Dashboard їх більше немає; `filtering_active` там замінив цей банер |
| Статистика заблокованого (сьогодні) | `u32` | §8 "статистика заблокованого" | лічильник | обчислюваний з логу — ⚠️ T-139: реалізовано інакше за цей чернетковий рядок — `/admin/ui`'s dashboard показує `blocked`/`total`/`in_flight` (вже `AdminStats`, T-52/T-149) плюс частку у відсотках, обчислену клієнтським JS з тих самих полів (не окремий backend-лічильник, і не "сьогодні" — те саме live log-вікно, що й решта статистики) |
| Стан backstop одночасності | `AdminStats.rejected_connections: u64` (кумулятивно відхилених на стелі) + `AdminStats.active_connections: u64` (утримуються просто зараз) | §1.1, T-169 | лічильники | обчислювані — `admission::ConnectionGate` проти `[limits].max_concurrent_connections`. Live, не з логу (відхилене з'єднання не створює `LogEntry`; `active` — миттєвий знімок). DTO-поля готові; окрема UI-картка — Backend-before-UI, ще не реалізована. `rejected_connections = 0` після аптайму = backstop жодного разу не спрацював (здоровий стан) |
| **[basic]** Прев'ю останніх N записів логу | `Vec<LogEntry>` (§4.1) | §6 | компактна таблиця, 5-10 рядків, у базовому вигляді | посилання "показати весь журнал" розкриває повний лог (`#log-body`) |
| **[basic]** Секція «Підключення браузера» (T-176; T-189) | статичний текст + `AdminStatusResponse.port` | README §"Швидкий старт" / §"Перевірка" | завжди доступна картка вгорі: copy-paste `https://127.0.0.1:<port>/dns-query` + згорнуті покрокові інструкції; **T-189:** блоки кроків per-браузер (Chromium — Chrome/Edge/Brave/Opera з відповідним `chrome://`/`edge://`/`brave://` рядком і кнопкою «Копіювати»; Firefox — `about:preferences#privacy`; «інший») усі в статичному HTML, `main.js` лише розкриває один за `navigator.userAgent` (+`navigator.brave.isBrave()`); при першому візиті авто-розгорнута (`localStorage` на admin-origin, без бекенд-сигналу); крок перевірки називає `ERR_ADDRESS_INVALID` (те, що T-172 робив вручну) | лише читання + кнопки «Копіювати» |
| Посилання "Приватність кворуму" | — | §8, ВП№4 | текстове посилання/іконка інфо, **не дрібним шрифтом** | відкриває пояснення тексту з ВП№4 |

### 3.2 Лог запитів (Ф1)

| Поле | Тип | Джерело | Контрол UI | Що приймає / валідація |
|---|---|---|---|---|
| Пошук по domain | `String` | §6 | текстове поле | підрядковий, регістронезалежний фільтр |
| Фасет: заблоковані / дозволені / не вдалося | `enum{ALL,ALLOWED,BLOCKED,FAILED}` | §6 | сегментований перемикач | одне з чотирьох — **реалізовано T-54** (`GET /admin/log?decision=`, `admin::DecisionView`); T-147's третє значення `FAILED` тепер має власний варіант замість застарілого 3-значного чернеткового enum'а |
| Фасет: за voter'ом | `String?` | §6 | випадаючий список | назва провайдера з поточного `ProviderConfig` списку |
| Рядок логу — `timestamp` | `DateTime` | §6 | колонка таблиці | лише читання |
| Рядок логу — `domain` | `String` | §6 | колонка таблиці | лише читання, нормалізований вигляд |
| Рядок логу — `qtype` | `QType` | §6 | колонка таблиці (бейдж) | лише читання |
| Рядок логу — `decision` | `ALLOWED/BLOCKED/FAILED` | §6 | колонка, кольоровий бейдж | лише читання; `FAILED` додано T-147 |
| Рядок логу — `decision_source` | enum, 7 значень (§4.3) | §6 | колонка, іконка/бейдж | лише читання; значення поза Ф1 (`CCTLD_BLOCK`,`RATING_FILTER`) не з'являються фактично до своєї фази |
| Рядок логу — `voters` | `Vec<VoterResult>` (§4.2) | §6 | розгортна деталізація по кліку | лише читання, ключове поле юзабіліті |
| Рядок логу — `geoip_country` | `String?` (ISO-код) | §6, §3.5 | колонка, з'являється лише коли `decision_source=GEOIP` | лише читання; DTO-поле готове, UI-колонка ще не реалізована (T-79, названо, не виправлено при T-161) |
| Рядок логу — `resolved_ip_country` | `String?` (ISO-код) | §6 | колонка-бейдж, поруч із `qtype`; **не показується** на рядках `decision_source=GEOIP` (щоб не читатись як причина блоку — там значуще поле `geoip_country`, а не це) | лише читання — **реалізовано T-161**, суто інформаційне, заповнюється незалежно від `decision_source`/`GeoIP`-налаштувань |
| Рядок логу — `latency_ms` | `u32` | §6 | колонка | лише читання |
| Дія "в allowlist" | команда | §6 | кнопка в рядку | приймає `domain` з рядка; конфлікт з існуючим blocklist-записом → попередження (§5) |
| Дія "в blocklist" | команда | §6 | кнопка в рядку | те саме, симетрично |
| Кнопка "очистити лог" | команда | §6 | кнопка, підтвердження не описане в SPEC.md — ⚠️ додано тут як звичайна UX-практика для деструктивної дії, не з джерела | — |

### 3.3 Списки виключень (Ф1)

| Поле | Тип | Джерело | Контрол UI | Що приймає / валідація |
|---|---|---|---|---|
| Allowlist — список записів | `Vec<OverrideEntry>` (§4.4) | §5 | редагований список/таблиця | домен або `*.domain` (суфіксний wildcard, не regex, §5) |
| Blocklist — список записів | `Vec<OverrideEntry>` (§4.4) | §5 | редагований список/таблиця | те саме |
| Поле додавання домену | `String` | §5 | текстове поле + кнопка | нормалізація перед збереженням: lowercase, IDNA2008→punycode, обрізана кінцева крапка (§5) |
| Підсвітка конфлікту | — | §5, §8 | візуальний маркер на записі, присутньому в обох списках | allowlist виграє за пріоритетом (§5) — текст пояснення поруч |

### 3.4 Провайдери (Ф1 база / Ф2 розширення)

**T-72/T-73 реалізували провайдер-частину** як окрему картку `#providers-body` на `/admin/ui`
(власний fetch/render-цикл, поза 2-с status-поллом) поверх маршрутів
`GET /admin/providers` + `POST /admin/providers/{add,remove,set-enabled}`
(`ProvidersResponse`/`ProviderView`/`ProviderAddRequest` — `diagrams/ui-dto-model.md`). Режим
таймауту лишився на картці "Режим таймауту" в `#app-body` (`AdminConfigUpdate` тепер несе
`timeout_mode` + `serve_baseline_when_filters_unreachable` — T-155, повна заміна кожного поля).
Порт і baseline-резолвер (select) — досі чернетка (не в картці).

**T-176:** картка `#providers-body` (поштучні тумблери, «додати пресет», власний DoH) і
картка «Режим таймауту» переїхали в розкриття `<details>` «Розширені налаштування» — ID і
JS-логіка без змін. У **базовому вигляді** їх замінюють три категорійні перемикачі
(§3.1), що бʼють у новий атомарний маршрут `POST /admin/providers/set-category-enabled`
(один запис конфігу, все-або-нічого — на відміну від N окремих `set-enabled`, які могли б
persist'нути напівстан). Рядок «N сторін бачать запити» і попередження `filtering_active`
теж піднято в базовий вигляд (§3.1), не лишились у розкритті.

| Поле | Тип | Джерело | Контрол UI | Що приймає / валідація | Фаза |
|---|---|---|---|---|---|
| Режим таймауту | `TimeoutMode` (§4.5) | §3.3 | radio: fail_open / fail_closed / degraded, картка `#app-body` | одне з трьох, дефолт `fail_open` | Ф1 ✅ |
| Baseline-fallback коли жоден фільтр не відповів | `bool` (`serve_baseline_when_filters_unreachable`) | §3.7, T-155 | чекбокс `#baseline-fallback-toggle`, картка `#app-body`; `persisted:false` notice при невдалому збереженні | дефолт **вимкнено** (DECISIONS.md 2026-09-03 — OFF = сьогоднішня поведінка, лише рядок логу `BASELINE_FALLBACK`); ON = віддати нефільтровану baseline-відповідь незалежно від режиму таймауту | Ф3 ✅ |
| Значення таймауту (мс) | `u32` | §3.3 | числове поле | дефолт ~2000мс, конфігурований (не в UI-картці) | Ф1 |
| Порт локального DoH | `u16` | §1 | числове поле | конфліктний порт → **явна помилка**, не мовчазний fallback (§1); не в UI-картці | Ф1 |
| Список voter'ів, згрупований за категорією | `ProviderView[]` (`ProvidersResponse.active`) | §3.4, T-72/T-73 | заголовки `SECURITY`/`ADS_TRACKERS`/`ADULT_CONTENT`, у кожній рядок із тумблером | тумблер → `POST /admin/providers/set-enabled`; бейдж `block_signature`; дефолт `quad9`+`cloudflare-malware`+`adguard` ON (T-170, DECISIONS.md 2026-09-05 — два Security-tier §3.4 + AdGuard для реклами) | Ф2 ✅ |
| Додати пресет | `ProviderView[]` (`available_presets` мінус уже активні) | §3.4, T-73 | рядок «назва + бейдж категорії + Додати» | `POST /admin/providers/add` з `{ id }` (решта полів — з таблиці `BUILTIN_PRESETS`) | Ф2 ✅ |
| Додати власний DoH-провайдер | `ProviderAddRequest` | §3.4, T-72 | суб-форма: `id` (`[a-z0-9-]{1,64}`), URL, показова назва, select категорії, select `block_signature` (дефолт `NULL_IP_OR_NXDOMAIN`) | `POST /admin/providers/add`; клієнт дублює бекендові перевірки `is_valid_provider_id` / `https://`; сервер відхиляє SSRF-хост (loopback/private/link-local літерал), дублікат id, неповну форму — payload-free 400 | Ф2 ✅ |
| Видалити власний запис | `ProviderRemoveRequest` | §3.4, T-72 | confirm-gated кнопка «Видалити» лише на рядках `is_builtin=false` | `POST /admin/providers/remove` з `{ id }`; пресет видалити не можна (лише вимкнути) | Ф2 ✅ |
| Рядок «N третіх сторін бачать запити» | `usize` (`third_party_count`) | §3.4, CLAUDE.md «не ховати» | текст, лише читання | увімкнені voter'и + 1 baseline | Ф2 ✅ |
| Попередження «фільтрація не активна» | `bool` (`filtering_active`) | §3, §8.1, T-72/T-73 closing review | `notice warn`, з'являється умовно | показується, коли жоден voter не увімкнено (легітимний pass-through, але має бути видимим) | Ф2 ✅ |
| Позначка DNS4EU | текст-бейдж | §3.4 | "provider run by EU institution" поруч із назвою | лише читання; **ще не реалізовано** (бейдж показує лише `block_signature`) | Ф2 |
| Baseline-резолвер | `String` (URL) | §3.1, §3.4 | select з дефолтом Cloudflare 1.1.1.1 | одна з baseline-альтернатив таблиці §3.4; **поза scope T-72/T-73** (окрема задача) | Ф1 |

### 3.5 GeoIP (Ф2)

| Поле | Тип | Джерело | Контрол UI | Що приймає / валідація |
|---|---|---|---|---|
| Список заблокованих країн | `Vec<String>` (ISO-коди) | §3.5 | multi-select / список тегів | **дефолт порожній** — свідомий opt-in |
| Попередження про CDN over-blocking | текст | §3.5 | банер при додаванні країни | з'являється при кожному додаванні нового запису |
| Дата останнього оновлення бази | `DateTime` | §8, T-78 | текст, лише читання | обчислюване з фонового апдейтера |
| Активне джерело бази | `Option<DatabaseSource>` (`DB_IP_LITE`/`GEO_LITE2`/`OTHER`) | §3.5, T-162 | текст, лише читання | класифіковано на сервері з метаданих **завантаженого** reader-а; рядок у `#geoip-body` |
| MaxMind GeoLite2 креденшели | `account_id: String` + `license_key: String` (write-only) | §3.5, T-80/T-162 | окрема картка `#geoip-maxmind-body`: текст account_id, `type="password"` ключ, «Зберегти», confirm-gated «Очистити» | обидва поля обов'язкові (порожнє → 400); `POST` показує `check` (`VERIFIED`/`REJECTED`/`UNVERIFIED`) з save-time проби; діє після перезапуску `dnsqb-service` |
| Атрибуція DB-IP Lite | текст-посилання | Наскрізні вимоги | футер сторінки `#credits` (не футер вкладки — UI однобічний) | **CC BY 4.0** (не CC BY-SA), юридично обов'язково; реалізовано T-81 |

> Перші три рядки реалізовані — T-77 (список, попередження) і T-78 (дата бази) — на `/admin/ui`'s
> `#geoip-body` (`crates/dnsqb-service/ui/`). Список — реальний список тегів (`<li>` + кнопка
> "Видалити"), не `<select multiple>` — той самий шаблон, що й `#overrides-body` (T-47).
> Попередження над цим чернетковим рядком читається як "банер зʼявляється, коли країну вже
> додано" — реалізація навмисно суворіша: перший клік "Додати" лише озброює підтвердження й
> показує банер, нічого не надсилаючи; лише другий клік (той самий код) чи "Підтвердити додавання"
> реально відправляє запит. Причина — постійно видимий банер функціонально ідентичний його
> відсутності (той самий підступ, що вже задокументований для T-56 і зворотнього T-57,
> DECISIONS.md), тож попередження мусить бути подією, а не фоновим текстом.
>
> Рядок "Дата останнього оновлення бази" реалізований інакше, ніж заявлено в чернетці: не один
> `DateTime`, а два поля `GeoipCountriesResponse` — `database_loaded: bool` +
> `database_built_at_ms: Option<u64>` (мілісекунди від епохи Unix). Причина розбіжності —
> advisor-catch під час планування T-78: одинарний `Option<DateTime>` не може розрізнити "база
> взагалі не завантажена" (фільтрація за країною не діє) від "база завантажена, але дата збірки
> невідома" — два різних, реально досяжних стани `GeoipState` (`dispatch.rs`). UI показує три
> окремих завжди-видимих рядки тексту (не банер, не одноразовий toast), по одному на стан. Значення
> саме по собі — дата **збірки бази видавцем** (`GeoipReader::build_time`'s `build_epoch`), не
> час останнього опитування `geoip_updater` (T-75's власна нотатка в `CLAUDE.md` — момент опитування
> завжди читався б як "сьогодні", що вводить в оману щодо реальної застарілості).
>
> Рядок "Активне джерело бази" та картка MaxMind-креденшелів — **T-162** (часткова доставка
> T-80's advanced-режиму). `database_source` (`Option<DatabaseSource>`, closed enum) на
> `GeoipCountriesResponse` класифікується на сервері з `GeoipReader::database_type()`
> **завантаженого** файлу, не з налаштованого `GeoipSource` — ці двоє розходяться, коли
> креденшели задані, але MaxMind їх відхилив (файл досі DB-IP Lite). Картка `#geoip-maxmind-body`
> має власний fetch/render цикл (поле ключа не гине від 2-сек поллінгу, як `#overrides-body`);
> `POST /admin/geoip/maxmind` пише файл (ACL-обмежений, той самий примітив, що `key.pem`), тоді
> робить одну автентифіковану пробу проти `download.maxmind.com` (10-сек таймаут, лише статус-код)
> і повертає `check`. Секрет **ніколи** не повертається у відповіді (`MaxmindCredentialsView` не
> має поля `license_key`). DPAPI, перечитування на `/admin/reset`, runtime-підхоплення джерела й
> виявлення "зламалися пізніше" — **T-163**.
>
> Останній рядок (атрибуція DB-IP Lite) реалізований — **T-81**, як постійний футер `#credits`
> в `crates/dnsqb-service/ui/index.html` (статичний HTML, без JS, без DTO). Не "футер вкладки" —
> UI однобічний, вкладок немає, тож футер сторінки покриває і GeoIP-картку, і колонку
> `resolved_ip_country` в логу. Ліцензія — **CC BY 4.0**, не CC BY-SA 4.0 як казала чернетка
> (SPEC.md §3.5's T-75 нотатка виправила це, підтверджено напряму проти db-ip.com при T-81).
> Обов'язковий сніпет db-ip.com — `<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>` —
> присутній дослівно. Футер також містить атрибуцію MaxMind GeoLite2 (обмежену фразою "у
> розширеному режимі", бо GeoLite2-дані діють лише при opt-in — T-80) і Apache-2.0-ліцензію
> самого застосунку (Ф1-рядок §3.7's таблиці, доти не реалізований — жодного екрана "Про
> застосунок" не існувало).

### 3.6 Розширені (Ф4/Ф5)

| Поле | Тип | Джерело | Контрол UI | Що приймає / валідація | Фаза |
|---|---|---|---|---|---|
| Рейтинговий фільтр «бульбашка» — перемикач | `bool` | §5.3, T-127 | ⚠️ реалізовано Батч 4.4 — картка `#rating-filter-body` у `<details>` «Розширені», **окремий обрамлений блок**, НЕ рядок-switch поруч з іншими | **дефолт OFF, без винятків**; OFF→ON — обовʼязковий крок підтвердження («заблокує переважну більшість інтернету», «Підтвердити ввімкнення» / «Скасувати»); ON→OFF миттєве. `POST /admin/rating-filter {enabled, lists}` (повна заміна). Fork B (`enabled` без завантаженого списку) → `notice warn` у картці | Ф4 |
| Рейтинговий фільтр — індикатор активності | `RatingFilterStatusView` | §5.3, T-128 | ⚠️ реалізовано Батч 4.4 — бейдж під hero (§3.1) **плюс** суфікс у підказці трею | лише читання. Бейдж має два стани (`active` / Fork B). **Трей-суфікс `— рейтинг-фільтр «бульбашка» активний` спрацьовує лише на `active`** (не на самому `enabled`): у треї Fork B суфікса не дає, це пояснює notice у картці. Трей-колір іконки не чіпає (вибір обсягу ≠ сигнал здоровʼя) | Ф4 |
| Зони доступності — вибір списків | `Vec<String>` (`RatingFilterStatusView.lists`, `available_lists`) | §5.3, T-111 | ⚠️ реалізовано Батч 4.4 — hand-rolled combobox (`input[role=combobox]` + `ul[role=listbox]`, ↑↓/Enter/Esc, `aria-activedescendant`) + стовпчик обраних із лічильником доменів і `×`; чекбокси рендеряться з `available_lists` (сервер), не з константи в JS. Кнопка «Зберегти зони» шле один `POST` (одна перебудова кешу) | коди зі `available_lists` (двобуквені країни + `"global"`); **`lists ⊆ available_lists` — гарантований інваріант** (T-127, `validate_rating_filter_lists` відхиляє код поза `AVAILABLE_TOPN_LISTS`). Мітки країн — клієнтська мапа в `main.js` (i18n сервера тут немає); невідомий код показується сам собою + `main.js` малює обʼєднання (обороняє конфіг, збережений до T-127) | Ф4 |
| Зони — розмір топ-N | — | — | ⚠️ **прибрано** — застаріла чернетка. Розмір курованого топ-N фіксує `examples/curate_topn.rs` при курації (Батч 4.1); клієнт його не бачить і не задає | — |
| Зони — персональний список (§5.1.1) | `bool` | §5.1.1, T-138 | switch, **дефолт OFF** | увімкнути локально навчений персональний список зон | Ф4 (Батч 4.5) |
| ccTLD-блок — список TLD | `Vec<String>` (§4.5) | §5.2 | текстове поле зі списком тегів | **дефолт порожній**; попередження про грубість евристики при додаванні | Ф5 |

### 3.7 Про застосунок (Ф1 база / Ф2 доповнення)

| Поле | Джерело | Фаза | Стан |
|---|---|---|---|
| Версія застосунку | — | Ф1 | не реалізовано — окремого екрана "Про застосунок" немає, версія ніде в UI не показана |
| Ліцензія Apache 2.0 | LICENSE | Ф1 | реалізовано T-81 — рядок у футері `#credits`, посилання на `apache.org/licenses/LICENSE-2.0` |
| Атрибуція DB-IP Lite, **CC BY 4.0** (не CC BY-SA) | Наскрізні вимоги, T-81 | Ф2 | реалізовано T-81 — футер `#credits` (не окремий екран); обов'язковий сніпет `<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>` + посилання на ліцензію; поряд — атрибуція MaxMind GeoLite2 ("у розширеному режимі", T-80) |

> Окремого екрана "Про застосунок" немає — UI однобічний. T-81 реалізував юридично обов'язкову
> частину (атрибуції + ліцензія) як постійний футер сторінки. Версія застосунку в UI досі не
> показана — низький пріоритет, не юридична вимога.

---

## 4. DTO — довідково (повна класова діаграма в `diagrams/ui-dto-model.md`)

Скорочений перелік типів, згаданих у таблицях §3, з номером підрозділу для
деталей:

1. `LogEntry` — §3.2 таблиця вище; повна структура в `diagrams/ui-dto-model.md`.
   **Реалізовано T-54** як `admin::LogEntryView` (`GET /admin/log`, HTTP-канал,
   не Tauri IPC — §5's власна примітка нижче) — `timestamp`→`timestamp_ms`
   (мілісекунди від епохи, не `DateTime`-об'єкт), решта полів 1:1.
2. `VoterResult { provider_name, status: VoterStatus }` — `VoterStatus` має
   **сім** варіантів (`Pending, Block, Allow(ip_count), Timeout,
   Error(message), Canceled, Disabled`) — розбіжність §6/§8 у самому SPEC.md
   вирішена й підтверджена користувачем 2026-08-25 (DECISIONS.md,
   `diagrams/ui-dto-model.md`). **Реалізовано T-54** як
   `admin::VoterVerdictView` (internally tagged, `#[serde(tag = "status")]`) —
   `Pending` лишається недосяжним із цього маршруту (зарезервований під
   майбутній live-канал), `Allow`/`Error` payload походить із нового
   `quorum::VoterRecord::allow_ip_count`/`error_message` (той самий T-54,
   `error_message` — лише грубий `error_kind()`-лейбл, ніколи сирий текст
   `UpstreamError::Http`, який ніс би URL-адресу запиту).
3. `DecisionSource` enum — 7 значень: `ALLOWLIST, BLOCKLIST, CCTLD_BLOCK,
   CACHE, RATING_FILTER, QUORUM, GEOIP` (§6). За часом появи: `RATING_FILTER` —
   Ф4, `CCTLD_BLOCK` — Ф5; обидва присутні в enum з Ф1 (принцип §1 цього файлу).
4. `OverrideEntry { domain, is_wildcard, list: ListKind }` — §5.
5. `TimeoutMode` enum, `ProviderConfig { name, doh_url, category, built_in,
   enabled }` — §3.3, §3.4.
6. `StatusIndicatorState` — не єдиний enum, а сукупність незалежних умов; див.
   `diagrams/ui-status-indicator.md` (включно з ⚠️ GAP про порядок пріоритету
   при одночасному виконанні кількох умов). **T-191:** трей-іконка (`dnsqb-tray`)
   несе той самий обчислений good/warn/bad три-стан кольором (green/amber/red)
   плюс grey для «вимкнено-за-вибором»; ті самі умови й той самий порядок, без
   нового поля DTO (`cert_trusted` — локальна read-only перевірка трея, не через
   адмін-канал). **T-188:** hero `/admin/ui` дістав ту саму cert-гілку — через
   `GET /admin/cert-status` (`CertTrustView` три-стан), окремим fetch-циклом, не
   на status-поллі; `NOT_TRUSTED` несе дію `POST /admin/install-cert`. **T-128
   (Батч 4.4):** `dnsqb-tray`'s `compose_tooltip` дописує суфікс `— рейтинг-фільтр
   «бульбашка» активний`, коли `AdminStatusResponse.rating_filter.active` — після
   нотатки про degraded-запити, ніколи не змінюючи колір іконки (та сама логіка
   «pass-through ≠ failure», що `NoActiveProvider`).

---

## 5. Чернетка allowlist Tauri-команд

> **Застаріло для двох реально поставлених екранів (T-149, DECISIONS.md) — Tauri
> видалено разом із `crates/dnsqb-ui`.** `get_status()` і
> `set_providers`/`set_timeout_mode` нижче (позначені ⚠️) тепер живуть як звичайні
> HTTP-маршрути `dnsqb-service`'s адмін-каналу (`GET /admin/status`, `POST
> /admin/config`, `POST /admin/reset`, `POST /admin/shutdown` — CONFIGURATION.md),
> викликані і треєм (`dnsqb-tray`), і вбудованим веб-UI (`/admin/ui`), не
> Tauri-командою через `invoke()`. **Списки** (T-47) — третій реально поставлений
> екран, тим самим патерном: HTTP-маршрути (`GET /admin/overrides`, `POST
> /admin/overrides/add`/`remove`), позначені ⚠️ нижче. Таблиця нижче лишається
> чернеткою для решти **непоставлених** екранів (Лог, GeoIP, Розширені —
> T-46/T-58/T-77 та ін.) — коли вони будуються, теж, найімовірніше, стануть
> HTTP-маршрутами на тому самому адмін-каналі, не Tauri-командами; форма нижче
> залишена як інвентар потрібних операцій, не буквальний майбутній
> API-контракт.

**Чернетка, не остаточний список** — SPEC.md §8 вимагає явний, короткий,
задокументований allowlist з snapshot-тестом (Наскрізні вимоги, T-59); ця
таблиця — вхідна точка для того списку, виведена з екранного інвентарю §2-3,
підлягає рев'ю при імплементації T-53.

| Команда | Повертає / приймає | Екран | Фаза |
|---|---|---|---|
| `get_status()` | ⚠️ реалізовано T-52 як `AdminStatusResponse` (ширше за чернетковий `StatusIndicatorState` — включає `stats`) | Header (всі екрани) | Ф1 |
| `get_dashboard_summary()` | статистика + прев'ю логу | Dashboard | Ф1 |
| ~~`set_category_enabled(category, bool)`~~ → `set_providers(quad9, adguard)` | ⚠️ реалізовано T-52 з іншою назвою/сигнатурою — Ф1 має лише 2 провайдери, не категорії (T-148); category-рівень лишається пізнішою фазою | Dashboard, Провайдери | Ф1 |
| ~~`get_log(filter)`~~ → `GET /admin/log?domain_contains=&decision=&voter=&limit=` | ⚠️ реалізовано T-54 — `LogQueryResponse{entries: Vec<LogEntryView>, truncated}`, не голий `Vec<LogEntry>`; `filter` розкладено на три незалежні query-параметри плюс `limit` (дефолт 200, хардкап 1000 — ринг-буфер сам більше не тримає), невизнане значення `decision`/`voter` — `400`, ніколи мовчазне "без фільтра" | Лог запитів | Ф1 |
| ~~`clear_log()`~~ → `POST /admin/log/clear` | ⚠️ реалізовано T-54, той самий CSRF-гейт що й інші admin `POST` | Лог запитів | Ф1 |
| ~~`add_to_allowlist(domain)`~~ / ~~`add_to_blocklist(domain)`~~ → `POST /admin/overrides/add` | ⚠️ реалізовано T-47 як один злитий маршрут (`OverrideAddRequest{pattern, list}`), не два окремих — той самий `pattern` приймає і точний домен, і `*.domain` | Списки (Лог — тепер теж, UI-екран лишається T-46) | Ф1 |
| `remove_from_list(domain, list)` → `POST /admin/overrides/remove` | ⚠️ реалізовано T-47 — `OverrideRemoveRequest{domain, is_wildcard, list}`, повна трійка, не лише `domain` | Списки | Ф1 |
| `get_override_lists()` → `GET /admin/overrides` | ⚠️ реалізовано T-47 як `OverrideListsResponse{allowlist, blocklist, conflicts}` — `conflicts` рахується сервером, не клієнтом | Списки | Ф1 |
| `get_provider_config()` / `set_timeout_mode(mode)` / `set_doh_port(port)` | `ResolverSettings` — ⚠️ `set_timeout_mode` реалізовано T-52 (повертає `AdminStatusResponse`, не окремий `ResolverSettings`); `get_provider_config()`/`set_doh_port(port)` ще ні | Провайдери | Ф1 |
| — (нова, не в цій чернетці) → `GET /admin/cache-config` / `POST /admin/cache-config/apply` | ⚠️ реалізовано T-153 як `CacheConfigView`/`CacheConfigUpdate` (5 полів TTL-меж/ємності, SPEC.md §4.1) — окремий маршрут від `set_timeout_mode`, навмисно не злитий у `AdminConfigUpdate`, щоб звичайний тумблер провайдера не тягнув за собою скидання кешу як побічний ефект. Секція "Кеш" на `/admin/ui` — окрема картка, не частина "Розширені" (та секція ще не існує в реалізованому UI) | Кеш (нова секція, backend-роут реалізовано T-153; UI-картка — той самий зріз, другий коміт) | Ф1 |
| — (нова, не в цій чернетці) → `GET /admin/cert-status` | ⚠️ реалізовано T-188 — `CertStatusResponse { trusted: CertTrustView }`, три-стан `TRUSTED` / `NOT_TRUSTED` / `UNKNOWN`. **T-211:** тепер чисте читання кешу `AppState.cert_trust` (`RwLock<Option<CertTrustView>>` — `None` «ще не перевіряли» → `UNKNOWN` на дроті), який тримає теплим фоновий 60 с-poll `cert_watch::run_cert_trust_watch` (+ синхронний poke із `install-cert`/`uninstall-local-state`); більше **не** спавнить `certutil` на виклик → прибрано з `FUZZ_EXCLUDED_ROUTES`. **T-204:** hero `/admin/ui` більше **не** fetch-ить цей маршрут — cert-гілка тепер у `AdminStatusResponse.hero_state`. Лишається для майстра трея / зовнішніх викликів | майстер трея | Батч 3.13 / T-211 |
| — (нова, не в цій чернетці) → `POST /admin/install-cert` | ⚠️ реалізовано T-188 — `{}`-тіло, CSRF-гейт як усі write-маршрути; `trust_store::ensure_installed(cert.pem)` через `spawn_blocking` → `InstallCertResponse { outcome: INSTALLED \| ALREADY_INSTALLED }`. Прецедент мутації trust store з маршруту — `POST /admin/uninstall-local-state` (T-70). **T-211:** на успіху поки́дає `AppState.cert_trust = Trusted`, щоб hero флипнувся одразу. Лишається в `FUZZ_EXCLUDED_ROUTES` (мутує) — `cert-status` вже ні | Кнопка hero «Встановити сертифікат» | Батч 3.13 |
| `add_custom_provider(name, url)` | — | Провайдери | Ф2 |
| `get_geoip_config()` / `set_blocked_countries(list)` | `GeoIPConfig` | GeoIP | Ф2 |
| `get_geoip_db_status()` | дата оновлення | GeoIP | Ф2 |
| `set_rating_filter(config)` → `POST /admin/rating-filter` | ⚠️ реалізовано Батч 4.4 — `RatingFilterConfigUpdate { enabled: bool, lists: Vec<String> }` (повна заміна, як `AdminConfigUpdate`); повертає свіжий `AdminStatusResponse` із полем `rating_filter: RatingFilterStatusView { enabled, active, lists, available_lists, loaded }`. Валідація списків спільна з завантаженням конфігу (`validate_rating_filter_lists` — форма + членство в `AVAILABLE_TOPN_LISTS`); невалідний код → `400`. Персональний список §5.1.1 — Батч 4.5, не в цьому DTO | Розширені | Ф4 |
| `set_cctld_blocklist(list)` | `CctldBlockConfig` | Розширені | Ф5 |
| `get_about_info()` | версія + атрибуції | Про застосунок | Ф1/Ф2 |

Події backend → UI (той самий принцип мінімальної типізованої поверхні, §8):
`log-entry-added(LogEntry)`, `status-changed(StatusIndicatorState)`.

---

## 6. Вирішене питання (див. DECISIONS.md)

**`VoterStatus` — п'ять варіантів у SPEC.md §6 vs п'ять варіантів у §8, що не
збігалися буквально (`TIMEOUT` лише в §6, `Pending` лише в §8).** Вирішено
[2026-08-25](DECISIONS.md) на користь об'єднаного 6-варіантного enum
(`Pending, Block, Allow, Timeout, Error, Canceled`) — підтверджено
користувачем після показу, що канонічне джерело §3.6 саме по собі містить
лише 5 значень і не згадує `Pending`. Деталі й наслідки — в DECISIONS.md,
запис "VoterStatus: 6 варіантів, включно з Pending".
