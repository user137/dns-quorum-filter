# review/arch/00-DELTA.md — Фаза 0: Орієнтація і дельта

> Review-артефакт архітектурного огляду, не частина DOC MAP (`CLAUDE.md`). Джерело істини —
> `SPEC.md`/`DECISIONS.md`. Знахідки, що переживають огляд, переїжджають у `TASKS.md`. Виміри
> позначено місцем (`gnu-local` / `CI` / `MSIX-installed`).

Дата: 2026-10-04. База порівняння: `6e5cae5` (2026-09-10 21:14, попереднє Rust-ревʼю) → `HEAD`
`d31176b`. Встановлений застосунок у цій фазі не торкався (усе — читання репозиторію).

**Скоуп фази:** `git diff 6e5cae5..HEAD -- crates/` (174 файли), `Cargo.toml`×3, `Cargo.lock`,
`dispatch.rs` (`ROUTES`, `AppState`), `config.rs`/`orchestrate.rs` (шлях збереження/завантаження
конфігу), заголовки нових модулів, `review/05-BACKLOG.md`, `TASKS.md` (Батч RV, Батч QA-FIX),
`review/QA-FIX-PLAN.md`. Одна партія.

---

## 1. Обсяг змін

`ВИМІРЯНО (gnu-local)`: `git log --oneline 6e5cae5..HEAD | wc -l` → **183 коміти**;
`git diff --stat 6e5cae5..HEAD -- crates/` → 174 файли, +29 981 / −2 412.

LOC — скрипт `scratchpad/loc.py` над `git archive 6e5cae5` vs робоче дерево: «прод» = рядки до
першого `#[cfg(test)]` + `mod`, «тест» = після. Doc-коментарі входять у «прод». Евристика
пропускає `#[cfg(all(test, windows))]` — для `dnsqb-watcher/src/main.rs` виправлено вручну
(прод 379 / тест 68).

| Шар | 6e5cae5 прод / тест | HEAD прод / тест | Δ прод |
|---|---|---|---|
| `crates/*/src/**/*.rs` | 19 991 / 19 467 | 26 179 / 26 021 | **+6 188 (+31 %)** |
| `crates/*/tests/` | 280 | 608 | +328 |
| `crates/*/examples/` | 2 548 / 125 | 2 453 / 78 | −95 |
| `ui/main.js` | 2 883 | **4 412** | +1 529 (+53 %) |
| `ui/smoke.js` (новий) | — | 199 | — |
| `#[test]`/`#[tokio::test]` | 791 | **1 080** | +289 |
| `#[ignore]` | 22 | 26 | +4 |

Тест/прод у Rust-джерелах тримається ≈1:1 (як і на базі). **`main.js` — найбільший одиничний
файл логіки, що не має Rust-тестів і росте найшвидше** (+53 %); вирішальна логіка винесена на
сервер у T-204, але рендер/редагування форм лишились — QA-баги T-242/T-248/T-250 саме звідти.

### Найбільший приріст (прод / тест, у дужках — база)

| Δ | Файл | HEAD | База |
|---|---|---|---|
| +1891 | `dnsqb-service/src/dispatch.rs` | 4108 / 6334 | 3253 / 5298 |
| +1213 | `blocklist_updater.rs` (новий) | 700 / 513 | — |
| +1103 | `admin_ui.rs` | 142 / 1563 | 91 / 511 |
| +1012 | `orchestrate.rs` (новий, T-210 — рух з `main.rs`) | **1012 / 0** | — |
| +974 | `config.rs` | 1221 / 1386 | 851 / 782 |
| +895 | `pipeline.rs` | 1274 / 3928 | 1097 / 3210 |
| +892 | `blocklist_download.rs` (новий) | 432 / 460 | — |
| +845 | `admin.rs` | 2104 / 878 | 1638 / 499 |
| +499 | `personal_zone_stats.rs` (новий) | 326 / 173 | — |
| +481 | `dnsqb-tray/src/main.rs` | 1134 / 171 | 824 / 0 |

Найбільші прод-файли: `dispatch.rs` 4108, `admin.rs` 2104, `pipeline.rs` 1274, `config.rs` 1221,
`dnsqb-tray/main.rs` 1134, `orchestrate.rs` 1012. **`orchestrate.rs` — 23 функції, 0 inline-тестів**
(`ПІДТВЕРДЖЕНО В КОДІ`: `grep cfg(.*test orchestrate.rs` — порожньо). Це свідомий прецедент
«`main` не тестується», але після T-210 тут уже 1012 рядків startup-логіки, включно з рішенням
«битий конфіг → `exit(1)`» (див. §6, R-1).

### Нові модулі

`dnsqb-service`: `blocklist_download`, `blocklist_updater`, `cctld_block`, `cert_watch`,
`cli_help`, `install_region`, `orchestrate`, `personal_zone_persist`, `personal_zone_stats`,
`public_suffix` (+ `public_suffix_list.dat` переїхав з `examples/` у `src/` — PSL тепер у
прод-бінарі), `zone_removal_persist`; `tests/admin_client.rs`.
`dnsqb-tray`: `browser_nudge`, `nudge_popup` (T-229, `softbuffer`), `i18n`.

### Дані (не-Rust)

`ВИМІРЯНО (gnu-local)`, `du -sh` / `json.load`:
- `dnsqb-service/ui/i18n/` — 37 локалей, **257 ключів** у `en.json`, 996 KB;
- `dnsqb-tray/i18n/` — 37 локалей, 48 ключів, 324 KB;
- `dnsqb-service/cli-help-i18n/` — 37 файлів, 160 KB.

Разом ≈1.5 MB тексту, вбудованого (`include_str!`) у бінарі. Три окремі дерева перекладів —
рішення задокументоване (CLAUDE.md, рядок `cli_help`; TASKS.md Батч 5.5). Вплив на розмір
`.exe` — у Фазі 6.

### Маршрути

`ПІДТВЕРДЖЕНО В КОДІ` `dispatch.rs:149` (`ROUTES`): база — 30 записів; HEAD — **32 + 37
i18n-маршрутів** (`I18N_ROUTES`, macro). Нові: `POST /admin/blocklist-bundles`,
`POST /admin/cctld-block`, `GET /admin/ui/i18n/<locale>.json`×37. Allowlist-модель
(точний збіг рядка, без параметрів шляху) збережена.

### `AppState`

`ПІДТВЕРДЖЕНО В КОДІ` `dispatch.rs` `pub struct AppState`: **25 → 35 полів**. Нові:
`cctld_block`, `cert_trust`, `rating_filter_removed`, `personal_zone_config`,
`personal_zone_stats` (не `Arc` — `RwLock<PersonalZoneStats>`, мутується на гарячому шляху),
`rating_filter_personal_zone`, `personal_zone_refresh_wake`, `system_region`,
`blocklist_bundles`, `blocklist_bundles_config`, `blocklist_bundles_refresh_wake`.
Три окремі `Mutex<()>`: `persist_lock` (10 захоплень у `dispatch.rs`),
`overrides_persist_lock`, `geoip_source_lock` (разом 5). Чотири `Notify`-«будильники» фонових
оновлювачів. Одна структура — власник усього живого стану служби; перевірка дисципліни —
Фаза 2.

### Залежності

`ВИМІРЯНО (gnu-local)`: пакетів у `Cargo.lock` 475 → **480**. Нові записи: `softbuffer`,
`sys-locale`, `bytemuck`, `objc2-io-surface`, `objc2-quartz-core` (два останні — macOS-гілка
`softbuffer`, у Windows-збірку не лінкуються, лише lockfile). Нові прямі залежності:
`sys-locale` (service + tray), `winreg` (service, `cfg(windows)`; уже був у lock транзитивно),
`softbuffer`, `serde_json` (tray). `rfd` дістав фічу `common-controls-v6` (без нового крейта).
Унікальних крейтів у ship-графі MSVC (`cargo tree --workspace -e normal --target
x86_64-pc-windows-msvc`, за іменем) — **208**; на бінар: service 202, tray 222, watcher 203
(рядків `cargo tree --prefix none`, з повтором версій). Приріст ланцюга постачання за 183 коміти
малий; кожна нова пряма залежність має обґрунтування в `Cargo.toml`/SECURITY.md.

`#![forbid(unsafe_code)]` — у всіх трьох `main.rs` і `lib.rs` (`ПІДТВЕРДЖЕНО В КОДІ`).

CI на `main`: останні 4 прогони (CI + CodeQL) — `success` (`gh run list --branch main --limit 4`,
`CI`).

---

## 2. Статус бекологу попереднього ревʼю

`review/05-BACKLOG.md` (16 знахідок + 4 doc-фікси) → **Батч RV, T-197…T-216 — усі `[x]`**
(`TASKS.md:2248–2490`). Вибірково перевірено, що виправлення досі в коді (`ПІДТВЕРДЖЕНО В КОДІ`):

| Знахідка | Задача | Слід у HEAD |
|---|---|---|
| 3-B вирішальна логіка `main.js` → сервер | T-204 | `admin.rs:423 compute_hero_state` |
| 3-A версіонування DTO | T-205 | `admin.rs:56 ADMIN_DTO_SCHEMA_VERSION: u32 = 6` |
| 1.2-B тести `AdminClient` | T-201 | `tests/admin_client.rs`, 13 `fn` |
| 1.4-A routing трея | T-202 | `dnsqb-tray/src/main.rs:515 menu_action_for` + 2 тести |
| 1.4-B `observe` watcher-а | T-203 | `dnsqb-watcher/src/main.rs:209` + 2 тести |
| 3-C stampede | T-206 | `pipeline.rs:2325` |
| 4-A doc-тести | T-207 | 9 `# Examples` у `src/` |
| 2-B кеш trust | T-211 | `cert_watch.rs` |
| 4-B `pub fn run()` | T-210 | `orchestrate.rs` |

Регресій не виявлено. Схема DTO за 3,5 тижні пройшла 6 версій — механізм T-205 реально
використовується.

**Процесна примітка (nit, підтримуваність):** закриті задачі RV лишились у `TASKS.md` як `[x]`
(їх нема в `TASKS-DONE.md` — `grep -c` дає 1 збіг), хоча DOC MAP каже «`TASKS.md` — open
backlog, status only». Загалом у `TASKS.md` **82 `[x]` проти 67 `[ ]`**, файл 309 KB.
`TASKS-DONE.md` — 955 KB, `DECISIONS.md` 269 KB, `SPEC.md` 281 KB, `CLAUDE.md` 89 KB (гейт
140 000). Разом документація ≈1.9 MB. Розмірний гейт стоїть лише на `CLAUDE.md`. Детально —
Фаза 2/7 (вартість контексту для агента = економність процесу), тут лише фіксація.

---

## 3. Карта: процеси, межі, власники стану

### Процеси (три бінарі, одна lib)

```
           MSIX tile / автозапуск
                    │
            dnsqb-watcher  (current_thread, windows_subsystem)
             │ spawn_sibling (DETACHED|BREAKAWAY)
     ┌───────┴────────┐
 dnsqb-tray        dnsqb-service  (rt-multi-thread)
   │  2 с опит.        │  127.0.0.1:<port> TLS (hyper+rustls)
   │  /admin/status ──►│  /dns-query  /health  /admin/*  /admin/ui
   │                   │
 браузер ◄─ /admin/ui ─┤──► N апстрім-DoH (fan-out, OR-кворум)
 (DoH-клієнт) ────────►│──► baseline-ланцюг, маркери reachability
                       │──► фіди: GeoIP, top-N, blocklist bundles (24 год)
```

### Межі між процесами

| Канал | Напрям | Писач | Читач | Durable? |
|---|---|---|---|---|
| Named pipe (heartbeat кан. 1) | watcher ↔ service | service (сервер) | watcher (клієнт) | ні |
| `service.hb` / `watcher.hb` (кан. 2) | обидва | кожен свій | інший | так (mtime) |
| `GET /health` (кан. 3) | watcher → service | — | watcher | ні |
| `watchdog-state.json` | watcher → tray, `/admin/status` | **лише watcher** (§7.1 #7) | tray, service | так |
| `stop.flag` / `quit.flag` | tray → service/watcher | tray (set), watcher (clear на старті) | service (`pause_watch`), watcher | так |
| `/admin/*` (CSRF JSON-гейт) | tray, браузер → service | — | — | — |
| `*.pid`, `*.lock` | кожен свій | `instance::acquire` | `launcher` | так |
| `onboarding.seen`, `browser-nudge.seen` | tray | tray | tray | так |

### Власники durable-стану (app-data)

| Файл / секрет | Писач | Запис | Примітка |
|---|---|---|---|
| `resolver_config.toml` | `dispatch.rs`, 5+ маршрутів під `persist_lock` | **`fs::write`, не атомарно** (`config.rs:847`) | битий файл → `exit(1)` (`orchestrate.rs:985–990`) — див. R-1 |
| `overrides.toml` | `dispatch.rs` під `overrides_persist_lock` | **`fs::write`, не атомарно** (`overrides.rs:515`) | — |
| `query-log.enc`, `cache.enc`, `zone-removals.enc` | персистери, 60 с | `paths::write_atomic` | ключ `persistence-key` |
| `personal-zone.enc` | `personal_zone_persist` | `write_atomic` | окремий ключ `personal-zone-key` |
| `cert.pem` | `tls`/`cert_rotation` | — | ключ — у Credential Manager |
| `topn/*.txt`, `blocklists/*.txt` (+`.count`), GeoIP `.mmdb` | оновлювачі (24 год) | `write_atomic` після integrity-гейта | — |
| `logs/<role>.log` | кожен процес | ротація 5 MiB на старті | — |
| Credential Manager: `doh-tls-private-key`, `persistence-key`, `personal-zone-key`, `maxmind-credentials` (+`:<hash>`) | `key_store` / `geoip_credentials` | — | 4 записи |
| `CurrentUser\Root` | `trust_store` (tray-меню, `/admin/install-cert`, uninstall) | `certutil` абсолютним шляхом | Windows-only, без шва (відомо) |

Стан, що **живе лише в памʼяті** і зникає з рестартом: verdict-кеш (якщо `persist_cache=false`,
дефолт), журнал (дефолт), лічильники `ConnectionGate`, `BaselineSelector`, `reachability`,
бюджет рестартів напрямку service→watcher (задокументовано, CLAUDE.md «What's built»).

---

## 4. Ранні знахідки фази 0

```
[ARCH-01] severity: major
Де: crates/dnsqb-service/src/config.rs:847, overrides.rs:515, orchestrate.rs:985–990
Категорія: архітектура
Джерело: ПІДТВЕРДЖЕНО В КОДІ (запис і завантаження); наслідок для користувача — ГІПОТЕЗА
Три Б: user | lower-layer
Кому шкодить (аудиторія): людина, у якої вимкнулось живлення / завис ноутбук саме під час
  збереження перемикача на /admin/ui. `ResolverConfigFile` має `#[serde(default,
  deny_unknown_fields)]` (`config.rs:968`), тож наслідки розходяться на два різні порушення
  правила 1:
  (1) файл обрізаний **до нуля байтів** (truncate відбувся, write — ні) або по межі рядка →
      розбір успішний, відсутні поля/таблиці беруть дефолт → **налаштування тихо скинуті**
      (провайдери, режим, країни…), і наступне збереження закріплює дефолт. Не помітить.
  (2) файл обрізаний **посеред рядка** → помилка розбору → `std::process::exit(1)`; watchdog
      перезапускає 5 разів за 600 с → GaveUp → червоний значок. Помітить, але **дії, що виправляє,
      немає** — треба знайти й видалити файл у `%LOCALAPPDATA%\Packages\<PFN>\LocalCache\...`.
Що: обидва TOML-конфіги пишуться `fs::write` (truncate + write), хоча в коді вже є
  `paths::write_atomic` (temp + `sync_all` + `rename`), яким користуються всі `.enc`-файли й фіди.
  Сам коментар `dispatch.rs:951` фіксує «plain `fs::write`, not atomic», але лише як аргумент
  на користь `persist_lock` (гонка двох запитів), не про обрив запису.
Варіанти: (а) перевести `ResolverConfig::save`/`Overrides::save` на `paths::write_atomic` —
  кілька рядків, патерн готовий; (б) (а) + на старті при помилці розбору перейменувати файл
  у `.orphaned-<ts>` (як `log_persist::rename_orphan`) і стартувати з дефолтом + гучний
  сигнал у hero/трей замість `exit(1)` — але це змінює задокументовану політику «hard
  cutover, loud parse error» (CLAUDE.md «Recurring patterns»), потребує рішення; (в) не
  чіпати — ймовірність мала (вікно запису — мілісекунди, файл ~1–2 KB).
Рекомендація: (а) безумовно — дешево і закриває клас. (б) — винести на рішення у Фазі 1
  (місія: «жодної тиші, одна дія») разом з тим, що відбувається при ручному редагуванні.
  **Закрито у Фазі 1:** (б) увійшло в ARCH-03 (а) як дія «Скинути налаштування»; ARCH-01 (а) —
  передумова ARCH-03, бо там трей писатиме конфіг, поки служба лежить.
Тест / вимір, що це зловив би: unit — `save` ніколи не лишає на диску частковий файл
  (симуляція: temp-файл існує, `rename` не відбувся → оригінал цілий); наживо — скретч-інстанс
  з обрізаним `resolver_config.toml` → спостерігати `GaveUp`.
Перевірка «вже відомо»: grep `KNOWN-LIMITATIONS.md`, `TASKS.md`, `DECISIONS.md`, `SPEC.md`,
  `RUST-GOTCHAS.md`, `review/*.md` за «atomic/атомар/corrupt/пошкодж/битий» поряд із
  `resolver_config` — лише T-252 (QA-FIX хвиля 7: приватність **тексту** помилки розбору), не
  атомарність і не реакція `exit(1)`. Не зафіксовано.
```

```
[ARCH-02] severity: nit
Де: TASKS.md (82 `[x]`), DOC MAP-правило «TASKS.md — open backlog»
Категорія: підтримуваність
Джерело: ВИМІРЯНО (grep -c, wc -c; gnu-local)
Три Б: —
Кому шкодить (аудиторія): не кінцевому користувачу; агенту/розробнику — 309 KB `TASKS.md`
  читається на кожному «що далі», більшість — закрите.
Що: закриті задачі (зокрема весь Батч RV) не переносяться в `TASKS-DONE.md`, всупереч DOC MAP.
Варіанти: (а) одноразовий скриптовий перенос `[x]` → `TASKS-DONE.md` + розмірний гейт на
  `TASKS.md` за зразком `claude-md-size.yml`; (б) змінити правило DOC MAP; (в) не чіпати.
Рекомендація: розглянути в Фазі 7 разом з економністю процесу; не терміново.
Тест / вимір: N/A (процес).
```

---

## 5. `already-filed` (перевірено в ході фази, не дублюю)

- `trust_store` без шва Фази 6 — вже в CLAUDE.md «Current phase boundaries».
- Ін'єкція «жмені» доменів у бандли (small-injection gap) — вже в `KNOWN-LIMITATIONS.md`.
- Текст помилки розбору `toml` у лозі може цитувати рядок файлу — вже T-252 (QA-FIX хвиля 7).
- `/admin/ui` i18n не перевірена в справжньому браузері — вже `KNOWN-LIMITATIONS.md`
  (частково знято QA-проходом).
- Бюджет рестартів service→watcher не durable — задокументовано CLAUDE.md «What's built».

---

## 6. Зони ризику для фаз 1–6

| # | Зона | Чому | Фаза |
|---|---|---|---|
| R-1 | Реакція на битий/недійсний конфіг: `exit(1)` → GaveUp, без дії для користувача (ARCH-01) | місія «жодної тиші, одна дія» | 1, 2 |
| R-2 | Шлях «встановив → захищений»: браузер справді ходить через службу? (T-229 nudge лише «чи був хоч один запит»), T-243/T-257/T-266/T-268/T-269 як класи | користувач може вважати себе захищеним | 1 |
| R-3 | Обсяг фіч Фаз 4/5/7 (бульбашка, персональна зона, ccTLD, бандли 5.5M, 37 локалей) проти аудиторії «домогосподарки» — розростання поза нішею? | +31 % прод-коду | 1 |
| R-4 | `dispatch.rs` 4108 прод-рядків: транспорт + валідація + персист у одному файлі; 35 полів `AppState`; 3 `Mutex` + live-snapshot-дисципліна — рекурентний баг-клас | ріст +855 | 2 |
| R-5 | `orchestrate.rs` 1012 рядків без тестів; startup-рішення (exit, порядок спавну, перший цикл оновлювачів) | нетестований шлях старту | 2, 3 |
| R-6 | `main.js` 4412 рядків, лише `smoke.js` + `contains`-тести; QA знайшов 4 баги рендеру | найшвидше росте | 3 |
| R-7 | Фіди третіх сторін: 8 URL бандлів, top-N, GeoIP — integrity-гейти T-233; ін'єкція відома | lower-layer | 4 |
| R-8 | PSL у прод-бінарі (`public_suffix_list.dat` переїхав у `src/`) — застарівання статичного файлу | lower-layer | 4 |
| R-9 | Гарячий шлях після бандлів: `RandomState::hash_one` суфікс-волк на кожен запит + `binary_search` у ~5.5M `Vec<u64>`; `personal_zone_stats` — `RwLock::write()` на кожен запит, коли `[personal_zone].enabled` (`dispatch.rs:1384–1389`, дефолт OFF) | контенція під сплеском браузера | 5 |
| R-10 | Памʼять: бандли `Vec<u64>` (~44 MB при 5.5M), сирі `.txt` ~111 MB на диску; 1.5 MB вбудованих перекладів; tray 222 крейти | ноутбук «домогосподарки» | 6 |
| R-11 | Фонові мережеві запити: reachability-проби (30 с ідл / 3 с при збої) + DoH-sentinel до baseline на кожен Online-цикл | мережева ввічливість, батарея | 6 |
| R-12 | Документація ≈1.9 MB, розмірний гейт лише на `CLAUDE.md` (ARCH-02) | вартість контексту | 7 |

---

## Стан Фази 0: **ЗАВЕРШЕНА**

Blocker — немає. 1 `major` (ARCH-01), 1 `nit` (ARCH-02), 5 `already-filed`.
