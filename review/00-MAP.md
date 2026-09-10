# review/00-MAP.md — Фаза 0: Інвентаризація та карта місій

> Це review-артефакт, не частина DOC MAP (`CLAUDE.md`). Джерело істини —
> `SPEC.md`/`DECISIONS.md`. Знахідки, що переживають ревʼю, переїжджають
> у `TASKS.md`. Baseline-прогони позначено місцем: **`gnu-local`** =
> хост розробки `x86_64-pc-windows-gnu`, Rust 1.98.0; **`CI`** =
> `windows-latest` / MSVC (не прогонявся в цій сесії).
>
> Дата: 2026-09-10. HEAD `0ecab35`. `review/` — тимчасове риштування;
> вихід знахідок — у `TASKS.md` (Фаза 5).

---

## 1. Структура workspace

`resolver = 2`, `members = ["crates/*"]`. `Cargo.lock` — 475 крейтів
(увесь граф; `deny.toml` пінить оцінюваний граф до
`x86_64-pc-windows-msvc`). `[profile.release] codegen-units = 1` заради
відтворюваності (T-100).

| Крейт | Ціль | Модулі | Прод-LOC¹ | Всього LOC¹ | Версія |
|---|---|---|---|---|---|
| `dnsqb-service` | `lib` + `[[bin]]` | 40 (`lib.rs` `mod`) | ≈17 552 | 36 885 | 0.3.1 |
| `dnsqb-tray` | `[[bin]]` | 4 (`browser`, `onboarding`, `self_uninstall`, `status`) | ≈1 354 | 2 175 | 0.3.1 |
| `dnsqb-watcher` | `[[bin]]` | 1 файл | 337 | 337 | 0.3.1 |
| `tests/conformance` | integration (`dnsqb-service`) | 10 RFC-файлів | — | 269 | — |
| `examples/` (`dnsqb-service`) | 5 (`load_test`, `phase1_metrics`, `sinkhole_probe`, `topn_fp_probe`, `curate_topn`) | — | — | 2 668 | — |

¹ Прод-LOC = обрізано на першому `#[cfg(test)]` у файлі (`awk`). Різниця
з «Всього» — 54 inline `#[cfg(test)]` модулі (у `dnsqb-service`) +
`dnsqb-tray` 4. Отже понад половина `dnsqb-service` src — тести inline;
будь-яке твердження «файл X завеликий» у Фазі 3 наводить **обидва** числа.

Найбільші прод-файли: `dispatch.rs` 3 253 / 8 550 · `admin.rs` 1 638 /
2 136 · `pipeline.rs` 1 097 / 4 306 · `quorum.rs` 856 / 2 082 ·
`config.rs` 851 / 1 632 · `dnsqb-tray/main.rs` 823 · `dnsqb-service/main.rs`
804 · `geoip_updater.rs` 704 · `upstream.rs` 573.

---

## 2. Місія кожного крейта — **з коду**, і звірка з назвою/SPEC/README

### `dnsqb-service` — `crates/dnsqb-service/src/{lib.rs,main.rs}`
Місія (код): **DoH-лістенер на `127.0.0.1` + quorum-резолвер + адмін-канал
`/admin/*` із вбудованою веб-панеллю (`include_str!`), плюс GeoIP-фільтр,
rating-filter «бульбашка» і сервісна половина watchdog'а.** `main.rs` —
лише TCP accept-loop + TLS-термінація; уся логіка запиту в lib-модулі
`dispatch` (юніт-тестований без сокета). `main.rs` **свідомо не
юніт-тестований** (задокументований прецедент). Звірка: збігається з
SPEC.md §1/§3 і SERVICES.md. Розбіжностей нема.

### `dnsqb-watcher` — `crates/dnsqb-watcher/src/main.rs`
Місія (код): **(1) ідемпотентний autostart-лаунчер** (перевіряє кожного
сиблінга через instance-guard / PID, спавнить відсутнього; повторний
запуск ярлика нічого не дублює); **(2) `watcher→service` heartbeat-цикл**
(5с тік: IPC ping/pong ч.1, `watcher.hb`/`service.hb` ч.2, `GET /health`
ч.3; 2-of-3 тихе голосування → `watchdog::loop_driver`; респавн мертвого
сервісу по абсолютному шляху). **Єдиний писар `watchdog-state.json`**
(§7.1 #7), переписує щотіку заради свіжості `mtime`.
`#[tokio::main(flavor = "current_thread")]` (§7.1 #9). `main` не
юніт-тестований (прецедент); логіка — у `watchdog::loop_driver`. Звірка:
збігається з SPEC.md §7. Розбіжностей нема.

### `dnsqb-tray` — `crates/dnsqb-tray/src/main.rs`
Місія (код, цитати з модуль-док): **«has no window of its own»**, **«full
configuration moved to the browser»**, **«never owns `dnsqb-service` as a
child process»**. Довготривалий фоновий процес, робота якого — (а) живий
статус резолвера в тултипі/кольорі іконки (опитує `/admin/status` кожні
2с на власному OS-потоці), (б) ~5 мишо-орієнтованих lifecycle-дій через
`/admin/*` + флаг-файли, без термінала. → **Це UI-клієнт + lifecycle-
актуатор, а не «сервіс»** у сенсі «виконує роботу / тримає контракт».
Звірка: SPEC.md §0 рядок 12a вже кваліфікує його як «окремий довготривалий
**фоновий процес**… інший клас», SERVICES.md каже «три **бінарники** /
процеси» (не «сервіси»). **Репозиторій уже класифікує це коректно** —
єдина правка стосується скороченого формулювання самого ревʼю: не
«три сервіси», а **«1 сервіс + 1 watchdog + 1 tray-актуатор»**. Це не
знахідка про репо (Правило 0), лише уточнення рамки для Фази 3
(«контракти між трьома сервісами» → «контракти сервіс↔watchdog і
актуатор→сервіс», різні класи).

---

## 3. Baseline інструментів (усе `gnu-local`, `--locked`, 2026-09-10)

| Крок | Команда | Результат |
|---|---|---|
| build | `cargo build --workspace` | **OK** (29 с) |
| unit | `cargo test --workspace --lib --bins` | **OK** — 722 passed, 6 ignored, 0 failed |
| conformance | `cargo test --test conformance -p dnsqb-service` | **OK** — 32 passed, 0 failed |
| conformance `--ignored` | `… -- --ignored` | **2 passed, 0 failed** — «інформаційний red board» із CLAUDE.md фактично зелений (усі Фаза-1/2 `#[ignore]` знято по мірі закриття задач). Розбіжність тексту CLAUDE.md з фактом — `minor`, у беклог. |
| examples | `cargo test --workspace --examples` | **не прогнано окремо локально** (компіляція в build OK; CI має цей крок для тестів `curate_topn`) |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | **OK** (exit 0) |
| fmt | `cargo fmt --all -- --check` | не прогонявся (CI зелений на HEAD) |
| doc + doctests | `cargo doc … -D warnings` / `cargo test --doc` | не прогонявся локально; **doc-тестів нуль** (гейт існує) |
| audit | `cargo audit` | **exit 0**, 2 non-fatal warnings (див. нижче) |
| deny | `cargo deny check` | **OK** — advisories / bans / licenses / sources усі `ok` |
| coverage | `cargo llvm-cov` | **інструмент не встановлено локально** (лише CI через `taiki-e/install-action`); `llvm-tools-preview` у пін-toolchain є |
| Miri | — | **N/A** — недоступний для `1.98.0-windows-gnu`, потребує nightly. Не в CI. |

### `cargo audit` — 2 попередження (не suppress, це дефолтна поведінка)
Немає `.cargo/audit.toml`, немає `ignore` у `deny.toml` — «2 allowed
warnings» = звичайне non-fatal ставлення `cargo audit` до
`unmaintained`/`unsound`.
- `proc-macro-error` 1.0.4 — unmaintained (RUSTSEC-2024-0370)
- `glib` 0.18.5 — unsound `Iterator` impl (RUSTSEC-2024-0429)

Обидва — транзитивні по GTK/Linux-гілці (`rfd`/`tray-icon` all-target
lockfile-записи). **`cargo deny` їх не бачить** (граф пінений до
`x86_64-pc-windows-msvc`), **`cargo audit` сканує весь `Cargo.lock`** без
target-фільтра. Жоден не компілюється у бінарник, що постачається.
Записано як tooling-нотатка, не безпекова знахідка — перевірити у Фазі 2,
чи це вже десь зафіксовано (ймовірно SECURITY.md).

### Оточення
Хост `gnu`, ship-таргет `msvc` — усі локальні baseline можуть розійтися
з CI (T-50 — власний шрам: локально зелено, на раннері червоно через
інші дефолтні ACL). Локальний build пройшов без gnu-специфічних зачіпок
лінкера.

---

## 4. Межі між процесами — контракти й власники

| # | Канал | Транспорт | Формат | Власник / писар | Що при частковому оновленні |
|---|---|---|---|---|---|
| 1 | service ↔ watcher, liveness ч.1 | named pipe (`#[cfg(windows)]`) | 20-байт `Frame` (`watchdog::frame`) | pipe-сервер у service; клієнт у watcher | нова версія `Frame` без узгодження = `NoSignal` → хибний респавн-цикл. **Перевірити версіонування `Frame` у Фазі 3.** |
| 2 | liveness ч.2 | файли `service.hb` / `watcher.hb` / `tray.hb` | mtime (`heartbeat_file::is_stale`) | кожен процес чіпає свій | формат — лише mtime, крос-версійно стабільний |
| 3 | liveness ч.3 | `GET /health` на DoH-порту | JSON `HealthResponse` | service віддає; watcher-`AdminClient` читає | 200 сам є сигналом; зміна тіла сумісна |
| 4 | стан watchdog | `watchdog-state.json` | JSON `WatchdogStateFile` (§7.1 #7) | **watcher — єдиний писар**; читачі: tray, `/admin/status` | stale/absent → «watchdog не працює», ніколи не «записаний стан». `resume` <90с. |
| 5 | lifecycle | `stop.flag` / `quit.flag` | наявність файлу (вміст не читається) | пише tray; читають service (`pause_watch`) і watcher; watcher чистить обидва на старті | крос-версійно стабільно (сама наявність) |
| 6 | onboarding | `onboarding.seen` | наявність файлу | лише tray | — |
| 7 | single-instance | `service.lock` / `watcher.lock` / `tray.lock` + `*.pid` | `share_mode(0)` + JSON `{pid,exe_path,started_at}` | кожен процес свій | `.pid` не видаляється на виході — джерело PID для watchdog |
| 8 | адмін-канал (дії) | HTTPS `127.0.0.1`, **той самий порт/cert, що DoH** | JSON DTO, `application/json` CSRF-гейт на write | service; клієнти: tray (cert-пінінг `cert.pem`), браузер | **tray нової версії + service старої**: DTO-сумісність не версіонована явно — **зона ризику Фази 3** |
| 9 | вбудований UI | `GET /admin/ui[/main.js,/style.css]` | HTML/CSS/JS `include_str!`, строгий CSP | service | — |
| 10 | конфіг на диску | `resolver_config.toml` / `overrides.toml` | TOML | людина пише / service читає; кожен write-роут ділить `persist_lock` + читає інші поля перед save | hard-cutover без dual-format shim (зафіксований патерн) |
| 11 | секрети | Windows Credential Manager (`keyring`) | 3 записи: TLS-ключ, MaxMind-креди, `persistence-key` | service | — |
| 12 | апстріми | HTTPS зовн. | DoH RFC 8484 | service | недовірені (Lower-layer) |
| 13 | GeoIP / top-N фіди | HTTPS зовн. | `.mmdb` / `.tar.gz` / список + checksum | service; atomic-swap після integrity-gate | недовірені (Lower-layer) |

Маршрути `/admin/*` (з коду, `dispatch::ROUTES` — allowlist перед
хендлер-`match`): `status`, `config`, `reset`, `shutdown`, `overrides[/add,/remove]`,
`cache-config[/apply]`, `geoip[/add,/remove,/maxmind,/maxmind/clear]`,
`providers[/add,/remove,/set-enabled,/set-category-enabled]`,
`rating-filter`, `log[/clear]`, `cert-status`, `install-cert`,
`uninstall-local-state`, `ui[/main.js,/style.css]`; поза `/admin/` на тому
ж лістенері — `GET /health`, `GET|POST /dns-query`.

---

## 5. Зони ризику для Фаз 1–5

| # | Зона | Файли | Фази | Чому |
|---|---|---|---|---|
| R1 | Пайплайн резолву §5.3 | `pipeline.rs` (1.1k прод) | 1, 2 | серце коректності: 7 упорядкованих кроків, cache-vs-live TTL, rating-filter «не кешується», GeoIP «live на кожен ALLOW» |
| R2 | Quorum OR-логіка + сигнатури блоку | `quorum.rs` (856), `upstream.rs` (573) | 1, 2 | `BlockSignature` евристики, sinkhole-префікси (hard-coded — вже зафіксовано як brittleness), `is_usable_answer` для baseline-fallback, CIDR на hot-path |
| R3 | `dispatch.rs` — транспорт + бізнес-логіка | `dispatch.rs` (3.25k прод, 18 роутів) | 1, 2, 3 | найбільший файл; CSRF-гейт однорідність; `FUZZ_EXCLUDED_ROUTES` ↔ fuzz-property взаємодія; чи логіка протекла в транспорт |
| R4 | Watchdog стан-машина + I/O-шели | `watchdog/{transition,loop_driver,budget,vote,state}.rs`, обидва `main.rs` | 1, 2, 3 | хибний респавн-цикл; budget не durable у напрямку service→watcher (вже зафіксовано); pure-крок мутує стан як побічний ефект (зафіксована гоча T-185) |
| R5 | Приватність — витік доменів у логи | `quorum.rs` `error_kind`, будь-який `tracing::` на шляху помилки | 2 | рекурентний баг-клас: `reqwest::Error` Display = домен; `toml::de::Error` = рядок `overrides.toml`; `ProtoError` |
| R6 | Персистенція / крипто | `encrypted_file.rs`, `persist_dto.rs`, `cache_persist_dto.rs`, `log_persist.rs`, `cache_persist.rs`, `key_store.rs` | 2, 3 | header-as-AAD валідація; версіонування формату (`PersistedFileV1`); осиротілі `.enc` накопичуються (вже зафіксовано); `Block` не персиститься (навмисно) |
| R7 | Довіра до вводу | `config.rs` (851), `overrides.rs`, `topn_download.rs`, `geoip_download.rs`, `geoip_updater.rs` | 2 | TOML-парсери; bounded decompress архівів; integrity-gate **перед** свопом; SSRF custom URL (literal-host only — вже зафіксовано) |
| R8 | Windows desktop-інтеграція | `local_state.rs`, `dnsqb-tray/self_uninstall.rs`, `trust_store.rs`, `cert_rotation.rs`, `watchdog/spawn.rs` | 2, 3 | MSIX без uninstall-хука → in-app wipe; `CurrentUser\Root` trust; detached-спавни (job breakaway, fallback на ERROR_ACCESS_DENIED) |
| R9 | Публічний API lib (споживач — tray) | `admin.rs` (1.6k), `admin_ui.rs`, `lib.rs` re-exports | 4 | `AdminClient` + DTO — єдина lib-поверхня, яку споживає інший крейт; API Guidelines, `must_use`, версіонування DTO |
| R10 | `persist_lock` cross-field-read | кожен write-роут, що ре-серіалізує `resolver_config.toml` | 2, 3 | рекурентний баг-клас T-57/T-139/T-149/T-47/T-77 — перевірити кожного писаря |
| R11 | Залежності | `Cargo.lock`, `deny.toml`, `SECURITY.md` | 2, 4 | 2 audit-warning (Linux-гілка); `multiple-versions = warn` шум; 475 крейтів у графі |
| R12 | Async-дисципліна | `pipeline.rs`, `geoip_updater.rs`, `reachability.rs`, `*_updater.rs`, `pause_watch.rs` | 2 | синхронне читання `.mmdb` на старті (T-160 — вже зафіксовано); lock через `.await`; detached-цикли, що публікують `Copy` в `AppState` |

Свідомо не покриті тестами класи (назвати ОДИН раз у Фазі 1, не по
сайтах — кожен має прецедент у CLAUDE.md): `#[cfg(windows)]` I/O-шели у
двох `main.rs`; `local_state::remove_all` / `remove_cert`; цикл
`pause_watch`; real-external-resource межа `trust_store` / `cert_rotation`
(їхні власні тести її не перетинають).

---

## 6. План партій Фази 1 (НАЙВИЩИЙ ПРІОРИТЕТ, ~17.5k прод-LOC, 722+32 тести)

Фаза 1 не влазить в один прохід. **4 партії**, кожна — окрема сесія:

| Партія | Модулі в скоупі | Приблизно прод-LOC |
|---|---|---|
| 1.1 — ядро резолву | `pipeline.rs`, `quorum.rs`, `upstream.rs`, `wire.rs`, `timeout.rs`, `cache.rs`, `overrides.rs` | ≈4.0k |
| 1.2 — адмін-межа | `dispatch.rs`, `admin.rs`, `admin_ui.rs`, `config.rs` | ≈6.6k |
| 1.3 — watchdog + персистенція | `watchdog/**`, `encrypted_file.rs`, `*_persist*.rs`, `persist_dto.rs`, `key_store.rs`, `lifecycle.rs`, `pause_watch.rs` | ≈4.5k |
| 1.4 — периферія + tray/watcher | `geoip*`, `reachability.rs`, `baseline_selector.rs`, `topn_*`, `rating_filter.rs`, `trust_store.rs`, `cert*.rs`, `local_state.rs`, `logging.rs`, `dnsqb-tray/**`, `dnsqb-watcher/main.rs`, `tests/conformance/**`, `examples/**` | ≈4.5k |

Кожна партія покриває свій зріз чотирьох сценарних категорій
(Happy / Security & Boundary / Misuse & Fool / Error, + Concurrency/Recovery)
і межу `/admin/*` за SPEC.md §8.1 (smoke / exploit / misuse / fuzz).

---

## 7. Що НЕ увійшло в baseline (чесний список прогалин Фази 0)
- `cargo fmt --check`, `cargo doc`, `cargo test --doc`, `cargo test --examples`
  — не прогонялися локально (CI зелений на HEAD `0ecab35`; docs-only коміти
  CI не запускають, але HEAD не docs-only).
- Покриття (`llvm-cov`) — інструмента локально нема. Фаза 1 бере ручну
  карту «поверхня vs тести» або артефакт `coverage-lcov` з CI.
- MSVC-прогін будь-чого — нема (хост gnu).
- `cargo tree` повний аналіз графа — відкладено на Фазу 2/4 (R11).
