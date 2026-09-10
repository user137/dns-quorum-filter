# review/02-CORRECTNESS.md — Фаза 2: Коректність і безпека (рамка Три Б)

> Це review-артефакт, не частина DOC MAP (`CLAUDE.md`). Джерело істини —
> `SPEC.md`/`DECISIONS.md`. Знахідки, що переживають ревʼю, переїжджають
> у `TASKS.md`. Прогони baseline позначено місцем (`gnu-local` / `CI`).
>
> Дата: 2026-09-10. HEAD `0ecab35`.

---

## Скоуп і структура фази

Фаза 2 — **наскрізна**, не помодульна: `unsafe` / panic-поверхня /
модель помилок / приватність / async / конкурентність / довіра до вводу /
authn-authz / ресурси — по всьому `crates/**/src` (≈19.2k прод-LOC),
`SECURITY.md`, `deny.toml`.

**Один прохід, не партії.** Причина: статична половина (`unsafe`, panic,
модель помилок, приватність) дала **лише вже-зафіксовані пункти + один
`minor` про доку `SECURITY.md`** — окремий звіт «Батч 2.1» був би майже
порожній. Динамічна половина (async / конкурентність / вхід / authz)
теж підтверджує наявну дисципліну. Тому все в одному файлі.

Baseline (з `00-MAP.md`, `gnu-local`, `--locked`, 2026-09-10) не
перепрогонявся — HEAD не змінився.

---

## 1. `unsafe` — first-party = 0  ✅

`#![forbid(unsafe_code)]` на **всіх** кореневих одиницях компіляції:
`crates/dnsqb-service/src/lib.rs:1`, `dnsqb-service/src/main.rs:4`,
`dnsqb-tray/src/main.rs:2`, `dnsqb-watcher/src/main.rs:5`. Кожне
входження токена `unsafe` в `crates/**` — у `//!`/`///`/`//` коментарі
(перевірено grep'ом: 8 входжень, усі — пояснення *чому тут немає*
`unsafe`). Перший-party `unsafe` = **0**, без винятків.

### Vendored-FFI поверхня vs containment-твердження `SECURITY.md`

`SECURITY.md` §"Runtime dependencies" (рядки 165–174) веде колонку
`unsafe / accepted risk` для кожного крейта з FFI:

| Крейт | FFI-поверхня | Рядок `SECURITY.md` | Твердження досі істинне? |
|---|---|---|---|
| `keyring` → `windows-native-keyring-store` | Win32 `Cred*` | 170 | ✅ (+ рядок сам фіксує `cargo audit`↔`cargo deny` асиметрію) |
| `sysinfo` → `ntapi` / `windows-*` | NT process table | 171 | ✅ (+ фіксує асиметрію з §7.1 #2, який цей самий стек *відхилив* для instance-guard) |
| `chacha20` / `poly1305` | SIMD | 172 | ✅ |
| `embed-resource` → `vswhom-sys` | локатор `rc.exe`, лише build-host | 174 | ✅ (не лінкується у shipped binary) |
| `maxminddb` / `flate2` / `tar` | — (pure-Rust, `default-features = false`) | 165–166, 169 | ✅ |

**Знахідка 2-A нижче**: `aws-lc-sys` (C-крипто за `rustls`/`rcgen`
`aws_lc_rs`) — єдина FFI-несуча залежність, чий containment **не**
розписаний у цій таблиці так, як решта.

Miri — `N/A` на цьому оточенні (недоступний для `1.98.0-windows-gnu`,
не в CI). Не фабрикую вивід.

---

## 2. Panic-поверхня — **0 прод-сайтів** ✅  (закриває 1.3-B)

Скан коректним патерном (`#[cfg(test)]` **і** `#[cfg(all(test, …))]`
відсікаються):

- `.unwrap()` / `.expect()` поза тест-модулями: **0**. Усі 4 текстові
  збіги в `crates/*/src/**` — у `//!`/`///` коментарях
  (`encrypted_file.rs:194`, `geoip.rs:247`, `tls.rs:23/30` — усі
  пояснюють, чому `.expect()` тут *не* вживається).
- `panic!(` / `unreachable!(` / `todo!(` / `unimplemented!(` поза
  тестами: **0**. Усі ~800 текстових входжень `panic!(` — у
  `#[cfg(test)]` / `#[cfg(all(test, windows))]` модулях (патерн
  `let-else { panic!() }` замість `.unwrap()`, бо
  `#![deny(clippy::unwrap_used, clippy::expect_used)]` діє й на inline-
  тести — CLAUDE.md gotcha).
- `#![deny(clippy::unwrap_used, clippy::expect_used)]` на всіх трьох
  кореневих, і **жодного** `#[allow(clippy::unwrap_used|expect_used|panic)]`
  ніде (grep — 0).
- Startup-збої (`main.rs:483/487/494`, `AlreadyRunning` / `Io` на
  lock-файлі / `UnsupportedPlatform`) — `tracing::error!` + `std::process::
  exit(1)`. Це fail-fast на старті, не паніка в працюючому сервісі;
  `UnsupportedPlatform`-гілка іменована лише для exhaustiveness
  (`deny.toml` пінить таргет до windows-msvc), з коментарем «never
  `unreachable!()`».

**Наслідок для 1.3-B**: підказка ревʼю-промпту («`watchdog/instance.rs`
~13, `tls.rs` 2, `quorum.rs` 1, `main.rs` 1 panic-сайтів») була
**повністю** артефактом `awk`-скану, що не відсікав `#[cfg(all(test,
windows))]`. Реальна прод-panic-поверхня = 0. Виправити цифри в
`00-MAP.md` §3 і `01-TESTS.md` 1.1 у Фазі 5 (як і планувалося в 1.3-B).

### Арифметика / індексація на зовнішніх числах

- CIDR (`SinkholeNet::contains`, `upstream.rs:312+`) — `(ip.to_bits() ^
  net.to_bits()).leading_zeros() >= prefix`, **без зсуву** → немає
  `<< 32` / `<< 128` overflow-панік (CLAUDE.md gotcha; інваріант
  `1..=32` / `1..=128` робить «match everything» непредставним — немає
  `Default`).
- TTL — `cache::clamp_ttl` / `chain_cache_ttl`; лічильники → `u64::
  try_from(...).unwrap_or(u64::MAX)` (`admin.rs:1152`) — panic-free
  конверсія, не `.unwrap()`.
- Жодного raw slice-індексування (`[a..b]`, `[n]`) чи `as usize` на
  wire/hot-path (`wire`/`pipeline`/`quorum`/`cache`/`upstream`) — grep
  дав лише один збіг, і той у doc-коментарі. Wire-парсинг — через
  `hickory-proto`, не ручний.

---

## 3. Модель помилок  ✅

- `thiserror` наскрізно; **`anyhow` / `eyre` — 0 входжень** у всьому
  workspace (grep). Відповідає `~/.claude/rules/rust.md` §4 (lib =
  типізовані `enum`, не контекстні помилки).
- `?` — не губить контекст: помилки везуть `#[source]`-ланцюг
  (`UpstreamError`, `TlsError`, `ConfigError`, `AdminResetError`, …).
- Проковтнуті помилки (`let _ =`, `.ok()`, `Err(_) =>`, `=> {}`): скан
  ~120 сайтів — **усі** або в тест-модулях, або з коментарем-чому
  (`lifecycle.rs:88–91`, `cache.rs:377–386`), або очевидно навмисні
  (`dispatch.rs:1418/1423` — «running it *is* the check», health-probe;
  event-loop `_ => {}` fallthrough меню). Порушень «порожній catch без
  причини» немає.
- **Знахідка 2-C** (нижче, `nit`): `dispatch.rs:1397` / `:1789` —
  `Err(_) => status_response(500 / 400)` без жодного `tracing::debug!`
  коарс-лейбла.

---

## 4. Приватність — доменні імена в логах  (наскрізний підрозділ)

### Гарячий шлях — чисто ✅

- `pipeline.rs` — **0** викликів `tracing::` у всьому модулі. Нічого
  логувати, нічого текти.
- `quorum::error_kind` (`quorum.rs:584`) — мапить `UpstreamError` у
  `&'static str` (`"encode"`/`"http"`/`"decode"`), **свідомо не чіпає**
  `Display` помилки; `log_outcome` / `log_canceled` логують лише
  `provider = <id>` (власний конфіг, не браузинг) + фіксований рядок.
  Коментар на місці пояснює точно цей leak-клас. Це **еталон**.

### Чек-ліст відомих векторів витоку (з ревʼю-промпту)

| Вектор | Стан | Джерело |
|---|---|---|
| `reqwest::Error` Display = base64url-запит = домен | `UpstreamError::Http(#[source] reqwest::Error)` з `#[error("… {0}")]` (`upstream.rs:518`) — Display **тече**, але **жоден прод-сайт його не викликає** (перевірено: усі `tracing::` на шляху апстрім-помилки йдуть через `error_kind`). `TopnUpdaterError::Http` / `GeoipUpdateError::Http` теж wrap `reqwest::Error`, але їхні URL — статичні `raw.githubusercontent.com` / db-ip, без браузинг-домену, і коментарі підтверджують «every `reqwest::Error` is dropped». `AdminClientError` — URL `127.0.0.1/admin/*`, без браузинг-домену. | **ВЖЕ ЗАФІКСОВАНО** — CLAUDE.md gotchas + review 1.1-B (немає guard-тесту на `UpstreamError` Display, як `overrides.rs` має на своєму) |
| `toml::de::Error` Display/Debug друкує рядок файлу | `config.rs:68` (`ResolverConfigError::Toml`) **тримає** payload — свідомо: `resolver_config.toml` не містить доменів. `overrides.rs:141` (`OverrideError::Parse`) — **payload-free** за дизайном, бо `overrides.toml` містить домени. | **ВЖЕ ЗАФІКСОВАНО** — `SECURITY.md:160` («deliberate leak-prevention split»), `overrides.rs:141` doc |
| `ProtoError` повідомлення | `overrides::InvalidReason` — закритий enum із фіксованими `#[error(...)]` рядками замість `reason: ProtoError` (перша версія леакала). `Debug` `InvalidEntry` редагує `raw`, є тест `…debug_output_never_contains_the_raw_pattern_text`. | **ВЖЕ ЗАФІКСОВАНО** — `overrides.rs:62–64` doc + CLAUDE.md gotcha |

Query-log — in-memory ring buffer за замовчуванням; персист опційний +
`XChaCha20Poly1305` (`encrypted_file`), ключ у OS secret store. Без змін
з Фази 1.

**Нова знахідка приватності — немає.** Механізми відомі, кодифіковані,
з тестами; єдина прогалина (guard-тест на `UpstreamError`) вже
зафіксована як 1.1-B.

---

## 5. Async-дисципліна  ✅

- **Lock через `.await`**: `persist_lock` / `overrides_persist_lock` /
  `geoip_source_lock` — це синхронні `parking_lot::Mutex<()>`. Перевірено
  `apply_rating_filter_change` (`dispatch.rs:2153–2215`) як зразок: guard
  живе рівно в синхронному блоці `{ … config.save(&paths.config) … }`
  (де `config.save` = `std::fs::write`, `Cache::new` = синхронний
  конструктор `moka::future::Cache`), потім дропається; async (побудова
  відповіді через `admin_status`) — **після** дропу. Doc-коментарі
  всіх писарів це стверджують явно («response built after the guard
  drops», «avoids a blocking watchdog-file read under the lock»).
  Порушень немає.
- **Блокуючі виклики в async**: `certutil` спавн → `tokio::task::
  spawn_blocking` (`dispatch.rs:3065`, `serve_admin_install_cert`).
  Синхронні `std::fs::read`/`write` — лише в: (1) startup-шляху
  (`load_geoip_state`, `load_*_persisted_*`, `tls::load_or_generate`),
  (2) виділених фонових тасках (`run_geoip_updater`/`run_topn_updater`/
  персистери), не на shared-runtime hot-path. T-160 (синхронний ~8 MB
  `.mmdb` на старті, безумовно) — **ВЖЕ ЗАФІКСОВАНО** (CLAUDE.md).
- **Unbounded-канали / витік task'ів**: `mpsc::unbounded_channel` — 0.
  Пробудження апдейтерів — `tokio::sync::Notify` (без черги). ~9
  `tokio::spawn` у `main.rs` — довічні daemon-таски (персистери,
  апдейтери, reachability, watchdog-халфи) + per-connection спавн в
  accept-loop, обмежений `admission::ConnectionGate`
  (`OwnedSemaphorePermit`, T-169). Daemon-таски не `.abort()`-яться на
  shutdown — прийнятно: stateful (`run_query_log_persister` /
  `run_cache_persister`) роблять flush по shutdown-сигналу,
  connection-таски дренуються `hyper_util` graceful (5 с кеп,
  `main.rs:715–718`).
- **Cancellation-safety**: доведена в `quorum::resolve` (`start_paused`
  + `Instant::now()` elapsed ≈ 0 проти `pending()`-мока) — Фаза 1 1.1
  підтвердила.

---

## 6. Конкурентність  ✅  (R10 — рекурентний баг-клас — активно стережений)

- **`persist_lock` cross-field-read** (T-57/T-139/T-149/T-47/T-77):
  кожен писар `resolver_config.toml` бере `persist_lock` **перед**
  read-modify-write і читає живі значення інших полів перед `save`.
  Перевірено всі 7:
  `apply_admin_config` (1309), `apply_admin_reset` (1555),
  `apply_overrides_*` (1735, через `overrides_persist_lock`),
  `apply_cache_config` (1859), `apply_provider_change` (2011),
  `apply_geoip_change` (2164), `apply_rating_filter_change` (2508),
  `set_category_enabled` (усі через `persist_lock`). Кожен
  `ResolverConfig { … }`-літерал явно тягне `persist_query_log` /
  `persist_cache` / `limits` / `providers` / `geoip` з живого стану
  (див. `dispatch.rs:2194–2202` — коментар «this write rewrites the
  whole file»).
- **Порядок замків задокументований**: `geoip_source_lock` →
  `persist_lock` → `overrides_persist_lock`; `apply_admin_reset` —
  **єдина** функція, що тримає більше одного (`dispatch.rs:779–783,
  1523–1524`). Deadlock-цикл структурно неможливий.
- **5 concurrency-тестів** саме на цю дисципліну (Фаза 1 1.2 —
  `concurrent_admin_config_posts…`, `…_and_cache_config_posts…`,
  `…reset_and_cache_config_apply…`, `a_zone_removal_survives_a_
  concurrent_zone_swap`). Один із них раніше падав 16/20 без
  `persist_lock` (`dispatch.rs:4810`).
- **`RwLock<Arc<T>>` патерн**: читач `Arc::clone`-ає й не тримає lock
  через `.await` — дотримано (`state.cache.read()`, `.geoip_countries.
  read().as_ref().clone()`, `providers_snapshot()`, `runtime.read()`).
  `parking_lot::RwLock` для query-log ring buffer — `SECURITY.md:149`
  стверджує «no `.await` under this lock», підтверджено.

---

## 7. Довіра до вводу (Software safety)  ✅

- **Bounded decompress — на ДВОХ рівнях**:
  `MAX_GEOIP_COMPRESSED_BYTES` 64 MiB (стрімовий кеп під час
  завантаження, `geoip_updater.rs:513/632`) **і**
  `MAX_GEOIP_DECOMPRESSED_BYTES` 256 MiB
  (`GzDecoder::new(...).take(max_bytes + 1)` → помилка при
  перевищенні, `geoip_download.rs:129`). `topn_download`: `MAX_TOPN_BYTES`
  8 MiB. Tar-entry «already length-delimited by the archive header», без
  path-traversal («no path is ever built from an archive entry» —
  `SECURITY.md:169`).
- **Integrity gate ДО свопу**: sha256/sha1 sidecar
  (`topn_download::verify_sha256`, `geoip_updater` `.sha256`/`.sha1`) +
  atomic-swap (`paths::write_atomic` = temp + `sync_all` + `rename`).
  Відповідає SPEC.md §3.5. Іменовані тести (Фаза 1 1.4).
- **SSRF на custom provider URL** (`upstream::validate_provider_url:462`):
  `scheme != "https"` → відмова; для **літерального IP-хоста** —
  `is_loopback|is_private|is_link_local|is_unspecified` (v4) + ULA/
  link-local/loopback/unspecified (v6). Хост, що *резолвиться* у
  приватну адресу під час запиту, — не ловиться. **ВЖЕ ЗАФІКСОВАНО** —
  CLAUDE.md «Known limitations» (T-72), «literal-host only».
- **DNS wire** — `hickory-proto`, не ручний парсер. Негативний юніт на
  `decode_wire_message` — **ВЖЕ ЗАФІКСОВАНО** як 1.1-D (клас «панік на
  wire-декоді» покрито на рівні `serve` fuzz — 1.2-C).
- **TOML-конфіги** — `config.rs` / `overrides.rs`: кожна таблиця має
  тест на помилковий ключ, розмірний ліміт на межі + байт над (Фаза 1
  1.2 — «рівень еталона»).

---

## 8. authn / authz веб-панелі  ✅

- **`127.0.0.1`-only bind** — `listener::bind_listener`; тест
  `binding_an_already_bound_port_is_an_explicit_error_not_a_silent_
  fallback` (Фаза 1 1.4). Ніколи `0.0.0.0`.
- **`dispatch::ROUTES` allowlist перед хендлер-`match`** — path/method
  не з таблиці не досягає хендлера (T-59, «властивість зроблено даними»);
  тести `serve_matches_the_documented_admin_route_allowlist`,
  `serve_enforces_the_route_table_it_matched_above`.
- **CSRF-гейт `application/json` на КОЖНОМУ write-роуті** —
  `every_json_post_route_rejects_a_missing_or_wrong_content_type`
  **ітерує `ROUTES`** (Фаза 1 1.2), тож новий write-роут автоматично
  під покриттям.
- **`GET /health`, `GET /admin/cert-status`** — без CSRF-гейта, і це
  **коректно** (GET, без мутації стану). Але див. 2-B.

---

## 9. Ресурси  ✅

- Atomic-write — `temp + sync_all + rename` (scratch-probed, CLAUDE.md
  gotcha; `sync_all` **до** rename — інакше renamed-but-empty при
  power-loss).
- Graceful shutdown — `hyper_util` `server-graceful`, 5 с кеп на дренаж
  зʼєднань; персистери роблять фінальний flush по shutdown-сигналу.
- Процеси — `certutil` через `certutil_command` з `CREATE_NO_WINDOW`
  (T-194); detached-спавни (`watchdog::spawn`, `self_uninstall`) —
  `DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB` з fallback на
  `ERROR_ACCESS_DENIED`.
- Файли/сокети — RAII (`Drop`), instance-guard `share_mode(0)`.

---

## ЗНАХІДКИ

```
[2-A] severity: minor
Файл: SECURITY.md §"Runtime dependencies" (таблиця, рядки 150 і 153)
Категорія: безпека / документація
Джерело: ПІДТВЕРДЖЕНО В КОДІ (grep SECURITY.md рядки 150/153; `cargo tree
-e no-dev --target x86_64-pc-windows-msvc -i aws-lc-sys` — Фаза 5: у
ship-графі, `aws-lc-sys` v0.44.0 ← `aws-lc-rs` v1.18.0 ← `rcgen` +
`rustls` + `rustls-webpki`, лінкується в усі 3 бінарники; `ring` у
ship-графі немає — лише lockfile)
Три Б: lower-layer (vendored C-крипто — недовірений код у shipped binary)
Що: таблиця ветингу залежностей веде колонку «`unsafe` / accepted risk»
і для КОЖНОГО крейта з FFI явно стверджує containment
(`windows-native-keyring-store` рядок 170, `sysinfo`→`ntapi` 171,
`chacha20`/`poly1305` SIMD 172, `embed-resource`→`vswhom-sys` 174,
`maxminddb`/`flate2`/`tar` «no exception needed» 165–169). Рядки
`rustls` (153) і `rcgen` (150) у колонці accepted-risk говорять про
резолюцію crypto-провайдера і `zeroize`, але **не згадують `aws-lc-sys`**
— C-бібліотеку (форк BoringSSL) з найбільшою `unsafe`-поверхнею в
усьому shipped binary.
Чому важливо: не «баг», а прогалина у власній ветинг-дисципліні проєкту.
`aws-lc-sys` компілює C і має обширний `unsafe` FFI; якщо мета таблиці —
«де живе `unsafe` кожної залежності, actionable today» (її власне
формулювання, рядок 136), то найбільший блок пропущено. Ворожий
сценарій: майбутній RUSTSEC проти `aws-lc-sys` не має рядка-якоря для
тріажу; контриб'ютор, що звіряє «first-party unsafe = 0» з реальністю,
не знаходить у таблиці, чим це компенсовано для крипто-стека.
Вже зафіксовано в: — (SPEC.md §2 називає TLS-leaf «найбільшою поверхнею
атаки», але про *ключ*, не про `aws-lc-sys` як код).
Варіанти:
  1. Додати один рядок accepted-risk до `rustls`/`rcgen`: «`unsafe` C
     FFI у `aws-lc-sys` (форк BoringSSL, FIPS-audited lineage);
     `#![forbid(unsafe_code)]` first-party інтакт; альтернатива —
     `ring` — теж C/asm, а pure-Rust провайдера продакшн-рівня в
     `rustls` немає». Дешево, чесно, нічого в коді не змінює.
  2. Дослідити pure-Rust rustls-провайдер (`rustls-rustcrypto` —
     не production-ready). Дорого, регрес по зрілості крипто.
  3. Не чіпати. Тредоф: таблиця лишається асиметричною — єдиний
     FFI-крейт без явного containment-рядка.
Рекомендація: Варіант 1. Це доку-фікс у `SECURITY.md` (ревʼю його НЕ
пише — виносити рядком у `TASKS.md` у Фазі 5).
Тест, який би це зловив: N/A (повнота ветинг-таблиці).
```

```
[2-B] severity: nit
Файл: dispatch.rs:3018 (`serve_admin_cert_status`), 3065
(`serve_admin_install_cert`)
Категорія: безпека
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: lower-layer / software
Що: `GET /admin/cert-status` не має CSRF-гейта (коректно — це GET) і на
кожен виклик спавнить 2 процеси `certutil` (`-dump` / `-store` через
`trust_store::is_trusted`). Будь-який процес на `127.0.0.1` (не лише
браузер) може ганяти цей роут у циклі → керований потік спавнів
`certutil`.
Чому важливо: мінімально. Пом'якшення на місці: bind лише `127.0.0.1`;
`admission::ConnectionGate` кеп на конкурентні зʼєднання; `certutil
-dump` — дешева локальна операція; `CREATE_NO_WINDOW` (нема вікон-
флешу). Локальний процес і так має більше прав, ніж дає цей вектор. Але
«GET спавнить процес» — це не безкоштовний read, як `/health`.
Вже зафіксовано в: частково — `FUZZ_EXCLUDED_ROUTES` виключає обидва
cert-роути з fuzz-property саме тому, що вони спавнять `certutil`
(dispatch.rs коментар ~3035–3040); але це про тест-навантаження, не про
рантайм-вектор.
Варіанти:
  1. Кешувати результат `is_trusted` на N секунд у `AppState` (той
     самий «detached watch публікує стан» патерн, що вже є в tray
     `status::spawn_trust_watch`) — `GET /admin/cert-status` читає кеш,
     не спавнить. Тредоф: ще одна фонова нитка / поле стану.
  2. Не чіпати — прийняти як «локальний процес і так всемогутній».
Рекомендація: Варіант 2 для PET-масштабу; Варіант 1 лише якщо
`cert-status` колись піде на частий poll з `/admin/ui` (зараз — на
відкриття сторінки + дію оператора).
Тест, який би це зловив: N/A (навантажувальна властивість, не баг).
```

```
[2-C] severity: nit
Файл: dispatch.rs:1397, 1789
Категорія: спостережуваність (не приватність)
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: —
Що: `Err(_) => status_response(StatusCode::INTERNAL_SERVER_ERROR)`
(1397) і `Err(_) => status_response(StatusCode::BAD_REQUEST)` (1789) —
помилка відкидається без жодного `tracing::debug!`/`warn!` навіть із
коарс-лейблом. 500 без рядка в лозі не діагностується без дебагера.
Чому важливо: мінімально — це шляхи serde-серіалізації статус-відповіді
(1397) і парсингу (1789), обидва структурно без доменних імен, тож
коарс-лог тут приватнісно безпечний (на відміну від апстрім-шляху, де
`error_kind` обов'язковий). Контраст із рештою `dispatch.rs`, де кожен
disk-persist-фейл логується `tracing::warn!("… : {err}")`.
Вже зафіксовано в: —
Варіанти: один, очевидний — `tracing::debug!` з `&'static str` міткою
(«status response serialization failed» / «admin log query parse
failed»), без інтерполяції помилки.
Рекомендація: розглянути в Фазі 3 разом із загальною оцінкою
достатності `logging` (чи можна діагностувати збій без дебагера) — не
окрема Фаза-2-дія.
Тест, який би це зловив: N/A (спостережуваність).
```

```
[2-D] severity: nit
Файл: admin.rs:1185
Категорія: стиль (застаріла доку)
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Що: doc-коментар `AdminClient` каже «(e.g. `dnsqb-ui`'s Tauri commands)»
і «avoids two crates having to track matching `reqwest` versions». Tauri-
канал і крейт `dnsqb-ui` видалені на T-149 (DECISIONS.md). Реальні
споживачі тепер — `dnsqb-tray` і `dnsqb-watcher`.
Чому важливо: тривіально; вводить в оману читача про архітектуру.
Рекомендація: доку-фікс у Фазі 5 (переїзд у `TASKS.md` не потрібен).
Тест, який би це зловив: N/A.
```

---

## Вже зафіксовано (Правило 0 — рядком, не блоком)

- `upstream.rs:518` — `UpstreamError::Http` Display тече домен; жоден
  прод-сайт не викликає, guard-тесту немає — CLAUDE.md gotchas + review
  **1.1-B**.
- `upstream.rs:462` — SSRF `validate_provider_url` literal-host only —
  CLAUDE.md «Known limitations» (T-72).
- `SECURITY.md:170` — `cargo audit` (весь `Cargo.lock`) vs `cargo deny`
  (граф пінений до windows-msvc): 2 warning'и (`proc-macro-error`
  unmaintained, `glib` unsound — Linux/GTK-гілка) — **закриває відкритий
  пункт `00-MAP.md` §3**: так, це вже зафіксовано, як «stated, live
  maintenance liability».
- `main.rs` `load_geoip_state` — синхронний ~8 MB `.mmdb` read на старті
  безумовно — CLAUDE.md «Known limitations» (T-160).
- Осиротілі `.enc` (`query-log.enc` / `cache.enc`) накопичуються, немає
  cleanup-шляху — CLAUDE.md «Known limitations».
- `fail_closed` timeout-`Block` кешується в памʼяті на `block_verdict_ttl`
  і переживає мережевий outage — CLAUDE.md «Known limitations».
- `quorum::combine().incomplete` не спрацьовує на SERVFAIL-воутері —
  CLAUDE.md gotchas + `lib.rs` `should_serve_stale` коментар.
- `toml::de::Error` / `ProtoError` leak-вектори — закриті за дизайном:
  `SECURITY.md:160` (deliberate split), `overrides::InvalidReason`
  закритий enum.

---

## Позитив (Правило 5 — по одному реченню)

- **`unsafe` = 0, прод-panic = 0, `anyhow` = 0** — тройка, яку
  `rust.md` §4/§6 вимагає, тут виконана буквально, без жодного `#[allow]`.
- **`persist_lock` дисципліна** (R10, рекурентний баг-клас проєкту):
  усі 7 писарів `resolver_config.toml` йдуть через неї, порядок замків
  задокументований, `apply_admin_reset` — єдиний мульти-холдер, guard
  живе лише в синхронному коді, 5 concurrency-тестів стережуть це.
- **Bounded decompress на двох рівнях** (compressed 64 MiB + decompressed
  256 MiB) + sha256/sha1 sidecar + atomic-swap після integrity-gate —
  точно як мандат SPEC.md §3.5.
- **Гарячий шлях резолву німий**: `pipeline.rs` — 0 `tracing::`;
  `quorum::error_kind` мапить у `&'static str`, ніколи не чіпаючи
  `Display` помилки — еталон закриття leak-класу.

---

## Стан Фази 2: **ЗАВЕРШЕНА**

**Blocker — немає.** Фаза не виявила жодного баг-класу коректності й
жодної нової експлуатовної діри. Всі динамічні дисципліни (async-lock-
scope, порядок замків, bounded input, CSRF-однорідність) — на місці й
покриті тестами. Чотири знахідки — усі `minor`/`nit`, з них 2-A і 2-D —
доку-фікси в `SECURITY.md` / `admin.rs`, 2-B — добре пом'якшений
рантайм-нюанс, 2-C — спостережуваність (→ Фаза 3).

Per протокол: `advisor()` між фазами — лише якщо фаза підняла `blocker`.
Не підняла → без виклику.
