# review/01-TESTS.md — Фаза 1: Тести й тестопридатність

> Це review-артефакт, не частина DOC MAP (`CLAUDE.md`). Джерело істини —
> `SPEC.md`/`DECISIONS.md`. Знахідки, що переживають ревʼю, переїжджають
> у `TASKS.md`. Baseline-прогони позначено місцем (`gnu-local` / `CI`).
>
> Фаза 1 розбита на 4 партії (див. `00-MAP.md` §6), кожна — окрема сесія.
> Дата старту: 2026-09-10. HEAD `0ecab35`.

---

## Партія 1.1 — ядро резолву  ✅ (ця сесія)

Скоуп (7 файлів, R1/R2): `pipeline.rs` (1097 прод) · `quorum.rs` (856) ·
`upstream.rs` (573) · `wire.rs` (133) · `timeout.rs` (78) · `cache.rs` (427) ·
`overrides.rs` (284).

### Стан на вході — коротко
Ядро **щільно протестоване**. ~230 тест-функцій у цих 7 файлах
(`pipeline` ≈70, `quorum` ≈60, `overrides` ≈40, `cache` ≈25, решта менше)
плюс conformance `rfc_1035` / `rfc_4033_4035` / `rfc_2181` / `rfc_2308`.
Тавтологій (`assert_eq!(2+2,4)`-класу) **не знайдено** — навіть межові
випадки (`timeout_mode_round_trips_…_json`) несуть коментар-обґрунтування,
чому це доказ, а не формальність.

Детермінізм — чисто: `#[tokio::test(start_paused = true)]` скрізь, де час
має значення (`timeout.rs` обидва тести, `quorum.rs` 7 тестів скасування
з перевіркою `tokio::time::Instant::now()` elapsed ≈ 0), `cache.rs`
інʼєктує `now: Instant` у `is_fresh` / `CacheExpiry`, один свідомий
реальний `sleep` для перевірки саме moka-таймінгу (задокументовано в
CLAUDE.md gotchas). `overrides.rs` має `proptest` на `parse_pattern`
(ніколи не панікує, ніколи не повертає рядок із `*`).

### Знахідки

```
[1.1-A] severity: major
Файл: pipeline.rs — увесь модуль тестів (рядки ~1270–3000)
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: —
Що: ~70 тестів `handle_query`, і кожен — один послідовний виклик. Немає
жодного тесту категорії Concurrency/Recovery: два одночасні cache-miss на
той самий `CacheKey`, конкурентний доступ до спільного кешу в `AppState`,
поведінка при гонці «reload override-списків ↔ активний запит».
Чому важливо: `handle_query` — найгарячіший шлях, async, мережевий, зі
спільним станом — рівно той профіль, для якого власне правило проєкту
(`~/.claude/dev-practices.md`, «Test-first») вимагає окремої категорії
Concurrency/Recovery. moka не робить single-flight: N одночасних
однакових промахів = N повних quorum-fan-out'ів до N×(3–10) апстрімів.
Ця поведінка ніде не задокументована як свідомий тредоф і ніде не
перевірена. Під навантаженням (сплеск однакових запитів після TTL-
протухання популярного домену) це кратне множення вихідного трафіку до
третіх сторін — і приватнісний, і навантажувальний наслідок.
Вже зафіксовано в: частково — PERFORMANCE.md «Fan-out ceiling» згадує
відсутність стелі на конкурентні quorum-резолви, але саме *stampede*
(дедуплікація однакових in-flight) — ні.
Варіанти:
  1. Додати тест, що фіксує ПОТОЧНУ поведінку (N промахів → N fan-out),
     + рядок у PERFORMANCE.md «свідомо без single-flight, бо …». Дешево,
     чесно, нічого не змінює. Тредоф: множення трафіку лишається.
  2. Single-flight (`moka` має `try_get_with` / `get_with` — один
     обчислювач на ключ, решта чекають). Прибирає множення. Тредоф:
     новий шлях у гарячому коді, cancellation-safety обчислювача треба
     довести (та сама дисципліна, що вже є в `quorum::resolve`).
  3. Не чіпати. Тредоф: мовчазна множинність лишається неперевіреною —
     наступний рефактор `handle_query` може її зламати непомітно.
Рекомендація: Варіант 1 зараз (Фаза 1 — тест + доказ поведінки), рішення
про Варіант 2 винести в `03-ARCH.md` як явне архітектурне питання
(«чи прийнятний stampede на PET-масштабі»). Не тягнути Варіант 2 у цю
фазу — це зміна коду, не тест.
Тест, який би це зловив: `#[tokio::test] async fn
two_concurrent_misses_for_the_same_key_each_run_quorum` — спільний
`AppState`, `MockClient` з `AtomicU32`-лічильником, `tokio::join!` двох
`handle_query`, `assert_eq!(client.calls(), 2 * voters)` (Варіант 1) або
`== voters` (Варіант 2).
```

```
[1.1-B] severity: minor
Файл: upstream.rs:554–575 (`impl DohClient for ReqwestDohClient`)
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: software (приватність — див. R5)
Що: `ReqwestDohClient::query` — єдина реальна мережева дія модуля —
приварена до `reqwest` без шва: увесь `send/error_for_status/bytes` +
мапінг у `UpstreamError::{Encode,Http,Decode}` вкладені в один `async fn`,
тестований лише одним `#[ignore]`-live-тестом проти Quad9. Немає
юніт-тесту на мапінг помилок (non-2xx → `Http`, HTML-тіло → `Decode`,
локальний encode-fail → `Encode`).
Чому важливо: `UpstreamError::Http(#[source] reqwest::Error)` з
`#[error("… {0}")]` — Display інтерполює `reqwest::Error`, чий власний
Display містить URL запиту = base64url DNS-запит = **доменне імʼя**.
CLAUDE.md gotcha це підтверджує («Never log an `UpstreamError::Http`'s
message text directly … Caught in self-review while writing T-29»). Скраб
(`quorum::error_kind`) тестований на рівні `VoterRecord`
(`voter_record_error_carries_a_coarse_error_kind_never_the_raw_upstream_error`),
але **самого `UpstreamError` ніщо не стереже** так, як `overrides.rs`
стереже `OverrideError`/`InvalidEntry` Display
(`load_error_display_never_contains_the_raw_toml_input`). Один
`tracing::error!("{err}")` на новому шляху помилки = мовчазний витік.
Вже зафіксовано в: механізм витоку — CLAUDE.md gotchas; але
характеризаційного тесту на `UpstreamError` немає, і шва для тесту
мапінгу теж.
Варіанти:
  1. Характеризаційний тест: `UpstreamError::Http` з штучним
     `reqwest::Error` (напр. від `Client::get("bad")…send().await` на
     127.0.0.1:1) — `assert!(!format!("{err}").contains("<домен>"))`.
     Плюс: винести мапінг у `pub(crate) fn classify_reqwest_error(&reqwest::Error) -> UpstreamError`
     — шов для юніт-тесту без мережі. Тредоф: мінімальний рефактор.
  2. Тільки характеризаційний тест на Display, без шва. Дешевше;
     мапінг лишається під live-тестом.
  3. Не чіпати. Тредоф: R5-регресія можлива непомітно.
Рекомендація: Варіант 1 — цей тип провокує рекурентний баг-клас проєкту
(privacy leak у логи), а `overrides.rs` уже показує еталон, як його
закривають.
Тест, який би це зловив: як у Варіанті 1.
```

```
[1.1-C] severity: minor
Файл: timeout.rs:66–77 (`query_with_timeout`) / тести 127–157
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: —
Що: гілка `Ok(Err(err)) => VoterOutcome::Errored(err)` не має тесту.
Покриті лише `Responded` (`responds_in_time_…`) і `TimedOut`
(`exceeding_duration_…`).
Чому важливо: `Errored` — це шлях «апстрім відповів помилкою, не
таймаутом», який `quorum::combine` інтерпретує окремо від `TimedOut`
під `FailClosed`/`Degraded`. Регресія (напр. хтось згорне `Errored` у
`TimedOut`) пройде повз тести цього модуля.
Варіанти: один і очевидний — додати тест.
Тест, який би це зловив: `#[tokio::test(start_paused = true)] async fn
upstream_error_yields_errored_not_timed_out` з mock-клієнтом, що повертає
`Err(UpstreamError::Decode(...))`; `assert!(matches!(outcome, VoterOutcome::Errored(_)))`.
```

```
[1.1-D] severity: minor
Файл: wire.rs:18–20 (`decode_wire_message`); 39–43 (`attach_edns` — пункт (б), знято у Фазі 5)
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: software (межа вводу)
Що: (а) `decode_wire_message` — обгортка над `Message::from_vec` — не має
жодного негативного тесту (обрізані/сміттєві байти → `Err`). Єдиний
тест, що її торкається, годує валідні байти (encode→decode round-trip).
(б) `attach_edns` — 0 тестів.
Чому важливо: (а) `decode_wire_message` — це межа зовнішнього вводу (тіло
`POST /dns-query` від браузера, відповіді апстрімів). Fuzz на тілі
`POST /dns-query` — **вже зафіксована прогалина** (CLAUDE.md: «T-58
narrowed … the `/dns-query` POST body are not fuzzed»). Але навіть
3-рядкового юніта «сміття → Err» немає. (б) `attach_edns` не має
продакшн-виклику. **ВИПРАВЛЕНО (Фаза 5, Правило 1 — перевірено перед
ремедіацією): `attach_edns` НЕ мертвий код.** Його викликає
`tests/conformance/rfc_6891.rs`
(`attach_edns_adds_an_opt_record_above_the_512_byte_legacy_minimum` —
доказ RFC 6891 §6.2.3 payload-size), а `rfc_7871.rs` явно спирається на
його не-використання як на аргумент, що ECS — навмисно не-ціль (T-164).
Це conformance-протестований sentinel, не dead code — видаляти НЕ можна.
Пункт (б) знято.
Варіанти:
  (а) додати `decode_wire_message(&[0xFF; 3]).is_err()` + опційно
      `proptest` «будь-який `&[u8]` не панікує» (той самий патерн, що
      `overrides::parse_pattern` proptest). Fuzz тіла `POST /dns-query`
      лишити для Фази, що займеться T-58.
Рекомендація: (а) юніт + proptest — дешево, закриває клас «панік на
wire-декоді». (б) — знято (див. вище).
Тест, який би це зловив: `#[test] fn decode_rejects_truncated_bytes` +
`proptest! { fn decode_never_panics(bytes: Vec<u8>) { let _ = decode_wire_message(&bytes); } }`.
```

```
[1.1-E] severity: nit
Файл: cache.rs:397 (`snapshot`), 408 (`restore`)
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Що: `snapshot()` / `restore()` не мають прямого тесту в `cache.rs` — їх
споживає `cache_persist` (партія 1.3). `snapshot` покладається на
задокументовану, але слабку гарантію `moka::Cache::iter()` (може віддати
logічно-протухлий-але-не-виметений запис — CLAUDE.md gotcha).
Рекомендація: round-trip тест (`insert ×3 → snapshot → new Cache → restore
→ get ×3`) + один тест «snapshot не віддає протухлий запис» варто
зробити в `cache.rs`, а не лише в `cache_persist`, бо це властивість
`Cache`, не персистера. Звірити в партії 1.3, не дублювати.
Тест, який би це зловив: `#[tokio::test] async fn snapshot_restore_round_trips_fresh_entries`.
```

### Вже зафіксовано (не окремими блоками — Правило 0)
- `quorum::combine().incomplete` використовує слабкий стандарт
  (`Responded` = complete, не спрацьовує на SERVFAIL-воутері) — CLAUDE.md
  gotchas + `lib.rs` `should_serve_stale` коментар. Тест на «incomplete
  при SERVFAIL» свідомо відсутній до розробки stale-if-error.
- `fail_closed` timeout-`Block` кешується в памʼяті на `block_verdict_ttl`
  — CLAUDE.md «Known limitations». Тест на пайплайн-рівні не потрібен,
  поки поведінка навмисна.
- Fan-out ceiling: немає окремої стелі на конкурентні quorum-резолви —
  PERFORMANCE.md «Fan-out ceiling». (1.1-A — суміжне, але про stampede,
  не про стелю.)
- `#[cfg(windows)]` I/O-шели двох `main.rs`, `local_state::remove_all`,
  цикл `pause_watch`, real-external-resource межа `trust_store`/
  `cert_rotation` — свідомо не покриті, кожне з прецедентом у CLAUDE.md.
  (Стосується партій 1.3/1.4 — тут лише називаю клас один раз.)

### Тестопридатність — шви
**Добре:** `DohClient` trait — DI через весь `pipeline`/`quorum`/`timeout`
(мок-клієнти з `AtomicU32`-лічильниками, `all_panic`-клієнт для
«не-має-викликатися»); `overrides::load`/`save` беруть `&Path`
(`tempfile` у тестах); `cache::is_fresh(now)` + `CacheExpiry` — інʼєктовний
годинник; `handle_query` генерик по `C: DohClient + Sync` — межа
тестується без сокета.
**Точки зварювання:** `ReqwestDohClient::query` (reqwest, шва немає —
1.1-B); moka реальний годинник
для таймінгу евікції (задокументовано, один свідомий реальний sleep).

### Ранжований список «не покрито і має бути» (скоуп 1.1)
| # | Що | Ризик | Зусилля |
|---|---|---|---|
| 1 | Concurrency-тест на `handle_query` (stampede / спільний кеш) — 1.1-A | навантаження + приватність (множення fan-out) | тест ½ дня; архітектурне рішення (single-flight?) окремо в `03-ARCH.md` |
| 2 | `UpstreamError` Display «ніколи не містить домен» + шов для мапінгу — 1.1-B | рекурентний баг-клас (витік у логи) | <1 год + мінірефактор |
| 3 | `query_with_timeout` `Errored`-гілка — 1.1-C | регресія інтерпретації fail-closed | <30 хв |
| 4 | `decode_wire_message` негативний юніт + `proptest` non-panic — 1.1-D(а) | панік на wire-декоді untrusted вводу | <1 год |
| 5 | `cache::snapshot`/`restore` round-trip у `cache.rs` — 1.1-E | звірити в 1.3 | <1 год |

### Позитив (Правило 5 — одне речення)
- `overrides.rs` — еталон: `proptest` non-panic, Debug-редакція
  перевірена окремим тестом, розмірні межі (точно на ліміті + один байт
  над), помилковий top-level ключ ловиться замість тихого відкидання
  списку.
- `quorum::resolve` — скасування доведене правильно: `start_paused` +
  `Instant::now()` elapsed ≈ 0 проти `pending()`-мока, а не лише «вердикт
  збігся».

---

## Партія 1.2 — адмін-межа  ✅

Скоуп (4 файли, R3): `dispatch.rs` (3253 прод) · `admin.rs` (1638) ·
`admin_ui.rs` (91 прод / 601) · `config.rs` (851).

### Стан на вході — коротко
Межа `/admin/*` — **еталон SPEC.md §8.1**. ~200 тест-функцій:
- **smoke**: happy-path для кожного `serve_admin_*` роуту + `/dns-query`
  GET/POST + `/health`.
- **misuse**: `every_json_post_route_rejects_a_missing_or_wrong_content_type`
  — **ітерує `ROUTES`** (новий write-роут автоматично під CSRF-покриттям),
  плюс per-route `rejects_non_{post,get}_methods` / `rejects_a_malformed_body`.
- **exploit**: `serve_returns_404_for_every_path_outside_the_documented_allowlist`,
  `serve_matches_the_documented_admin_route_allowlist` (`ROUTES ==
  EXPECTED_ADMIN_ROUTES` — фікс T-59 «зробити властивість даними»),
  `serve_enforces_the_route_table_it_matched_above`, SSRF-відмови на
  `/admin/providers/add`, 413 на завеликому тілі.
- **fuzz**: `serve_never_panics_on_arbitrary_input_for_any_documented_route`
  — **справжній `proptest`** (64 кейси), кермований `ROUTES` через
  `route_method_at(pair_index)`, `FUZZ_EXCLUDED_ROUTES` фільтрує лише 3
  роути, що спавнять `certutil`/видаляють стан (кожен має власну пару
  method+CT тестів). Advisor зловив у першій версії дві діри «property
  ніколи не доходить до коду, який нібито фазить» — **обидві виправлені й
  емпірично підтверджені** тимчасовим `panic!()` у цільовій гілці. Плюс
  окремі `proptest`: `wire_bytes_from_get_never_panics`,
  `parse_log_query_never_panics`, `serve_admin_config_never_panics`.
- **Concurrency/Recovery**: 5 тестів (`concurrent_admin_config_posts…`,
  `concurrent_admin_overrides_add_posts_lose_no_updates`,
  `concurrent_admin_config_and_cache_config_posts…`,
  `concurrent_admin_reset_and_cache_config_apply…`,
  `a_zone_removal_survives_a_concurrent_zone_swap`) — рівно дисципліна
  `persist_lock` cross-field-read (R10, рекурентний баг-клас проєкту),
  тут активно стережена. **Контраст із партією 1.1**: `pipeline.rs` має 0
  concurrency-тестів, `dispatch.rs` — 5.

Детермінізм: `proptest!`-кейси будують власний `current_thread` runtime
(немає async у `proptest!`), `concurrent_*` — `tokio::join!` на спільному
`AppState`, без реальних sleep'ів. Чисто.

### Знахідки

```
[1.2-A] severity: major
Файл: admin_ui.rs — увесь модуль тестів (22 тести) + ui/main.js
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: user
Що: усі 22 тести `admin_ui` — це `assert!(MAIN_JS.contains("…"))` /
`INDEX_HTML.contains(…)` над `include_str!`-вбудованими статичними
ресурсами. Імена обіцяють перевірку поведінки
(`main_js_computes_the_hero_from_watchdog_network_and_provider_state`,
`main_js_master_switch_only_flips_categories_that_already_have_a_voter`,
`main_js_rating_filter_card_arms_turn_on_and_drives_the_zone_picker`),
але можуть лише підтвердити наявність підрядка в джерелі. Уся клієнтська
логіка `main.js` — обчислення стану hero, guard master-switch, стан-
машина картки rating-filter, скидання confirm-лейбла danger-zone —
**не виконується ніде в тест-сюїті**. Немає headless JS-раннера, немає
виокремленого модуля.
Чому важливо: це керівна поверхня — тумблери, що реально вмикають/
вимикають фільтрацію. Логічна помилка в `main.js` (hero показує
«захищено», поки фільтрація на паузі; master-switch вмикає категорію без
воутера) їде мовчки — єдиний гейт — ручний огляд мокапу. Це та сама
форма «тест проходить, не доводячи властивість» (T-59, власний
рекурентний урок проєкту), масштабована на кількасот рядків JS.
Тестопридатність: JS приварений до `fetch` + DOM, шва немає.
Вже зафіксовано в: `/admin/ui` як `include_str!` без бандлера — CLAUDE.md
Commands; але про відсутність виконуваного тесту логіки — ніде.
Варіанти:
  1. Виокремити чисті вирішальні функції JS (hero-state, master-switch
     guard, badge) в окремий модуль + мінімальний headless-раннер
     (`node --test` над чистими функціями, без jsdom). Тредоф: додає
     JS-тулчейн, якого проєкт свідомо уникає («no bundler»).
  2. Перенести вирішальну логіку на сервер: `/admin/status` вже віддає
     сирий стан — додати обчислені `hero_state` / `master_switch_allowed`
     як поля DTO в `admin.rs` (Rust, повністю тестовно), `main.js` лише
     рендерить. Той самий патерн, що вже є для `rating_filter_is_active`
     («єдина влада, badge і пайплайн не можуть розійтися» — CLAUDE.md).
     Тредоф: зростання DTO + рефактор рендера.
  3. Не чіпати. Прийняти ручний огляд мокапу як гейт; задокументувати,
     що логіка `main.js` не покрита автотестами.
Рекомендація: Варіант 2 для справді вирішальної логіки (hero-state,
master-switch guard) — дзеркалить наявний патерн «єдина влада»; чиста
презентація лишається як є. Це архітектурне рішення → винести в
`03-ARCH.md`; у Фазі 1 лише називаю непокриту поверхню.
Тест, який би це зловив (за Варіантом 2): `#[test]
fn hero_state_is_paused_when_filtering_paused_even_if_providers_active`
в `admin.rs` над чистою `compute_hero_state(&AdminStatusResponse)`.
```

```
[1.2-B] severity: minor
Файл: admin.rs:1204–1546 (`impl AdminClient`)
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: —
Що: `AdminClient` — основна публічна lib-поверхня, яку споживають
`dnsqb-tray` **і** `dnsqb-watcher` (`status`, `health`, `apply`, `reset`,
`shutdown`, `providers`, `add_provider`, `set_provider_enabled`,
`set_category_enabled`, `set_rating_filter`, `maxmind_credentials`, …) —
**не має жодного тесту**. Приварена до `reqwest` + cert-пінінг проти
`cert.pem` + живий `127.0.0.1:port`. `AdminClientError`-мапінг (сервіс
лежить / не той cert / non-200 / зламаний JSON) не перевірений.
Чому важливо: мовчазна поломка (не той шлях URL, не той метод, розбіжність
DTO клієнт↔сервер) доходить до tray/watcher без жодного тесту між ними.
Той самий корінь, що 1.1-B — reqwest-зварювання без шва.
Вже зафіксовано в: —
Варіанти:
  1. Інтеграційний тест-модуль: підняти реальний `serve()` на ефемерному
     порту з тестовим cert у `#[tokio::test]`, ганяти round-trip'и
     `AdminClient` (`serve` уже генерик + тестовний). Покриває узгодження
     URL/метод/DTO клієнт↔сервер в одному місці. Зусилля ≈½ дня.
  2. Виокремити побудову URL+метод у чисту `fn` (тест без мережі),
     транспорт лишити live-смоуку.
  3. Не чіпати — покладатися на ручні смоуки tray/watcher.
Рекомендація: Варіант 1 — дає контрактне покриття, якого зараз немає з
жодного боку, а тестопридатність `serve` робить його дешевим.
Тест, який би це зловив: `admin_client_round_trips_status_and_apply_against_a_live_serve`.
```

```
[1.2-C] severity: nit
Файл: CLAUDE.md «Known limitations» — bullet про admin-channel fuzz (T-58)
Категорія: тести (доку-vs-код)
Джерело: ПІДТВЕРДЖЕНО В КОДІ (dispatch.rs:3524–3600)
Що: bullet каже «Admin-channel fuzz (T-58, narrowed) covers `parse_pattern`
/ `wire_bytes_from_get` / `/admin/config` POST body only — other routes and
the `/dns-query` POST body are not fuzzed». Це **застаріло**:
`serve_never_panics_on_arbitrary_input_for_any_documented_route` (T-54,
`proptest`, кермований `ROUTES`) фазить **усі** не-виключені роути,
**включно з `/dns-query` POST** — тіло = `application/dns-message` +
довільні байти, і коментар документує, що досяжність гілки `decode`
підтверджена тимчасовим `panic!()`.
Чому важливо: bullet applies-as-known-gap те, що вже закрито; це також
частково знімає 1.1-D (клас «панік на wire-декоді» покрито на рівні
`serve`; залишок 1.1-D — лише прямий негативний юніт + `proptest` у
самому `wire.rs`).
Рекомендація: поправити bullet у Фазі 5 (переїзд у `TASKS.md` не потрібен
— це доку-фікс). Один варіант, очевидний.
Тест, який би це зловив: N/A (розбіжність доку).
```

### Вже зафіксовано / не є знахідкою
- `FUZZ_EXCLUDED_ROUTES` (3 роути: `/admin/uninstall-local-state`,
  `/admin/cert-status`, `/admin/install-cert`) — кожен спавнить реальний
  `certutil`/мутує trust store; кожен має власну пару method+CT тестів
  (патерн `serve_admin_shutdown`). Працює як задумано — не знахідка.
- `1.1-D` (wire-decode negative) — частково знято 1.2-C; залишок = прямий
  юніт у `wire.rs`, лишається `minor`.

### Тестопридатність — шви
**Добре:** `serve` генерик по тілу + `AppState<C>` генерик по `DohClient`
— уся межа `/admin/*` тестується без сокета; `ROUTES` як дані (не
структура `match`) → fuzz/CSRF/allowlist автоматично покривають новий
роут; `config::load`/`save` беруть `&Path`.
**Точки зварювання:** `main.js` логіка (DOM+`fetch`, 1.2-A);
`AdminClient` (reqwest+live service, 1.2-B).

### Ранжований список «не покрито і має бути» (скоуп 1.2)
| # | Що | Ризик | Зусилля |
|---|---|---|---|
| 1 | Виконуваний тест вирішальної логіки `main.js` — 1.2-A | керівна поверхня, логічний баг їде мовчки | арх-рішення в `03-ARCH.md`; за Варіантом 2 — рефактор + тести в Rust, 1–2 дні |
| 2 | `AdminClient` round-trip + error-мапінг — 1.2-B | розбіжність контракту клієнт↔сервер доходить до tray/watcher | інтеграційний модуль, ½ дня |
| 3 | Поправити застарілий fuzz-bullet — 1.2-C | доку вводить в оману про покриття | доку-фікс, хвилини |

### Позитив (Правило 5)
- `dispatch.rs` — **еталон §8.1**: `proptest` (не фіксований корпус),
  кермований `ROUTES`, тож новий роут не втече від fuzz/CSRF/allowlist;
  діри «property не доходить до коду» зловлені advisor'ом і спростовані
  емпірично тимчасовим panic'ом. 5 concurrency-тестів стережуть саме
  `persist_lock` cross-field-read (R10).
- `config.rs` — рівень `overrides.rs`: кожна таблиця має тест на
  помилковий ключ, розмірний ліміт на межі + один байт над, кожне
  нульове значення відкидається явно.

## Партія 1.3 — watchdog + персистенція  ✅

Скоуп (R4/R6, 22 файли): `watchdog/{frame,channel,pipe,heartbeat_file,
instance,vote,backoff,pid_check,transition,budget,state,loop_driver,spawn,
launcher,mod}.rs` · `encrypted_file.rs` · `log_persist.rs` ·
`cache_persist.rs` · `cache_persist_dto.rs` · `persist_dto.rs` ·
`key_store.rs` · `lifecycle.rs` · `pause_watch.rs`.

### Стан на вході — коротко
**Найсильніше протестована група в кодовій базі.** ~130 тест-функцій.
Ключове архітектурне рішення, що робить це можливим: стан-машина —
**чисті total-функції з інʼєктованим `now`** (`transition`,
`next_backoff`, `RestartBudget::register_attempt(now)`,
`loop_driver::tick(now, &ChannelObs)`, `heartbeat_file::is_stale(now, …)`),
тому детермінізм **не потребує `start_paused`** — і `loop_driver` тестує
багатоцикловими сценаріями (`two_silent_channels_restart_once_then_recover`,
`budget_exhaustion_gives_up_once_and_stops_spawning`,
`restored_with_a_spent_budget_gives_up_immediately`) саме клас T-185
(побічний ефект pure-кроку `register_attempt` через багато тіків) — те,
чого бракувало `pipeline.rs` у партії 1.1.

Персистенція: `encrypted_file.rs` (14 тестів) і `cache_persist_dto.rs`
(7) — **кожен інваріант із CLAUDE.md має іменований тест**:
`the_header_is_bound_as_associated_data`,
`open_reports_an_unsupported_version_distinctly_from_tampering`,
`a_block_verdict_is_dropped_at_snapshot` («лише Allow персиститься»),
`a_monotonic_clock_reset_does_not_inflate_the_remaining_ttl`
(«`Instant` безглуздо персистити»),
`an_entry_whose_deadline_passed_during_downtime_is_dropped_on_restore`.
`key_store.rs` (14): «створено рівно раз»
(`a_second_call_returns_the_same_key`), `MalformedKey`
(`a_stored_key_of_the_wrong_length_is_rejected`), `orphaned_ciphertext`
(`ciphertext_present_with_no_stored_key_signals_an_orphan`), із
`STORE_TEST_GUARD` проти Windows-гонки Credential Manager.

### Знахідки

```
[1.3-A] severity: nit
Файл: watchdog/transition.rs:53–63 (VerifyingPid) / тести 199–252
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: —
Що: `transition` документує себе як total і тести майже вичерпні
(усі out-edge кожного з 7 станів), але одна під-гілка не покрита:
`VerifyingPid` + `PidCheck::Alive` + `vote == Dead` +
`!any_channel_degraded` → повертає `ChannelDegraded` через **перший**
операнд `||` (рядок 55). Тест перевіряє лише другий операнд
(`any_channel_degraded: true`).
Чому важливо: мінімально — обидва операнди `||` ведуть у той самий стан,
це false-alarm-recovery шлях. Але «total, доведено тестами» має покривати
обидва входи в цю гілку.
Вже зафіксовано в: —
Варіанти: один, очевидний — 2-рядковий `assert_eq!` у
`verifying_pid_routes_on_the_check_result`. Опційно `proptest` над
`(WatchdogState, TransitionInput)` — не панікує / `GaveUp` нерухома /
результат валідний стан; для 7-станового `match` радше перестраховка.
Тест, який би це зловив: `assert_eq!(transition(S::VerifyingPid,
&TransitionInput { pid: Some(PidCheck::Alive), vote: Liveness::Dead,
..input() }), S::ChannelDegraded);`
```

```
[1.3-B] severity: nit
Файл: review/00-MAP.md §3 + review/01-TESTS.md партія 1.1 (panic-scan)
Категорія: тести (метрика ревʼю, самовиправлення)
Джерело: ПІДТВЕРДЖЕНО В КОДІ (watchdog/instance.rs:174)
Що: panic-поверхня з батчу 1.1 («`watchdog/instance.rs` ~13 поза
тест-модулями») — **артефакт скану**. `instance.rs` не має bare
`#[cfg(test)]`; його ~8 тестів — `#[cfg(all(test, windows))]`, тож
`awk`-обрізка «до першого `#[cfg(test)]`» просканувала весь файл, разом
із `panic!()` у тест-модулі. Реально прод-panic-сайтів ≈ 0 (`acquire`/
`write_pid_file`/`read_pid_file` повертають `Result`). Той самий артефакт
у `key_store.rs` («52 прод» недооцінює через ранній guard-`#[cfg(test)]`
на рядку 55; реально ≈220 прод, 2 тест-модулі).
Чому важливо: Фаза 2 (panic-поверхня, R-…) мусить сканувати патерном
`#\[cfg\((all\()?test`, інакше цифри збиті, і `instance.rs` виглядатиме
ризиковим без причини.
Рекомендація: виправити цифри в `00-MAP.md` §3 і `01-TESTS.md` 1.1 у
Фазі 5; Фаза 2 повторює скан коректним патерном.
Тест, який би це зловив: N/A (метрика).
```

### Реконсиляція 1.1-E — ЗНЯТО (до `nit`)
`cache_persist.rs::persist_cache_snapshot_writes_a_file_that_decrypts_back_to_the_same_entries`
+ `log_persist.rs::seed_from_file_round_trips_a_persisted_snapshot_into_a_fresh_log`
ганяють `cache::snapshot`→`restore` end-to-end через персистер.
`cache_persist_dto.rs::a_not_fresh_entry_is_dropped_at_snapshot` покриває
фільтр свіжості, що робить moka stale-grace вікно неспостережним. Залишок
1.1-E = суто локальний round-trip у `cache.rs` — `nit`, опційно, не потреба.

### Вже зафіксовано / не є знахідкою
- `ensure_sibling_running` (T-187), `run_pause_watcher` цикл,
  `run_{query_log,cache}_persister` impure-хвости, `dnsqb-watcher::main`,
  `dnsqb-service::spawn_watchdog_tasks` — I/O-шели, свідомо не тестовані,
  кожен із прецедентом у CLAUDE.md. Тестовні ядра (`persist_snapshot`,
  `persist_cache_snapshot`, `plan_launch`, `LoopDriver::tick`) виокремлені
  й покриті.
- `pause_watch.rs` — 0 тестів; детачнутий 1-с polling-цикл, той самий
  «detached loop публікує `Copy` в `AppState`» прецедент, що `reachability`.
- T-185 (pure-крок мутує стан) — знято T-193 (DECISIONS.md); клас усе одно
  покритий `loop_driver::budget_exhaustion_gives_up_once_and_stops_spawning`.

### Тестопридатність — шви
**Добре (наскрізно):** інʼєктований `now` у кожному pure-ядрі; `&Path` +
`tempfile` у файлових тестах; `encrypted_file::{seal,open}` беруть ключ
параметром (реальний = `key_store`); `persist_*_snapshot` розділені на
тестовне ядро + тонкий impure-хвіст; `to_json(snapshot, now_wall,
now_mono)` — обидва годинники інʼєктовані.
**Точки зварювання:** лише задокументовані-прецедентом I/O-шели (вище).

### Ранжований список «не покрито і має бути» (скоуп 1.3)
| # | Що | Ризик | Зусилля |
|---|---|---|---|
| 1 | `transition` VerifyingPid+Alive+Dead під-гілка — 1.3-A | «total, доведено» неповне | 2 рядки |
| 2 | Локальний `cache::snapshot`/`restore` round-trip у `cache.rs` — 1.1-E залишок | косметика (покрито через персистер) | <1 год, опційно |
| 3 | Виправити метрику panic-скану — 1.3-B | Фаза 2 працює на збитих цифрах | доку-фікс + повторний скан |

### Позитив (Правило 5)
- `watchdog/` — стан-машина як чисті total-функції з інʼєктованим
  годинником: `loop_driver` тестує багатоцикловими сценаріями клас, який
  T-185 навчив (побічний ефект pure-кроку), а не одним тіком.
- `encrypted_file.rs` / `cache_persist_dto.rs` / `key_store.rs` — кожен
  задокументований у CLAUDE.md інваріант має іменований тест; жодної
  прогалини між «gotcha» і «regression-тест».

---

## Партія 1.4 — периферія + tray/watcher  ✅

Скоуп (~25 файлів): `geoip{,_credentials,_download,_updater}.rs` ·
`reachability.rs` · `baseline_selector.rs` · `topn_{download,updater}.rs` ·
`rating_filter.rs` · `trust_store.rs` · `cert{,_rotation}.rs` ·
`local_state.rs` · `logging.rs` · `admission.rs` · `paths.rs` ·
`listener.rs` · `tls.rs` · `dnsqb-tray/{main,browser,onboarding,
self_uninstall,status}.rs` · `dnsqb-watcher/main.rs` ·
`tests/conformance/**` · `examples/**`.

### Стан на вході — коротко
Периферія `dnsqb-service` — **щільно покрита**: `geoip*` 15+15+18,
`reachability` 11, `baseline_selector` 7, `trust_store` 10, `tls` 10,
`cert*` 6+7, `rating_filter` 8, `admission` 5, `paths` 5. Bounded-
decompress + sha-sidecar + atomic-swap мають іменовані тести
(`geoip_download`, `topn_download`). Детермінізм: `geoip_updater` — 2
`start_paused` (24-год цикл), решта — pure або `&Path`+`tempfile`.

`dnsqb-tray/status.rs` — **20 поведінкових тестів** на виокремлені чисті
функції (`icon_colour`, `compose_tooltip`, `from_response`, `next_delay`,
`watchdog_override`): `untrusted_cert_reddens_only_filtering`,
`an_active_rating_filter_never_changes_the_icon_colour`,
`filtering_icon_is_amber_only_when_every_recent_query_degraded` (T-196),
`trust_poll_cadence_stays_fast_until_a_confirmed_trusted_cert`. Це
**еталон** тестування UI-суміжної логіки — і готова відповідь на 1.2-A /
1.4-A.

**Спростовані підозри (Правило 1 — перевірив, перш ніж писати):**
- `listener.rs` (1 тест) — це саме safety-property:
  `binding_an_already_bound_port_is_an_explicit_error_not_a_silent_fallback`
  → `Err(BindError::AddrInUse(p))`. Не прогалина.
- `admission.rs` — DoS-backstop (R12) **має concurrency-тест**:
  `parallel_admits_never_exceed_the_ceiling_and_the_reject_count_is_exact`
  (`JoinSet` + точний лічильник). Саме дисципліна, якої бракує
  `pipeline.rs` (1.1-A). Не прогалина.
- `rating_filter::zone_match` — межі покриті: bare public suffix,
  trailing dot, empty/single-label, multi-source union, removed-overlay.

### Знахідки

```
[1.4-A] severity: minor
Файл: dnsqb-tray/src/main.rs — увесь файл (823 прод, 0 тестів)
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: user
Що: `dnsqb-tray/main.rs` не має жодного тесту. Прецедент CLAUDE.md
(«running I/O shells … untested») стосується *I/O-шелу* — але тут значна
частина не шел: `handle_menu_event` (маршрутизація ~15 пунктів меню →
дії), `format_uninstall_report(&UninstallReport) -> String` (чиста),
`refresh_tray` (guard T-191 «коммітить `last_colour` лише на
`Ok(set_icon)`» — регресував раз). Сусідній `status.rs` довів, що патерн
«виокремити чисте → тестувати» в цьому крейті працює.
Чому важливо: помилково перемкнутий пункт меню («Призупинити фільтрацію»
→ не та дія) або зламаний guard `refresh_tray` (іконка застрягла на
неправильному кольорі на все життя процесу) їде мовчки — гейт лише
ручний клік.
Вже зафіксовано в: частково — прецедент CLAUDE.md, але він про I/O-шел,
не про чисту логіку, яку `status.rs` уже навчив виокремлювати.
Варіанти:
  1. Виокремити routing `handle_menu_event` у чисту `fn menu_action_for(
     id) -> MenuAction` (тест таблицею); `format_uninstall_report` —
     прямий тест; guard — `fn should_commit_colour(prev, new, ok) -> bool`.
  2. Тільки `format_uninstall_report` (найдешевше, найменша віддача).
  3. Не чіпати — розширити прецедент CLAUDE.md явно на цей файл.
Рекомендація: Варіант 1 для routing (найбільший ризик — user-visible
mis-wire) + `format_uninstall_report`. Той самий рефактор-патерн, що дав
`status.rs`.
Тест, який би це зловив: `#[test] fn pause_menu_item_maps_to_the_pause_action`.
```

```
[1.4-B] severity: nit
Файл: dnsqb-watcher/src/main.rs (337 прод, 0 тестів)
Категорія: тести
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Що: вирішальне ядро (`LoopDriver::tick`) покрите в `loop_driver.rs`;
нетестований залишок — startup-послідовність і побудова `ChannelObs` із
трьох сирих читань каналів (pipe / два `.hb` / `/health`) перед `tick`.
Чому важливо: мінімально — ~30 рядків мапінгу «сирі читання →
observation»; переплутати два heartbeat-файли → хибний `ChannelObs` →
хибне голосування.
Вже зафіксовано в: CLAUDE.md прецедент «untested by design».
Варіанти: (1) виокремити `fn observe(...) -> ChannelObs` + тест;
(2) не чіпати — ядро покрите, шел тонкий.
Рекомендація: Варіант 2 прийнятний; Варіант 1 дешевий, якщо торкатимешся
файлу.
Тест, який би це зловив: `observe_maps_the_two_heartbeat_files_to_the_right_directions`.
```

```
[1.4-C] severity: nit
Файл: crates/dnsqb-service/tests/conformance/*.rs (23 тести / 10 RFC)
Категорія: тести
Джерело: ГІПОТЕЗА (звірити з SPEC.md Крок 0)
Що: conformance-сюїта виглядає тонко (rfc_1035 — 1 тест, rfc_6891 — 1,
rfc_8484 — 1). SPEC.md Крок 0 мандат — «один рядок на RFC-вимогу». Чи
покриває сюїта таблицю повністю — не перевірити без самої таблиці.
Чому важливо: RFC-conformance — заявлений step-0; недопокрита таблиця =
вимоги «зелені» лише через відсутність тесту.
Вже зафіксовано в: CLAUDE.md — «count changes as tasks land»; звірки
«таблиця ↔ сюїта» немає.
Рекомендація: звірити рядок-у-рядок проти SPEC.md Крок 0 у Фазі 3
(відповідність місії), не Фаза-1-дія.
Тест, який би це зловив: N/A (аудит таблиці).
```

### Вже зафіксовано / не є знахідкою
- `dnsqb-tray/main.rs` + `dnsqb-watcher/main.rs` I/O-шел, `local_state::
  remove_all`, `run_setup_wizard`/`confirm_*` (`rfd`-діалоги),
  `examples/{load_test,phase1_metrics,sinkhole_probe,topn_fp_probe}.rs`
  (ручні live-харнеси) — свідомо не тестовані, прецедент CLAUDE.md.
  1.4-A/B стосуються лише *чистої логіки* в тих файлах, не шелу.
- R12 залишок (немає окремої стелі на конкурентні quorum-резолви) —
  CLAUDE.md «Known limitations». `admission` backstop сам покритий.
- `geoip_credentials.rs` «54 прод» — той самий awk-артефакт, що 1.3-B
  (ранній guard-`#[cfg(test)]`); реально ≈200 прод. Додати до списку
  виправлення метрики.

### Позитив (Правило 5)
- `dnsqb-tray/status.rs` — 20 поведінкових тестів на чисті функції,
  виокремлені з event-loop шелу; модель тестування UI-суміжної логіки й
  пряма відповідь на 1.2-A / 1.4-A.
- `admission.rs` — DoS-backstop із реальним паралельним тестом
  (`JoinSet` + точний лічильник) — дисципліна, якої бракує `pipeline.rs`.

---

## Зведений backlog тестів — Фаза 1 (усі 4 партії)

Сортування за (вплив × ймовірність) / зусилля. Знахідки, що переживуть
ревʼю, у Фазі 5 переїжджають у `TASKS.md`.

| # | ID | severity | Що | Зусилля | Примітка |
|---|---|---|---|---|---|
| 1 | 1.1-A | major | Concurrency-тест `handle_query` (stampede / спільний кеш); поведінка N-fan-out ніде не задокументована | тест ½ дня | рішення про single-flight → `03-ARCH.md` |
| 2 | 1.2-A | major | Виконуваний тест вирішальної логіки `main.js` (hero-state, master-switch guard) — зараз лише `contains("…")` | 1–2 дні (Варіант 2: логіка в DTO) | арх-рішення → `03-ARCH.md`; `status.rs` — готовий патерн |
| 3 | 1.2-B | minor | `AdminClient` (споживають tray+watcher) — 0 тестів; reqwest+cert без шва | ½ дня (інтеграційний модуль проти `serve()`) | той самий корінь, що 1.1-B |
| 4 | 1.1-B | minor | `UpstreamError` Display «ніколи не містить домен» + шов для мапінгу reqwest-помилок | <1 год + мінірефактор | R5, рекурентний баг-клас; `overrides.rs` — еталон |
| 5 | 1.4-A | minor | `dnsqb-tray/main.rs` — routing `handle_menu_event` + `format_uninstall_report` у нетестованому шелі | ½–1 день (виокремити як `status.rs`) | user-visible mis-wire їде мовчки |
| 6 | 1.1-C | minor | `query_with_timeout` `Errored`-гілка без тесту | <30 хв | — |
| 7 | 1.1-D | minor | `decode_wire_message` прямий негативний юніт + `proptest` non-panic у `wire.rs` | <1 год | клас «панік на wire» покрито на рівні `serve` (1.2-C); залишок — локальний |
| 8 | 1.3-A | nit | `transition` під-гілка `VerifyingPid+Alive+vote==Dead+!degraded` | 2 рядки | «total, доведено» неповне |
| 9 | 1.4-B | nit | `dnsqb-watcher/main.rs` — виокремити `observe(...) -> ChannelObs` + тест | <1 год | ядро (`tick`) уже покрите |
| 10 | 1.4-C | nit | Звірити conformance-сюїту з SPEC.md Крок 0 | аудит, Фаза 3 | не Фаза-1-дія |
| 11 | 1.1-E (залишок) | nit | Локальний `cache::snapshot`/`restore` round-trip у `cache.rs` | <1 год, опційно | покрито через персистер (1.3) |
| 12 | 1.2-C, 1.3-B | nit | Доку-фікси: застарілий fuzz-bullet CLAUDE.md; метрика panic-скану (`#[cfg(all(test`)`) у `00-MAP`/`01-TESTS` 1.1 | хвилини, Фаза 5 | самовиправлення ревʼю |

**Топ-2 важелі:** 1.1-A і 1.2-A — обидва вимагають архітектурного
рішення (single-flight? логіка UI в DTO?), тому виносяться в `03-ARCH.md`,
а не закриваються тестом наосліп.

**Що НЕ робити:** не додавати `proptest` до кожного pure-парсера
(`transition`, `zone_match`, `parse_pattern` уже має) заради симетрії —
де межі перелічені вручну й вони саме ті, що з gotchas, `proptest`
додає прогони, не покриття. Не тестувати `rfd`-діалоги / `tao` event-
loop / `certutil`-спавни — прецедент і реальні-зовнішні-ресурси.

### Стан Фази 1: **ЗАВЕРШЕНА** (усі 4 партії)
Загальний висновок: **тестова база проєкту — сильна**. `overrides`/
`config`/`dispatch`/`watchdog/**`/`encrypted_file`/`status.rs` — еталонні.
Два реальних структурних провали: (а) `pipeline.rs` без жодного
concurrency-тесту при тому, що `dispatch`/`admission` показують дисципліну;
(б) клієнтська логіка (`main.js`, частина `dnsqb-tray/main.rs`) верифікована
лише `contains`-асертами або ніяк. Обидва — вхід у Фазу 3.
