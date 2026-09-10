# review/04-IDIOM.md — Фаза 4: Ідіоматичність і якість API

> Це review-артефакт, не частина DOC MAP (`CLAUDE.md`). Джерело істини —
> `SPEC.md`/`DECISIONS.md`. Знахідки, що переживають ревʼю, переїжджають
> у `TASKS.md`. Прогони baseline позначено місцем (`gnu-local` / `CI`).
>
> Дата: 2026-09-10. HEAD `0ecab35`.

---

## Скоуп і структура фази

Наскрізна, один прохід. Розглянуто: clippy `pedantic`-стан і
`#[allow]`-тріаж; володіння/лайфтайми (`String` vs `&str`, `clone`/`Arc`);
дизайн типів (newtype, невиразні невалідні стани, `#[non_exhaustive]`);
публічний API `dnsqb-service` lib (`lib.rs` re-exports, `must_use`,
`Debug`, stdlib-трейти); документація (`missing_docs`, doc-тести).

Baseline не перепрогонявся (HEAD не змінився). Релевантні цифри з
`00-MAP.md` §3: `cargo clippy --workspace --all-targets -- -D warnings`
**exit 0** (`gnu-local`) — тобто **`pedantic` уже чистий** (лінт
`#![warn(clippy::pedantic)]` + `-D warnings` промотує все у помилку).

---

## 1. Clippy `pedantic` і `#[allow]`-тріаж  ✅

- `#![warn(clippy::pedantic)]` — **усі 3 кореневих** (`lib.rs:3`,
  `dnsqb-service/main.rs:5`, `dnsqb-tray/main.rs:3`,
  `dnsqb-watcher/main.rs:6`). `#![deny(clippy::unwrap_used,
  clippy::expect_used)]` — теж усі 3.
- **`#[allow(clippy::…)]` у прод-коді = 0.** Єдині входження:
  `pipeline.rs:4034` `#[allow(clippy::too_many_arguments)]` — у
  тест-модулі (межа на рядку 1098); `dispatch.rs:6373` `#[allow(dead_code)]`
  на полі тест-структури; `lib.rs:9` `#![allow(rustdoc::private_intra_doc_links)]`
  — задокументовано в CLAUDE.md (крейт ніколи не публікується, завжди
  `--document-private-items`).
- **`too_many_arguments` / `too_many_lines` виправлені структурно** —
  cohesive param-структи (`UpstreamContext`, `CacheContext`, `GeoipFilter`,
  `RuntimeInit`, `GeoipInit`, `PersistPaths`), не `#[allow]`. Точно
  зафіксований патерн T-147/T-148 + `rust.md` §9.

Це зразкова дисципліна. Нічого тріажувати — множина заглушок порожня.

---

## 2. Володіння / лайфтайми  ✅

- **`String` де мав би бути `&str`**: grep по сигнатурах — **один**
  збіг, `dispatch.rs:1012` `record_zone_removal(&self, registrable:
  String)`. І він **коректний**: функція *зберігає* значення в
  `HashSet<String>`-оверлеї, виклик (`dispatch.rs:592`) передає
  `meta.zone_removal: Option<String>` рухом, не клоном. Consuming-by-value
  — правильний вибір.
- **`clone` / `Arc`**: `upstream.rs` — **0 `.clone()`**. `pipeline.rs`
  21, `cache.rs` 18, `dispatch.rs` 44 (з них у прод-портії більшість —
  `Arc::clone` снапшот-патерну `RwLock<Arc<T>>`, який Фаза 3 §2
  підтвердила як коректний: читач бампає refcount під lock'ом, не
  тримає lock через `.await`). Фази 1.1–1.4 не зафіксували clone-важкості
  в жодному модулі. Не роздуваю без доказу зайвості.
- **`Vec` де ітератор**: не виявлено систематичного; `rust.md` §5
  (internal iteration) дотримано — парсери й проєкції — ітераторні
  ланцюги.

---

## 3. Дизайн типів  ✅

- **«Make illegal states unrepresentable» — застосовано наскрізно**
  (`rust.md` §2):
  - `SinkholeNet` — без `Default`, інваріант `1..=32` / `1..=128`
    робить «match everything» непредставним.
  - `pipeline::Voters` — enum `{ Enabled, Disabled }` замість `&[Provider]`
    (свідома відмова від slice, чий «partial subset» тихо ігнорувався —
    CLAUDE.md gotcha).
  - `overrides::InvalidReason` — закритий enum замість `reason: ProtoError`
    (структурно не може нести домен).
  - `WatchdogState` (7 варіантів) / `WatchdogTarget` (2) / `PidCheck` /
    `Liveness` / `BudgetVerdict` — ADT замість bool-прапорців.
  - Типізовані IP-SAN у `cert` (`rcgen` `SanType::IpAddress`, не
    `DnsName` з текстом IP).
- **`#[non_exhaustive]` — 0 входжень** у всьому workspace. Це
  **свідомий, когерентний вибір** для внутрішнього (не публікованого)
  крейта: `#[non_exhaustive]` пригнітив би саме ту exhaustiveness-
  перевірку, якої проєкт хоче (`rust.md` §2 — «розширення enum
  автоматично тригерить compile-помилку на кожному сайті»; додав
  `DecisionSource`-варіант → усі `match` ламаються → знайшов усі).
  Проєкт знає патерн (`hickory_proto::op::Message` є `#[non_exhaustive]`
  — CLAUDE.md gotcha), обирає не вживати на власних типах. **Не
  знахідка** — але якщо крейт колись публікуватиметься, error-enum'и
  (`ConfigError`, `TlsError`, `UpstreamError`, …) захочуть
  `#[non_exhaustive]`.

---

## 4. Публічний API `dnsqb-service` lib  

- **`#[must_use]` — застосовано первазивно**: не лише `watchdog/**`, а
  `admin`, `admission`, `baseline_selector`, `cache`, `geoip`,
  `overrides`, `quorum`, `rating_filter`, `upstream`, `wire`,
  `dnsqb-tray/status` — 90+ сайтів, включно з описовою формою
  `#[must_use = "dropping the guard immediately releases the single-
  instance lock"]` (`watchdog/instance.rs:70`). `pedantic`
  `must_use_candidate` під `-D warnings` це й тримає.
- **`Debug` на публічних типах** (`rust.md` §3) — **3 винятки**:
  → **Знахідка 4-C** (з них `overrides::InvalidEntry` — хибний
  позитив: має **рукописний** редагувальний `Debug`, це і є правильно).
- **`missing_docs`**: `#![warn(missing_docs)]` (`lib.rs:2`) + CI
  `-D warnings` зелений → **кожен `pub` елемент має `///`**. Дисципліна
  документації висока.
- **Розмір публічної поверхні**: `lib.rs` — ~60 груп `pub use`, що
  реекспортують майже всі внутрішні деталі кожного модуля
  (`pipeline::handle_query`, `quorum::resolve`, `encrypted_file::{seal,
  open}`, `wire::*`, `watchdog::transition::transition`, …).
  → **Знахідка 4-B**.

---

## 5. Документація — doc-тести

**0 (нуль) ` ```rust ` фенсів у всьому `src/`.** `cargo test --workspace
--doc` зелений, бо запускати нічого. `rust.md` §10 — «Documentation for
key functions **must include code examples**» — **не виконано ніде в
проєкті**. → **Знахідка 4-A**. Вже названо в CLAUDE.md як відомий факт
(«Zero doctests exist yet … the step exists so the first one is actually
run»), але Фаза 4 — місце оцінити це як ідіоматичний борг.

---

## ЗНАХІДКИ

```
[4-A] severity: minor
Файл: увесь `crates/dnsqb-service/src/**` (0 doc-тестів); гейт —
CLAUDE.md Commands («cargo test --workspace --doc»)
Категорія: стиль (ідіоматичність) / документація
Джерело: ПІДТВЕРДЖЕНО В КОДІ (grep — 0 ` ```rust ` / ` ```no_run ` фенсів)
Три Б: —
Що: жодна публічна функція не має executable-прикладу в rustdoc.
`rust.md` §10 називає це обовʼязковим для ключових функцій; гейт
`cargo test --doc` існує й проганяється в CI, але порожній.
Чому важливо: не баг рантайму. Але (а) executable-приклад — це
одночасно жива документація і тест, що ловить зміну сигнатури/семантики
публічної функції; (б) проєкт має гейт саме під це й декларує намір
(«so the first one is actually run») — намір не реалізовано; (в)
публічна поверхня велика (див. 4-B) і росте без цього шару.
Вже зафіксовано в: CLAUDE.md Commands («Zero doctests exist yet … not
met anywhere»).
Варіанти:
  1. Додати doc-тести до ~8 чистих leaf-функцій із re-export поверхні
     `lib.rs`: `normalize_domain`, `min_rrset_ttl`, `negative_cache_ttl`,
     `next_backoff`, `channel_status`, `SinkholeNet::contains`,
     `ZoneLists::zone_match`, `verify_pid_alive`-суміжні. Прості
     сигнатури, кожен приклад ≈3–5 рядків. Активує дрімаючий гейт.
     Зусилля ≈півдня.
  2. Тільки `normalize_domain` + `next_backoff` (мінімум, аби гейт
     мав що ганяти). Дешевше, менша віддача.
  3. Не робити — прийняти, що `rust.md` §10 тут не виконується;
     зафіксувати рішення явно.
Рекомендація: Варіант 1 як `TASKS.md`-рядок, низький пріоритет. Чисті
leaf-функції — найкраща стартова точка (немає setup, приклад
самодостатній).
Тест, який би це зловив: самі doc-тести (за визначенням).
```

```
[4-B] severity: nit
Файл: lib.rs:162–264 (~60 груп `pub use`)
Категорія: архітектурний борг / ідіоматичність (`rust.md` §8)
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Три Б: —
Що: `lib.rs` реекспортує майже всю внутрішню машинерію —
`pipeline::handle_query`, `quorum::resolve`, `encrypted_file::{seal,
open}`, `wire::{decode,encode}_wire_message`, `overrides::*`, `cache::*`,
`watchdog::transition::transition`, `watchdog::vote::*`. Заявлені
споживачі: `dnsqb-tray` (потребує `AdminClient` + жменю DTO) і
`dnsqb-watcher` (потребує `watchdog::*` decision-core + `AdminClient`,
§7.1 #6).
Чому важливо: широка поверхня — **наслідок split'у lib+bin в одному
пакеті**: `dnsqb-service/src/main.rs` лінкує lib як зовнішній крейт, тож
усе, що потрібно самому сервіс-бінарнику (`handle_query`, `wire::*`,
`quorum::*`), мусить бути `pub`, не `pub(crate)`. Для непублікованого
внутрішнього крейта ціна низька, але: (а) кожен внутрішній елемент стає
semver-подібним зобовʼязанням; (б) розширює `missing_docs`-поверхню
(4-A); (в) розмиває «фінальний публічний API» (`rust.md` §8 — least
privilege).
Вже зафіксовано в: — (суміжне з 3-A/3-B — структурна вага `dispatch`/
`AppState`).
Варіанти:
  1. Перенести оркестрацію з `main.rs` у lib як `pub fn run(config) ->
     …`, `main.rs` стає 3-рядковим шимом. Тоді `handle_query`/`wire`/
     `quorum`-внутрішні реекспорти → `pub(crate)`, публічна поверхня
     звужується до того, що справді потрібно tray+watcher. Зусилля ≈1
     день. Тредоф: `run()` тягне багато параметрів (зважується
     config-структом, як усе інше тут).
  2. Розбити на два крейти: `dnsqb-core` (lib, вузький API) +
     `dnsqb-service` (bin). Чистіше, але 3-й крейт у workspace і
     переміщення файлів. Дорожче.
  3. Не чіпати — прийняти, що внутрішній крейт має широкий `pub`.
Рекомендація: Варіант 1, якщо колись торкатиметься `main.rs`
структурно (суміш із 3-B рефактором). Не окрема дія для PET-масштабу.
Тест, який би це зловив: N/A (структура API).
```

```
[4-C] severity: nit
Файл: dispatch.rs (`GeoipState`), pipeline.rs (`RatingFilterView<'a>`)
Категорія: стиль (`rust.md` §3 — «для всіх публічних типів обовʼязково
Debug»)
Джерело: ПІДТВЕРДЖЕНО В КОДІ
Що: два `pub`-типи без `Debug`:
  - `dispatch::GeoipState` (`#[derive(Default)]`) — імовірно тому, що
    `maxminddb::Reader<Vec<u8>>` усередині не є `Debug`; тоді рішення —
    рукописний терсний `impl Debug` («reader: <present/absent>»), не
    просто пропуск.
  - `pipeline::RatingFilterView<'a>` (`#[derive(Clone, Copy)]`) —
    borrowed-view; `#[derive(Debug)]` тривіальний і нешкідливий.
(`overrides::InvalidEntry` без `#[derive(Debug)]` — **хибний позитив**:
має рукописний редагувальний `Debug`, що приховує `raw` — саме
правильно, приватність.)
Чому важливо: мінімально — обидва внутрішні, `Debug` потрібен на
практиці для `tracing`/тест-діагностики. `rust.md` §3 — «обовʼязково».
Вже зафіксовано в: —
Варіанти: один розумний — додати `#[derive(Debug)]` до `RatingFilterView`,
рукописний терсний `impl Debug` до `GeoipState`.
Рекомендація: дешевий фікс у Фазі 5 (доку/стиль) або при дотику до
файлів.
Тест, який би це зловив: `#[test] fn geoip_state_is_debug()` з
`fn assert_debug<T: std::fmt::Debug>() {}` — compile-time.
```

---

## Вже зафіксовано / не є знахідкою

- `#[non_exhaustive]` відсутній на всіх публічних типах — **свідомий
  когерентний вибір** для внутрішнього крейта (`rust.md` §2 — хоче
  exhaustiveness-перевірку; `#[non_exhaustive]` її пригнітив би). Не
  знахідка; релевантно лише при публікації.
- `#![allow(rustdoc::private_intra_doc_links)]` (`lib.rs:9`) —
  задокументовано в CLAUDE.md (крейт не публікується, завжди
  `--document-private-items`).

---

## Позитив (Правило 5 — по одному реченню)

- **`#[allow(clippy::*)]` у прод-коді = 0**; `too_many_*` виправлені
  структурно cohesive param-структами — точно `rust.md` §9 +
  зафіксований патерн T-147/T-148.
- **`#[must_use]` застосовано первазивно** по кожному модулю, включно
  з описовою формою на instance-guard.
- **«Illegal states unrepresentable»** — `SinkholeNet` без `Default`,
  `pipeline::Voters` enum замість slice, `InvalidReason` закритий enum,
  `WatchdogState`/`PidCheck`/`Liveness` ADT — застосовано послідовно
  (`rust.md` §2).
- **`pedantic` реально чистий** під `-D warnings`; `missing_docs`
  увімкнено й зелено → кожен `pub` елемент несе `///`.

---

## Стан Фази 4: **ЗАВЕРШЕНА**

**Blocker — немає.** Ідіоматичність — **сильна**: `pedantic` чистий без
жодного прод-`#[allow]`, `must_use` первазивний, дизайн типів
послідовно закриває невалідні стани, кожен `pub` задокументований.

Борг:
- **4-A `minor`** — `rust.md` §10 (doc-тести з прикладами) не виконано
  ніде; дрімаючий гейт `cargo test --doc` порожній.
- **4-B `nit`** — широкий публічний API як наслідок lib+bin в одному
  пакеті (`rust.md` §8); PET-прийнятно, суміж із 3-B рефактором.
- **4-C `nit`** — 2 `pub`-типи без `Debug`.

Per протокол: `advisor()` між фазами — лише на `blocker`. Не піднято →
без виклику. Наступна фаза — 5 (консолідація): вимагає `advisor()` перед
фіналізацією `05-BACKLOG.md`.
