# Задачі

Формат: `- [ ] T-N — опис (розділ SPEC.md, якщо застосовно)`. Нумерація наскрізна
через увесь файл (не по фазах), нові задачі отримують наступний вільний номер.
Завершені задачі переносяться в [`TASKS-DONE.md`](TASKS-DONE.md), не видаляються.

UI-задачі нижче (T-47, T-52 та ін.) мають детальні таблиці полів/DTO/мокап у
[`UI-SPEC.md`](UI-SPEC.md) — звірити перед імплементацією.

## Фаза 1 — Proof of concept

**Формально закрита 2026-08-29 (SPEC.md's Фазований план, той самий запис).** Закриттєвий план
нижче виконано повністю (усі 5 кроків — готово чи звужено з явним обґрунтуванням, чому решта не
блокує). Два `- [ ]`-рядки нижче (T-51, T-56) лишаються у списку — вони carried-forward backlog,
не невиконана частина оригінального Ф1-бул-списку SPEC.md (жоден з двох не був у тому списку
взагалі), і обидва заблоковані на явно поза-MVP задачах (T-132, T-134). **Closing-advisor-рев'ю
цього самого закриття (перед комітом) знайшло два реальні розриви, не заблоковані ні на чому, лише
не зроблені**: (1) жоден зафіксований тест не проганяв фактичний "браузер → локальний DoH"-прохід
(реально налаштований Chrome із `127.0.0.1:<port>/dns-query` як Custom DoH provider, живий домен) —
усе наявне підтвердження на рівні DoH-клієнта (`Invoke-WebRequest`) чи Chrome-automation проти
`/admin/ui` (інша сторінка); (2) T-66's метрики не підтвердили гіпотезу "кворум ловить більше за
найкращий одиночний провайдер" на зібраному зразку — SPEC.md сам ставить це умовою перед Фазою 2.
Обидва — не задачі з номером, а відкриті рішення (живий прохід дешево зробити зараз, cert уже
довірений; метрики — переміряти чи додати провайдера, чи прийняти результат як є). **Оновлення
2026-08-31:** Фаза 2 тим часом стартувала (рішенням користувача, попри цей відкритий гейт) і
формально закрита — обидва пункти несуться далі у Фазу 3 як відкриті (див. `## Фаза 2` нижче).

**План закриття (2026-08-29, plan-mode + advisor, збережено для наступних сесій).** П'ять
відкритих задач лишалось на момент плану: T-49, T-51, T-53, T-56, T-58 (T-53/T-58 вже раз звужені
раніше; T-49 закрито тим самим днем — TASKS-DONE.md). Порядок і критерій "готово" на кожну:

0. ~~**Проба**~~ — **виконано користувачем 2026-08-29, результат зафіксовано (SPEC.md §2)**:
   `CurrentUser\TrustedPeople` **не спрацював** для Chrome (реальний тест — "не довірено");
   `CurrentUser\Root` **спрацював**, без адмін-прав, з одноразовим діалогом підтвердження від ОС
   (не повний UAC, не `LocalMachine`). Це й відповідає на CT-політику питання T-51 для Chrome:
   локально довірений якір звільнений від CT/SCT-вимог, підтверджено відсутністю відповідного
   попередження.
1. ~~**T-49**~~ — **готово** (TASKS-DONE.md, 2026-08-29). Автоматизація install/uninstall у
   `CurrentUser\Root` через `dnsqb-tray`'s дві нові, підтверджені нативним діалогом дії — не тихий
   автозапуск при старті `dnsqb-service` (жоден живий тест не підтвердив, чи сама команда
   `certutil -addstore` показує ще й окремий діалог ОС; залишено для живої перевірки користувачем).
   Ідентичність розділена за напрямком: install — SHA-1 thumbprint поточного `cert.pem` (точна
   перевірка), uninstall — `CommonName` (вичерпне видалення, включно із застарілими записами після
   перевипуску). DECISIONS.md отримав новий запис, SPEC.md §2 правлено на місці.
2. **T-51 — звужено, не закрито повністю**: Chrome-половина підтверджена (побічний результат
   проби вище). Firefox-половина — окрема NSS-база на кожній платформі (SPEC.md §2, уточнено
   2026-08-29), не системний trust store, тож поза скоупом цієї проби; лишається блокованою на
   T-132 (поза межами MVP). Не блокує закриття Ф1 — Firefox-автоматизація й так була поза Ф1-
   скоупом до цього уточнення.
3. ~~**T-53**~~ — **готово** (TASKS-DONE.md, 2026-08-29). Письмовий вердикт по кожному DTO в
   `admin.rs`: рівно два свідомі прямі реюзи (`EnabledProviders`/`TimeoutMode`), решта — справжні
   проєкції; жоден внутрішній тип без `Serialize` (`LogEntry`/`VoterRecord`) не може випадково
   потрапити в `json_response`.
4. ~~**T-58**~~ — **готово** (TASKS-DONE.md, 2026-08-29). Allow+block конфлікт misuse-приклад
   перевірено, а не дописано — вже покритий: `dispatch::tests::
   serve_admin_overrides_returns_the_current_lists_and_conflicts` (рівень каналу),
   `overrides::tests::decision_allowlist_wins_on_conflict` +
   `conflicts_reports_identical_domain_string_in_both_lists` (рівень юніта) — план вище помилково
   називав це "залишком", виправлено після перевірки. Fuzz-планка перевизначена як дані:
   `serve_never_panics_on_arbitrary_input_for_any_documented_route` — одна властивість на кожну
   `(path, method)`-пару з `dispatch::ROUTES` (не лише на маршрут, включно з `/dns-query`'s POST,
   яку перший драфт пропускав через `route.methods.first()`). Два реальні advisor-catch перед
   комітом (жоден не production-баг, обидва — "властивість не досягає коду, який заявляє"):
   percent-encoding усього query-рядка ламало `key=value`-структуру (жоден GET-кейс не досягав
   розпізнаваного параметра), і POST завжди ніс `Content-Type: application/json`, тож `/dns-query`
   завжди 415-ився до декодування тіла. Обидва фікси емпірично підтверджені — тимчасовий
   `panic!()` у `parse_log_query`'s циклі й у `serve_dns_query`'s POST-гілці, властивість
   червона в обох випадках, відкат → знову зелена (295/295).
5. ~~**T-56** (звужена частина)~~ — **звужений сигнал зроблено 2026-08-29** (TASKS.md's власний
   рядок нижче лишається відкритим — не повне закриття, той самий узор, що й T-51 вище):
   "деградований апстрім" з уже наявного `QueryLog`-вікна (`admin::AdminStats.degraded_events`/
   `degraded_window`, `VoterVerdict::Timeout`/`Error` за останні 20 quorum-записів), у
   `dnsqb-tray`'s tooltip. Без жодного повідомлення "браузер може не використовувати цей DoH" —
   та вісь уже одного разу розвернута (DECISIONS.md, приватність-notice). Виявлення реального
   використання браузером (T-134) лишається відкритим — немає механізму domain→fixed-IP для
   canary, названо явно, не приховано.

Каденс не змінюється: одна задача — один комміт, advisor-гейт до і після, пауза й звіт між
задачами (project memory: `feedback_task_by_task_delegation_cadence.md`).

- [ ] T-51 — **Звужено 2026-08-29**: Chrome-половина підтверджена емпірично (проба вище — `Root`,
  не `TrustedPeople`, довірено без CT/SCT-попередження). Firefox-половина лишається відкритою,
  блокована на T-132 (окрема NSS-база, поза межами MVP) — не CT-політика сама по собі, а взагалі
  інший trust-store механізм, тож "перевірити CT-політику Firefox" не має сенсу перевіряти, доки
  сертифікат навіть не потрапляє в Firefox's власну базу. **Другий, окремий живий тест 2026-08-29
  (SPEC.md §2, метод описано там — probe-скрипт сам видалений разом зі scratch-проєктом,
  відтворюваний з опису)**: `cA=FALSE`-containment (сама причина, чому leaf-компрометація
  не еквівалентна повному MITM) також підтверджена емпірично, не лише виведена з RFC 5280 —
  "evil"-лист, підписаний ключем довіреного leaf-сертифіката для іншого хоста, отримав помилку
  сертифіката в Chrome, довірений leaf лишився довіреним. Незалежна властивість від CT/SCT-питання
  вище — не однакового рівня впевненості: `cA=FALSE`-containment це справжній позитивний результат
  (Chrome активно відмовив другому сертифікату), CT/SCT-відсутність попередження — це відсутність
  спостереженого попередження на одній версії Chrome, одній машині (n=1), не підтверджений офіційно
  виняток. Обидва пункти для Chrome більше не зовсім невідомі, але не варто рахувати їх однаково
  надійними.
- [ ] T-56 — Індикатор стану: чи браузер використовує локальний DoH, чи фільтрація активна, деградовані апстріми, окремий стан "фільтрацію вимкнено — 0 voters" (8, 3.3, 8.1) — `dnsqb-tray`'s tooltip (T-149) — простіший 3-станний попередник, не заміна: без перевірки браузера/watchdog, ціль лишається веб-UI чи повноцінному майбутньому екрану. **Звужена частина зроблено 2026-08-29** (TASKS-DONE.md не отримало запису — задача лишається відкритою, той самий узор "звужено, не закрито", що й T-51): "0 voters" уже було з T-149 (`NoActiveProvider`); "деградовані апстріми" тепер теж є — `admin::AdminStats.degraded_events`/`degraded_window`, сирі лічильники (не булевий прапорець і не відсоток — advisor-catch під час планування: поріг "хоч один timeout за N" був би майже завжди `true` при звичайному fail-open, а вигаданий відсотковий поріг не мав би джерела в SPEC.md), рахуються за останні 20 `decision_source = QUORUM`-записів, показані в tooltip лише коли `degraded_events > 0`. Лишається відкритим: перевірка браузера, watchdog-стан (Фаза 3 — покривається **T-95**, не будувати двічі), повний екран/веб-UI-версія. **T-134 (SPEC.md Відкриті питання п.10) дала кандидатну, але неперевірену техніку** для "браузер не використовує локальний DoH": активний canary-запит із `/admin/ui` — потребує нового, ще не спроєктованого механізму прив'язки домену до фіксованої IP (override-список сьогодні вміє лише Allow/Block, не довільну відповідь) і окремого empirical scratch-прогону перед довірою, не готовий план імплементації.

## Фаза 2 — Автоматизація сертифіката (Windows)

**Формально закрита 2026-08-31.** Усі задачі фази поставлені або свідомо закриті: GeoIP-workstream
(T-74–T-82), сертифікат-примітиви — генерація leaf + self-signed SAN (T-48), приватний ключ у
Windows Credential Manager (T-67), install/uninstall у `CurrentUser\Root` (T-49), ротація (T-69);
MaxMind-режим + креденшели в OS secret store (T-162/T-163); рантайм-список провайдерів + кастомний
DoH-URL (T-72/T-73); T-164 (ECS-preset) — відхилено (див. вище). Дет. — TASKS-DONE.md.

**Перенесено з Ф2, не втрачено:**
- **T-70 → Фаза 3** (нижче): Windows-половина — пакетований деінсталятор (MSIX) — заблокована на
  T-156 (пакування), яка і так у Фазі 3; логічно тримати їх разом. macOS-половина вже у Фазі 6.
- **Ф1-гейт лишається відкритим у Фазі 3**: T-66's метрики не підтвердили приріст кворуму над
  найкращим одиночним провайдером (AdGuard 0/38, n=1), і жоден зафіксований тест не проганяв
  живий "браузер → локальний DoH" прохід (реально налаштований Chrome Custom DoH provider). Ф2
  стартувала рішенням користувача *попри* цей відкритий гейт (див. план нижче) — її закриття не
  закриває гейт, а несе його далі.
- ~~**`DEFAULT_PROVIDER_IDS` (`upstream.rs`) — відкрите рішення без номера**~~ — **вирішено
  T-170 (2026-09-05, DECISIONS.md):** дефолтний активний набір першого запуску = `quad9` +
  `cloudflare-malware` + `adguard` (два Security-tier §3.4 + AdGuard для реклами). Було `quad9`
  + `adguard`.
- **T-51, T-56** лишаються carried-forward backlog у секції `## Фаза 1` (заблоковані на
  поза-MVP T-132 / T-134); не є частиною Ф2. T-56's watchdog-half покривається **T-95** у Фазі 3.

**План виконання Ф2 (2026-08-29, plan-mode + advisor — виконано, збережено як історія).** Ф2
стартувала з відкритим Ф1-гейтом — T-66's метрики не підтвердили гіпотезу кворуму, живий
browser-DoH-прохід так і не проведений (SPEC.md/TASKS.md, коміт `631f96a`) — старт зараз це
рішення користувача цієї сесії, не закриття гейта; наступна сесія не повинна читати цей план так,
ніби гейт пройдено.

**Реальний блокер, вирішений з користувачем 2026-08-29, уточнено 2026-08-31**: T-68/T-70's
macOS-половини, T-71 (порт на macOS), T-83 (CI matrix +macOS) усі потребують реального macOS
build/test-доступу (Keychain API, `security` CLI) — це середовище суто Windows. **Рішення
користувача: вся друга/третя платформа (macOS, Linux) — це окрема, свідомо остання `## Фаза 6`
нижче** (не "може колись", а планова ціль винесена в кінець). Фаза 2 = лише Windows-можливе.
Порядок нижче побудований навколо того, що реально збирається й тестується в цьому середовищі
зараз.

Три ключові знахідки з дослідження (три паралельні Explore-агенти, перед цим планом):
1. **GeoIP (T-74–T-82) повністю самодостатній і неблокований.** SPEC.md §3.5 уже дає повний
   дизайн (DB-IP Lite дефолт, MaxMind опційно — T-80; крок 8 конвеєра, живцем на cache-hit і
   свіжий Quorum-Allow, ніколи не кешується сам; OR по IP; порожній список країн — nop; дефолт
   порожній; UI-попередження про over-blocking при кожному доданні країни; TLS+checksum перед
   atomic swap файлу бази — нового патерна в кодовій базі ще нема). Точки підключення в
   `pipeline.rs` уже знайдені: `response_from_cache_entry`/`cache_hit_response_with_meta`
   (cache-hit) і `handle_allow` (свіжий Quorum-Allow, після `extract_ips`). DTO-шар в `admin.rs`
   (`DecisionSourceView::GeoIp`, `LogEntryView.geoip_country`) уже існує, запінений `None` до
   T-79 — компайл-тайм forcing function, не дизайн з нуля.
2. **Сертифікат-автоматизація (T-67–T-71, T-83) чисто ділиться на Windows-можливе й
   macOS-блоковане.** T-69 (ротація сама викликає вже наявний CN-based `trust_store::
   uninstall()`) — чиста Windows-логіка, мала. T-67 (приватний ключ у DPAPI) — Windows-можливо,
   але `cert.rs` під крейт-широким `#![forbid(unsafe_code)]` (не локальним для файлу), а DPAPI —
   сирий Win32 FFI; проєктний стек-принцип "`#![forbid(unsafe_code)]` де тільки можливо" робить
   гілку "safe wrapper crate" сильно пріоритетнішою за гілку "точковий виняток" — власний
   `EnterPlanMode`+`AskUserQuestion`+advisor цикл при старті T-67, не advisor сам по собі
   (вплив на крейт-широкий інваріант — рішення користувача, не лише агента). `trust_store.rs` не
   має жодної абстракції під другу платформу сьогодні (ні трейта, ні `#[cfg(target_os)]`) —
   портування на macOS будує цю межу з нуля, названо явно заздалегідь.
3. **Кастомний DoH-провайдер + presets (T-72/T-73) — найризикованіша задача фази.**
   `quorum::resolve()`/`combine()`/`voter_records()`/`representative_allow_answer()`/`evaluate()`
   усі хардкоджені на рівно два named-параметри (`quad9`, `adguard`), не список; per-provider
   block-signature (`evaluate()`'s match) — теж код, не дані. Узагальнення на довільний список
   провайдерів чіпає сигнатури всіх цих функцій — справжня архітектурна правка (global CLAUDE.md's
   "state machine / протокол / велика структурна правка" поріг). Власний `EnterPlanMode`+advisor
   цикл при старті задачі, не спроєктовано в цьому фазовому плані.

**Порядок виконання:**
1. GeoIP, T-74→T-82 у цьому внутрішньому порядку: T-74 (`maxminddb`-рідер — fixture-ризик
   перевірено живим WebFetch: `maxmind/MaxMind-DB`'s `test-data/` має малі Apache-2.0/MIT
   fixture-файли, вендоряться напряму, без git submodule — T-74 не залежить від T-75) → T-75
   (завантажувач, TLS+checksum перед atomic swap, нова `AppState`-секція за зразком
   `CacheState`/`OverridesState`, зберігає timestamp для T-78) → T-76 (підключення в конвеєр на
   обох знайдених точках, OR по IP, nop на порожньому списку) → T-79 (`DecisionSource::Geoip` +
   `geoip_country`, одразу після T-76) → T-82 (закриваючі юніт-тести на OR/nop як іменовані
   властивості, той самий T-60 прецедент) → T-77 (UI: список країн, over-blocking попередження,
   за зразком T-47's overrides-картки) → T-78 (UI: дата останнього оновлення бази) → T-80
   (advanced-режим, власний MaxMind-ключ) → T-81 (атрибуція CC BY-SA 4.0).
2. Сертифікат-автоматизація, лише Windows-можливе: T-69 (ротація) → T-67 (DPAPI, власний
   plan+advisor цикл перед стартом).
3. Кастомний DoH-провайдер + presets, останнє, найризикованіше: T-72/T-73 (власний plan+advisor
   цикл перед стартом).

**Винесено у `## Фаза 6` (друга/третя платформа), не в цьому плані** (рішення користувача вище):
T-68/T-70's macOS-половини, T-71, T-83. Фаза 6 — свідомо остання; повернутись до неї після
Фаз 3–5 або коли з'явиться реальний macOS-доступ, що настане раніше.

Каденс не змінюється: одна задача — один комміт, advisor-гейт до і після, пауза й звіт між
задачами (project memory: `feedback_task_by_task_delegation_cadence.md`).

**Прогрес (оновлюється по ходу):** T-74 done (TASKS-DONE.md, коміт `8ba3cf6`), T-75 done
(TASKS-DONE.md, 2026-08-29) — обидва разом закрили весь fixture-ризик і checksum-невизначеність,
названі вище в самому плані. T-76 done (TASKS-DONE.md, 2026-08-30) — GeoIP-фільтр підключено в
конвеєр на обох знайдених точках. T-79 done (TASKS-DONE.md, 2026-08-30) —
`decision_source = GEOIP`'s `geoip_country`-поле тепер реальне (`geoip::blocks_any` розширено до
`blocking_country -> Option<String>`), проведено без змін через увесь стек до `GET /admin/log`.
T-82 done (TASKS-DONE.md, 2026-08-30, докс-only, без нового коду) — той самий T-60 прецедент:
OR-по-кількох-IP і nop-на-порожньому-списку вже мали власні тести з T-76/T-79, `git log -S`
підтверджує. T-77 done (TASKS-DONE.md, 2026-08-30, три коміти) — `GET /admin/geoip`/`POST
/admin/geoip/add`/`remove` + `#geoip-body` на `/admin/ui`, перший живий шлях запису
`[geoip] blocked_countries` без ручної правки TOML. T-78 done (TASKS-DONE.md, 2026-08-30, один
коміт) — `GeoipCountriesResponse` розширено `database_loaded`/`database_built_at_ms`, три
завжди-видимих рядки на `#geoip-body` замість одного банера. T-161 done (TASKS-DONE.md,
2026-08-30, один коміт, поза фазами — той самий T-134/T-139/T-141-прецедент нумерованих ad-hoc
задач, закритих напряму в TASKS-DONE.md без окремого рядка тут) — `LogEntry`/`LogEntryView`
отримали `resolved_ip_country`, інформаційна країна першої резолвленої IP для КОЖНОГО рядка логу
з реальною відповіддю (не лише `decision_source=GEOIP`, на відміну від наявного `geoip_country`).
T-80 done (TASKS-DONE.md, 2026-08-30, один коміт) — опційний MaxMind GeoLite2 як джерело GeoIP-бази:
новий `geoip_credentials.rs` читає plaintext `geoip_maxmind.toml`, `geoip_updater` гілкується на
`GeoipSource` (DB-IP Lite / MaxMind); Basic-auth завантаження модерного permalink (ендпоінт
перевірено `curl`-пробою — `401`, не `404`), опортуністичний `.tar.gz.sha256`, розпаковка
`.mmdb`-члена з `.tar.gz` у памʼяті (`tar`-крейт, без хендмейд-парсера). UI + DPAPI +
UI-сигнал про зламані креденшели свідомо відкладені на **T-162** (той самий T-74/T-75→T-77
backend-before-UI поділ). T-81 done (TASKS-DONE.md, 2026-08-30, один коміт) — постійний футер
`#credits` на `/admin/ui`: обов'язковий сніпет-посилання db-ip.com + ліцензія **CC BY 4.0**
(підтверджено напряму проти db-ip.com, не лише web-пошуком T-75), атрибуція MaxMind GeoLite2
"у розширеному режимі" (T-80), Apache-2.0 самого застосунку; статичний HTML, без DTO/маршруту.
**GeoIP-workstream (T-74–T-82) завершений.** T-69 done (TASKS-DONE.md, 2026-08-30, один коміт,
plan-mode + advisor) — механізм ротації сертифіката: дія трею "Перевипустити сертифікат" →
`dnsqb_service::rotate_certificate` як упорядкована композиція наявних примітивів (generate →
`uninstall` CN-вичерпний → persist → `ensure_installed`), без нового примітиву видалення; порядок
"очистити перед записом" вимушений спільним `CommonName`; новий сертифікат діє лише після ручного
перезапуску `dnsqb-service`. T-162 (part) done (TASKS-DONE.md, 2026-08-31, один коміт, plan-mode +
advisor) — MaxMind-режим отримав UX: адмін-маршрут `GET`/`POST /admin/geoip/maxmind` +
`/maxmind/clear` + картка на `/admin/ui` (файл `geoip_maxmind.toml` більше не редагується руками),
save-time проба проти `download.maxmind.com` (`check`: VERIFIED/REJECTED/UNVERIFIED — Три Б),
`database_source` (closed enum) на `GeoipCountriesResponse` з метаданих завантаженого reader-а.
Plaintext-файл лишається (ACL-обмежений). **Решта T-162 → T-163** (DPAPI, `/admin/reset` re-read +
runtime-підхоплення джерела, виявлення "зламалися пізніше"). T-72/T-73 **done** (TASKS-DONE.md,
2026-08-31, plan-mode + advisor, 3 коміти: backend → closing-review → UI-картка) — `quorum`
більше не хардкодить 2 провайдери: рантайм-список `[[providers]]`, усі 10 presets §3.4 + кастомний
`https`-URL, 3 евристики `BlockSignature`, маршрути `GET /admin/providers` +
`POST /admin/providers/{add,remove,set-enabled}`, картка `#providers-body` на `/admin/ui`,
`AdminConfigUpdate` втрачає `providers`, `AdminStatusResponse.providers` → `active_providers`;
SSRF-валідація (літеральний хост), `url` як пряма залежність. ECS-провайдер (Quad9 9.9.9.11)
— T-164, **відхилено 2026-08-31** (TASKS-DONE.md): жива проба показала, що `dns11.quad9.net`
і так пересилає реальну /24 клієнта авторитативним серверам без опції від нас — privacy-ціна
не варта нішевого preset-у; ECS лишається навмисно не-ціллю.

**T-67 done** (2026-08-31, plan-mode + AskUserQuestion + advisor обидва боки, 1 коміт) —
приватний ключ TLS-сертифіката тепер у Windows Credential Manager через крейт `keyring`
(`key_store.rs`), на диску лишається лише публічний `cert.pem`. Рішення користувача: `keyring`
(safe wrapper, `#![forbid(unsafe_code)]` цілий), не точковий `unsafe` DPAPI-виклик; одноразова
міграція старого plaintext `key.pem` у сховище (декод → запис → занулити-й-видалити). Ім'я
запису прив'язане до app-data-теки, тож scratch-екземпляр не чіпає реальний ключ.
`windows-native-keyring-store` несе `unsafe` FFI; `keyring`-фіча `v1` обов'язкова, Unix/Apple
store-крейти target-gated (тільки в `Cargo.lock`, `deny`/`audit` чисті). Повний запис —
TASKS-DONE.md. macOS Keychain / Linux Secret Service `keyring` абстрагує, але не перевірено —
**Фаза 6 (T-71)**.

## Фаза 3 — Продакшн-hardening

**План виконання Ф3 (2026-09-01, plan-mode + advisor, збережено для наступних сесій).** 26
задач цієї секції (+ T-146 з бэклогу) у 5 незалежних напрямах (watchdog-ядро, мережевий стан,
шифрована персистентність, enterprise policy, release-інженерія + пакування) згруповано у
**9 батчів (3.0–3.8)** за спільним дизайном, не за кількістю задач.

**Каденс за батчами — без зниження якості.** Стояча каденс (одна задача — один коміт, advisor
до/після, пауза-звіт між задачами) лишається **на рівні задачі**. Батчинг міняє лише
**plan-mode + advisor kickoff**: один цикл на батч (на першій задачі батча), не один на задачу
— бо задачі в батчі ділять один дизайн. Межі батчів = точки, які важко відкотити. Closing
advisor — перед тим, як останній коміт батча вважається зробленим; CI-green — після кожного
пушу; пауза-звіт — між батчами (і всередині батча, якщо задача відкриває розвилку). Кожен
новий модуль/ендпоінт — 4 категорії тестів (Happy / Security-Boundary / Misuse-Fool / Error) +
Concurrency/Recovery.

- **Батч 3.0 — kickoff (без номера задачі)**: дизайн-spike watchdog + `diagrams/watchdog-{state,
  channels}.md` (SPEC §7 — лише проза, ground-truth ритуал вимагає діаграму до коду). Вирішити
  крос-батчеві рішення: IPC-транспорт Windows (`tokio::net::windows::named_pipe`, safe —
  `#![forbid(unsafe_code)]` цілий, жодного raw `CreateNamedPipeW`; ім'я каналу з хешу app-data
  теки, як `key_store::entry_name`); single-instance guard (safe-крейт `named-lock`/`single-
  instance`/`fslock` чи advisory file lock — вет у SECURITY.md + deny.toml); heartbeat wire-
  формат (мала фікс-структура, length-prefixed, не JSON; інтервал ~5с, поріг 3 пропуски поспіль
  на канал — SPEC §7); spawn через `current_exe().parent()`, ніколи PATH; `dnsqb-watcher` як
  lib-залежність від `dnsqb-service` (як трей — для `AdminClient`); як `dnsqb-watcher` без UI
  сигналить `GaveUp` (файл стану в app-data теці, який трей полить і `/admin/status` читає →
  Батч 3.3). Власний plan-mode + AskUserQuestion + advisor. Виводить сам цей блок у TASKS.md.
- **Батч 3.1 — liveness-примітиви (T-92, T-84, T-85, T-86)** — ✅ зроблено 2026-09-02 (див. Прогрес нижче): single-instance guard першим (кожен
  spawn-шлях його потребує); named-pipe IPC ping/pong (framing/parse чистий, окремо від I/O);
  shared heartbeat-файл (`mtime` touch + чистий предикат "stale?"); `/health` на `dnsqb-service`
  (у `dispatch::ROUTES` + хендлер + перенести з `serve_returns_404_for_every_path_outside_the_
  documented_allowlist` у справжній 200-тест). **`/health` глибша за "процес існує", але БЕЗ
  жодного upstream-виклику** — інакше рестарт при обриві мережі (саме той false positive, від
  якого мультиканальність SPEC §7 і захищає); "чи є інтернет" — робота Батча 3.4. **T-93
  розділено**: тут — per-channel "канал N недоступний, peer живий → канал каже 'нема сигналу',
  сам не робить висновок 'смерть'" (один тест на канал); end-to-end voting-assert — у Батчі 3.2,
  **не** покривається per-channel тестами.
- **Батч 3.2 — ядро рішень (T-87, T-88, T-89, T-90, T-91, T-93, T-94)**: голосування
  (`vote_watcher_checks_service` 2-з-3, `vote_service_checks_watcher` unanimous), `next_backoff`,
  `restart_budget -> Allowed | GiveUp` — чисті функції. **T-93** тут = end-to-end "один канал
  мовчить + два живі → не рестарт"; **T-94** = гілки 2-з-3 та unanimous. `start_paused` де є час
  (SPEC §7 — найважливіші тести модуля). Імпурна оболонка: `verify_pid_alive` (вет-крейт напр.
  `sysinfo`, не raw FFI), spawn/kill, запис файлу стану. **T-91 GaveUp** несуча вимога — після N
  рестартів у вікні: зупинитись, записати GaveUp, ніколи не циклити (SPEC §7).
- **Батч 3.3 — збірка (T-150, T-95)**: `dnsqb-watcher` як ідемпотентний entry point автозапуску
  (на старті перевіряє обидва siblings через guard+PID примітиви 3.1/3.2, піднімає відсутнє,
  повторний запуск — no-op; реєстрація Run-key/ярлика — у T-156, тут лише поведінка); стан
  watchdog у tray-tooltip + поле `/admin/status` (через `AdminClient`, читає файл стану 3.0).
  Частково закриває watchdog-half T-56. Кінець 3.3 = watchdog демонстрований end-to-end.
- **Батч 3.4 — мережевий стан (T-155, T-154, T-152)**: власний plan+advisor (T-155 додає
  `DecisionSource` + admin-тумблер; T-154 чіпає hot-path резолвера). Спершу емпірична проба (SPEC
  + T-155 вимагають): чи `reqwest`/OS уже пробує 2-гу A-адресу DoH-хостнейма при відмові 1-ї —
  результат визначає обсяг T-154. T-155 — явний тумблер + окремий `DecisionSource` ("фільтри
  недоступні, fallback на baseline"), незалежний від fail-open/closed/degraded; зробити наявну
  неявну fail-open поведінку явною й логованою. T-154 — baseline-failover на резерв
  (Cloudflare→Quad9→Google §3.4) лише при повній невідповіді, логовано, не рутинний
  load-balancing. T-152 — офлайн як окремий стан: multi-marker досяжність (кілька незалежних
  `generate_204`-ендпоінтів), швидкий шлях замість повного per-query таймауту коли інтернету
  просто нема; окремо в індикаторі T-95 від "апстрім деградований". Дизайн відкритий у SPEC →
  AskUserQuestion на kickoff (які маркери, як часто, як узгоджується з timeout-режимами).
- **Батч 3.5 — шифрована персистентність**: ~~T-146 + T-96 (лог)~~ **зроблено 2026-09-03**
  (plan+advisor kickoff+closing) — `encrypted_file` (`XChaCha20Poly1305`, RustCrypto, рішення
  користувача), ключ у OS secret store (`key_store`, T-67-механізм), формат `query-log.enc`,
  `persist_query_log` конфіг-прапорець (без UI-тумблера), пасивний `/admin/ui`-індикатор
  (`AdminStatusResponse.query_log_persisted`). Наратив → TASKS-DONE.md.
- **T-97 — шифрована персистентність кешу**: ~~`persist_cache`~~ **зроблено 2026-09-03**
  (plan+advisor kickoff+closing, коміти `9f5a316`…) — `cache.enc` (той самий `encrypted_file` /
  `FileKind::Cache` / один `persistence-key`), `cache_persist_dto` (абсолютний настінний дедлайн
  замість монотонного `Instant`; лише `Verdict::Allow` — `Block` не персиститься), `cache_persist`
  (`Cache::snapshot`/`restore`, 60 s + shutdown флаш), `AdminStatusResponse.encrypted_persistence`
  + пасивний `/admin/ui`-рядок. Наратив → TASKS-DONE.md.
- **Батч 3.6 — enterprise policy (T-98, T-99) — завершено 2026-09-04, docs-only.** **T-98**
  (research): механізм звірено з Chromium `policy_definitions` YAML — `DnsOverHttpsMode` enum
  `off/automatic/secure` (Chrome 78+), `secure` = без тихого фолбеку; `DnsOverHttpsTemplates`
  (Chrome 80+) обов'язковий при `secure`, `{?dns}` ⇒ GET, некоректний шаблон мовчки ігнорується;
  реєстр `HKLM\SOFTWARE\Policies\Google\Chrome`, `REG_SZ`; tiered-докази в SPEC.md §"Відкриті
  питання" п.3. **T-99 закрито без коду** (kickoff-AskUserQuestion, формат T-164): `secure` =
  Chrome-резолвінг hard-fail при мертвому сервісі (Три Б user-safety), `HKLM\...\Policies` =
  адмін-права + машинно-глобально (конфлікт із «без постійних підвищених прав»), Chrome-only —
  той самий висновок, що T-134 для Firefox. Пом'якшення п.10 лишається за індикатором T-56.
- **Батч 3.7 — release-інженерія (T-100, T-102, T-103) — завершено 2026-09-04, CI-only**
  (plan+advisor kickoff+closing). T-100: `--locked` скрізь + `.cargo/config.toml` `/Brepro`
  (MSVC-triple) + `[profile.release] codegen-units = 1` (типове 16 збирало `dnsqb-service`
  недетерміновано — зловлено cross-path gate'ом) + блокуюча джоба `repro` (дві чисті `--release`
  збірки в **різних абсолютних теках**, SHA-256). T-102: `release.yml` підписує 3 бінарники —
  **ефемерний self-signed `test-signed`** за замовчуванням (рішення користувача: реальний cert
  опційно через secret `CODESIGN_PFX`; продакшн-довіра = пере-підпис Microsoft Store при
  публікації MSIX, Батч 3.8); ім'я артефакту несе режим. T-103: тег `v*` → повторний доказ
  cross-path репродукованості → **чернетка** GitHub-релізу з 3 `.exe` + `SHA256SUMS`, публікує
  людина. Плюс `Swatinem/rust-cache` на cargo-джобах (**не** `repro`/release), `concurrency:
  cancel-in-progress` на всіх 3 workflow, `paths-ignore` для `**/*.md`/`diagrams/**`/`mockups/**`
  на ci.yml+codeql.yml (коміт лише з докам не запускає жодного CI). **Нова задача T-167**
  (ревізія всіх `.md` для читача-людини) — у списку задач нижче.
- **Батч 3.8 — пакування + повне видалення (T-156, T-70) — завершено 2026-09-04, останній батч
  Фази 3.** (plan+advisor kickoff+closing, kickoff-AskUserQuestion 3 форки). T-156 — MSIX
  (`packaging/`), entry point + `windows.startupTask` обидва `dnsqb-watcher.exe`, `msix`-job у
  `release.yml`. T-70 — `local_state::remove_all`, in-app дія (MSIX не має uninstall-хука), не
  «деінсталятор кличе». macOS-половина → Ф6. Наратив → TASKS-DONE.md.

**Порядок:** 3.0 → ~~T-101~~ → ~~3.1~~ → ~~3.2~~ → ~~3.3~~ → ~~3.4~~ → ~~3.5: T-146 + T-96~~ →
~~T-97~~ → ~~3.6~~ → ~~3.7: T-100/T-102/T-103~~ → ~~3.8: T-156/T-70~~ → ~~T-167~~ → ~~T-168~~ →
~~T-169~~ → **3.9: ~~T-170~~/T-171/T-172** → **3.10: T-173**. Після 3.10 Фаза 3 закрита **повністю**
(усі перенесені Ф1-гейти — закриті чесним записом, не проігноровані), із реліз-тегом `v0.3.0`.

**План фінального закриття Ф3 (2026-09-05, збережено для наступних сесій).** Фаза 3 формально
закрита 2026-09-04 (Батч 3.8), але три Ф1-гейти несуться відкритими з часу закриття Ф1 (`## Фаза 1`
closing-advisor, `## Фаза 2` "Перенесено з Ф2"): (1) T-66's метрики не підтвердили гіпотезу кворуму
на n=1; (2) жоден зафіксований тест не проганяв живий "браузер → локальний DoH" прохід;
(3) `DEFAULT_PROVIDER_IDS` = `quad9`+`adguard`, не SPEC §3.4/§3.5-й "лише Security" — **закрито
T-170 2026-09-05: `quad9` + `cloudflare-malware` + `adguard`, DECISIONS.md**. Батчі 3.9–3.10
закривають ці три — **не новою фічею, а завершенням верифікації** — і ставлять реліз-тег.

- **Батч 3.9 — закриття відкритих Ф1-гейтів (T-170, T-171, T-172).** Спільна тема = чесно
  довести/спростувати те, що лишилось недоказаним. **Гейт-модель:** T-170 міняє shipped-поведінку
  першого запуску, тож **його kickoff-AskUserQuestion _є_ його gate** — окремого advisor-проходу
  на T-170 не треба (вибір робить користувач). Плюс **один closing-advisor на весь батч після
  T-172** — він перевіряє фактичний результат усіх трьох (набір, виміри, браузерний leg), не
  повторює план. Порядок усередині: T-170 (визначити фінальний дефолтний набір) → T-171
  (переміряти кворум уже цим набором) → T-172 (живий браузерний прохід). Кожна задача — свій
  коміт; T-171/T-172 — manual-прогони (не CI), як `load_test`/`phase1_metrics`.
- **Батч 3.10 — фінальний реліз Фази 3 (T-173).** Бамп `0.2.0` → `0.3.0`, оновлення "Фаза 3
  повністю закрита" в TASKS.md/SPEC.md/README, тег `v0.3.0` → наявний `release.yml` (`repro` +
  build+sign + `msix`-job) → **чернетка** GitHub-релізу (3 `.exe` + `SHA256SUMS` + `.msix` + `.cer`),
  публікує людина. Свій короткий kickoff + **обов'язковий closing-advisor перед пушем тега** (тег —
  точка, яку важко відкотити). CI-green на бамп-коміті; після пушу тега — `gh run watch` на
  `release.yml`. **Відкат, якщо `release.yml` падає _після_ приземлення тега** (напр. `repro`-
  недетермінізм — це перший тег відколи `main.rs` змінився в T-169, а `repro` порівнює дві чисті
  release-збірки): видалити віддалений тег `git push origin :refs/tags/v0.3.0`, полагодити на
  `main`, перетегувати. Тег без чернетки релізу — не глухий кут, перетегування дозволене.

**Не в цих батчах (свідомо перенесено далі, не Ф3-закриття):**
- **T-51** — Firefox-половина cert-автоматизації (окрема NSS-база на платформу) — заблокована на
  поза-MVP T-132; Chrome-половина вже підтверджена (Ф1 closing-проба).
- **T-56** — повний єдиний індикатор стану (усі умови як конкуруючі стани, не `Filtering`-суфікс):
  browser-DoH-usage детекція (умова #1) заблокована на поза-MVP T-134. Watchdog-half закрито T-95.
- Обидві — carried-forward backlog у `## Фаза 1`, не невиконана Ф3-робота.

**Батч 3.4 зроблено 2026-09-03** (plan+advisor kickoff+closing, 8 комітів `850d650`…): T-154(a)
`connect_timeout` + T-154(b) `baseline_selector` (sticky failover Cloudflare→Quad9→Google з
авто-поверненням, ведений reachability-проб-таском); T-155 `DecisionSource::BaselineFallback` +
перемикач `serve_baseline_when_filters_unreachable` (дефолт OFF, DECISIONS.md 2026-09-03); T-152
`reachability`-модуль + офлайн-швидкий-шлях (миттєвий SERVFAIL, без fan-out/кешу) + індикатор
умова #3. Наратив → TASKS-DONE.md.

**Батч 3.5 — T-146 + T-96 зроблено 2026-09-03** (plan+advisor kickoff+closing, коміти
`b179870`…): `encrypted_file` (`XChaCha20Poly1305`, RustCrypto — рішення користувача, DECISIONS.md
2026-09-03), `key_store::load_or_create_persistence_key` (3-й секрет, orphan-детект),
`persist_dto` + `log_persist` (`QueryLog::restore`, `write_atomic`, 60 s + shutdown флаш),
`persist_query_log` конфіг-прапорець, пасивний `/admin/ui`-індикатор. Наратив → TASKS-DONE.md.

**T-97 (persist_cache) зроблено 2026-09-03** (plan+advisor kickoff+closing, коміти `9f5a316`…):
`cache.enc` (спільний `encrypted_file` / `persistence-key` з логом), абсолютний настінний дедлайн
замість `Instant`, лише `Allow`-вердикти (рішення користувача — `fail_closed`×persist взаємодія),
`AdminStatusResponse.encrypted_persistence`.

**Батч 3.6 (T-98 + T-99) завершено 2026-09-04** (docs-only): T-98 звірив Chrome DoH
enterprise-policy механізм із Chromium `policy_definitions` YAML (SPEC.md §"Відкриті питання"
п.3, tiered); **T-99 закрито без коду** (kickoff-AskUserQuestion — hard-fail-залежність +
конфлікт із «без постійних підвищених прав», як T-134).

**Батч 3.7 (T-100/T-102/T-103, release-інженерія) завершено 2026-09-04, CI-only** (plan+advisor):
`--locked` + `/Brepro` + `codegen-units = 1` + блокуюча `repro`-джоба (cross-path bit-identical);
`release.yml` build+sign (ефемерний `test-signed`, реальний cert опційно) + тег `v*` → чернетка
GitHub-релізу; rust-cache/concurrency/paths-ignore на CI. Нова задача **T-167** (ревізія всіх
`.md`).

**Батч 3.8 (T-156 + T-70) завершено 2026-09-04 — Фаза 3 формально закрита.** Деталі —
TASKS-DONE.md. **T-168 (аналіз перфомансу) + T-169 (запобіжник resource-exhaustion) завершено
2026-09-05. T-170 завершено 2026-09-05** (дефолтний набір = `quad9` + `cloudflare-malware` +
`adguard`, DECISIONS.md; kickoff-AskUserQuestion як gate). **Наступне — Батч 3.9 (T-171 переміряти
quorum-coverage → T-172 живий браузерний прохід) → Батч 3.10 (T-173 — реліз `v0.3.0`), і Фаза 3
закрита повністю. План — вище, «План фінального закриття Ф3».**

**Наскрізні гейти (батч ≠ шорткат):** pure/impure розділення (голосування/backoff/budget/
офлайн-рішення/stale-mtime-предикат/heartbeat-framing — чисті fn з іменованими тестами; сокети/
spawn-kill/registry/disk I/O — тонкі імпурні оболонки); `#![forbid(unsafe_code)]` цілий у кожному
крейті, Win32-примітиви лише через вет-safe-обгортки чи `tokio`; spawn через
`current_exe().parent()`, ніколи PATH; діаграми watchdog до коду (3.0); watchdog **повідомляє,
не лікує себе тихо в циклі** (SPEC §7, T-91 GaveUp).

**Прогрес (оновлюється по ходу):** Батч 3.0 зроблено 2026-09-01 (plan-mode + advisor) —
`diagrams/watchdog-state.md` + `diagrams/watchdog-channels.md` створені; SPEC.md §7.1
(9 реалізаційних рішень: IPC-транспорт, свій share_mode-lockfile guard, pid-файли,
wire-формат, spawn-шлях, lib-залежність, файл стану, числа інтервалу/backoff/бюджету, рантайм
watcher'а) зафіксовано.

**T-101 зроблено 2026-09-01** (opening advisor, docs+CI, окремий коміт) — `.github/workflows/
codeql.yml`: CodeQL SAST, мова `rust`, `build-mode: none` (без cargo build), `windows-latest`
(видимість `#[cfg(windows)]`-коду watchdog'а), на кожен push/PR. Алерти в Security-табі, не
валять білд; тріаж у тому ж проході. Винесено вперед з Батча 3.7, щоб код 3.1+ від початку
сканувався.

**T-165 зроблено 2026-09-01** (відступ на прохання користувача; opening+closing advisor, 3 коміти)
— розбір 17 знахідок першого CodeQL-скану, усі pre-existing. `disabled-certificate-check`
(`examples/phase1_metrics.rs`) виправлено реально — пінінг `app_data_dir()/cert.pem` як в
`AdminClient::new`, більше нема `danger_accept_invalid_certs`. 14 із 16 `cleartext-logging`
закрито реструктуризацією тестових catch-all (`other => panic!("{other:?}")` → явні
`Ok(None)`/`Ok(Some(_))`/`Err(err)` arms, форматується лише coarse `{err}` Display). 2 останні
(`trust_store.rs` 497/501 — `assert` друкує SHA-1 публічного сертифіката) dismiss'нуто через
API (`used in tests`, коментар про несекретність). **0 open alertів.**

**Батч 3.1 зроблено 2026-09-02** (plan-mode + advisor kickoff і closing, 6 комітів) —
liveness-примітиви як бібліотечний код у `crates/dnsqb-service/src/watchdog/`:
- передуючий рефактор: `paths::app_data_dir_hash` (`pub(crate)`) витягнуто з `key_store` (§7.1 #6).
- **T-92** — `watchdog::instance`: `share_mode(0)` advisory lockfile `<app-data>/<role>.lock`
  (2-й same-role процес → `AlreadyRunning`, OS звільняє на виході), `write_pid_file`/
  `read_pid_file` (`{pid,exe_path,started_at}` JSON, round-trip тест пінить формат для 3.2).
  Wired у `dnsqb-service` main **перед** cert-генерацією (closing-advisor: інакше 2 паралельні
  first-run'и пишуть неузгоджені cert.pem+ключ). `acquire` створює app-data теку.
- **T-84** — `watchdog::frame` (чистий: 20-байтний кадр, `len`=18 після себе), `watchdog::channel`
  (чистий: `channel_status(misses)` → `Signal|NoSignal` на `MISS_THRESHOLD`=3; T-93 per-channel
  половина = тип без `Dead`-варіанта), `watchdog::pipe` (`#[cfg(windows)]`: `HeartbeatPipeServer`/
  `Client` над `tokio` named_pipe, `recreate()` = `first_pipe_instance(false)`).
- **T-85** — `watchdog::heartbeat_file`: `touch`/`read` + чистий `is_stale(now,mtime,threshold)`
  (майбутній mtime → не stale). Чужий/обрізаний файл зі свіжим mtime → `marker_ok:false`.
- **T-86** — `GET /health` (peer `/dns-query`, не `/admin/*`): у `ROUTES`+`serve`+`serve_health`
  (прогонить локальний префікс pipeline для sentinel-домену, без upstream) → `HealthResponse
  {active_providers, geoip}`; `AdminClient::health()`. Manual smoke: 200 через реальний TLS.
- Не в 3.1: pipe-server/hb-touch цикли в main + `dnsqb-watcher` main + його Cargo.toml → Батч 3.3;
  voting/backoff/budget/PID-identity → Батч 3.2. **T-93 per-channel тест** структурний
  (тип без `Dead`), спостережуваний per-channel тест приходить із wiring у Батчі 3.3.

**Батч 3.2 зроблено 2026-09-02** (plan-mode + advisor kickoff і closing, 8 комітів) — ядро
рішень watchdog у `crates/dnsqb-service/src/watchdog/`, усе — тестовані бібліотечні одиниці:
- **T-87/T-88** — `watchdog::vote`: дві названі функції фіксованої арності (не одна на зрізі —
  T-41 slice-footgun): `vote_watcher_checks_service(ipc,file,health)` → `Dead` на `>=2` `NoSignal`
  (2-з-3), `vote_service_checks_watcher(ipc,file)` → `Dead` лише коли обидва `NoSignal` (unanimous).
- **T-90** — `watchdog::backoff`: `next_backoff(attempt)` над фіксованим розкладом `1→2→4→8→16 s`,
  cap 16 s; lookup через `.get().unwrap_or(CAP)`, in-bounds з рядка.
- **T-91** — `watchdog::budget`: `RestartBudget::register_attempt(now)` → `Allowed|GaveUp`, 5 / 600 s
  rolling window, per-target. Майбутній `window_started_at` (persisted, читається після годинникового
  стрибка) → вікно скидається (`duration_since` майбутнього старту → `Duration::MAX`), помилка в бік
  «дозволити рестарти», не «вічний GaveUp».
- **T-89** — `watchdog::pid_check`: `verify_pid_alive(pid, expected_exe)` → `Alive|Gone|
  IdentityMismatch` через `sysinfo` (0.39.6, `default-features=false`, `["system"]`; API звірено
  scratch-пробою). Звіряє PID **і** exe-шлях (fallback на `name()`, якщо `exe()`=`None`) — recycled
  PID інакше = тихий вічний збій. `sysinfo` тягне транзитивний `winapi` 0.3.9 (via `ntapi`) — 0
  нових advisory, без змін `deny.toml`; повне обґрунтування в SECURITY.md.
- **spawn** — `watchdog::spawn`: чиста `resolve_sibling_path(current_exe, role)` (відхиляє
  не-абсолютний шлях → `NotAbsolute`, ніякого CWD-relative), тонка `spawn_sibling` (`is_file()` →
  `NotFound`, hard error, ніколи PATH). `kill` свідомо не будується.
- **state** — `watchdog::state`: `WatchdogState` (7 варіантів 1:1 з `watchdog-state.md`),
  `WatchdogTarget` (2, вужче за `instance::Role`), `WatchdogStateFile` + атомарний `write`/`read`
  `watchdog-state.json` (§7.1 #7). `last_error: Option<WatchdogErrorLabel>` — закритий enum, не
  `String` (структурно не несе домен).
- **transition** — `watchdog::transition`: чиста `transition(current, &TransitionInput) ->
  WatchdogState`, композиція vote/pid/budget/backoff у автомат `watchdog-state.md`, тотальна.
  Побічний ефект 3.3 виводить із поверненого стану.
- **T-93 — чесно:** per-channel половина зроблена структурно в 3.1 (`ChannelStatus` без `Dead`);
  vote-рівень тут (Коміт 1); e2e «один канал мовчить, два живі → не рестарт» на рівні `transition`
  (Коміт 7, спостережувано на стані); loop-рівень — Батч 3.3. **T-94** — обидві гілки, напряму й
  крізь `transition`.
- Не в 3.2: робочі цикли на 5 s тику на обох бінарниках; `dnsqb-watcher` main + його Cargo.toml
  (`tokio` `process`/`rt`/`time`, §7.1 #9); `/admin/status.watchdog` + tray-tooltip → Батч 3.3 /
  T-95; `kill` sibling'а → лише якщо 3.3 доведе потребу.

**Батч 3.3 зроблено 2026-09-02** (plan-mode + advisor kickoff і closing, 7 кодових + 1 docs коміт)
— watchdog зібраний і демонстрований end-to-end:
- **`watchdog::loop_driver`** (чистий) — один напрям як тік-автомат: тримає per-channel лічильники
  пропусків, `RestartBudget`, backoff-дедлайн, spawn-once латч; `tick(now, ChannelObs) ->
  TickOutcome { state, effects }` композить `channel_status`→`vote_*`→`transition`. **Loop-рівневі
  T-93/T-94** тут (Батч 3.2 їх відклав): один канал мовчить → `ChannelDegraded`, **нуль** `Spawn`;
  два мовчать → рестарт **рівно один** `Spawn` за епізод; 5/600s бюджет → `GaveUp` + `LogGaveUp`
  один раз, далі нуль `Spawn`.
- **`watchdog::launcher::plan_launch`** (чистий) — T-150 ідемпотентність: `AlreadyRunning` лише за
  наявний pid-файл + `PidCheck::Alive`; усе інше → `Spawn`.
- **`dnsqb-service` main** — 3 detached tokio-таски: pipe-сервер (канал 1; публікує `last_ping_at`),
  `service.hb` touch (канал 2), цикл `service→watcher` (`LoopDriver` unanimous; `spawn_sibling
  (Watcher)`; **не** персиститься — §7.1 #7). Service-side канал 1 = «час від останнього ping'а»,
  без server-initiated кадру.
- **`dnsqb-watcher`** — `todo!()` замінено: `#[tokio::main(flavor = "current_thread")]`
  (`Cargo.toml` features per §7.1 #9; flavor тримає однопотоковість, бо lib-dep уніфікує
  `rt-multi-thread`); guard + `watcher.pid`; **T-150 ланчер** (`ensure_sibling_running` для service
  і tray, лише на старті — tray launcher-scope, не heartbeat-monitored); цикл `watcher→service`
  (3 канали, `LoopDriver::restored`-або-`new`, пише `watchdog-state.json` **кожен тік** для
  свіжості mtime). Вікно resume — 90s (покриває ~40s латентність service→watcher рестарту).
- **T-95** — `AdminStatusResponse.watchdog: Option<WatchdogStatusView>` (2-варіантна проєкція
  `RESTARTING`/`GAVE_UP`; `dispatch::read_watchdog_view`, стале/відсутнє/проміжне → `None`);
  tray `TrayStatus::{ServiceRestarting, ServiceGaveUp}` (`status::watchdog_override`, перевіряється
  **перед** `/admin/status` — watchdog вище за 0-voters, DECISIONS.md 2026-09-02).
- **`dnsqb-tray`** — тепер бере `Tray` guard + пише `tray.pid` (ланчер це вимагає, інакше кожен
  старт watcher'а плодив би трей).
- **⚠️ GAP закрито:** DECISIONS.md 2026-09-02 — порядок пріоритету індикатора
  `браузер → watchdog → 0-voters → деградація`.
- Ручний end-to-end (scratch `%LOCALAPPDATA%`): (a) старт лише watcher'а → підняв service + один
  tray, усі lock/pid/hb/state файли; (b) kill service → `HEALTHY→SUSPECT_DEAD→VERIFYING_PID→
  RESTARTING→BACKOFF_WAIT→(spawn)→HEALTHY`, `watchdog-state.json` пройшов усі переходи; (c) kill
  watcher → service підняв його за ~39s; (d) `/admin/status.watchdog` = `null` у HEALTHY,
  `RESTARTING` під час рестарту; relaunch watcher'а → нуль дублів.

**Батч 3.5 (T-146 + T-96) зроблено 2026-09-03. T-97 (persist_cache) зроблено 2026-09-03.**
**Батч 3.6 (T-98 research + T-99 закрито без коду) завершено 2026-09-04.**
**Батч 3.7 (T-100/T-102/T-103, release-інженерія) завершено 2026-09-04, CI-only.**
**Батч 3.8 (T-156 MSIX + T-70 local-state removal) завершено 2026-09-04 — Фаза 3 формально
закрита.** **T-167 (ревізія документації) завершено 2026-09-04.** **T-168 (аналіз перфомансу +
навантажувальний тест + дизайн-рішення) завершено 2026-09-05** (plan+advisor kickoff+closing,
3 коміти) — розділено: імплементація запобіжника винесена в **T-169**. **T-169 (запобіжник
resource-exhaustion — `admission::ConnectionGate` + `[limits]`-конфіг + хендшейк/idle-таймаути)
завершено 2026-09-05** (plan+advisor kickoff+closing, 6 комітів, включно з closing-advisor).
**T-170 завершено 2026-09-05** — дефолтний набір `DEFAULT_PROVIDER_IDS` = `quad9` +
`cloudflare-malware` + `adguard` (DECISIONS.md 2026-09-05; kickoff-AskUserQuestion як gate, без
окремого advisor-проходу). Наступне — **Батч 3.9** (T-171 переміряти quorum-coverage, T-172
живий браузерний прохід) → **Батч 3.10** (T-173 бамп `v0.3.0` + тег + чернетка MSIX-релізу) →
Фаза 3 закрита повністю.

- [x] T-70 — (Батч 3.8) **Windows-половина — зроблено 2026-09-04**: MSIX (T-156) не має хука на
  видалення взагалі, тож замість «деінсталятор кличе» — новий `local_state::remove_all`
  (`crates/dnsqb-service/src/local_state.rs`), in-app дія (трей «Повністю видалити» + `/admin/ui`
  + `POST /admin/uninstall-local-state`): `trust_store::uninstall()` + `key_store::delete_secret`
  для всіх трьох ключів (TLS, persistence, MaxMind), звіт по кожному артефакту незалежно
  (`Removed`/`NotPresent`/`Failed`). **macOS-половина (Keychain) → Фаза 6.** TASKS-DONE.md.
- [x] T-98 — (Батч 3.6) Перевірити актуальну документацію Chrome `DnsOverHttpsTemplates` enterprise policy перед імплементацією (Відкриті питання п.3) — **зроблено 2026-09-04, docs-only** (SPEC.md §"Відкриті питання" п.3 tiered; TASKS-DONE.md)
- [x] T-99 — (Батч 3.6) Enterprise policy автоматизація (Chrome `DnsOverHttpsMode=secure` + `DnsOverHttpsTemplates` через registry) — **закрито без коду 2026-09-04** (kickoff-AskUserQuestion, формат T-164): hard-fail-залежність Chrome від сервісу + конфлікт із «без постійних підвищених прав», Chrome-only, той самий висновок, що T-134 для Firefox; механізм задокументовано в SPEC.md §"Відкриті питання" п.3 для можливої майбутньої фази; TASKS-DONE.md
- [x] T-100 — (Батч 3.7) Reproducible builds — **зроблено 2026-09-04**: `--locked` скрізь у CI +
  `.cargo/config.toml` `/Brepro` (MSVC-triple) + `[profile.release] codegen-units = 1` + блокуюча
  джоба `repro` (дві чисті `--release` збірки в різних теках, SHA-256 порівняння). TASKS-DONE.md.
- [x] T-102 — (Батч 3.7) CI code-signing релізних бінарників — **зроблено 2026-09-04**:
  `.github/workflows/release.yml` підписує 3 бінарники (не бандл). Модель (рішення користувача):
  ефемерний self-signed `test-signed` за замовчуванням, реальний cert опційно через secret
  `CODESIGN_PFX`; продакшн-довіра = пере-підпис Microsoft Store при публікації MSIX (Батч 3.8).
  Ім'я артефакту несе режим. TASKS-DONE.md.
- [x] T-103 — (Батч 3.7) CI release-pipeline — **зроблено 2026-09-04**: тег `v*` → джоба `release`
  повторно доводить cross-path репродукованість → чернетка GitHub-релізу з 3 `.exe` + `SHA256SUMS`,
  публікує людина. `per-OS` = лише Windows (macOS/Linux → Ф6). MSIX-пакет — прогалина для Батча
  3.8. TASKS-DONE.md.
- [x] T-167 — (Батч Ф3, після 3.7) **Повна ревізія документації для читача-людини — зроблено
  2026-09-04** (plan+advisor kickoff+closing, kickoff-AskUserQuestion 2 форки). (a)+(d) README:
  додано передумову "встанови Rust", доведено обидва шляхи встановлення (з джерел і MSIX) до
  реального "тепер налаштуй браузер", чесно позначено, що живого браузер→DoH-проходу проєкт не
  підтвердив (замість вигаданого кроку перевірки — посилання на `/admin/ui`); (b) нова секція
  "Як працює фільтрація" — 8 кроків SPEC.md §5.3 простою мовою + легкий mermaid flowchart,
  вбудований у README без ритуалу `diagrams/README.md` (рішення kickoff); (c) SECURITY.md's
  таблиця залежностей стиснута зі знімком-не-логом — 57065→19099 символів (~66%), кожен рядок
  звірений по чек-листу "чому цей крейт / де unsafe / прийнятий ризик" до й після. Заразом
  виправлено дрейф: README's статус-бейдж і "Workspace" все ще казали "Фаза 3 не почата" /
  `dnsqb-watcher` — заглушка, хоча Фаза 3 вже закрита. TASKS-DONE.md.
- [x] T-156 — (Батч 3.8) MSIX-пакування — **зроблено 2026-09-04** (kickoff-AskUserQuestion, 3
  форки: sideload зараз/Store-identity пізніше; T-70 = in-app дія, не хук; повний скоуп із CI).
  `packaging/AppxManifest.template.xml` (`runFullTrust`, entry point + `windows.startupTask` обидва
  `dnsqb-watcher.exe`) + `packaging/pack-msix.ps1` (`makeappx pack` + `signtool sign`, той самий
  ефемерний/`CODESIGN_PFX` вибір, що T-102) + `release.yml`'s `msix`-job (`.msix`+`.cer` у чернетці
  релізу). `assets/gen-icon.py` — єдине джерело іконки застосунку всюди (не лише MSIX). Емпірично
  перевірено локально (Windows SDK 10.0.26100.0, той самий, що CI) і на реальному тег-релізі.
  **Store-субміт і Mac App Store/Flathub — свідомо поза скоупом**, лишається майбутньою задачею;
  маніфест структурований під підміну identity без переписування решти. TASKS-DONE.md.
- [x] T-168 — (Батч Ф3, після 3.8) **Аналіз перфомансу + навантажувальний тест + дизайн-рішення
  щодо resource-exhaustion — зроблено 2026-09-05** (plan+advisor kickoff+closing, 3 коміти).
  `PERFORMANCE.md` (новий) — таблиця складності всіх кроків конвеєра §5.3 + реальні цифри
  `examples/load_test.rs` (новий, manual, не CI): деградація **плавна й прогнозована**, нуль
  відмов до 3000 одночасних з'єднань / 2000 стрімів, `overrides::decision`'s O(n) при ~10k
  записів — +17% p50, не ризик. Дизайн-рішення в SPEC.md §1.1: обмежена одночасність із
  негайною відмовою (не глибока черга), щедра межа як backstop проти патологічного накопичення,
  Три Б-наслідок reject-vs-SERVFAIL лишено відкритим питанням. **Імплементація → T-169.**
  TASKS-DONE.md.
- [x] T-169 — (Батч Ф3, після 3.8) **Імплементація запобіжника resource-exhaustion — зроблено
  2026-09-05** (plan+advisor kickoff+closing, 5 комітів). Новий модуль `admission::ConnectionGate`
  (обмежена одночасність через `tokio::sync::Semaphore` + `AtomicU64` — без `Mutex`/`Arc<Mutex>`),
  негайна відмова на стелі: `main.rs` accept-loop бере `OwnedSemaphorePermit` до `tokio::spawn`, а
  на стелі закриває TCP **до TLS** (`drop(stream)` — рішення kickoff-AskUserQuestion). **Разом зі
  стелею**: `tokio::time::timeout` навколо `acceptor.accept` + `auto::Builder` http1
  `header_read_timeout` / http2 keep-alive — інакше гола стеля = slow-loris DoS. Нова
  `[limits]`-таблиця в `resolver_config.toml` (kickoff-рішення: конфіг-поля, не хардкод):
  `max_concurrent_connections` (дефолт 4096, `0`/`>1_000_000` — фатальна помилка завантаження),
  `handshake_timeout_ms` (10000), `idle_timeout_ms` (30000). `AdminStats.rejected_connections`
  (live-лічильник, як `in_flight`) → `GET /admin/status`. Аналіз складності по пам'яті + slow-loris
  smoke (`examples/load_test.rs` новий режим): (а)(б)(в) підтверджено, ~4–10 КіБ на утримуване
  pre-handshake з'єднання. Тести на 4 категорії (`admission` + `dispatch`). `tower` не додано.
  Окрема менша стеля на одночасні quorum-резолюції «у польоті» — **не в цьому обсязі** (backstop на
  вхідні з'єднання закриває основний вектор; fan-out ceiling лишається арифметичним, PERFORMANCE.md).
  TASKS-DONE.md.
- [ ] T-171 — (Батч 3.9, після T-170) **Переміряти T-66 quorum-coverage більшим зразком.**
  `examples/phase1_metrics.rs` (manual, не CI) уже тягне живий URLhaus recent-CSV feed і рахує
  detection-rate кожного провайдера vs OR-кворум vs baseline. Прогнати з **фінальним**
  T-170-набором + baseline на зразку ~100–200 доменів (T-133 ToS — обсяг помірний, жодного
  high-volume abuse). Зафіксувати: per-provider rate, кворум-rate, дельта над найкращим одиночним.
  **Нова секція PERFORMANCE.md «Quorum coverage (T-66/T-171)»** + вердикт у **DECISIONS.md**:
  гіпотезу підтверджено / не підтверджено на цьому зразку — і що це **не блокує** (Ф2/Ф3 вже
  стартували рішенням користувача; це закриття відкритого гейта чесним записом, як сам SPEC це
  формулює). Числа фіксуються, не припускаються. **Один прогін — один запис.** Якщо більший
  зразок _спростовує_ гіпотезу (ймовірно при варіанті (а) T-170 — ті самі два провайдери, що
  дали AdGuard 0/38): зафіксувати «спростовано на n=…» у DECISIONS.md і **підняти як відкрите
  дизайн-питання для Ф4+** (OR-кворум — весь фундамент проєкту), **не** переганяти вимір із
  іншим набором/зразком, доки не «підтвердиться». **Готово:** прогін проведено (рівно один),
  реальні числа в PERFORMANCE.md, вердикт (будь-який) у DECISIONS.md, Ф1-гейт #1 позначено
  закритим у `## Фаза 1`/`## Фаза 2`.
- [ ] T-172 — (Батч 3.9, після T-171) **Живий "браузер → локальний DoH" прохід.** Реально
  налаштований Chrome із `https://127.0.0.1:<port>/dns-query` як Custom DoH provider (cert уже
  довірений — `CurrentUser\Root`, T-49). **Дискримінантна перевірка (не просто «є рядок у логу»):**
  звичайний дозволений домен, що дає `QUORUM`/`CACHE`-рядок, **не** відрізняє «Chrome сходив через
  нас» від «щось інше сходило через нас» — той самий розрив, який зловив Ф1 closing-advisor (усі
  дотеперішні підтвердження були на рівні DoH-клієнта, `Invoke-WebRequest`). Тож ядро тесту —
  **негативний контроль**: (1) додати в **локальний blocklist** (`overrides.toml`) домен, який
  інакше резолвився б (напр. свіжостворений тест-піддомен або нині-дозволений сайт), (2) відкрити
  його в Chrome, (3) підтвердити **разом**: браузер показує помилку з'єднання до `0.0.0.0` (не
  «сайт просто не працює») **і** в `GET /admin/log` з'являється рядок `BLOCKLIST` для цього домену
  з таймстемпом усередині вікна кліку. Тільки збіг «браузерний фейл + корельований у часі
  BLOCKLIST-рядок» доводить, що резолюцію зробив саме Chrome через сервіс. Додатково (санітарна,
  не дискримінантна): живий дозволений домен → `QUORUM`/`CACHE`-рядок. **Увага на Chrome DoH
  mode:** режим має бути такий, що Chrome **не** робить тихий fallback на системний резолвер
  (Custom-provider у налаштуваннях = template-only, без fallback; НЕ enterprise `automatic`) —
  інакше негативний контроль нічого не доводить (сторінка завантажиться повз нас). Спроба
  автоматизації через Chrome MCP (`chrome://settings/security` → Custom); якщо DoH-конфіг
  недоступний для автоматизації (типово потребує UI + можливо рестарт Chrome) — **задокументована
  покрокова ручна процедура в README** (секція browser-DoH-config), користувач проганяє, докази
  (`/admin/log`-витяг + скрін помилки браузера) фіксуються. **Готово:** негативний контроль
  проведено (авто або user-manual), збіг «браузерний фейл + корельований BLOCKLIST-рядок»
  зафіксовано в TASKS-DONE.md, Ф1-гейт #2 позначено закритим; README-процедура актуальна.
- [ ] T-173 — (Батч 3.10) **Фінальне закриття Фази 3 + реліз `v0.3.0`.** **Бамп `0.2.0` → `0.3.0`
  — точний обсяг звірено 2026-09-05:** версія **не** інхерититься (нема `[workspace.package].version`
  у кореневому `Cargo.toml`), тож правити **три літерали** `version = "0.2.0"` у
  `crates/dnsqb-{service,tray,watcher}/Cargo.toml` + `Cargo.lock` (три `[[package]]`-записи — через
  `--locked`-перезбірку або `cargo update -p`). `AppxManifest`-версію `pack-msix.ps1` рахує з Cargo
  (`throw` на розбіжність), ручної правки маніфесту нема. README **не має** version-бейджа — лише
  статус-бейдж «Phase 3 complete» (формулювання вже коректне, чіпати не треба). TASKS.md + SPEC.md
  §"Фазований план" — запис «Фаза 3 повністю закрита 2026-09-…, усі Ф1-гейти закриті
  T-170/T-171/T-172». Коміт бампу+доків → CI-green. Потім `git tag v0.3.0` + `git push origin
  v0.3.0` → наявний `release.yml` (`repro` cross-path + build+sign 3 бінарники + `msix`-job) →
  **чернетка** GitHub-релізу (3 `.exe` + `SHA256SUMS` + `.msix` + `.cer`), публікує людина. `gh run
  watch` на `release.yml` після пушу тега. **Обов'язковий closing-advisor перед пушем тега** — тег
  важко відкотити. **Якщо `release.yml` падає після приземлення тега** (перший тег відколи `main.rs`
  змінився в T-169 → `repro`-недетермінізм можливий): `git push origin :refs/tags/v0.3.0`,
  полагодити, перетегувати — див. «Батч 3.10» вище. **Готово:** `v0.3.0` тег на `origin`,
  `release.yml` завершився success, чернетка релізу з усіма артефактами існує, TASKS-DONE.md-нотатка.
  Публікацію релізу лишаємо людині (як `v0.2.0`).

## Фаза 4 — Виключення топ-сайтів з Ads/Adult-voters

- [ ] T-104 — Виміряти реальний false positive rate Ads/Adult-категорій саме на топ-N-доменах у QA перед стартом фічі; переоцінити цінність фічі, якщо rate вже низький (Фазований план, Фаза 4)
- [ ] T-105 — Підтвердити, що механізм версійованих файлів з перевіркою цілісності (Фаза 2, GeoIP) обкатаний, перш ніж переюзовувати його тут (Фазований план, Фаза 4)
- [ ] T-106 — Перевірити ToS Cloudflare Radar API щодо публікації похідного списку доменів (Відкриті питання п.7)
- [ ] T-107 — CI-конвеєр курації: fetch Cloudflare Radar Domain Rankings → публікація версійованого списку доменів по країнах (5.1)
- [ ] T-108 — Легка крос-перевірка списку на етапі курації проти Security-блоклиста (гігієна, не захисний механізм) (5.1)
- [ ] T-109 — Voter scope: топ-N домен поточної країни отримує лише Security-tier voters, Ads/Adult виключаються з voters (5.1)
- [ ] T-110 — Лише точний домен для винятку, без wildcard-збігу (5.1)
- [ ] T-111 — UI: конфігурованість N і списку країн для фічі, можливість вимкнути глобально чи по країні (5.1)
- [ ] T-112 — Лог: поле `voter_scope` (`FULL` / `SECURITY_ONLY`) (5.1, 6)
- [ ] T-113 — Юніт-тест: Security-tier voters завжди опитуються для топ-N доменів, навіть коли Ads/Adult виключені (найчутливіший регресійний тест фічі) (Наскрізні вимоги)
- [ ] T-114 — Юніт-тест: топ-сайт-виняток спрацьовує лише на точний домен, не на піддомен (5.1)
- [ ] T-138 — Персональний варіант топ-N: локальне навчання частоти + регулярності відвідувань, джерело — лише вже-`ALLOW`-вердикти кворуму, той самий виняток лише з Ads/Adult-voters; окреме (не T-96/T-97) опційне (дефолт вимкнено) шифроване сховище; вирішити `voter_scope` DTO-прогалину (5.1.1, Відкриті питання п.11)

## Фаза 5 — Рейтинговий фільтр та ccTLD-блок

- [ ] T-115 — ccTLD-блок (5.2): чиста функція перевірки суфікса домену, конфігурований список, порожній за замовчуванням (5.2)
- [ ] T-116 — Позиція ccTLD-блоку в конвеєрі — одразу після Blocklist, до Cache (5.2, 5.3 конвеєр)
- [ ] T-117 — Лог: `decision_source = CCTLD_BLOCK` (5.2, 6)
- [ ] T-118 — UI-попередження про грубість ccTLD-евристики (аналогічно GeoIP over-blocking) (5.2)
- [ ] T-119 — Юніт-тест ccTLD-блоку: домен блокується без жодного мережевого виклику, навіть без Cache/Quorum-моків (5.2, Наскрізні вимоги)
- [ ] T-120 — Підтвердити готовність передумови — Фаза 4 (топ-N-інфраструктура) обкатана — перед стартом рейтингового фільтра (5.3)
- [ ] T-121 — Курація топ-N сайтів країни для рейтингового фільтра, переюзати інфраструктуру 5.1 (5.3)
- [ ] T-122 — Курація державних доменів: евристичне кандидування за TLD-патерном (`*.gov`, `*.gov.ua`, `*.gob.*` тощо), обов'язкове ручне рев'ю перед публікацією, дефолт N=10 на країну (5.3)
- [ ] T-123 — Курація глобального науково-освітнього/некомерційного списку: ручна, версіонована, з процесом рев'ю й changelog (5.3)
- [ ] T-124 — Реалізувати рейтинговий фільтр як останній локальний крок конвеєра (після Allowlist, Blocklist, ccTLD, Cache; перед Voter scope/Quorum) (5.3)
- [ ] T-125 — Поведінка — лише BLOCK для доменів поза зонами, ніколи force-ALLOW для доменів у зоні (5.3)
- [ ] T-126 — Дефолт — вимкнено, без винятків (5.3)
- [ ] T-127 — UI: окремий візуально виділений перемикач з явним попередженням при увімкненні (не звичайний checkbox поруч з іншими) (5.3)
- [ ] T-128 — UI: обов'язковий, завжди видимий індикатор активності рейтингового фільтра (5.3, 8)
- [ ] T-129 — Юніт-тест: домен поза зонами блокується без звернення до quorum-моків (перевірка виклику, не лише вердикту) (5.3, Наскрізні вимоги)
- [ ] T-130 — Юніт-тест: домен у зоні не отримує force-ALLOW, продовжує звичайний конвеєр (регресія на "лише BLOCK") (5.3, Наскрізні вимоги)
- [ ] T-131 — Юніт-тест: user-allowlist працює як виняток навіть з увімкненим рейтинговим фільтром (5.3, Наскрізні вимоги)
- [ ] T-151 — Інтернаціоналізація UI: рядки веб-UI (`/admin/ui`) та `dnsqb-tray` (меню/tooltip) винесені у файли перекладу замість хардкоду в `admin_ui.rs`/`main.js`/Rust-рядках трея, підтримка щонайменше української й англійської, вибір мови — автовизначення з ОС + ручний перемикач в UI; SPEC.md/UI-SPEC.md наразі не називають жодної мовної вимоги — новий, не раніше зафіксований скоуп

## Фаза 6 — Друга / третя десктопна платформа (macOS, Linux)

**Свідомо остання фаза — не "може колись", а планова ціль, винесена в кінець** (SPEC.md
§"Фазований план", Фаза 6). Середовище розробки суто Windows, macOS build/test-доступу немає;
вся друга-платформна робота зібрана тут замість того, щоб розповзатись по Фазах 2–3.

**Стояча вимога до всіх попередніх фаз (архітектурний інваріант, не задача цієї фази):**
платформна специфіка ховається за абстракційними межами, які виносяться під `#[cfg(target_os)]`
/ трейт **без переписування** — не хардкодяться безповоротно на Windows. Стан меж на 2026-08-31:
- `key_store.rs` — **готово**: `keyring` уже абстрагує (Windows Credential Manager / macOS
  Keychain / Linux Secret Service), фіча `v1` тягне всі три back-end'и; лишається зняти
  `#[ignore]` / перевірити на реальному macOS/Linux.
- `trust_store.rs` — **межі ще немає** (ні трейта, ні `#[cfg(target_os)]`): порт на Keychain /
  NSS будує її з нуля. Названо явно заздалегідь, щоб не було сюрпризом.
- Spawned system process — `icacls` прибрано (T-163); лишаються `certutil` (`trust_store`),
  `rundll32` (`dnsqb-tray/browser.rs`) — абсолютний шлях від `%SystemRoot%`, на macOS/Linux
  еквіваленту немає, потрібна платформна гілка.
- Трей (`tray-icon`/`tao`/`rfd`) — крос-платформний за задумом, поведінка на macOS menu bar
  емпірично не перевірена (SPEC.md, Відкриті питання).

- [ ] T-68 (macOS) — trust-store install через Keychain (`security add-trusted-cert`);
  Windows-половина готова, T-49. (Фазований план, Фаза 6)
- [ ] T-70 (macOS) — trust-store uninstall + secret-store cleanup через Keychain; Windows —
  зроблено, Батч 3.8 (`local_state::remove_all`). (Фазований план, Фаза 6)
- [ ] T-71 — Портувати `dnsqb-service` + `dnsqb-tray` на macOS (Keychain, `security` CLI,
  menu-bar трей). Linux — можлива третя ціль із **ручною** інсталяцією сертифіката (той самий
  підхід, що Windows у Фазі 1); automated NSS DB install лишається окремим epic'ом (T-132).
  (Фазований план, Фаза 6)
- [ ] T-83 — CI: розширити build matrix на macOS (і Linux, якщо додається як ціль). (Фазований план, Фаза 6)

## Поза фазами / бэклог

- [ ] T-132 — **Уточнено 2026-08-29 (SPEC.md §2)**: NSS DB автоматизація для Firefox
  (`Certificates.Install` через `policies.json`, або NSS-власний `certutil`) — крос-платформна
  задача (Windows/macOS/Linux, Firefox ніколи не читає системний trust store на жодній з них), не
  лише Linux, як раніше сформульовано. Linux додає ще один шар — Chrome/Chromium там теж власна
  NSS DB, не системний store. Явно поза межами MVP.
- [ ] T-133 — Юридична перевірка ToS Quad9/AdGuard щодо автоматизованих DoH-запитів стороннього клієнта (Відкриті питання п.2)
- [ ] T-135 — Постійний редакційний процес рев'ю державного та науково-освітнього списків — триває й після релізу, не одноразова задача (Фазований план Фаза 5, Відкриті питання п.8)
- [ ] T-136 — Merge публічних блок-листів (EasyList тощо) — окрема фіча поза quorum-логікою (Явно поза межами MVP)
- [ ] T-140 — UI: топ відвідуваних сайтів — рейтинг доменів у поточному log-вікні за кількістю входжень; не плутати з 5.1.1 (без персистенції/частоти-регулярності); некритична (8, 6)
- [ ] T-157 — **Аналіз** (не імплементація) можливості переходу на системний DNS усього ПК через
  локальну адресу `127.0.0.53`, а не лише браузерний DoH-канал. `127.0.0.53` — конвенція
  systemd-resolved (Linux stub-listener), не Windows-конвенція; перш ніж будь-що планувати —
  перевірити емпірично (scratch-пробa), чи Windows взагалі дозволяє прив'язати слухача до
  довільної адреси в `127.0.0.0/8`, відмінної від `127.0.0.1`, і як (якщо взагалі) системний
  DNS-резолвер конфігурується на цю адресу через мережевий адаптер (NRPT / TCP/IP-налаштування
  інтерфейсу, не файл конфігурації як на Linux). **Кандидатний механізм, названий користувачем,
  ще не перевірений емпірично**: технологія secondary IP — додавання `127.0.0.53` як другої
  (secondary) IP-адреси на мережевому інтерфейсі (`netsh interface ip add address ... secondary`
  чи PowerShell-еквівалент), а не покладання на автоматичне охоплення всього `127.0.0.0/8`
  loopback-інтерфейсом — це те, що поле "Preferred DNS server" в налаштуваннях адаптера могло б
  прийняти без додаткової валідації. Перевірити емпірично як окремий крок аналізу, не приймати як
  готове рішення. **Це не нова ідея, а переоцінка вже відхиленого
  дизайну** — SPEC.md, розділ "Чому саме такий дизайн", вже відхилив "System-wide DNS override
  (127.0.0.1:53)" саме через відсутність надійної крос-платформної гарантії відновлення після
  краху, особливо на Windows (немає OS-рівневого primitive відкату, аналогічного macOS Network
  Extension) — будь-який висновок цієї задачі або підтверджує це відхилення (і закривається без
  коду), або явно його переглядає через DECISIONS.md, а не тихо. Ключова відмінність від чинного
  дизайну: системний DNS (порт 53, plain DNS, не DoH) обслуговує **весь** мережевий трафік ПК, не
  лише браузер — не crash-safe одноточкова відмова (Три Б, user safety: якщо `dnsqb-service`
  впаде, а він єдиний налаштований DNS-сервер, ламається резолвінг для всієї системи, гірше за
  теперішній стан, де ламається лише браузерний DoH-фолбек). Аналіз має покрити: (1) прив'язку
  адреси на Windows (емпірично), (2) механізм конфігурації системного резолвера (NRPT vs. пряма
  зміна DNS-сервера інтерфейсу — останнє скидає й на un-filtered у разі падіння сервісу, перше
  теоретично дозволяє fallback-правило), (3) чи потрібен новий, не-DoH прото-хендлер (`dispatch.rs`
  зараз говорить лише HTTP(S)/DoH, не raw DNS-over-UDP/TCP на 53), (4) взаємодію з
  watchdog/crash-recovery (Фаза 3, SPEC.md §7) — чи новий "OS-рівневий rollback" механізм взагалі
  можливий на Windows, чи це лишається відкритим ризиком. **Мотивуючий сумнів уточнено 2026-08-29**:
  задача виникла частково з занепокоєння користувача, що поточний "leaf-сертифікат напряму в
  `CurrentUser\Root`" механізм — нестабільний хак; два живі теста того ж дня (SPEC.md §2, T-51 вище)
  емпірично підтвердили, що (a) це задокументована, свідома Chrome-поведінка ("local trust
  decisions", не недокументований побічний ефект), і (b) `cA=FALSE`-стримування реально працює, не
  лише декларація в коді — тобто сам мотивуючий сумнів для *чинного* дизайну закрито, і ця задача
  лишається чистим "чи варте це переходу заради ширшого покриття (весь ПК, не лише браузер)", а не
  "чи поточний дизайн ненадійний". Поза межами MVP, дослідницька задача, той самий прецедент
  "research, not implementation", що й T-134/T-141.

  **Поглиблений порівняльний аналіз 2026-08-29** (за прямим запитом користувача — "я схиляюсь до
  стандартного DNS, а не сертифікат", тобто трактує cert-trust і системне покриття як пакетний
  вибір; дослідження нижче показує, що це не так). **Три варіанти, не два**:

  - **(A) Чинний дизайн** — браузерний Custom DoH provider, per-app opt-in, `CurrentUser\Root`
    cert-trust (щойно емпірично підтверджено безпечним, T-51/SPEC.md §2 вище).
  - **(B) Системний plain DNS на `127.0.0.53:53`** — новий, не-DoH прото-хендлер (`dispatch.rs`
    сьогодні вміє лише HTTP(S)/DoH, не raw DNS-over-UDP/TCP — RFC 1035 retransmission/UDP→TCP
    truncation, EDNS0 (RFC 6891) — реальний новий шматок RFC-conformance поверхні, не тривіальна
    обгортка). Жодного сертифіката не треба — увесь сенс cert-trust-механізму був виключно
    сумісністю з браузерним "HTTPS-only" API-ворітьми (CA не можуть видавати сертифікати на
    loopback-IP за CA/B Forum baseline requirements — це якраз і є причина, чому self-signed
    взагалі неминучий у варіанті A; тут ця причина просто не застосовується, бо немає HTTPS).
  - **(C) Системний Windows-native DoH-клієнт** (нове, не розглядалось раніше в SPEC.md).
    **Розділити рівень підтвердження**: Windows Server 2022 — підтверджено напряму live-фетчем
    Microsoft Learn (`doh-client-support`, оновлено 2025-04-25). Windows 10/11 client (це — фактична
    Ф1-ціль проєкту, DECISIONS.md) — підтримка **лише** з вторинних джерел пошуку
    (elevenforum.com, bleepingcomputer, Insider-блог допису), **не** підтверджено прямим фетчем
    офіційної Microsoft-документації саме для client-редакції; той самий UI-скріншот/термінологія
    ("Preferred DNS encryption") співпадає з Learn-сторінкою, що робить це правдоподібним, але не
    еквівалентним до перевіреного факту — саме та слабкість джерела, яку варто закрити перед тим,
    як спиратись на варіант C. `Add-DnsClientDohServerAddress
    -ServerAddress <IP> -DohTemplate <URL>` реєструє довільну IP+DoH-URL пару у "known DoH servers"
    список, потім `Set-DnsClientServerAddress` на цю IP вмикає DoH системно для всього, що йде через
    ОС-рівневий DNS-клієнт (`Dnscache`-сервіс) — не лише браузери. **Ключова знахідка**: це
    переюзовує наявний `dispatch.rs`'s DoH-сервер і наявний, щойно підтверджений безпечним
    cert-trust механізм без змін — жодного нового прото-хендлера. Користувач трактує "системний DNS"
    і "без сертифіката" як пакетну умову — варіант C доводить, що це не так: можна отримати системне
    покриття, залишаючись на DoH і на вже перевіреній cert-довірі.

  **Емпірично перевірено сьогодні (без зміни системних мережевих налаштувань — лише bind-тест,
  ніяких DNS-конфігів чи trust-store дій)**:
  - Windows дозволяє прив'язати TCP- і UDP-слухач до `127.0.0.53` (і будь-якої адреси в
    `127.0.0.0/8`) **без жодної додаткової конфігурації інтерфейсу** — те саме "весь `127.0.0.0/8`
    належить loopback за замовчуванням", що й на Linux. Кандидатний "secondary IP"-механізм,
    згаданий користувачем раніше, виявився зайвим — принаймні для самого біндингу.
  - Порт 53 на `127.0.0.53`/`127.0.0.1` вільний і біндиться без адмін-прав (перевірено TCP і UDP
    окремо).
  - **Важлива знахідка, не пов'язана напряму з `127.0.0.53`, але релевантна для порту 53 взагалі**:
    на цій-таки dev-машині UDP `0.0.0.0:53` вже зайнятий `svchost.exe` (ймовірно ICS/`SharedAccess`-
    сервіс — типово активний, коли ввімкнено Mobile Hotspot/Hyper-V default switch NAT). Специфічна
    адреса (`127.0.0.1:53`/`127.0.0.53:53`) все одно біндиться без конфлікту — Windows не трактує
    wildcard-бінд як блокування конкретної адреси того самого порту. Це **незалежно підтверджує**
    вже чинне архітектурне рішення проєкту ("слухати лише `127.0.0.1`, ніколи `0.0.0.0`",
    `listener.rs`) — воно виявилось саме тим, що уникає цього класу конфлікту, а не лише
    приватність-мотивованим вибором, яким задумувалось спочатку.
  - **Не перевірено емпірично цього разу** (потребує зміни системних мережевих налаштувань —
    навмисно поза межами того, що я виконую сам, той самий "modifying system settings" бар'єр, що
    й для trust-store): чи `Add-DnsClientDohServerAddress`/`Set-DnsClientServerAddress` взагалі
    приймають loopback IP + власний DoH-шаблон (Microsoft-документація мовчить про обмеження на
    список лише публічних резолверів — синтаксис виглядає як довільна IP-реєстрація, дефолтний
    список (Cloudflare/Google/Quad9) — лише preset, не hard-coded стеля — але це не підтверджено
    прямим тестом).

  **Найважливіше відкрите питання варіанту C, ще не вирішене, вагоміше за все інше в цьому
  аналізі**: `Dnscache` — це Windows-сервіс, що працює під системним service-акаунтом
  (`NT SERVICE\Dnscache`), **не** під інтерактивним акаунтом користувача, на відміну від Chrome.
  T-51/SPEC.md §2's підтвердження стосувалось саме `CurrentUser\Root` (акаунт користувача) — чи
  `Dnscache` взагалі читає `CurrentUser\Root`, чи потребує `LocalMachine\Root` (що по чинному
  T-49-плану потребує адмін-прав, на відміну від `CurrentUser`) — **не перевірено, не
  задокументовано ніде знайденому**. Якщо C потребує `LocalMachine\Root` — це не блокер (T-49 і так
  згадує `LocalMachine` як опцію з адмін-правами), але ламає "той самий, уже проведений одноразовий
  діалог" — знадобиться окремий сценарій встановлення саме для цього.

  **Ключовий структурний висновок, що стосується запиту користувача "порівняти" напряму**:
  crash-recovery ризик — **однаковий для B і C**, він про "один системний резолвер замінює всі
  інші", а не про сам протокол (DoH чи plain DNS). Підтверджено живим фетчем Microsoft Learn:
  режим "Encrypted only" = повна відмова резолвінгу при недоступності сервера (не graceful
  fallback), режим "Encrypted preferred, unencrypted allowed" = мовчазний відкат на **plain,
  нефільтрований** DNS без жодного попередження користувачу — саме той клас "silent unfiltered
  fallback", що SPEC.md's Відкриті питання п.10 вже називає найгіршим сценарієм для браузерного
  DoH-фолбеку, тут відтворений на рівень нижче, для всієї системи. **Підтверджено ще й живим,
  2026-датованим свідченням поза цим проєктом**: NextDNS (зрілий, комерційний, добре фінансований
  продукт з роками інженерної роботи) досі має відкриті баг-репорти про втрату контролю над
  DNS-налаштуваннями на Windows 25H2 (live WebSearch, 2026) — SPEC.md's оригінальне обґрунтування
  відхилення ("не вирішена проблема навіть у зрілих продуктів") **не застаріле, а реально чинне й
  сьогодні**, не припущення з моменту написання спеки.

  **Приватність — вісь, яку SPEC.md писав з припущенням "лише браузер"**: системне покриття (B чи
  C) означає, що DNS-активність **усіх** застосунків на ПК (не лише тих браузерів, у яких
  налаштовано Custom DoH) іде через fan-out до Quad9/AdGuard/baseline — суттєво ширша поверхня
  приватності, ніж те, що SPEC.md's наскрізна вимога "це має лишатись видимим користувачу, не
  захованим" описувала на момент написання. Потребує оновлення тексту цієї вимоги, якщо B/C колись
  реалізується.

  **Висновок аналізу (рекомендація, не рішення — вибір лишається за користувачем)**: якщо мета —
  саме ширше покриття (не лише браузер), варіант **C потенційно домінує над B, умовно** — той самий
  результат (системний DNS), менше нового коду (жодного нового DNS-прото-хендлера), той самий, уже
  перевірений безпечним cert-trust механізм. Умова не декоративна, а вирішальна: якщо
  `Add-DnsClientDohServerAddress` не приймає loopback-шаблон, варіант C не існує в принципі, не
  просто дорожчий; якщо `Dnscache` потребує `LocalMachine\Root`, C виграє менше нового коду ціною
  адмін-елевації, якої A не потребує. Жодне з двох не перевірено — рекомендація "C кращий за B"
  тримається лише за умови, що обидві невідомі вирішаться на користь C. Crash-recovery ризик
  залишається **однаковим для B і C незалежно від цих невідомих**, і саме він — а не протокол —
  була справжня причина SPEC.md's оригінального відхилення; жодна знахідка цього аналізу цей ризик
  не знімає й не применшує. Практичний шлях уперед, якщо
  користувач вирішить рухатись далі: (1) підтвердити `Dnscache`'s trust-store поведінку живим
  тестом (той самий формат, що й T-49/T-51 — а не системний DNS-конфіг, лише перевірка через
  `Get`/`Add-DnsClientDohServerAddress` на реальній машині користувача), (2) не заміняти варіант A,
  а додати B/C як окремий, явно **опційний** режим із власним, чесно позначеним ризик-профілем —
  той самий "явний вибір користувача, не мовчазна поведінка" принцип, що SPEC.md §3 вже застосовує
  до порожнього voter-set, (3) не вмикати цей режим до існування `dnsqb-watcher` (Фаза 3) — не
  тому, що watchdog вирішує crash-recovery повністю (окремий userland-процес сам може впасти чи не
  встигнути — не той самий рівень гарантії, що OS-рівневий rollback-примітив macOS's Network
  Extension, вже названий у SPEC.md), а тому, що без нього вікно відмови взагалі нічим не
  обмежене.

  **Рішення користувача 2026-08-29**: наразі лишаємось на варіанті A (браузерний Custom DoH
  provider + `CurrentUser\Root` cert-trust, чинний дизайн) — після ознайомлення з порівнянням вище.
  T-157 **не закривається й не відхиляється** — лишається відкритою дослідницькою задачею на
  майбутнє (варіанти B/C), просто не поточний пріоритет; два відкриті питання вище (loopback-шаблон
  для `Add-DnsClientDohServerAddress`, `Dnscache`'s trust-store контекст) так і лишаються
  неперевіреними, чекають наступного разу, коли ця задача підніметься знову.

- [ ] T-158 — **Онбординг-майстер: виявлення відсутнього сертифіката/DoH-налаштування браузера при
  першому відкритті сайту, пропозиція налаштувати автоматично** (виникло 2026-08-29, одразу після
  живого підтвердження T-49 — користувач: "нам треба якось запланувати як це робити більш
  юзер-френдлі"). Два реальні, окремі UX-факти, які мотивують задачу:
  1. **Подвійний діалог при встановленні сертифіката, підтверджено живим тестом того ж дня**:
     `certutil -addstore -user Root` показує **власний** діалог Windows ("Попередження системи
     безпеки") **поверх** застосункового `rfd`-підтвердження з `dnsqb-tray` — дві послідовні дії
     для однієї логічної операції, а не одна (SPEC.md §2, TASKS-DONE.md's T-49 запис).
  2. Навіть після встановлення сертифіката браузер **сам по собі не почне використовувати** local
     `DoH` — користувач і сьогодні мусить вручну зайти в налаштування Chrome/Firefox і вставити
     `https://127.0.0.1:<port>/dns-query` як Custom DoH provider (SPEC.md §1/§40, T-72's власний
     UI для цього — лише UI *в межах* `dnsqb-service`, не автоматизація самого браузерного кроку).
  **Дві окремі, названі користувачем підзадачі — жодна ще не спроєктована, обидві потребують
  research-проходу перед імплементацією (той самий "research, not implementation" прецедент, що й
  T-14/T-134/T-141/T-157)**:
  - (a) **Інтерактивний майстер першого запуску/першого відвідування `/admin/ui`**: виявляє, чи
    сертифікат уже встановлений (`trust_store::ensure_installed`-подібна перевірка, T-49 вже дає
    примітив), чи ні — пропонує встановити одразу з тієї ж сторінки, для Chrome і для Firefox
    окремо (Firefox — інша ціль, власна NSS-база, T-132, поки що зовсім не автоматизована). Де
    саме живе цей майстер (нова сторінка/крок у `/admin/ui`, окремий екран у `dnsqb-tray`, частина
    майбутнього інсталятора) — не вирішено, потребує plan-mode + advisor-рев'ю перед стартом,
    архітектурне рішення. Пересікається, але не дублює T-156 (яке про Store-специфічний
    onboarding-текст) — цей майстер загальніший, для будь-якого способу встановлення, не лише
    Store.
  - (b) **Скриптована конфігурація самого браузерного DoH-налаштування** ("через офіційне API
    браузерів", як сформулював користувач) — **не існуючий на сьогодні механізм у проєкті
    взагалі**, окрема від cert-trust задача. Для Chrome це вже частково назване T-98/T-99
    (`DnsOverHttpsTemplates` enterprise policy, registry/plist, Фаза 3, **не Firefox**) — T-99
    сьогодні написана як Chrome-only, обсяг потребує уточнення (чи T-99 розширюється на Firefox,
    чи Firefox отримує власний номер). Для Firefox кандидатний механізм уже назвала T-134's
    дослідницька задача (`DNSOverHTTPS` policy, `policies.json`, режим `Locked` + `network.trr.mode`
    = 3/TRR-only, SPEC.md's Відкриті питання п.10) — **дослідницька назва, не перевірена
    live-скриптингом**. Обидва механізми — enterprise policy, не "офіційне API" в сенсі
    programmatic browser API виклику під час роботи браузера; чи існує взагалі якийсь
    programmatic (не registry/plist-файловий) спосіб — окреме, ще зовсім не досліджене питання
    цієї задачі, а не готова відповідь.
  **Явно не вирішено, чи це один майстер (a+b разом) чи дві незалежні задачі** — залишено відкритим
  до окремого research-проходу; T-158 сам по собі — фіксація ідеї й пов'язаних задач, не готовий
  план. Поза межами Ф1 — cert-trust-половина (a) технічно вже має примітив (T-49), DoH-конфіг-
  половина (b) чекає на Фазу 3 (T-98/T-99) чи власний research-прохід для Firefox.

- [ ] T-159 — **Контекстна довідка для полів налаштувань на `/admin/ui`** (виникло 2026-08-29,
  користувач: "налаштувань купа і можна розгубитися що за що відповідає", попросив рекомендацію
  щодо механізму, не готове рішення). Рекомендований підхід (промислова конвенція для
  адмін-панелей з великою кількістю полів — SPEC.md's "Наскрізні вимоги"'s "коли SPEC.md мовчить,
  консенсус індустрії", застосовано тут до UI/UX, не протоколу): невеликий фокусованo-доступний
  значок "?" одразу після підпису кожного поля/картки (Провайдери, Timeout-режим, Кеш TTL/capacity,
  Override-списки тощо) — **не лише hover** (не працює на тач-екранах, не завжди доступний з
  клавіатури), а клік/Enter теж перемикає короткий, 1-2-реченевий опис. Дві реалізаційні опції,
  жодна не потребує нової залежності (проєкт уже свідомо уникає CDN/бандлерів для веб-UI, T-149):
  (1) нативний `<details><summary>?</summary>...</details>` — нуль JS, клавіатурна доступність з
  коробки; (2) невеликий, переюзаний CSS/vanilla-JS toggle-патерн у вже наявному `main.js`/
  `style.css` (той самий стиль, що вже в проєкті — жодного нового фреймворку). Не вирішено, яка з
  двох — рішення для наступного разу, коли задача підніметься, не зараз. Обсяг: кожне поле/картка
  на `/admin/ui`, що вже існує (Провайдери — T-52/T-148, Timeout-режим — T-52, Кеш — T-153,
  Override-списки — T-47, Лог-фільтри — T-45/T-54) отримує короткий опис; текст самих пояснень —
  окрема робота (UI-SPEC.md §3 — власник опису полів по екрану, кожен новий текст підпису туди й
  іде, не вигадується на льоту в коді). Поза межами Ф1 formally (жоден Ф1-документ це не вимагав),
  але низький ризик/розмір — можна підняти раніше інших backlog-задач, якщо пріоритет.

- [ ] T-160 — **Лінива/фонова ініціалізація `GeoIP`-бази при старті процесу** (виникло 2026-08-30,
  питання користувача під час T-78: "чи база завантажується ліниво в пам'ять, чи це читання з
  диска"). **Не плутати з per-query поведінкою — та вже коректна й не потребує задачі**:
  `GeoipReader::open` (`geoip.rs`) читає файл **рівно один раз**, повністю в `Reader<Vec<u8>>`
  (не `mmap` — `maxminddb`'s `mmap`-фіча свідомо вимкнена, T-74, щоб не робити виключення з
  `#![forbid(unsafe_code)]`); кожен наступний `country()`-виклик — чисто оперативна пам'ять, без
  жодного диск-IO на гарячому шляху запиту. Реальний, ще не задокументований раніше аспект — **час
  запуску процесу, не швидкість, а безумовність**: `main.rs`'s `load_geoip_state` виконується
  синхронно, до того як `serve_until_shutdown`'s accept loop починає приймати з'єднання (коментар
  на місці виклику вже документує це як свідомий вибір: "so a restart doesn't lose GeoIP
  filtering until the background updater's next periodic check completes"). **Виміряно емпірично
  під час T-78's живої перевірки, не припущено**: на реальному завантаженому DB-IP Lite
  Country-файлі (8 284 207 байт, не крихітна тестова фікстура) інтервал між рядком логу "loaded
  existing GeoIP database" і рядком "listening on https://127.0.0.1:8443/dns-query" — **~3 мс**
  (`13:40:47.398849` → `13:40:47.401562`). Тобто сама затримка старту сьогодні — не проблема;
  реальний, гідний задачі аспект — **безумовність**: файл читається й парситься щоразу при
  старті, навіть коли `blocked_countries` порожній (SPEC.md §3.5's власний opt-in-дефолт) —
  типовий Ф1/ранній-Ф2 користувач, що ще не додав жодної країни, все одно виконує цю (сьогодні
  дешеву) роботу щоразу, і синхронний виклик залишається на критичному шляху старту незалежно
  від того, чи фіча взагалі використовується. Задача — про структурну властивість
  ("безумовно й синхронно на шляху старту"), не про виміряну сьогодні латентність; майбутній
  більший `.mmdb`-файл (напр. T-80's advanced-режим MaxMind GeoLite2, зазвичай більший за
  DB-IP Lite Country) може змінити цю оцінку, тому варто перевимірювати, а не покладатись на
  сьогоднішні 3 мс як постійну межу. Кандидати рішення (жоден не обраний, потребує власного
  дизайн-рішення, не архітектурна
  зміна за порогом plan+advisor тільки якщо торкнеться `AppState`'s локів): (1) відкласти
  завантаження до першого реального виклику `geoip::blocking_country` через `OnceCell`/лінивий
  `Arc`-swap (справжня лінивість, але ускладнює "перший заблокований запит після рестарту раптово
  повільний" trade-off, який теж треба явно задокументувати, не сховати); (2) запускати
  синхронне читання файлу в `tokio::task::spawn_blocking`, паралельно з `bind_listener`, і
  чекати лише перед першим GeoIP-залежним запитом, а не перед стартом accept loop (менш
  інвазивно, не змінює "нуль зайвого IO на гарячому шляху" властивість). Обидва варіанти й досі
  повністю сумісні з T-75's "останній відомий-добрий стан ніколи не стирається на невдалому
  рефреші" гарантією — жодного ризику для Три-Б user safety тут немає, це суто про час старту,
  не про коректність фільтрації.
- [ ] T-166 — **Оновити pinned versions GitHub Actions у обох workflow'ах** (виникло 2026-09-01
  під час T-101 — CodeQL-ран показав annotation-warning: `actions/checkout@v4` таргетить
  deprecated Node.js 20, GitHub форсить його на Node 24). Не помилка, не валить білд — soft
  warning, зникне сам коли runner прибере Node 20. Треба підняти:
  - `.github/workflows/ci.yml` — `actions/checkout@v4` ×6, `actions/upload-artifact@v4` ×1
    (перевірити чи не той самий Node-20-warning) → `@v5`/актуальні.
  - `.github/workflows/codeql.yml` — `actions/checkout@v4` → `@v5` (CodeQL-стартер GitHub'а
    тепер на `actions/checkout@v7`; `github/codeql-action/{init,analyze}@v4` уже актуальні).
  - `taiki-e/install-action@cargo-*` — окремий екосистемний pin, перевірити чи є свій warning.
  Одноразовий CI-only коміт, без plan/advisor; зробити разом з іншим CI-тюнінгом якщо трапиться.
