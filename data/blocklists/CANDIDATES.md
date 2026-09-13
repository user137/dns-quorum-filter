# DNS-фільтрація: кандидати блоклистів для pet-проекту (Rust)

> **Статус: kickoff завершено (Батч 4.7.C → Фаза 7, 2026-09-13), реалізація не почата.** Матеріал
> надано користувачем 2026-09-11, дослідження зі стороннього чату. **Kickoff-сесія 2026-09-13
> звірила з першоджерелами все, що досліджують §1-2 нижче** (ліцензія/свіжість/сайдкар для
> кожного зачепленого джерела — inline-нотатки "ВИЛУЧЕНО 2026-09-13" там, де перевірка знайшла
> блокер) — деталі рішень і обґрунтування в DECISIONS.md 2026-09-13. §3 нижче переписано на
> авторитетний, звірений набір. TASKS.md §"Фаза 7" веде подальший батч-план і перший
> дизайн-артборд (`mockups/gui-dashboard.html`, Артборд F) — реалізація коду ще не почата,
> design-рев'ю користувача — наступний крок.

Підсумок аналізу для обговорення з Claude Code. Критерій відбору: список має
бути публічно доступний онлайн без реєстрації/API-ключа, у статичному
форматі (hosts / plain domain list / adblock-синтаксис), придатний для
прямого DNS-рівневого блокування (не cosmetic-правила браузерних розширень).

---

## 1. Ads & Trackers — фінальний відібраний набір

Обрано з першого раунду аналізу (порівняння ~80 списків з довідника
NextDNS). Критерій: чистий доменний/hosts-формат, активне оновлення
(не старше кількох тижнів), без авторизації.

| Список | Джерело | Записів | Оновлення | Коментар |
|---|---|---|---|---|
| HaGeZi Multi PRO | github.com/hagezi/dns-blocklists | ~222k | кожні кілька годин | баланс агресивності/false positives. **Звірено 2026-09-13: GPL-3.0, самостійно курований, без .sha256-сайдкара — прийнято в §3** |
| OISD | oisd.nl | ~247k | ~26 хв | популярний, є full/small варіанти. **ВИЛУЧЕНО 2026-09-13** — репозиторій під GPLv3, але агрегатор десятків чужих списків, кожен зі своєю ліцензією ("see source for license and credits" — окрема сторінка на інгредієнт); аудит кожного інгредієнта не входив у обсяг kickoff'у |
| AdGuard DNS filter | github.com/AdguardTeam/AdguardSDNSFilter | ~177k | щогодини | вже адаптований під DNS-рівень (не ABP cosmetic). **Звірено 2026-09-13: GPL-3.0, самостійно курований AdGuard (не агрегатор), без сайдкара — прийнято в §3** |
| Steven Black hosts | github.com/StevenBlack/hosts | ~80k | 2 дні | класичний hosts-формат. **ВИЛУЧЕНО 2026-09-13** — репозиторій MIT, але агрегує CC BY-NC-SA 4.0 (MVPS) і "non-commercial with attribution" (Dan Pollock) джерела прямо в об'єднаний файл без розділення — той самий клас блокера, що вже відхилив Cloudflare Radar у T-106 |
| 1Hosts (Lite) | github.com/badmojr/1Hosts | ~102k | ~8 днів | стабільний, малий % false positive. **Звірено 2026-09-13: MPL-2.0 (та сама ліцензія, що вбудований PSL у `curate_topn`), агрегатор із єдиною декларованою ліцензією на весь артефакт, без сайдкара — прийнято в §3** |

**Відхилено:** EasyList / EasyPrivacy / AdGuard Base / Fanboy's Annoyance —
ABP-синтаксис (cosmetic-правила `##`, `$domain=`), не прямий список доменів,
потребує парсингу лише мережевих (`||domain^`) правил. Все, що не
оновлювалось 2+ роки (Goodbye Ads, notracking, NSABlocklist, MVPS HOSTS,
WindowsSpyBlocker) — мертві проєкти. NextDNS Ads & Trackers — сам є
агрегатором вищевказаних джерел, тягти окремо немає сенсу.

---

## 2. NextDNS Security tab — розбір фіч і публічних аналогів

Другий раунд: 17 security-фіч з NextDNS (Threat Intelligence Feeds,
AI-Driven Threat Detection, Google Safe Browsing, Cryptojacking, DNS
Rebinding, IDN Homographs, Typosquatting, DGA Domains, Newly Registered
Domains, Free Hosting Domains, Dynamic DNS Hostnames, Tunneling Endpoints,
Data Drop Services, Residential Hosting, Decentralized Web Gateways, TLD
blocking, CSAM). Мета — яка частина реалізовна через публічний список.

### ✅ Є готовий публічний список (без реєстрації)

| NextDNS-фіча | Публічний аналог | Формат/розташування |
|---|---|---|
| Threat Intelligence Feeds | HaGeZi TIF | `raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt` |
| Newly Registered Domains | HaGeZi NRD | той самий репозиторій, plain domain list. **Уточнено 2026-09-13 (Батч 7.1):** насправді окремий репозиторій `hagezi/nrd` (теж GPL-3.0), не `hagezi/dns-blocklists` — `nrd7.txt`, ~49 MB |
| DGA Domains | HaGeZi NRD/DGA | plain domain list (офіційно підтверджено в FAQ репо). Той самий `hagezi/nrd`, `dga7.txt`, ~13 MB |
| Dynamic DNS Hostnames | HaGeZi DynDNS | той самий репозиторій |
| Free Hosting Domains | HaGeZi Badware Hoster | найближчий аналог, не 1-в-1 (NextDNS блокує конкретні піддомени типу *.pages.dev/*.vercel.app, Badware Hoster — ширше по хостерах) |
| Top-Level Domains (TLD) | HaGeZi Most Abused TLDs | або просто хардкодиш список TLD сам — зовнішні дані не обов'язкові. **Вилучено з Фази 7 набору (Батч 7.1, 2026-09-13)** — колізує з T-115/T-116's ccTLD-блоком (§5.2, Фаза 5); §3 нижче має повне обґрунтування |
| Cryptojacking | CoinBlockerLists (Zerodot1/CoinBlockerLists) | + частково покрито HaGeZi TIF. **ВИЛУЧЕНО 2026-09-13** — офіційний сайт востаннє оновлювався жовтень 2023, GitHub-репозиторій позначений `[ARCHIVE] ... discontinued`; порушує власний критерій свіжості цього документа |
| DNS Rebinding | HaGeZi DNS Rebind Protection | ⚠️ формат сумісний лише з AdGuard/AdGuard Home/AdGuard DNS — або конвертувати, або писати правило самому (перевірка приватних IP у відповіді — проста евристика, список не обов'язковий) |

### ⚠️ Потребує реєстрації/API-ключа (безкоштовно, але не "без авторизації")

- **Google Safe Browsing** — офіційний API (v5), безкоштовна квота, але вимагає Google Cloud API key. Навіть ендпоінт для пакетного завантаження хеш-листів (`hashLists:batchGet`) все одно вимагає `key=...` — статичного файлу без авторизації немає, і відкритих сторонніх дзеркал хеш-бази теж не знайдено (ймовірно, заборонено ToS). Некомерційне використання (pet-проект підходить), для комерційного — Web Risk API.

**Відкриті альтернативи без ключа**, що покривають схожий функціонал (фішинг/malware URL):
- **OpenPhish Community Feed** — `openphish.com/feed.txt`, plain-text, оновлення раз на 12 год, без реєстрації. Дзеркало: `github.com/openphish/public_feed`. **ВИЛУЧЕНО 2026-09-13** — `openphish.com/terms.html` прямо забороняє комерційне використання (дослівно назване "product development, automation") і будь-яку редистрибуцію; суворіше за CC BY-NC із T-106, той самий клас блокера
- **URLhaus (abuse.ch)** — `urlhaus.abuse.ch`, malware-URL, відкриті фіди без ключа. **ВИЛУЧЕНО 2026-09-13 як нез'ясоване, не остаточно відхилене** — загальні умови "fair use" з платною підпискою для комерційного/for-profit використання; сторінка з точними умовами саме на bulk-завантаження (не API) віддала 403 при спробі перевірити напряму цим проходом — потребує окремої майбутньої перевірки перед тим, як розглядати знову

### ❌ Немає публічного статичного списку

- **AI-Driven Threat Detection** — власна модель NextDNS, за визначенням не існує як список.
- **IDN Homographs** / **Typosquatting** — це алгоритм (порівняння з відомими брендами через edit-distance/гомогліфи, як утиліта `dnstwist`), не датасет. Реалізується кодом, не списком.
- **Tunneling Endpoints**, **Data Drop Services**, **Residential Hosting**, **Decentralized Web Gateways** — всі позначені `EARLY ACCESS` у NextDNS, пропрієтарні фічі без відкритих аналогів. Residential Hosting зокрема — це комерційні бази (IP2Proxy, IPQualityScore), платний доступ.
- **CSAM (Project Arachnid)** — дані Canadian Centre for Child Protection, доступні лише перевіреним партнерам за угодою; публічно не розповсюджуються.

---

## 3. Результуючий набір для проєкту

**Переписано 2026-09-13 (kickoff-сесія, звірка з першоджерелами — DECISIONS.md); скориговано
того ж дня (Батч 7.1, звірка URL/розмірів/форматів перед кодом — DECISIONS.md).** Авторитетний
набір — **7 джерел**, кожне самостійно курироване або з єдиною декларованою ліцензією на весь
артефакт (не агрегатор з per-ingredient ліцензійною плутаниною), усі вже покриваються дозволеним
мережевим allowlist (`raw.githubusercontent.com`, `github.com`):

1. HaGeZi Multi PRO (основний ads/trackers/malware набір) — GPL-3.0
2. HaGeZi Threat Intelligence Feeds (TIF) — GPL-3.0
3. HaGeZi Newly Registered Domains / DGA — GPL-3.0 (окремий репозиторій `hagezi/nrd`, теж
   GPL-3.0, два URL — `nrd7.txt`/`dga7.txt` — одне логічне джерело)
4. HaGeZi Dynamic DNS (DynDNS) — GPL-3.0
5. HaGeZi Badware Hoster — GPL-3.0
6. AdGuard DNS filter (ads/trackers, доповнює HaGeZi Multi PRO) — GPL-3.0
7. 1Hosts Lite (ads/trackers, доповнює HaGeZi Multi PRO) — MPL-2.0

**HaGeZi Most Abused TLDs — вилучено з набору Батчем 7.1, 2026-09-13** (було пунктом 6 у
редакції kickoff'у). Причина: записи цього джерела — голі TLD, не домени; через суфіксний
матчинг, який Фаза 7 і так використовує, це 4.4-кілобайтне джерело заблокувало б більше
інтернету, ніж решта шести разом, і дублює вже специфікований T-115/T-116 (TASKS.md, Фаза 5,
§5.2, ccTLD-блок — "конфігурований список, порожній за замовчуванням") через інші двері й інший
дефолт. Файл лишається кандидатним джерелом даних для T-115, коли той крок будується — не для
цієї фічі.

Жодне з семи не публікує `.sha256`-сайдкар (звірено) — Фаза 7 (TASKS.md) потребує власного
контролю цілісності, не прямого переюзання `data/topn/`'s sha256-контракту.

**Виключено (деталі — inline-нотатки §1-2 вище, дата 2026-09-13):** OISD (агрегатор без єдиної
ліцензії), Steven Black hosts (підтверджений CC BY-NC-SA/NC інгредієнт), CoinBlockerLists
(discontinued/archive), OpenPhish (ToS забороняє комерційне використання й редистрибуцію),
URLhaus (нез'ясовано — окрема майбутня перевірка, не остаточна відмова).

Поза межами: IDN-гомографи та typosquatting-детекція — це окрема задача на
алгоритм (можна портувати логіку на кшталт `dnstwist` в Rust), не питання
підбору списку.
