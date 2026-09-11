# DNS-фільтрація: кандидати блоклистів для pet-проекту (Rust)

> **Статус: research, not implementation.** Матеріал для T-218 (TASKS.md, "Поза фазами / бэклог") —
> надано користувачем 2026-09-11, дослідження зі стороннього чату, **жодне джерело нижче ще не
> перевірено цим проєктом** (ліцензія/оновлення-cadence/формат — жодне поле в таблицях не
> підтверджене емпірично, на відміну від `data/topn/README.md`'s CrUX/PSL атрибуції). T-218 (задача,
> не батч) сам поки не почат — потребує окремого plan+advisor kickoff перед будь-яким кодом. Три
> питання, що фактично визначать дизайн, перелічені в TASKS.md's T-218 бульбашці, не тут.

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
| HaGeZi Multi PRO | github.com/hagezi/dns-blocklists | ~222k | кожні кілька годин | баланс агресивності/false positives |
| OISD | oisd.nl | ~247k | ~26 хв | популярний, є full/small варіанти |
| AdGuard DNS filter | github.com/AdguardTeam/AdguardSDNSFilter | ~177k | щогодини | вже адаптований під DNS-рівень (не ABP cosmetic) |
| Steven Black hosts | github.com/StevenBlack/hosts | ~80k | 2 дні | класичний hosts-формат |
| 1Hosts (Lite) | github.com/badmojr/1Hosts | ~102k | ~8 днів | стабільний, малий % false positive |

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
| Newly Registered Domains | HaGeZi NRD | той самий репозиторій, plain domain list |
| DGA Domains | HaGeZi NRD/DGA | plain domain list (офіційно підтверджено в FAQ репо) |
| Dynamic DNS Hostnames | HaGeZi DynDNS | той самий репозиторій |
| Free Hosting Domains | HaGeZi Badware Hoster | найближчий аналог, не 1-в-1 (NextDNS блокує конкретні піддомени типу *.pages.dev/*.vercel.app, Badware Hoster — ширше по хостерах) |
| Top-Level Domains (TLD) | HaGeZi Most Abused TLDs | або просто хардкодиш список TLD сам — зовнішні дані не обов'язкові |
| Cryptojacking | CoinBlockerLists (Zerodot1/CoinBlockerLists) | + частково покрито HaGeZi TIF |
| DNS Rebinding | HaGeZi DNS Rebind Protection | ⚠️ формат сумісний лише з AdGuard/AdGuard Home/AdGuard DNS — або конвертувати, або писати правило самому (перевірка приватних IP у відповіді — проста евристика, список не обов'язковий) |

### ⚠️ Потребує реєстрації/API-ключа (безкоштовно, але не "без авторизації")

- **Google Safe Browsing** — офіційний API (v5), безкоштовна квота, але вимагає Google Cloud API key. Навіть ендпоінт для пакетного завантаження хеш-листів (`hashLists:batchGet`) все одно вимагає `key=...` — статичного файлу без авторизації немає, і відкритих сторонніх дзеркал хеш-бази теж не знайдено (ймовірно, заборонено ToS). Некомерційне використання (pet-проект підходить), для комерційного — Web Risk API.

**Відкриті альтернативи без ключа**, що покривають схожий функціонал (фішинг/malware URL):
- **OpenPhish Community Feed** — `openphish.com/feed.txt`, plain-text, оновлення раз на 12 год, без реєстрації. Дзеркало: `github.com/openphish/public_feed`.
- **URLhaus (abuse.ch)** — `urlhaus.abuse.ch`, malware-URL, відкриті фіди без ключа.

### ❌ Немає публічного статичного списку

- **AI-Driven Threat Detection** — власна модель NextDNS, за визначенням не існує як список.
- **IDN Homographs** / **Typosquatting** — це алгоритм (порівняння з відомими брендами через edit-distance/гомогліфи, як утиліта `dnstwist`), не датасет. Реалізується кодом, не списком.
- **Tunneling Endpoints**, **Data Drop Services**, **Residential Hosting**, **Decentralized Web Gateways** — всі позначені `EARLY ACCESS` у NextDNS, пропрієтарні фічі без відкритих аналогів. Residential Hosting зокрема — це комерційні бази (IP2Proxy, IPQualityScore), платний доступ.
- **CSAM (Project Arachnid)** — дані Canadian Centre for Child Protection, доступні лише перевіреним партнерам за угодою; публічно не розповсюджуються.

---

## 3. Результуючий набір для проєкту

Практично реалізовуване без гемороя з авторизацією, усі джерела вже
покриваються дозволеним мережевим allowlist (`raw.githubusercontent.com`,
`github.com`):

1. HaGeZi Multi PRO (основний ads/trackers/malware набір)
2. HaGeZi Threat Intelligence Feeds (TIF)
3. HaGeZi Newly Registered Domains / DGA
4. HaGeZi Dynamic DNS (DynDNS)
5. HaGeZi Badware Hoster
6. HaGeZi Most Abused TLDs
7. CoinBlockerLists (cryptojacking)

Опційно окремим шаром: OISD або Steven Black hosts як альтернатива/доповнення
до HaGeZi Multi, якщо потрібна ширша база для порівняння false positive rate.

Поза межами: IDN-гомографи та typosquatting-детекція — це окрема задача на
алгоритм (можна портувати логіку на кшталт `dnstwist` в Rust), не питання
підбору списку.
