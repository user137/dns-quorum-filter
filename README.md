# DNS Quorum Filter

Кросплатформний лайтвейт-застосунок, що піднімає локальний DNS-over-HTTPS
(DoH) сервер на `127.0.0.1`. Браузер (через вбудовану опцію "Custom DoH
provider") відправляє всі DNS-запити на цей локальний сервер, який опитує
паралельно кілька публічних фільтруючих DNS-провайдерів (Quad9, AdGuard DNS
та ін.) і блокує домен за принципом **кворуму** (OR-логіка: блокувати, якщо
хоч один провайдер каже "блок").

Це не конкурент uBlock Origin — це мережевий (DNS-level) фільтр, не заміна
element-picker / cosmetic filtering. Ціль — покрити malware/phishing/adult/ads
на рівні резолюції домену, використовуючи одразу кілька незалежних джерел
threat-intelligence замість одного провайдера.

## Статус

Крок 0 (SPEC.md, розділ "Фазований план") у процесі: Rust workspace і CI
розгорнуті, резолвер ще не реалізований — `crates/dnsqb-service` і
`crates/dnsqb-watcher` наразі заглушки. Повна технічна специфікація — у
[`SPEC.md`](SPEC.md), поточний фазований план — там само.

## Workspace

```
crates/
  dnsqb-service/   # DoH-сервер + quorum-резолвер (Фаза 1)
  dnsqb-watcher/   # watchdog, взаємний heartbeat (Фаза 3, заглушка)
```

`cargo build --workspace` / `cargo test --workspace --lib` з кореня репо;
повний список команд — CLAUDE.md, розділ "Project state".

## Документація

- [`SPEC.md`](SPEC.md) — технічний спек: архітектура, обґрунтування рішень,
  таблиця RFC-відповідності, фазований план, відкриті питання.
- [`UI-SPEC.md`](UI-SPEC.md) — GUI: екранний inventory, таблиці полів по
  екрану, DTO, чернетка Tauri-команд; мокап у [`mockups/`](mockups/).
- [`TASKS.md`](TASKS.md) — поточні задачі.
- [`DECISIONS.md`](DECISIONS.md) — журнал архітектурних рішень.
- [`SECURITY.md`](SECURITY.md) — модель загроз, жорсткі обмеження, таблиця ветингу залежностей.
- [`diagrams/`](diagrams/) — діаграми.

## Стек

Rust (`tokio`, `hickory-dns`, `hyper`, `reqwest`, `rustls`, `moka`,
`maxminddb`) + Tauri для UI. Деталі й обґрунтування вибору кожного
компонента — у SPEC.md, розділ "Технічний стек".

## Ліцензія

[Apache License 2.0](LICENSE).
