# Сервіси

Workspace складається з двох бінарників. Обидва — окремі, довготривалі процеси, без
взаємозалежності на рівні збірки (кожен — свій `[[bin]]` в `crates/*/Cargo.toml`).

* * *

## `dnsqb-service`

DoH-сервер + quorum-резолвер — основний і єдиний зараз працюючий процес (SPEC.md §1, §3).
Слухає **тільки** `127.0.0.1`, ніколи `0.0.0.0`.

### Запуск

Немає жодних CLI-прапорців чи підкоманд — усе поведінкове налаштування йде через
[`CONFIGURATION.md`](CONFIGURATION.md)'s два TOML-файли, не через аргументи командного рядка.

```
cargo run -p dnsqb-service              # dev-збірка, з логами в консоль
cargo build --release -p dnsqb-service  # release-бінарник у target/release/
```

Після старту сервіс слухає `https://127.0.0.1:<port>/dns-query` (порт із
`resolver_config.toml`, дефолт `8443`) — саме цю адресу треба вказати в браузері як
"Custom DoH provider".

### Що робить при старті

1. Завантажує (або, при першому запуску, генерує і зберігає) self-signed TLS-лист-сертифікат —
   `cert.pem`/`key.pem` у `%LOCALAPPDATA%\dns-quorum-filter\`, приватний ключ з ACL, обмеженим
   поточним користувачем (T-48/T-50/T-142). Це листовий сертифікат, **не CA** — компрометація
   його ключа дозволяє підробити лише `127.0.0.1`, не довільний домен (SPEC.md §2).
2. Завантажує `resolver_config.toml` і `overrides.toml` (обидва — див.
   [`CONFIGURATION.md`](CONFIGURATION.md); поведінка при відсутньому/зламаному файлі описана
   там).
3. Біндить TCP-слухач на вказаному порту — зайнятий порт це явна фатальна помилка, не тихий
   fallback на інший порт (SPEC.md §1).
4. Приймає з'єднання, термінує TLS (`rustls`), і на кожен DoH GET/POST-запит прогонює конвеєр
   allowlist → blocklist → cache → quorum (SPEC.md §5.3) через `dispatch::resolve_doh_request`.

### Логи

Через `tracing`, `tracing_subscriber::fmt::init()` пише у stdout. Дефолтний рівень —
`INFO` (`tracing_subscriber`'s `Subscriber::DEFAULT_MAX_LEVEL`); фільтрується змінною
оточення `RUST_LOG` (наприклад `RUST_LOG=debug cargo run -p dnsqb-service`) — це працює навіть
без Cargo feature `env-filter` (не увімкнена в `Cargo.toml`), бо `fmt::init()` у такому випадку
сам парсить `RUST_LOG` через легковаговий `Targets`-фільтр. **Службові логи ніколи не містять
доменних імен** (наскрізна вимога SPEC.md) — перевірено вручну для кожного `tracing::`-виклику
перед тим, як `main.rs` уперше увімкнув реальний subscriber (T-143).

### Відомі прогалини

- **Немає автоматичного встановлення сертифіката в довірене сховище ОС** (T-49) — до ручного
  імпорту `cert.pem` браузер показуватиме попередження про недовірений сертифікат при першому
  зверненні до `https://127.0.0.1:<port>/`.
- **Немає graceful shutdown / обробки сигналів** — очікується watchdog'ом (Фаза 3).
- Query log — лише in-memory ring buffer, без збереження на диск (SPEC.md §6; персистентність —
  T-146, заблокований на T-96).

* * *

## `dnsqb-watcher`

Мінімальний watchdog-процес — mutual heartbeat з `dnsqb-service` через 3 незалежні канали (IPC
socket, спільний heartbeat-файл, HTTP `/health`), majority/unanimous voting, щоб уникнути
false-positive рестарту (SPEC.md §7).

**Наразі — заглушка** (`todo!()` тіло в `crates/dnsqb-watcher/src/main.rs`), Фаза 3 scope.
Запуск `cargo run -p dnsqb-watcher` існуючим бінарником зараз одразу впаде на `todo!()`.
Не мати watcher'а на цій фазі — свідомий вибір (SPEC.md §"Фазований план"): при PoC ручний
рестарт `dnsqb-service` вважається прийнятним.
