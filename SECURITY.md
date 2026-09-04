# Security

Threat model summary, hard constraints, and dependency-vetting table. Full reasoning behind each
item lives in `SPEC.md` — this file tracks the current state, `SPEC.md` explains why.

## Threat model (summary — see SPEC.md §"Наскрізні вимоги", §2, §8.1 for full reasoning)

- **Local DoH cert compromise** — the largest single attack surface in the project. Mitigated by
  using a single self-signed leaf certificate on `127.0.0.1` (never a local CA): a compromised
  private key spoofs localhost only, not arbitrary domains. See SPEC.md §2. **Current storage
  posture (T-67, 2026-08-31):** the private key is held in the OS secret store — Windows
  Credential Manager via the `keyring` crate (`key_store.rs`), keyed on an entry name derived
  from the app-data directory (`dns-quorum-filter` / `doh-tls-private-key:<sha1(dir)[..8]>`) so a
  scratch/isolated instance never collides with the real one. Only the public `cert.pem` is on
  disk. A pre-T-67 install's plaintext `key.pem` is picked up once by
  `cert::migrate_legacy_key_into_store` (decode → store → zero-and-unlink the file), keeping the
  existing trusted cert. keyring's `windows-native-keyring-store` contains the Win32 FFI, so
  `dnsqb-service`'s crate-wide `#![forbid(unsafe_code)]` stays intact. The two-phase `icacls.exe`
  ACL helpers went out with the last plaintext secret file when **T-163** moved the MaxMind
  credentials into the OS store too — nothing this crate writes to disk is secret any more.
  macOS Keychain / Linux Secret Service are abstracted by `keyring` but unverified here
  (no build/test access) — **T-71**.
- **MaxMind account id + license key (T-80 / T-163).** The opt-in MaxMind GeoLite2 advanced mode's
  credentials are held in the OS secret store (`key_store::maxmind_credentials_entry`,
  `maxmind-credentials:<sha1(dir)[..8]>`) as a small JSON blob — the same `keyring` primitive as
  the TLS key, resolved once at startup and refreshed at runtime (T-163). A pre-T-163 install's
  plaintext `%LOCALAPPDATA%\dns-quorum-filter\geoip_maxmind.toml` (a dedicated file, never a table
  in `resolver_config.toml` — see `geoip_credentials.rs`'s module doc for why) is migrated once by
  `geoip_credentials::migrate_legacy_credentials_file` (parse → store → zero-and-unlink), then the
  file is gone. Leak surface while in memory / in transit is closed by: `LicenseKey`'s redacting
  `Debug` + no `Display` / no `Serialize`; the download using an `Authorization: Basic` header,
  never a URL query parameter; `reqwest` 0.13 stripping `Authorization` on the cross-host redirect
  to Cloudflare R2 (verified in the vendored `redirect.rs`); and every MaxMind `reqwest::Error`
  being mapped to a coarse label, never logged via `Display`.
- **~~Tauri IPC boundary (webview → Rust backend)~~ — historical, the channel no longer exists
  (T-149, SPEC.md "Відкриті питання" п.13, DECISIONS.md).** `crates/dnsqb-ui` is deleted; no
  process embeds a webview or exposes Rust functions to JS via `#[tauri::command]` anymore. The
  underlying principle (explicit allowlisted surface, no raw internal structs exposed, four test
  categories not one smoke test — SPEC.md §8.1) carries forward to the admin HTTP channel below,
  not lost with the removal.
- **Admin HTTP channel (browser/tray → `dnsqb-service`, loopback, T-52/T-149)** — the exposed route
  set is a structural allowlist, not just documentation: `dispatch::ROUTES` is the actual table
  `serve()` dispatches from (checked before the handler-selection `match`), so a path/method pair
  not listed there can never reach a handler no matter what arm a future `match` edit adds
  (T-59, verified empirically — an unlisted arm added to the `match` without a `ROUTES` entry stays
  unreachable; `serve_matches_the_documented_admin_route_allowlist` fails if `ROUTES` itself drifts
  from its own hand-written expected copy). Every mutating
  route (`POST /admin/config`, `POST /admin/reset`, `POST /admin/shutdown`) requires
  `Content-Type: application/json` (`dispatch::content_type_is_json`) as its whole CSRF defense:
  not a CORS-simple content type, so a cross-origin write forces a preflight this service never
  answers. DNS-rebinding is closed independently by the leaf cert's narrow SAN set
  (`127.0.0.1`/`::1`/`localhost` only, T-48), not by this gate. `POST /admin/reset` (T-149) reloads
  both on-disk TOML files and clears the cache + query log — a malformed file on disk fails closed
  (500, live state untouched), never a partial apply. **`POST /admin/shutdown` (T-149) is the
  highest blast-radius route on this whole channel** — it terminates the entire `dnsqb-service`
  process (a graceful drain via `hyper_util::server::graceful::GracefulShutdown`, never
  `std::process::exit`), meaning DNS resolution for the whole machine goes silently unfiltered
  (the browser falls back to system DNS, SPEC.md "Відкриті питання" п.10) until a human manually
  restarts the service — `dnsqb-watcher` (Фаза 3) is the only thing that would ever auto-recover
  this, and it doesn't exist yet. Reachable only from this same loopback-only, CSRF-gated,
  cert-pinned channel; the one shipped caller (`dnsqb-tray`'s "Зупинити фільтрацію" menu item)
  gates it behind a native confirm dialog naming this exact consequence before ever sending the
  request. The embedded web UI (`GET /admin/ui`, T-149) ships `Content-Security-Policy: default-src
  'self'; frame-ancestors 'none'` — the latter specifically to keep the page from becoming
  iframe-able/clickjackable once T-49 installs the cert and the current incidental
  untrusted-cert protection against framing goes away.
- **Upstream DoH providers and DNS wire format** — parsed via `hickory-dns`, not a hand-rolled
  parser, specifically because this is historically the highest-CVE-density code class in C-based
  DNS software.
- **GeoIP / top-sites data feeds** — binary blobs that influence blocking decisions; atomic
  replacement is gated on TLS + checksum verification before swapping in a new file (SPEC.md §3.5).
  T-80's MaxMind advanced mode fetches a Basic-auth'd `.tar.gz` from `download.maxmind.com` and
  extracts the `.mmdb` member in memory (`tar` crate, read-only, bounded) before the same atomic
  swap; a `.tar.gz.sha256` sidecar is verified opportunistically (present mismatch → hard fail,
  absent → the TLS + gzip-CRC + structural-parse fallback).
- **Browser silent DoH-fallback** — open, not fully closed: if `dnsqb-service` errors or times out,
  the browser may silently fall back to system DNS, bypassing quorum entirely with no built-in
  mitigation in the current design (SPEC.md, Відкриті питання, п.10).

## Hard constraints (see SPEC.md §"Наскрізні вимоги" for the full list)

- Listens only on `127.0.0.1` — never `0.0.0.0`, no network listener beyond loopback.
- `#![forbid(unsafe_code)]` in every crate where possible; any `unsafe` needs an explicit
  justification comment.
- Domain names live only in the in-memory ring buffer by default; disk persistence of the query log
  is opt-in and must be encrypted via platform secure storage. Diagnostic/service logs never contain
  domain names.
- Elevated privileges only once, for the one-time trust-store install/uninstall step — the main
  process runs as a normal user, never with standing elevated privileges.
- CI must run `cargo audit` (known CVEs) and `cargo deny` (license/duplicate checks) as required
  steps, not optional ones. A CodeQL SAST scan (`.github/workflows/codeql.yml`, language `rust`,
  `build-mode: none`) runs on every push/PR — its alerts are triaged and fixed in the same pass,
  not left open because the other gates are green (T-101).
- Reproducible builds / signed release binaries — the app installs a trusted certificate into the
  system, so binary trust is as security-critical as the certificate itself. Built (Батч 3.7,
  T-100/T-102/T-103): pinned toolchain + tracked `Cargo.lock` + `--locked` everywhere +
  `/Brepro` + `codegen-units = 1`, verified by a blocking CI job that clean-builds twice in
  different paths and compares SHA-256 (proven on the pinned toolchain + `windows-latest` runner
  image; a different Windows SDK could change `link.exe` output — untested). A third party on the
  same toolchain/SDK can rebuild a tag's source and confirm the unsigned binaries byte-for-byte. **CI signing is `test-signed` with an ephemeral certificate —
  not trusted; production trust comes only from Microsoft Store re-signing the MSIX at
  publication** (a real cert can be supplied as the `CODESIGN_PFX` secret to sign strictly
  instead). The `v*`-tag release job re-proves reproducibility before it publishes a **draft**
  release; a human publishes it.
- MSIX packaging (Батч 3.8, T-156) — `runFullTrust`, not an AppContainer sandbox: the app already
  needs ordinary Win32 access outside any package (spawning siblings, `CurrentUser\Root`,
  Credential Manager), and grants no capability beyond that (no hidden MITM/proxy — this is a DoH
  filter the browser is explicitly pointed at). The `.msix` signature must match `<Identity
  Publisher>` exactly (`packaging/pack-msix.ps1` derives both from one `-Publisher` value, never
  two literals). **The sideload trust certificate is a *different* certificate from the one the
  running app installs for `127.0.0.1` DoH traffic** — trusting one does not trust the other, and
  the two must never be conflated in operator-facing instructions. Confirmed empirically
  (2026-09-04): `Cert:\CurrentUser\TrustedPeople` is *not* sufficient for `Add-AppxPackage`
  (`0x800B0109`) — sideloading needs `Cert:\LocalMachine\Root` or `\LocalMachine\TrustedPeople`,
  both requiring an elevated session, which is itself a real (if one-time, install-only) elevation
  cost this project's "no persistent elevated privileges" principle doesn't otherwise carry.
- **T-70 residual risk, MSIX-specific**: MSIX has no uninstall-time code hook at all — the OS just
  deletes the package's files, nothing runs afterward. `local_state::remove_all` (tray "Повністю
  видалити" / `/admin/ui`'s danger-zone card) is therefore an **in-app, user-triggered** action
  that must run *before* the package is removed, not an automatic cleanup step. If a user removes
  the app from Windows Settings without running it first, the trusted certificate and Credential
  Manager secrets are left behind — the same class of bug as any other left-behind trusted cert,
  but not structurally preventable under MSIX's model. Stated, not silently assumed away.

## Dependency vetting

When a crate is added, add a row here **before merging**, not after. This table is a
**current-state snapshot**, not a log — `cargo audit` and `cargo deny` run clean on every CI
push (see CLAUDE.md's Commands section), which already re-verifies every row on every commit,
so "clean as of DATE" is not restated per crate. Full historical detail (exact advisory IDs,
which batch/task added a crate, the date it was checked) lives in `git blame` and each task's
own note in `TASKS-DONE.md` — not duplicated here. A row states only what's still true and
actionable today: why this crate over an alternative, where its `unsafe` (if any) lives, and
any accepted risk that isn't obvious from the crate's name.

| Crate | Why this one (not an alternative) | `unsafe` / accepted risk |
|---|---|---|
| `hickory-proto` 0.26.1 | Avoids a hand-rolled DNS wire-format parser — historically the highest-CVE-density code class in C-based DNS software | — (past DNSSEC-validation CVEs are fixed in this version) |
| `tokio` 1.53.1 | Async runtime for concurrent upstream queries | — |
| `reqwest` 0.13.4 | `rustls` backend avoids a system OpenSSL dependency (a stated stack constraint); `json` (T-52, admin DTOs) and `stream` (T-75, bounded GeoIP download) added later | — |
| `futures-util` 0.3.34 | Only `FuturesUnordered`/`StreamExt`, not the full `futures` crate | — (historical `Mutex`-soundness advisories don't apply — that type isn't used here) |
| `tracing` 0.1.44 + `tracing-subscriber` 0.3.23 | Diagnostic-only logging; `error_kind()` deliberately avoids a raw error's `Display` (`reqwest::Error`'s message embeds the request URL, i.e. the domain) | `tracing-subscriber`'s RUSTSEC-2025-0055 (ANSI-escape log injection) has an affected range that does **not** include 0.3.23 — checked specifically, not just "clean at add time" |
| `moka` 0.12.16 | Per-entry TTL via its `Expiry` trait (SPEC §4) | — |
| `serde` + `serde_json` | Admin-channel DTO layer | — |
| `tempfile` (dev) | RAII cleanup in `overrides.rs`'s load tests | dev-only, never shipped |
| `parking_lot` 0.12.5 | `std`-backed `RwLock` for the query-log ring buffer — no `.await` is ever held under this lock, so a `tokio::sync::RwLock` would only add overhead | — |
| `rcgen` 0.14.9 | `aws_lc_rs` feature, not the default `ring` — avoids a second crypto implementation in the binary; `IsCa::ExplicitNoCa`, not the `NoCa` default — encodes "not a CA" directly in the cert's bytes, provable rather than assumed | `zeroize` feature only wipes the key on an explicit call, no `ZeroizeOnDrop` — best-effort |
| `x509-parser` (dev) | Empirically decodes `rcgen`'s DER output rather than trusting its docs | dev-only |
| `zeroize` 1.9.0 | Wraps private-key bytes in memory (`Zeroizing<Vec<u8>>`) | **Best-effort only, not a guarantee** — by the time `.zeroize()` runs the bytes may already be in the OS page cache or swap; no test asserts an actual wipe |
| `rustls` 0.23.43 | Always `builder_with_provider(aws_lc_rs::default_provider())`, never the plain `builder()` — otherwise the resolved crypto provider silently depends on whatever `rustls` features are active anywhere else in the dependency graph | — |
| `hyper` 1.11.0 | The DoH listener's HTTP implementation (T-143) | — |
| `hyper-util` 0.1.20 | `server-graceful` for drain-on-shutdown; the `auto` builder negotiates HTTP/1.1 vs 2 per connection — a self-signed leaf cert doesn't always get ALPN h2 | — |
| `tokio-rustls` 0.26.4 | Standard `tokio` integration for `rustls` | — |
| `http` 1.5.0 | The shared `Request`/`Response` types `hyper` itself is built on | — |
| `http-body-util` 0.1.5 | `Limited::new` wraps a request body **before** `.collect()` — bounds the allocation itself, not just a length check on an already-fully-collected body (SPEC §8.1) | — |
| `bytes` 1.12.1 | Response bodies for the DoH listener | — |
| `toml` 1.1.4 | Replaced `serde_json` for on-disk config (T-145, comment support). `overrides.toml`'s parse-error variant deliberately carries **no** `toml::de::Error` payload — its `Display` echoes the offending input line, which is a domain name; `resolver_config.toml`'s variant keeps the real payload since that file never contains domains | **Deliberate leak-prevention split, not an inconsistency** |
| `tray-icon` 0.21.3 (+`muda`) | Same publisher as the removed `tauri` row — replaced the Tauri-based UI (T-149) | — |
| `tao` 0.31.1 | Owns the tray's main thread (`EventLoop::run` never returns) — the admin-status poll runs on its own OS thread instead | — |
| `rfd` 0.15.4 | `default-features = false` — the Linux-only XDG-portal backend never enters the tree on this Windows-only target | Backs the confirm dialog on the channel's highest-blast-radius action ("Зупинити фільтрацію") — a real security-UX role, not cosmetic |
| `proptest` 1.11.0 (dev) | `default-features = false` excludes `fork`/`timeout` — no process-spawning transitive deps | dev-only; the real property tests: `parse_pattern`, `wire_bytes_from_get`, and a fuzz pass over `/admin/config` POST bodies |
| `maxminddb` 0.30.3 (+`ipnetwork`) | `default-features = false` — no `mmap`/`simdutf8`/`unsafe-str-decode`; reads the whole DB into an owned `Vec<u8>` instead | Keeps `#![forbid(unsafe_code)]` true for this crate's usage with no exception needed |
| `flate2` 1.1.9 | `miniz_oxide` backend — pure Rust, no C toolchain, same `forbid(unsafe_code)` reasoning as `maxminddb` | — |
| `sha1` 0.10.7 | Verifies the DB-IP `.sha1` sidecar — chosen to match what db-ip.com actually publishes, not for collision resistance | Threat model here is cross-host consistency, not a resourced adversary |
| `sha2` 0.10.9 | Same role for MaxMind's `.sha256` sidecar | — |
| `tar` 0.4.46 (+`filetime`) | Read-only, in-memory `.tar.gz` extraction — no path is ever built from an archive entry, so there's **no path-traversal surface**. Chosen over a hand-rolled tar parser for the same reason as `hickory-proto`: untrusted network input into a hand-written parser | — |
| `keyring` 4.2.0 (+`keyring-core`, `windows-native-keyring-store`) | The single boundary storing the TLS key, MaxMind credentials, and the persistence key; `v1` feature is required (compile error without it) | `unsafe` Win32 FFI is contained in `windows-native-keyring-store`, `forbid(unsafe_code)` intact. **`v1` also pulls non-Windows store crates into `Cargo.lock`; they never compile for windows-msvc and `cargo deny` ignores them, but `cargo audit` reads `Cargo.lock` with no graph-target filter — a future advisory against one of them would still redden CI.** A stated, live maintenance liability, not history. |
| `sysinfo` 0.39.6 (+`ntapi`→`winapi` 0.3.9, `windows` 0.62 family) | The one caller: `verify_pid_alive` — PID+exe-identity check before a watchdog restart (§7.1 #3) | `unsafe` FFI is contained in `ntapi`/`windows-*`, `forbid(unsafe_code)` intact. **This is the same FFI stack §7.1 #2 *rejected* for the `single-instance` guard crate (which had a trivial safe lock-file alternative) — accepted here because no such alternative exists for a process-*identity* check.** The asymmetry is the decision, not an oversight. Links into `dnsqb-service` though only `dnsqb-watcher` calls it (§7.1 #6, accepted). |
| `chacha20poly1305` 0.11.0 (+`aead`/`poly1305`/`universal-hash`/`chacha20`/`cipher`) | Pure Rust, no C toolchain — chosen over promoting `aws-lc-rs` (user decision, 2026-09-03). Sole use: `encrypted_file::{seal,open}` for the opt-in encrypted query log and cache | SIMD `unsafe` contained in `chacha20`/`poly1305`, `forbid(unsafe_code)` intact. `chacha20` was pinned off a yanked 0.10.1 to 0.10.2 via `cargo update` — a real fixed issue, not hypothetical. |
| `getrandom` 0.3 | Promoted transitive→direct; its one call site draws the 24-byte `XChaCha20Poly1305` nonce | **A `fill` failure returns an `Rng` error and the flush is abandoned — never a zero or predictable fallback nonce** (nonce reuse under a fixed key breaks Poly1305 authentication and leaks the XOR of the plaintexts) |

Crates that are planned but not yet pinned to a version are tracked in `SPEC.md` §"Технічний
стек" / `CLAUDE.md` §"Planned stack" — that's design-time rationale, not a substitute for this
table once a version actually lands in `Cargo.lock`.
