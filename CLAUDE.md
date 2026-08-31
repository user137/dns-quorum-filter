# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

**Phase:** Фаза 2 (GeoIP workstream) in progress. Фаза 1 formally closed 2026-08-29 (SPEC.md
§"Фазований план"); Крок 0 (Rust workspace, CI, RFC-conformance table T-1–T-19) done. Фаза 1
target platform is Windows (DECISIONS.md, 2026-08-25 — SPEC.md left it open).

Per-task history — design rationale, advisor catches, verification notes — is recorded in
`TASKS-DONE.md` (one line + implementation note per task), `DECISIONS.md` (reversals of shipped
decisions), and git. This section is the at-a-glance snapshot; it does not repeat that history.

**Maintaining this section:** it is a snapshot, not a log. A finished task updates the phase line,
the module table, and the workstream status, and adds a bullet under "Known limitations in shipped
code" *only* if it leaves a live limitation there. The task's own narrative — rationale, advisor
catches, verification notes — goes to `TASKS-DONE.md`, never here. (This file was compressed from
~198k to ~62k chars on 2026-08-30 by moving 30 slices of appended narrative out; don't re-grow it.)

### What's built

`dnsqb-service` — a real `hyper` + `rustls` DoH listener on `127.0.0.1` (T-143), resolving queries
end to end through the Фаза 1 pipeline (allowlist → blocklist → cache → quorum; T-39) plus live
GeoIP filtering (SPEC.md §3.5 / §5.3 step 8). The intermediate SPEC.md §5.3 steps — ccTLD block,
rating filter, voter scope — are later phases, not built. Modules under `crates/dnsqb-service/src/`:

| Module | Responsibility |
|---|---|
| `pipeline` | `handle_query` request flow; `invalidate_changed` (cache eviction on override-list reload) |
| `quorum` | OR-logic `resolve(&[ProviderEntry])` over a runtime voter list (T-72/T-73); `evaluate(BlockSignature)` (3 heuristics: `NullIp` / `NxdomainVsBaseline` / `NullIpOrNxdomain`); early-return via `FuturesUnordered`; `VoterRecord { provider_id: String, .. }` / `VoterVerdict` |
| `cache` | `moka` per-entry-TTL cache; `CacheConfig`, `clamp_ttl`, `chain_cache_ttl`, `is_cacheable`, `invalidate_matching`, `clear` |
| `overrides` | allowlist/blocklist `load`/`save`/`decision`/`conflicts`; suffix-wildcard match; `InvalidEntry` (domain-redacting) |
| `upstream` | `ProviderSpec` / `ProviderEntry` / `Category` / `BlockSignature` + `BUILTIN_PRESETS` table (§3.4, T-72/T-73) + `builtin_preset` / `all_builtin_presets` / `validate_provider_url` (SSRF: `https` + non-loopback/private/link-local literal host) / `is_valid_provider_id`; `DohClient` trait + `ReqwestDohClient` (per-upstream HTTP/2 keep-alive) |
| `timeout` | `TimeoutMode` (fail-open / fail-closed / degraded); `query_with_timeout` |
| `wire` | DoH wire codec; block (`0.0.0.0`/`::`) / NODATA / SERVFAIL / direct-answer construction; AD-bit passthrough |
| `query_log` | in-memory ring buffer (`parking_lot::RwLock`); `LogEntry`, `DecisionSource`, `LogFilter` search, `clear` |
| `config` | `ResolverConfig` (TOML); `[providers]` / `[cache]` / `[geoip]` tables; per-field validation, loud errors |
| `cert` / `paths` / `trust_store` / `cert_rotation` / `key_store` | self-signed leaf cert generation (T-48); `cert.pem` on disk, private key in the OS secret store via `key_store` (T-67 — Windows Credential Manager through `keyring`; entry name = `dns-quorum-filter`/`doh-tls-private-key:<sha1(app-data dir)[..8]>` so a scratch instance never collides); `cert::migrate_legacy_key_into_store` copies a pre-T-67 plaintext `key.pem` into the store once, and `discard_legacy_key_file` zero-and-unlinks it **only after** `tls` proves the stored key loads against `cert.pem` (so a mismatched plaintext key is never destroyed first); the T-50 `icacls` ACL helpers were removed in T-163 (nothing writes a plaintext secret to disk any more); `CurrentUser\Root` trust-store install/uninstall (T-49); `cert_rotation::rotate_certificate` (T-69) = ordered composition generate → `uninstall` (CN-exhaustive) → persist → `ensure_installed`, no new primitive, clear-before-persist forced by the shared CN, tray-only, needs a manual `dnsqb-service` restart to take effect |
| `tls` | `load_or_generate_server_config` (runs the one-time `key.pem` migration, then loads `cert.pem` + the stored key, else regenerates — `CertOrigin::{Loaded,GeneratedFirstRun,Replaced}`) → `rustls::ServerConfig` (always `builder_with_provider(aws_lc_rs::default_provider())`) |
| `listener` | `bind_listener` / `BindError`; `127.0.0.1`-only; explicit error on port conflict, never a silent fallback |
| `dispatch` | route table (`ROUTES`), `serve` (generic over body type for testability), `resolve_doh_request`, `AppState<C>` |
| `admin` / `admin_ui` | `/admin/*` JSON DTOs + `AdminClient`; embedded browser config page (`include_str!` HTML/CSS/JS, strict CSP, no `unsafe-inline`) |
| `geoip` / `geoip_credentials` / `geoip_download` / `geoip_updater` | `GeoipReader` country lookup; `GeoipSource` = DB-IP Lite (default) or MaxMind GeoLite2 (opt-in, Basic auth, `.tar.gz` extract — T-80). `geoip_credentials::{save,load,clear}` (T-163) store the MaxMind account-id+license-key JSON blob in the OS secret store (`key_store::maxmind_credentials_entry`), not a file; `migrate_legacy_credentials_file` folds a pre-T-163 plaintext `geoip_maxmind.toml` in once and unlinks it (delete-after-store is safe here — a credential is re-typeable, unlike the TLS key). `geoip_updater::check_maxmind_credentials` = one status-only authed probe (10s timeout) for the save-time check; `MaxmindHealth` (`health_after_refresh`, pure) tracks whether the stored key is still accepted at the 24h background refresh. `GeoipSource` lives on `AppState` (`RwLock<Arc<_>>`); `run_geoip_updater` re-snapshots it each cycle and parks on `sleep`-or-`Notify` so a creds change is picked up with no restart. Bounded download + integrity gate + atomic swap |

Admin channel — same loopback TLS port as `/dns-query`, `application/json` CSRF gate on every
write route, the full set enumerated in `dispatch::ROUTES` (a path/method not in that table can
never reach a handler): `GET /admin/status`; `POST /admin/config`, `/admin/reset`,
`/admin/shutdown`; `GET|POST /admin/overrides[/add|/remove]`, `/admin/cache-config[/apply]`,
`/admin/geoip[/add|/remove]`, `GET|POST /admin/geoip/maxmind` + `POST /admin/geoip/maxmind/clear`
(T-162/T-163, MaxMind creds → OS secret store; POST stores then runs a save-time probe → `check`,
and updates the live `GeoipSource` + wakes the updater; `refresh_health` on the view flags a key
that started failing later), `GET /admin/providers`
+ `POST /admin/providers/{add,remove,set-enabled}` (T-72/T-73; provider list edited here, **not**
`/admin/config` — which now carries only `timeout_mode`), `/admin/log[/clear]`;
`GET /admin/ui`, `/admin/ui/main.js`, `/admin/ui/style.css`. The MaxMind creds are their own OS
secret-store entry with a single writer (that one POST route), not part of `resolver_config.toml`
— no shared lock.
Every route that re-serializes `resolver_config.toml` shares
`state.persist_lock` and reads the other fields' live values before saving — the cross-field-read
discipline, the recurring bug class in this project (T-57 / T-139 / T-149 / T-47 / T-77).

`dnsqb-tray` — tray icon (`tray-icon` / `tao` / `rfd`), polls `/admin/status` on its own OS thread;
menu: "Restart" = soft `/admin/reset` (clear cache + log, re-read both TOMLs), "Stop filtering" =
confirm-gated `/admin/shutdown`, "Close" exits the tray only, plus a confirm-gated cert group
(T-49/T-69): "Встановити"/"Видалити сертифікат" (`ensure_installed`/`uninstall`) and "Перевипустити
сертифікат" (`cert_rotation::rotate_certificate` — reissue + re-trust; needs a manual `dnsqb-service`
restart before the new cert is served — until then the running service still presents the previous,
now-untrusted cert and the browser warns on `/admin/ui`; the tray's own cached-client status poll
is unaffected). Replaced the deleted Tauri `dnsqb-ui` (T-149, DECISIONS.md). Tooltip has three top-level states (`Unreachable` / `NoActiveProvider` /
`Filtering`); `Filtering` appends a degraded-upstream suffix when `AdminStats.degraded_events > 0`
(raw counts over the last 20 `QUORUM` log entries — T-56, narrowed), not a fourth state.

`dnsqb-watcher` — still a `todo!()` stub; Фаза 3 (SPEC.md §7).

### GeoIP workstream (Фаза 2)

Done: T-74 (`GeoipReader`), T-75 (background updater), T-76 (pipeline wiring + `[geoip]` config +
`DecisionSource::Geoip`), T-79 (`geoip_country` in the log), T-82 (unit-test task, docs-only), T-77
(admin routes + `/admin/ui` card), T-78 (DB build-date indicator), T-161 (`resolved_ip_country` on
every real-answer log row), T-80 (opt-in MaxMind GeoLite2 source — `geoip_updater` branches on `GeoipSource`; Basic-auth
download of the modern permalink, opportunistic `.tar.gz.sha256`, in-memory `.mmdb` extraction
from the tarball), T-81 (attribution footer
`#credits` on `/admin/ui` — DB-IP link-back + **CC BY 4.0** (confirmed direct against db-ip.com),
MaxMind GeoLite2 "advanced mode" line, app Apache-2.0; static HTML, no DTO), T-162 (admin route +
`/admin/ui` card for MaxMind creds + save-time `check` probe + `database_source` closed enum
showing the *loaded* source), T-163 (MaxMind creds → OS secret store + one-time file migration +
`icacls` helpers removed; `GeoipSource` on `AppState` + `Notify` wake so a creds change needs no
restart; `MaxmindHealth`/`refresh_health` detecting a key that starts failing at a later refresh —
3 commits).

**The GeoIP workstream (T-74–T-82) is complete.** Remaining Ф2 work is separate: cert rotation
(T-69, its own plan+advisor cycle). **T-72/T-73 backend done** (2026-08-31, plan+advisor, split
into a backend commit + a `/admin/ui`-card commit) — `quorum` is no longer hardcoded to two
providers: runtime `[[providers]]` list, all 10 §3.4 presets + custom-URL entry, 3
`BlockSignature` heuristics, 4 `/admin/providers/*` routes, `AdminConfigUpdate` loses `providers`,
`AdminStatusResponse.providers` → `active_providers`. **T-164** re-files the deleted
`ecs_option_for_upstream` stub (ECS-enabled upstream preset). macOS-dependent tasks (T-68/T-70
halves, T-71, T-83) remain deferred — no macOS access.

GeoIP design invariants (SPEC.md §3.5): the verdict is never cached — a cheap local lookup applied
live on every cached-or-fresh ALLOW, so a blocked-country-list change takes effect on the next
lookup with no invalidation logic. `geoip::blocking_country` (the filtering decision) takes
`blocked_countries`; `geoip::resolved_ip_country` (informational log metadata, T-161) deliberately
does **not** — structurally incapable of becoming a filter later. The allowlist branch and the
every-provider-disabled pass-through are exempt from GeoIP *filtering* but still get
`resolved_ip_country` annotation.

### Фаза 1 closure — two open gaps (not numbered tasks; see SPEC.md's closure paragraph)

- No test anywhere exercises the real "browser → local DoH" leg — every existing confirmation is
  either DoH-client-level (`Invoke-WebRequest`) or Chrome automation against `/admin/ui`.
- T-66's metrics (the gate SPEC.md sets before investing in Фаза 2) did not confirm the quorum
  hypothesis on their one sample (AdGuard caught 0/38).

### Known limitations in shipped code (no task number; the full open backlog is in TASKS.md)

- **`should_serve_stale` (`lib.rs`) is an unconsumed predicate** — RFC 8767 stale-if-error is not
  wired into the live pipeline. Before wiring it, re-check `quorum::combine`'s `incomplete` flag
  against `is_usable_answer` (see the gotchas entry): `incomplete` currently won't fire on a
  SERVFAIL voter, exactly the case stale-if-error exists for.
- **A fresh quorum ALLOW that GeoIP then blocks logs `voters: Vec::new()`** (consistent with the
  "voters empty except for Quorum" rule) — so those samples fall outside `admin::degraded_counts`
  (which filters `decision_source == Quorum`), narrowing T-56's degradation window. A stated
  limitation, not a bug.
- **`#overrides-body` in `/admin/ui` still has the dead-`persisted: false` add-then-refresh bug**
  that was fixed for `#geoip-body` at T-77 — a failed disk save on an overrides add shows the tag
  appearing with no "won't survive restart" warning. Left as a pre-existing gap, not fixed in
  passing.
- **`geoip_country` (the log DTO field) has no UI column yet** — DTO-ready since T-79. It is the
  blocking IP's country, populated only on `GEOIP` rows; `resolved_ip_country` (T-161) is the
  first-IP field the log UI actually renders.
- **`quorum::resolve` has an unenforced precondition** (documented on its doc comment): called with
  an all-disabled `&[ProviderEntry]` it returns a cacheable baseline ALLOW indistinguishable from a
  filtered one. The one shipped caller (`pipeline::handle_query`) gates this out via
  `ProviderEntry::any_enabled`.
- **Custom provider URL SSRF check is literal-host only (T-72)** — `validate_provider_url` rejects
  a non-`https` scheme and a loopback/private/link-local *literal IP* host, but a hostname that
  *resolves* to such an address at request time is not caught (resolve-then-pin is a bigger
  mechanism). Stated gap.
- **`GET /admin/log?voter=<id>` for a *removed custom* provider is a 400 (T-72/T-73)** —
  `serve_admin_log` validates the facet against currently-configured ids ∪ every built-in preset,
  so a toggled-off preset stays filterable but a since-removed custom id does not; that voter's
  historical log rows become unfilterable by voter. Not worth a full log scan for the id.
- **Shipped default provider set (`quad9` + `adguard`) still differs from SPEC.md §3.4/§3.5's
  first-run "Security category only"** (Quad9 Filtered + Cloudflare Malware). T-72/T-73 kept the
  shipped default rather than change what gets filtered inside a large refactor — open decision,
  `DEFAULT_PROVIDER_IDS` in `upstream.rs`.
- **T-160** — `main.rs`'s `load_geoip_state` reads the ~8.3 MB `geoip.mmdb` synchronously at
  startup, unconditionally (even with an empty `blocked_countries`) — a one-time startup-latency
  cost, filed not fixed.
- **`refresh_health: AUTH_REJECTED` (T-163) only appears on the next `/admin/ui` load / operator
  action** — the `#geoip-maxmind` card has its own fetch cycle (so a key field being typed isn't
  wiped by the 2s status poll), so a key that MaxMind starts rejecting 20h into an open page shows
  no live banner until the page is reloaded or the card is interacted with. Acceptable; stated,
  not a live push.
- **The stored TLS private key (T-67) is never removed on uninstall yet** — `key_store::
  delete_secret` is no longer `#[cfg(test)]` (T-163 gave it a real caller — the creds-clear route)
  but nothing calls it for the *TLS key* entry on uninstall. A left-behind
  key in Windows Credential Manager after the app is removed is the same class of security bug as
  a left-behind trusted cert (SECURITY.md). Calling it for the TLS-key entry on uninstall is
  folded into **T-70** (the packaged uninstaller). Also `key_store::overwrite_with_zeros` before
  unlinking a migrated plaintext file is a best-effort scrub only — no defence against VSS shadow
  copies or SSD wear-levelling.
- **Admin-channel fuzz (T-58, narrowed)** covers `parse_pattern` / `wire_bytes_from_get` /
  `/admin/config` POST body only — other routes and the `/dns-query` POST body are not fuzzed.
- **The status indicator (T-56, narrowed)** — browser-DoH-usage detection and watchdog state are
  still unbuilt; the tray's degraded-upstream signal is a precursor, not the full indicator.

### Recurring patterns (seen across many task slices — apply, don't re-derive)

- **Backend before UI** — a config surface + admin route land before any `/admin/ui` card
  (T-153 / T-47 / T-52 / T-77).
- **`AppState`'s mutable slices are `RwLock<Arc<T>>`** — a reader `Arc::clone`s and holds no lock
  across `.await` (`CacheState`, `OverridesState`, `GeoipState`, `geoip_countries`).
- **`clippy::too_many_arguments` / `too_many_lines` are fixed structurally** — cohesive parameter
  structs, extracted helpers — never `#[allow(...)]` (T-147 / T-148 / T-153 / T-76).
- **"An always-on warning is functionally identical to no warning"** (Три Б, SPEC.md §8.1) —
  per-event confirm flows, not permanent banners (T-56 / T-57 / T-77).
- **A failed disk save must surface `persisted: false` to the client** — a silent live-apply that
  won't survive a restart is the recurring user-safety bug (T-57 / T-139 / T-149 / T-47 / T-77).
- **Hard TOML cutovers, no dual-format shim** — an old key/file becomes a loud parse error; only a
  legacy-sibling *presence* check warns (T-144 / T-145 / T-148).
- **A new `LogEntry` / DTO field is `None`/absent except for its one owning `decision_source`** —
  `voters` (Quorum only), `geoip_country` (Geoip only).
- **Migration/cutover code that removes the source defers the delete only when the source is
  irreplaceable** — `cert::discard_legacy_key_file` erases `key.pem` only on `tls` load-success
  (T-67 closing-review: a mismatched plaintext key must survive as a recovery path), but
  `geoip_credentials::migrate_legacy_credentials_file` (T-163) unlinks in the same step it stores,
  because a `store_secret` `Ok` is the confirmation and a MaxMind credential is re-typeable from
  the portal. Decide per the *replaceability of the thing*, not a blanket rule.

### Runtime dependencies

Vetting rows are in `SECURITY.md`; the license allowlist and `[graph] targets =
["x86_64-pc-windows-msvc"]` restriction are in `deny.toml`. Notable feature choices:

- `tokio` — `rt-multi-thread` / `macros` / `net` / `sync` / `time`; `test-util` (dev) for paused time.
- `reqwest` — `default-features = false`, `rustls` / `http2` / `json` / `stream`; no `native-tls`.
- `hickory-proto` — DNS wire format (no hand-rolled parser).
- `hyper` (+`server`) / `hyper-util` (`server-graceful` for drain-on-shutdown) / `tokio-rustls`
  (`tls12`) / `http` / `http-body-util` / `bytes` — the DoH listener (T-143 / T-149).
- `rustls` — `default-features = false`, `aws_lc_rs` / `std` / `tls12` (exact set `reqwest` already
  activates). `rcgen` (`aws_lc_rs` / `pem` / `zeroize`, not `ring`) + `zeroize` — cert generation.
- `moka` — `default-features = false`, `future` (per-entry TTL `Expiry`).
- `maxminddb` (+`ipnetwork`, `default-features = false`) — GeoIP; `flate2` (`miniz_oxide` backend) +
  `sha1` (RustCrypto) — bounded gzip decompress + `.sha1` checksum-sidecar verify (T-75).
- `sha2` (RustCrypto — shares `digest`/`cpufeatures`/etc. with `sha1`) + `tar` (+`filetime`,
  `default-features = false`) — T-80's MaxMind GeoLite2 path: `.tar.gz.sha256` verify + read-only
  in-memory `.mmdb` extraction from the tarball (no hand-rolled tar parser).
- `serde` (+`derive`) / `serde_json` — admin JSON DTOs + embedded web UI. `toml` — both on-disk
  config files (`resolver_config.toml`, `overrides.toml`); replaced JSON at T-145 (DECISIONS.md).
- `parking_lot` — `query_log` ring-buffer lock (no critical section holds it across `.await`).
- `thiserror`, `base64`, `futures-util` (`FuturesUnordered` only), `tracing` (+`tracing-subscriber`
  — every call site grepped for domain-name leaks before the first real subscriber was wired).
- `url` — custom DoH provider URL parsing + literal-host SSRF classification (T-72). Already in the
  tree transitively via `reqwest`/`hickory-proto`; promoted to a direct dep, no new licence entry.
- `keyring` (`default-features = false`, `features = ["v1"]`) — the OS secret store (`key_store.rs`):
  the TLS private key (T-67) and the MaxMind account-id+license-key blob (T-163). `v1` is required
  (compile error without it); it also lists the Unix/Apple store crates target-gated — lockfile-only
  for windows-msvc, no `deny.toml` change. `unsafe` FFI is contained in
  `windows-native-keyring-store`, `#![forbid(unsafe_code)]` intact.
- `crates/dnsqb-tray`: `tray-icon` / `tao` / `rfd` (`default-features = false`) / `parking_lot`;
  depends on `dnsqb-service` as a library for `AdminClient`.
- Dev-only: `tempfile` (`overrides` load tests), `x509-parser` (`cert` DER assertions), `proptest`
  (`default-features = false`, `std` — no `fork`/`timeout` process-spawning tail).

### Commands (from repo root)

- `cargo build --workspace` — build all three crates. No `tauri-cli` / frontend build step of any
  kind — `dnsqb-tray` is a plain Rust binary, and `/admin/ui` is served from `include_str!`-embedded
  HTML/CSS/JS, no bundler.
- `cargo test --workspace --lib --bins` — unit tests. **`--bins` is required, not optional** —
  `dnsqb-tray` / `dnsqb-watcher` are `[[bin]]`-only crates with no `[lib]` target, so `--lib` alone
  never compiles or runs their `#[cfg(test)]` modules (caught when `dnsqb-tray/src/browser.rs`'s
  test turned out to have never run in CI).
- `cargo test --test conformance -p dnsqb-service` — RFC-conformance tests; green (un-`#[ignore]`d
  ones must pass; the count of each changes as Фаза 1/2 tasks land — check `TASKS.md` or run
  `-- --ignored`, don't trust a hardcoded number).
- `cargo test --test conformance -p dnsqb-service -- --ignored` — the same tests without the ignore
  filter; intentionally red until each cited task lands (informational red-board step in CI, not a
  merge gate).
- `cargo clippy --workspace --all-targets -- -D warnings` — lint gate, required (`lib.rs`/`main.rs`
  also carry `#![warn(clippy::pedantic)]` + `#![deny(clippy::unwrap_used, clippy::expect_used)]`).
- `cargo fmt --all -- --check` — format gate.
- `cargo audit` / `cargo deny check` — dependency vetting, required (SECURITY.md, `deny.toml`).
- `cargo llvm-cov --workspace --lib --lcov --output-path lcov.info` — coverage artifact,
  non-blocking at the MVP stage (T-19).
- `cargo doc --workspace --no-deps --document-private-items` with `RUSTDOCFLAGS=-D warnings` —
  rustdoc gate, required. `lib.rs` carries `#![allow(rustdoc::private_intra_doc_links)]` (never
  published, always built with `--document-private-items`) — fix a broken link, don't add a second
  one-off `#[allow]`.
- `cargo test --workspace --doc` — doctest gate, required. Zero doctests exist yet
  (`~/.claude/rules/rust.md`'s "key functions must include code examples" is not met anywhere) —
  the step exists so the first one is actually run.

All of the above run in `.github/workflows/ci.yml` on every push/PR, except the `--ignored`
conformance step and `coverage` (both `continue-on-error: true`).

**Check the actual CI run after every push — local-green is not CI-green**, especially for
OS-permission/environment-dependent code. `gh run list --branch main --limit 5`; `gh run watch
<run-id> --exit-status`; `gh run view <run-id> --log-failed`. Confirmed the hard way: an
`icacls` ACL fix (T-50) passed the full local gate on a Windows 11 Pro dev box but failed on the
`windows-latest` CI runner, which has different default file ACLs.

**`SPEC.md` is the source of truth for all design decisions.** Read it before proposing any
architectural change — most non-obvious choices are already deliberated there with explicit
reasoning (search by section number rather than re-deriving a decision from scratch).

## Rust/tooling gotchas (learned by doing, T-20–T-147 batches)

- **A `match` arm required only because a helper's *declared* return type is wider than what it
  *actually* returns is a real compile error, not a false positive — and the fix is a documented
  catch-all arm, never `unreachable!()`** (forbidden in this crate, rust.md "Panic-Free Production
  Code"). `quorum::known_signal` returns `Option<Signal>` (3-variant `Signal`), but its own body
  always resolves `Signal::NeedsBaseline` down to `Blocked`/`NotBlocked`/`None` before returning —
  `Some(Signal::NeedsBaseline)` can never actually come back. `quorum::voter_record` (T-147) still
  had to name that arm for exhaustiveness (E0004 without it); folded into the same `VoterVerdict::
  Canceled` case as the genuinely-reachable `None`, with a comment explaining the arm exists for the
  compiler's benefit, not because it's reachable — caught immediately by `cargo build`, not assumed
  from reading `known_signal`'s body alone.
- `hickory-proto` 0.26.1's API is field-heavy, not method-heavy — `.answers`, `.authorities`,
  `.name`, `.data`, `.metadata.response_code` etc. are public fields, not methods. Check the
  compiler's "field, not a method" hint before assuming a method exists.
- `Message` is `#[non_exhaustive]` — build via `Message::new`/`::query`/`::response`, then mutate
  public fields; no struct-literal construction from outside the crate. `Metadata::
  response_from_request(&query.metadata)` is the documented way to derive a response header.
- `#![deny(clippy::unwrap_used, clippy::expect_used)]` in `lib.rs` applies to inline
  `#[cfg(test)] mod tests` too (same crate) — only the separate `tests/` integration binary is
  exempt. Use `panic!(...)` (via `let-else` or `match`) in inline unit tests instead.
- Async trait methods called via `tokio::join!` need `fn foo(&self, ...) -> impl Future<Output =
  T> + Send`, not `async fn foo`, or `-D warnings` fails on `async_fn_in_trait`'s missing Send
  bound. A mock impl with no `.await` inside needs `std::future::ready(...)` instead of `async fn`
  to satisfy `clippy::unused_async_trait_impl`.
- Windows: the bundled `curl.exe` (Schannel libcurl) has no `--http2` — use PowerShell's
  `Invoke-WebRequest -HttpVersion 2.0` for HTTP/2 (relevant here: `dns.quad9.net` requires it).
- The PowerShell tool's working directory doesn't reliably persist between separate tool calls in
  this environment — `cd` inside the same command string, don't rely on a prior call's `cd`. Its
  static guard also misfires on `/flag:value` args or `X:`-shaped substrings in a command that
  also runs `Remove-Item` ("Remove-Item on system path … is blocked") — split the delete out.
- **Verifying an OS-secret-store entry (`keyring`, T-67 / T-163):** use a scratch `cargo` bin
  calling `keyring` directly (re-derive `key_store::tls_key_entry` / `maxmind_credentials_entry` =
  `<prefix>:` + sha1 of the lowercased, trailing-separator-stripped app-data dir) — `pwsh` can't
  load WinRT `PasswordVault` and the backend is Win32 `Cred*` anyway. `windows-latest` CI has a
  working session Credential Manager, so these round-trip tests run un-`#[ignore]`d (unlike T-50's
  `icacls` DACLs). **But the Windows backend races under concurrent access from one process** even
  on distinct entries (a just-written secret intermittently reads back absent) — every
  credential-store test across the crate takes `key_store::STORE_TEST_GUARD` (a `parking_lot`
  static) on its first line, held via the per-test scratch guard; without it the suite is flaky,
  single-threaded it passes.
- Adding any `rustls`-backed dependency tends to surface new `cargo deny` license entries (seen:
  `ISC` for `aws-lc-rs`/`rustls-webpki`, `CDLA-Permissive-2.0` for `webpki-root-certs`) — expect
  and vet each one in `deny.toml`, don't reflexively widen the allowlist.
- **`reqwest::Error`'s `Display` includes the failed request URL** — for this project's DoH GET
  requests, that URL embeds the base64url-encoded query, i.e. the domain name. Never log an
  `UpstreamError::Http`'s message text directly in a diagnostic-log context (SPEC.md, Наскрізні
  вимоги: no domain names in service logs) — log a coarse error-kind label instead (`quorum.rs`'s
  `error_kind()`). Caught in self-review while writing T-29's logging, not by any lint.
- Boxing differently-shaped `async move { ... }` blocks into one `FuturesUnordered<Pin<Box<dyn
  Future<Output = T> + Send + 'a>>>` (T-30's tagged-future pattern) needs the borrowed generic
  type param itself bound `Sync`, not just `Send` — `&C` across an `.await` inside the box requires
  `C: Sync` or the compiler rejects the `Send`-future cast with a non-obvious error pointing at the
  `&` reference, not at `C`.
- `#[tokio::test(start_paused = true)]` (deterministic `tokio::time::sleep`/`timeout` tests, no real
  waiting) needs the default current-thread runtime — never add `flavor = "multi_thread"` to a
  paused-time test, it panics at runtime (`rt-multi-thread` being enabled for `main.rs`'s own needs
  doesn't carry over to test attributes, which pick their flavor independently).
- **Proving an async cancellation/early-return actually happened, not just that the final verdict
  matches:** a mock future that never resolves on its own (`std::future::pending()`) only proves
  the caller didn't *need* the answer — it doesn't prove the caller *dropped* the future instead of
  waiting out its own `tokio::time::timeout` before falling through to a slower-but-still-correct
  path. Pair the never-resolving mock with `#[tokio::test(start_paused = true)]` and assert
  `tokio::time::Instant::now()` elapsed stays near-zero (well under the configured timeout) — under
  paused time this is deterministic, no real waiting. Caught by advisor review on T-30's tests,
  which passed either way before this fix.
- Constructing a `hickory_proto::ProtoError` for a test-only error fixture: `ProtoError` implements
  `From<String>` — `"description".to_string().into()` is enough, no need to reach for an internal
  `ProtoErrorKind` variant.
- `clippy::duration_suboptimal_units` (this toolchain) rejects `Duration::from_secs(24 * 60 * 60)`
  — use `Duration::from_hours(24)` (stable on this Rust version) instead of a multiplied
  `from_secs`/`from_millis` literal.
- `clippy::unchecked_time_subtraction` rejects `Instant::now() - Duration::from_secs(n)` even in
  test fixtures — `#![deny(clippy::expect_used)]` also applies there (same gotcha as above), so
  pair `Instant::checked_sub` with a `let-else { panic!(...) }`, not `.expect(...)`.
- `moka::future::Cache`'s `Expiry` trait (`moka::policy::Expiry`) takes/returns plain
  `std::time::Instant`/`Duration` — no `moka`-specific time wrapper, confirmed by reading the
  vendored `policy.rs` before writing the impl (0.12.16). Don't assume a wrapper type without
  checking; the crate's own docs don't make this obvious from the trait signature alone.
- Proving `moka`'s `Expiry`-driven eviction actually applies a computed duration (not just that a
  pure freshness-predicate function is correct) needs `moka`'s own real clock — `tokio::time::pause`
  tests the caller's code, not `moka`'s internal removal timing. For that one assertion, a short
  real `tokio::time::sleep` is the right tool, not a `#[tokio::test(start_paused = true)]` violation
  of the usual "avoid real waits" preference.
- **`hickory_proto::rr::Name::from_utf8` silently accepts inputs that look malformed at first
  glance — verify empirically, don't assume a rejection.** `Label::from_utf8` (vendored `label.rs`,
  0.26.1) special-cases a label equal to exactly `"*"` as the legal RFC 1034 wildcard-RR label and
  accepts it without going through the normal IDNA/`Uts46` character check — so a domain like
  `"*.example.com"` parses and "normalizes" successfully, producing a string that still contains a
  literal `*` and can never match a real query domain. `overrides.rs`'s `parse_pattern` (T-37) had
  to add its own explicit `body.contains('*')` guard *before* calling `normalize_domain`, rather
  than trust IDNA to reject it — same for an empty-string domain (`Name::from_utf8("")` normalizes
  to the DNS root, not an error). Both were caught by writing the test first and watching it fail,
  not by reading the source and assuming.
- **Redacting one field of a "no domain names in logs" type doesn't close the leak if a sibling
  field can carry the same text.** `overrides::InvalidEntry`'s first draft (T-37) hand-wrote
  `Debug` to redact its `raw` field, but kept `reason: ProtoError` unredacted — `ProtoError`'s own
  message (and `hickory-proto`'s `Label::from_ascii`, which formats a decode failure as
  `"Malformed label: {s}"`) still carried the domain straight through. Caught by advisor review
  before commit, fixed by making `reason` a coarse, closed enum (`InvalidReason`) with fixed
  per-variant `#[error(...)]` strings — structurally incapable of carrying the domain — rather than
  auditing every field of the type by hand. Proved with a dedicated test
  (`overrides::tests::invalid_entry_debug_output_never_contains_the_raw_pattern_text`) that formats
  `{entry:?}` and asserts the raw text is absent, not just reasoned about.
- **A `Responded` voter outcome means the HTTP round-trip succeeded, not that the DNS answer is
  usable.** A baseline `SERVFAIL`/`REFUSED` is still HTTP 200 with an rcode set, so it decodes as
  `Responded` too. `quorum::representative_allow_answer` (T-39) first drafted "prefer baseline
  unconditionally" — advisor review caught that a baseline SERVFAIL with two working filtering
  voters would silently `forward_response` a failed resolution to the client. Fixed with
  `is_usable_answer` (`response_code` is `NoError` or `NXDomain`), applied to all three fallback
  candidates, not just baseline. **`combine()`'s `incomplete` flag still uses the old, weaker
  standard** (`Responded` = complete) — this is a known, recorded gap for whenever RFC 8767
  stale-if-error gets wired into `pipeline.rs`: `incomplete` won't fire on a SERVFAIL voter, exactly
  the transient-upstream-trouble case stale-if-error exists for. Re-check `combine()` against
  `is_usable_answer` before consuming `incomplete` as that trigger.
- **`Name::to_ascii()`, not `.to_string()`/`Display`, when re-feeding a wire-decoded domain back
  through `normalize_domain`** (`pipeline.rs`'s `handle_query`, T-39) — `to_ascii()` is the exact
  transformation `normalize_domain` performs internally (`Name::from_utf8(...).to_ascii()`), so the
  round trip has no extra punycode→Unicode→punycode detour `Display` would add. Verified
  empirically (not assumed) that a label containing a literal dot (`Name::from_labels([b"a.b",
  b"com"])`, only reachable from raw wire bytes, not text) escapes to `"a\\.b.com."` and
  `Name::from_utf8` re-parses it back to one label, not two — a small standalone `cargo run`
  scratch project, not a source-reading assumption.
- **A cache-hit response must serve the entry's *remaining* TTL, not the full TTL it was inserted
  with.** `entry.expires_at.saturating_duration_since(now)`, not `entry.ttl`, in
  `pipeline::response_from_cache_entry` (T-39) — using the full TTL on every hit would mean a
  60-second entry hands the browser a fresh 60s TTL on every read, and the effective cache lifetime
  from the client's point of view would never actually expire. Caught by advisor review before
  commit, not by any of T-33/T-34/T-36's own tests (they all test the *write* side of TTL
  discipline, not a read-time reconstruction path that didn't exist yet).
- **A mock `DohClient` used from an `async fn` generic over `C: DohClient + Sync` needs
  `std::sync::atomic::AtomicU32`, not `std::cell::Cell<u32>`, for a call counter** — `Cell` isn't
  `Sync`, so a struct containing one fails the bound at the `handle_query(...)` call site with an
  error that points at the whole mock struct, not the `Cell` field specifically. `pipeline.rs`'s
  tests (T-39) hit this immediately when adding a "prove no extra upstream call happened" counter to
  the existing `MockClient` pattern from `quorum.rs`'s tests (which didn't need a counter, only
  `Panic`-on-call).
- **`moka::future::Cache::invalidate_entries_if` needs `.support_invalidation_closures()` on the
  builder** — without it the call returns `Err(PredicateError::InvalidationClosuresDisabled)`
  instead of invalidating anything; `Cache::new` (T-40) now always calls it. **One predicate
  registration per whole batch of changed domains, not one per domain** — `moka` re-applies every
  currently-registered predicate on every `get()` until its own maintenance task sweeps an expired
  one away, so N separate `invalidate_entries_if` calls for an N-domain override-list reload would
  put N closures on the live DNS read path; `Cache::invalidate_matching` (T-40) takes the whole
  changed-domain list and builds one closure over it instead. Caught by advisor review before
  implementing, not by any test — the naive one-call-per-entry version would have passed every
  test in the plan, since none of them exercised a multi-entry reload. Before writing the
  "unreachable, safe to ignore" comment on `invalidate_entries_if`'s `Err` branch, read
  `PredicateError`'s definition in full (`moka-0.12.16/src/common/error.rs`) rather than trusting a
  grep filtered to the one call site already found — a second variant would have made the comment
  false and the swallowed error a silent regression of the exact bug T-40 exists to fix.
- **A "config subset" parameter typed as a slice (`&[Provider]`) that internally only checks
  `.is_empty()` is a footgun, not a convenience** — a caller passing a genuine partial subset
  (e.g. `&[Provider::Quad9]`, `AdGuard` meant to stay disabled) would silently get every provider
  queried anyway, since nothing downstream reads which elements are actually in the slice. Caught
  by advisor review of the T-41 plan before implementing, not by any test. Fixed by using a
  two-variant enum (`pipeline::Voters { Enabled, Disabled }`) instead — the unsupported partial
  case becomes unrepresentable rather than silently mishandled (rust.md "Make Illegal States
  Unrepresentable"). General lesson: when a function's real behavior only distinguishes two cases
  today, don't type the parameter as though it already supports N — that's a promise the code
  doesn't keep, and the type system won't catch the caller relying on it.
- **Promoting a helper from an edge-case path to an all-traffic path means re-auditing it for
  properties the edge case never needed** — `pipeline::resolve_via_baseline` (T-39, allowlist-only)
  called the baseline `DohClient` with no timeout at all; harmless when it only served a handful of
  allowlisted domains, but T-41 makes it the entire resolution path for every A/AAAA query while
  `Voters::Disabled`. An unbounded hang there would stall all traffic — worse than no filtering,
  the Три Б user-safety failure mode by name. Caught by advisor review of the T-41 plan, not by any
  test the original allowlist-only version had. Fixed by routing through the already-existing
  `timeout::query_with_timeout` (the same primitive every `quorum::resolve` voter call already
  uses), which fixes both call sites (allowlist and pass-through) at once since they now share one
  helper. Proved with a `#[tokio::test(start_paused = true)]` test asserting elapsed time stays
  near-zero against a client that never resolves — the same technique T-30's cancellation tests use
  (a passing "eventually returns SERVFAIL" assertion alone wouldn't distinguish "timed out
  correctly" from "waited out a much longer real-world hang before some other mechanism gave up").
- **`rcgen` 0.14's `zeroize` feature only adds a manual `Zeroize` impl, not `ZeroizeOnDrop`** —
  confirmed by reading the feature-gated `impl zeroize::Zeroize for KeyPair` in `rcgen`'s own
  source (0.14.9) before enabling anything: it requires an explicit `.zeroize()` call, so enabling
  the feature alone buys no automatic on-drop protection. Real Drop-based zeroization needs
  wrapping the key in `zeroize::Zeroizing<KeyPair>` (a second dependency) at the point the key gets
  a real owner — `cert.rs` (T-48) deliberately doesn't enable the feature yet for exactly this
  reason, deferred to T-50 where that owner/lifecycle actually exists.
- **`rcgen::CertificateParams::new`/`generate_simple_self_signed` classify each input string as
  `SanType::IpAddress` or `SanType::DnsName` correctly (`"127.0.0.1"`/`"::1"` → typed IP SANs,
  `"localhost"` → a `DnsName`)** — verified empirically with a scratch `cargo run` probe against
  real `rcgen` + `x509-parser` output (not assumed from docs) before relying on it in `cert.rs`
  (T-48), since a `DNSName` SAN containing the text `"127.0.0.1"` would satisfy a naive
  string-contains test while failing real TLS validation. `rcgen`'s own default validity
  (`not_before`/`not_after`) is `1975-01-01`/`4096-01-01` — an unexamined library default, not a
  considered choice; `cert.rs` overrides both explicitly rather than using them as-is.
- **`x509-parser` 0.18's `ASN1Time` has no public `to_datetime()`/year accessor** — its only public
  time accessor is `.timestamp()` (`i64` Unix seconds). To assert an expected calendar date in a
  test, compare against `rcgen::date_time_ymd(y, m, d).unix_timestamp()` rather than trying to
  extract a year/month/day from the parsed certificate directly.
- **`rcgen::IsCa::NoCa` (the default) omits the `BasicConstraints` extension entirely rather than
  encoding `cA=FALSE`** — confirmed empirically by dumping a generated cert's parsed extensions
  (only `SubjectAlternativeName` was present). A test asserting `!cert.is_ca()` against a `NoCa`
  cert passes because `x509-parser` treats a missing extension as "not a CA," not because the
  cert's bytes say so — indistinguishable from a cert that never considered the question. Use
  `IsCa::ExplicitNoCa` when the "never a CA" property needs to be provably encoded, not just
  assumed by omission (`cert.rs`, T-48 — caught by advisor review of the diff, not by the tests as
  first written, which passed either way).
- **A `pub` error enum can't directly wrap a `pub(crate)` error type via `#[from]`** — `rustc`'s
  `private_interfaces` lint fires because external consumers of the outer type can observe the
  field exists (e.g. via `Debug`/pattern matching) but can never name the inner type. `cert.rs`'s
  first draft had `CertError::AppDataDir(#[from] paths::PathsError)`; fixed by dropping the
  `#[from]`/source-chain and using a flat `CertError::MissingLocalAppData` variant instead, the
  same shape as the enum's other single-cause env-var-missing variants (`cert.rs`, T-50).
- **The `icacls` ACL helpers were deleted in T-163** (`cert::write_user_restricted_file` /
  `restrict_to_current_user` / `other_principals` / `icacls_path` — nothing writes a plaintext
  secret to disk any more; code in git history). The next several gotchas are kept as durable
  *lessons*, not a live-code index — the strongest being: "confirmed empirically on one machine"
  is a weaker class of evidence than CI on the actual target image.
- **`icacls` resolves a bare, unqualified `%USERNAME%` against the local machine first** —
  confirmed empirically (`icacls <path> /grant:r <name>:F` with no domain/computer prefix), not
  assumed from docs. No need to build a `%USERDOMAIN%\%USERNAME%` principal string, which the
  first draft of T-50's plan carried "just in case" — advisor review flagged that `USERDOMAIN` can
  diverge from what `icacls` actually resolves on some account types, and the empirical check
  showed the bare form works and echoes back as `<computer>\<user>:(F)`, so the domain lookup (and
  its own failure mode) was dropped entirely rather than kept unused.
- **A truncate-in-place file write (`fs::write`/shell `>` redirection to an existing path)
  preserves that file's ACL** — it does not delete-and-recreate the file, so restricting an ACL on
  an empty file *before* writing its real contents (rather than after) actually works, and isn't
  undone by the subsequent write. Confirmed empirically with a scratch probe before relying on it
  in `cert::write_key_file` (T-50) — the create-then-restrict-then-write ordering exists
  specifically to avoid a TOCTOU window where the private key sits on disk under a wider,
  inherited ACL even briefly (advisor review of the plan caught the first draft's
  write-then-restrict ordering as exactly that gap).
- **A substring denylist (`!stdout.contains("SYSTEM")`, `!stdout.contains("Everyone")`, ...) is
  not proof that an ACL restriction actually narrowed anything** — it can't distinguish "no
  residual grant" from "that word just doesn't happen to appear," and it can false-fail on a
  machine whose hostname/account name happens to contain one of the denied words. For `icacls`
  output specifically, count non-blank, non-summary lines instead and assert there's exactly one
  — a direct structural proof of "exactly one ACE," matching the real output shape confirmed by an
  actual restricted-file probe, not a shape assumed from docs (`cert.rs`'s
  `write_key_file_creates_a_file_restricted_to_the_current_user_only` test, T-50 — caught by
  advisor review of the diff before commit, the same "test that passes without proving the
  property" shape as the `IsCa::NoCa` gotcha above).
- **`icacls <path> /inheritance:r /grant:r <user>:F` in a single pass is not sufficient to
  restrict a file to one principal — confirmed only by CI, not by a local probe.**
  `/inheritance:r` removes only *inherited* ACEs; `/grant:r` replaces only the *same
  principal's* own prior explicit grant — neither touches another principal's pre-existing
  *explicit* ACE. On the Windows 11 Pro dev machine, a freshly created file's only ACEs were
  inherited, so this single pass happened to leave exactly one entry and the first-written
  test passed. On the GitHub-hosted `windows-latest` CI runner, a freshly created file already
  carries **explicit** `SYSTEM`/`Administrators`/local-admin grants (not inherited), which the
  single pass left untouched — CI failed with 3 ACEs where the test expected 1, a case the dev
  machine could not reproduce no matter how carefully probed there. Fixed with a second phase:
  read the ACL back and `/remove:g` every principal that isn't the target user, so the result
  is self-correcting against whatever a given Windows image's default file ACL happens to be,
  rather than hardcoding a denylist of expected group names (`cert::restrict_to_current_user`,
  T-50). **Lesson beyond this one bug: "confirmed empirically" on a single machine is not the
  same class of evidence as CI on the actual target image** — this project's empirical-
  verification discipline (scratch probes, real command output) still needs the probe run
  somewhere representative of where the code will actually execute, not just wherever the
  agent happens to be developing.
- **Matching an `icacls`-printed principal against a bare `%USERNAME%` needs a suffix
  comparison, not equality.** `icacls` always prints the qualified form
  (`DESKTOP-PA\Pa`, `runnervmeef0v\runneradmin`), never the bare account name passed to
  `/grant`. A first draft of the CI fix compared `principal != keep` with `keep` set to the
  bare `%USERNAME%` value — that treated the tool's own just-granted principal as "extra" and
  stripped it too, leaving the file with zero ACEs and turning the very next `fs::write` into
  an `Access is denied (os error 5)`. Caught immediately by this module's own new test, not by
  CI a second time. Fixed by comparing only the segment after the last `\` in the printed
  principal, case-insensitively (`cert::other_principals`, T-50).
- **`rustls::pki_types::PemObject` (the trait providing `from_pem_slice`/`from_pem_file`) lives at
  `rustls::pki_types::pem::PemObject`, not `rustls::pki_types::PemObject`** — the compiler's own
  suggested-import diagnostic named the correct path immediately, but `use rustls::pki_types::{...,
  PemObject, ...}` (the path that "looks right" by analogy with `CertificateDer`/`PrivateKeyDer`,
  which *are* directly under `pki_types`) fails to resolve (`tls.rs`, T-142).
- **Declaring a `rustls`-family crate with its *default* features (`rustls = "0.23"`, no
  `default-features = false`) is wrong even when the default feature set "looks safe" on paper.**
  `rustls` 0.23.43's own `Cargo.toml` default (`aws_lc_rs`, `logging`, `prefer-post-quantum`,
  `std`, `tls12`) already matches this project's chosen crypto backend, but Cargo unifies features
  across the *whole* dependency graph — declaring defaults would union `logging` (pulls in a new
  `log` dependency) and `prefer-post-quantum` into `reqwest`'s already-shipped, already-tested TLS
  client path too, a behavior change to unrelated code as a side effect of an unrelated task.
  Confirmed via `cargo tree -f "{p} {f}" -p rustls` *before* adding the dependency that `reqwest`
  already activates exactly `aws-lc-rs,aws_lc_rs,std,tls12` — matched that set explicitly
  (`default-features = false, features = ["aws_lc_rs", "std", "tls12"]`) and re-ran the same
  command after adding it to confirm zero features changed (T-142; caught by advisor review of the
  plan before implementing, not assumed from reading `rustls`'s `Cargo.toml` alone).
- **`rustls::ServerConfig::builder()` is not equivalent to "the config that reqwest's client
  already made work" — it re-resolves the process-default crypto provider from whichever `rustls`
  crypto-backend features are active *across the whole graph*, and `.expect()`s that resolution to
  be unambiguous** (confirmed by reading `rustls` 0.23.43's own source,
  `CryptoProvider::get_default_or_install_from_crate_features`) — a future dependency enabling the
  `ring` feature anywhere in the graph would turn that `.expect()` into a runtime panic on the
  `DoH` server's startup path, silently, since nothing in this project's own code would have
  changed. `tls::build_server_config` (T-142) uses
  `ServerConfig::builder_with_provider(aws_lc_rs::default_provider())` instead, naming the provider
  explicitly so this module's correctness doesn't depend on what else the dependency graph does —
  caught by advisor review of the plan, not the first draft, which had used plain `builder()`.
- **`rcgen::CertifiedKey<KeyPair>`'s `cert`/`signing_key` fields are `pub`, not just accessible via
  destructuring inside `rcgen` itself** — confirmed by constructing a deliberately mismatched
  `CertifiedKey { cert: a.cert, signing_key: b.signing_key }` from two independently generated
  certs in a test (`tls::tests::server_config_rejects_a_mismatched_cert_and_key_pair`, T-142), a
  real negative test that a wrong DER-extraction would actually fail, not just "the happy path
  returns `Ok`."
- **`hyper::body::Incoming` can only be produced by a real `hyper` server connection reading from
  an actual socket — it can't be constructed by hand in a test.** `dispatch::serve` (T-143) is
  generic over the request body type (`B: hyper::body::Body<Data = Bytes> + Send + 'static`, with
  `B::Error: Into<Box<dyn std::error::Error + Send + Sync>>` for `Limited<B>`'s own bound)
  specifically so it can be unit-tested with a hand-built `http::Request<http_body_util::Full<Bytes>>`
  instead of needing a live TCP/TLS connection just to get an `Incoming` value; `main.rs` calls the
  same generic function with the real `Incoming` type inferred from context, never spelled out.
  Hardcoding the parameter type to `Incoming` (the first draft) would have made `serve` itself
  fundamentally untestable without a real socket, the same class of gap `listener.rs`/`tls.rs`'s
  own pure/impure splits exist to avoid.
- **`http_body_util::Limited::new(body, limit)` only bounds allocation if it wraps the body
  *before* `.collect()`, not after.** A `body: &[u8]` (or `Bytes`) parameter checked against a size
  limit *after* the caller already ran `.collect()` on the raw, unbounded body has already
  allocated the full thing — the check at that point only proves the bound was measured, not
  enforced. `dispatch::serve`'s POST path (T-143) does
  `Limited::new(req.into_body(), MAX_MESSAGE_SIZE).collect().await` — `Limited`'s own `poll_frame`
  rejects a frame that would push the running total over the limit, so the allocation itself never
  happens for an oversized body, not just the post-hoc length check SPEC.md §8.1's "ліміт розміру,
  не необмежена алокація" actually requires. Caught by advisor review of the plan before
  implementing, not by any test the first draft's shape would have passed (a test posting an
  oversized body would still have measured a correctly-rejected length either way — it's the
  allocation, not the final `Err`, that the wrong ordering fails to bound).
- **Struct-level `#[serde(default, deny_unknown_fields)]` composes fine — a missing field falls
  back to `impl Default for TheStruct`'s corresponding field, an unknown key still fails loudly —
  but per-field `#[serde(default = "...")]` needs a *function path* returning that field's type,
  not a field-access expression.** `config::ResolverConfigFile` (T-144) needed one `impl Default`
  for the whole file-shape struct (mirroring `ResolverConfig::default()`'s values field-by-field),
  not four small `default_port()`/`default_timeout_mode()`/... functions — simpler, and confirmed
  (not assumed) to still reject a typo'd key. Advisor review of the plan caught the first draft
  reaching for the per-field function-path form before there was any code to test against.
- **`hickory_proto::op::Message::query()` leaves `recursion_desired` at its default (`false`) —
  a hand-built outgoing query needs `message.metadata.recursion_desired = true;` set explicitly, or
  a strict resolver can return SERVFAIL for anything not already edge-cached, masquerading as "the
  domain doesn't resolve."** Hit building `phase1_metrics.rs` (T-66): a first run against
  `BASELINE_DOH_URL` (Cloudflare) showed 39/40 sampled domains SERVFAILing, which looked at first
  like "URLhaus's fresh malware domains are mostly already dead" — plausible on its face — until a
  debug trace showed well-known, definitely-live domains (`res.cloudinary.com`, `filedn.com`)
  failing identically. Root cause confirmed by reading `hickory-proto` 0.26.1's own
  `Header::new`/`Message::query()` source, not guessed: `recursion_desired: false` is the hardcoded
  default, and `Message::query()` never sets it. **Does not affect any shipped production code
  path** — `pipeline::resolve_via_baseline`/`quorum::resolve` always forward the *original* decoded
  incoming query object to upstreams (confirmed by reading both call sites), never construct a fresh
  `Message::query()` for an outgoing upstream call, so a real browser's own RD bit (virtually always
  `true`) always survives to Quad9/AdGuard/baseline. The existing `#[ignore]`d live-Quad9 test
  (`upstream.rs`) also doesn't set it explicitly and still passes — Quad9 evidently tolerates
  `RD=0` where Cloudflare's public resolver does not, which is itself a useful fact about the two
  services' differing behavior, not a contradiction of this gotcha.
- **`toml::de::Error`'s `Display` *and* `Debug` both render an annotated snippet of the offending
  input line** (`TOML parse error at line N, column M\n  |\nN | <the actual line>\n  |  ^\n<message>`)
  — unlike `serde_json::Error`'s generic "expected value at line N column M", which never echoes the
  input back. Confirmed empirically with a scratch probe (a malformed TOML fixture containing a
  sentinel string, `format!("{err}")`/`format!("{err:?}")`, both contained the sentinel) before
  relying on it, not assumed from the crate's docs. For any file that can contain sensitive text
  (`overrides.toml`'s domain names, this project's own "no domain names in service logs" rule) —
  wrapping this error type directly in a `thiserror` variant and logging it is an automatic leak; the
  fix is a payload-free error variant with a fixed message (`overrides::OverrideError::Parse`, T-145
  — same shape as `InvalidReason`), not redacting a field after the fact. A file that structurally
  cannot contain sensitive text (`config.rs`'s `resolver_config.toml`, no domains) can keep the real
  `toml::de::Error` payload — the rich snippet is a genuine UX win there with no privacy cost, so the
  two error types are deliberately shaped differently on purpose, not an inconsistency to "fix" into
  matching each other later.
- **General lesson (third instance of this shape — `IsCa::NoCa`, the `icacls` substring denylist,
  now this): a test that passes today doesn't prove the property its name claims unless the
  property is something the test can actually observe changing.** T-59's first draft
  (`dispatch.rs`) hardcoded a list of admin-channel paths and swept `serve()`'s behavior against it
  — this proves a *removal*/method-*narrowing* regression (delete a route, widen a 405 to 200 →
  fails) but nothing about *addition*: a new `match` arm in `serve()` that the hardcoded list never
  knew to probe sails through unnoticed. Confirmed empirically, not asserted from reading the test
  — added a throwaway unlisted `match` arm to `serve()`, reran the test, watched it stay green.
  What made the two earlier instances of this shape different from this one: `IsCa::ExplicitNoCa`
  and the `icacls` ACE-count rewrite both fixed it by asserting a stronger *observation* of the
  same already-real artifact (the cert's actual DER bytes, the real ACL readback). Here the
  property genuinely couldn't be observed from outside at all — no black-box request sequence
  proves "nothing beyond this list is routable," because "beyond this list" isn't a fact about
  behavior, it's a fact about the *source code structure* of a `match` block, which a test exercises
  by calling, never by reading. The fix had to be structural: extract `dispatch::ROUTES` (`&[(&str,
  &[Method])]`) as the actual table `serve()` dispatches from — checked *before* the
  handler-selection `match`, so a path/method pair not in `ROUTES` can never reach a handler no
  matter what arm the `match` grows — then assert that live table against an independent
  hand-written copy. Only then does "a new route was added" become a fact the test can see, because
  it's now data the test can read rather than behavior it has to infer. **When a "prove nothing
  extra is exposed" test can't be made stronger by tightening an assertion, ask whether the property
  even has an external observation point before writing the test — if it doesn't, the fix is making
  the property into data, not writing a cleverer probe.**
- **`keyring` 4.x (T-67):** the crate refuses to compile without the `v1` or `cli` feature
  (`compile_error!`), so `default-features = false` still needs `features = ["v1"]`. `v1` bundles
  the Apple/Windows/Linux store crates; the non-Windows ones are `cfg`-gated and land in
  `Cargo.lock` only (never compiled or `cargo deny`-evaluated for the windows-msvc graph target —
  same shape as the old `tauri` rows). The all-in-one `keyring::Entry` works with **no**
  `set_default_store` call. Binary secrets go through `set_secret`/`get_secret` (not
  `set_password`); delete is `delete_credential`; a missing entry is `Err(keyring::Error::NoEntry)`
  on both `get_secret` and `delete_credential` (map it to `Ok(None)`/`Ok(())` yourself — delete is
  **not** idempotent by default). All four facts confirmed by a throwaway `cargo run` probe before
  writing `key_store.rs`, per this project's verify-empirically discipline.
- **`rustls::pki_types::PrivateKeyDer::Pkcs8(k)` — the byte accessor is `k.secret_pkcs8_der()`,
  not `secret_der()`** (which only exists on the outer `PrivateKeyDer` enum). `key_store` stores
  raw PKCS#8 DER, and `migrate_legacy_key_into_store` only accepts a `PrivateKeyDer::Pkcs8` arm
  from `from_pem_slice` — this project's own `key.pem` was always PKCS#8 (`rcgen`
  `serialize_pem`), so a non-PKCS#8 legacy file is rejected (`CertError::LegacyKeyDecode`, caller
  regenerates) rather than guessed at.

## Documentation map — who owns what

| File | Owns | Update when |
|---|---|---|
| `SPEC.md` | full design + reasoning: architecture, RFC table, phased plan, open questions | a design decision changes or a new one is made |
| `UI-SPEC.md` | GUI: screen inventory, per-screen field/type tables, Tauri command allowlist draft — no rationale, links back to SPEC.md §8 by section number | a screen, field, or DTO changes; rationale changes go in SPEC.md instead |
| `diagrams/` | architecture + UI diagrams, each anchored to a SOURCES section list; ground-truth ritual in `diagrams/README.md` applies from here on | a diagrammed state/flow/DTO changes — see the ritual's trigger list |
| `CLAUDE.md` | agent-facing summary: commands, architecture at a glance, non-obvious gotchas | architecture/commands change |
| `TASKS.md` | open backlog — status only, no reasoning | a task starts or gets added |
| `TASKS-DONE.md` | completed tasks, moved out of `TASKS.md` on finish, same format + a one-line implementation note per task | a task finishes |
| `DECISIONS.md` | retroactive corrections to already-shipped decisions, with reasoning; overrides SPEC.md by date on conflict | a past decision gets revised |
| `SECURITY.md` | threat model summary, hard security constraints, dependency-vetting table | threat model changes or a dependency is added |
| `README.md` | human-facing project description | repo structure changes, or the project's phase/status badge changes |
| `CONFIGURATION.md` | operator-facing reference for both TOML config files (`resolver_config.toml`, `overrides.toml`) — fields, defaults, validation, examples | a config field is added, changed, or removed |
| `SERVICES.md` | what each binary does, how to run it, its logs and startup behavior | a binary's runtime behavior, ports, or file I/O changes |

Don't duplicate a fact across files — link to the owner instead. `SPEC.md` stays the deep source of
truth; the other files summarize or track state, they don't re-derive it.

## Development practices for this project

(Adapted from a personal cross-project practices file — see it only if a point below turns out to
need more detail than fits here.)

- **Test-first, where a unit is isolatable.** SPEC.md §8.1 already instantiates this for the
  UI↔backend boundary specifically (smoke / exploit / misuse / fuzz, four categories, not one
  "smoke" test) — the boundary itself moved from Tauri IPC to the `/admin/*` HTTP routes at
  T-149, but the four-category discipline still applies there unchanged (§8.1's own header note,
  SPEC.md §8). Apply the same discipline (write the failing test before the implementation) to
  the resolver, cache, and override-list logic too, not just the UI channel. A bug fix gets a
  regression test written first, reproducing the bug, before the fix.
- **Три Б (three safety legs) — check all three, not just "is this correct."** This project already
  embodies all three without naming them; naming them is useful as a completeness check when adding
  new logic:
  - *User safety* — does a failure mode leave the user worse off than no filtering at all, and will
    they notice? (Already why silent DoH fallback bypassing quorum is flagged as an open risk in
    SPEC.md, and why the watchdog "must **notify**, not silently self-heal.")
  - *Software safety* — is the code safe against adversarial/malformed input, provably from the line
    itself? Two concrete input boundaries in this project: DNS wire format from upstream providers
    (why `hickory-dns`, not a hand-rolled parser) and the `/admin/*` HTTP channel from the tray/
    browser UI, formerly Tauri IPC from the webview (SPEC.md §8.1's exploit/misuse/fuzz categories
    exist exactly for this leg, unchanged by the T-149 channel swap).
  - *Lower-layer safety* — every layer this project doesn't own and can't fix is untrusted: the OS
    trust store, upstream DoH providers, the GeoIP/top-sites data feeds (why atomic-replace +
    integrity check before swapping in a new file), and the browser's own DoH-fallback behavior
    (open question 10 in SPEC.md).
- **When SPEC.md is silent on a design question**, don't invent a solution silently — SPEC.md's own
  rule ("RFC over intuition or a competitor's behavior," §"Наскрізні вимоги") is the domain-specific
  version of this; for anything outside RFC's reach (UI/UX choices, non-protocol behavior), fall
  back to: (1) current industry consensus for that class of problem, (2) the API shape of an
  established, well-designed library in the same niche, (3) exposing only the safe/modern mode
  externally, never a legacy/unsafe one as a public entry point. Flag the gap and the choice made,
  don't silently pick one.
- **Any spawned system process (installer invoking `certutil`/`security`, watchdog restarting
  `dnsqb-service`) uses an absolute path, never PATH lookup** — same class of risk as an unquoted
  autostart path; PATH is attacker-influenceable input, not a trusted constant.
- **An empty/ignored `Result`/error branch (`let _ = ...`, `.ok()`, empty `Err(_) => {}`) needs a
  one-line comment saying why it's safe to ignore** — same bar as any other comment (WHY, not WHAT),
  applied to Rust's equivalent of an empty catch block.
- **Before committing, check what's actually staged** (`git status` after `git add`) — don't trust a
  filename alone to mean "no secrets in here."
- **When splitting one working tree into separate commits, `git restore --staged <file>` only
  unstages that file — everything else you `git add`ed stays staged.** Run `git diff --cached
  --stat` immediately before each `git commit` to confirm the file list actually matches that
  commit's intent.
- **Diagram ground-truth ritual** (`~/.claude/diagram-ground-truth-ritual.md`) — now in effect,
  copied into `diagrams/README.md` once the first diagrams (`ui-*.md`) landed. Check the SOURCES
  block of any diagram you touch, and run the sync checklist before calling doc changes done.
- **Security-ops practices** (`~/.claude/security-ops-practices.md`, alert triage / log
  investigation) apply once `dnsqb-service` is a running system with logs/telemetry to investigate —
  not relevant pre-implementation.

## What this project is

A cross-platform local DoH (DNS-over-HTTPS) server that the browser is pointed at via its built-in
"Custom DoH provider" setting. It fans out each query in parallel to several public filtering DNS
providers (Quad9, AdGuard, Cloudflare, etc.) and blocks a domain if **any one** of them says block
(OR-logic quorum). This is a DNS-level filter, not a uBlock-style cosmetic/element blocker — scope
is deliberately limited to malware/phishing/ads/adult filtering at domain-resolution level.

Two rejected alternative designs, and why (see SPEC.md §"Чому саме такий дизайн"):
- Browser extension with live blocking: Manifest V3 `declarativeNetRequest` can't synchronously
  block a request on an async DoH lookup result; only Firefox still allows blocking `webRequest`.
- System-wide DNS override (`127.0.0.1:53`): no reliable cross-platform crash-recovery guarantee,
  especially on Windows (no OS-level rollback primitive equivalent to macOS's Network Extension).

## Planned stack

Rust workspace, `#![forbid(unsafe_code)]` everywhere it's possible. Explicit reasons for each
crate are in SPEC.md §"Технічний стек" — don't substitute an alternative without checking that
section first (e.g. `hickory-dns` is chosen specifically to avoid hand-rolling a DNS wire-format
parser, `moka` specifically for its per-entry TTL `Expiry` trait, `rustls` to avoid a system
OpenSSL dependency).

| Component | Crate |
|---|---|
| Async runtime | `tokio` |
| DNS wire format | `hickory-dns` |
| DoH server | `hyper` |
| Upstream HTTP client | `reqwest` |
| TLS | `rustls` |
| Cache | `moka` (per-entry TTL) |
| GeoIP reader | `maxminddb` |
| UI | Tray icon (`tray-icon`/`tao`/`rfd`) + browser-based config page served by `dnsqb-service` |
| Fuzz/property tests | `proptest` |

## Architecture (from SPEC.md)

Two long-running processes:
- **`dnsqb-service`** — the DoH server + quorum resolver. Listens **only** on `127.0.0.1`, never
  `0.0.0.0`. Fixed, configurable port (no silent fallback to another port on conflict).
- **`dnsqb-watcher`** — minimal watchdog process, mutual-heartbeat with the service over 3
  independent channels (IPC socket, shared heartbeat file, HTTP `/health`), majority/unanimous
  voting to avoid a false-positive restart loop (SPEC.md §7).

### Request pipeline (fixed order — see SPEC.md §5.3 for the authoritative, most-recently-corrected version)

```
1. Allowlist        → ALLOW, nothing below is consulted
2. Blocklist        → BLOCK
3. ccTLD block (5.2)→ BLOCK on domain-suffix match, no network call
4. Cache            → cached quorum verdict, if present
5. Rating filter (5.3, opt-in) → BLOCK if domain outside allowed zones (only blocks, never force-ALLOWs)
6. Voter scope (5.1)→ top-N-per-country domains get Security-tier voters only (5.1.1: a personal
                       locally-learned frequent/daily-visit list is a second, opt-in, default-off
                       source for the same exemption, Фаза 4+, T-138); others get all enabled categories
7. Quorum           → query the resolved voter set, OR-logic
8. GeoIP (3.5)      → applied live to cached or fresh ALLOW responses, never cached itself
```

This pipeline has been revised twice in SPEC.md (top-sites handling moved from a bypass mechanism
to a voter-scope exemption in §5.1; the rating filter's position moved from step 0 to a late local
step in §5.3) — when in doubt about ordering, treat the pipeline diagram in §5.3 as current and the
earlier ones in §3.5/§5 as superseded context, not conflicting truth.

### Key non-obvious decisions worth knowing before touching related code

- **Local TLS cert is a single self-signed leaf on `127.0.0.1`, never a local CA** (SPEC.md §2).
  This is called out as the single largest attack surface in the project — a compromised CA key
  enables MITM of arbitrary domains, a compromised leaf key only enables spoofing localhost. Do not
  "simplify" this to a CA-based setup.
- **Block response is `0.0.0.0`/`::` (NULL blocking), never NXDOMAIN** for A/AAAA (SPEC.md §3.2) —
  NXDOMAIN causes some browsers to fall back to a different resolver, silently bypassing the
  filter. Non-A/AAAA types (MX, TXT, HTTPS/SVCB) get NODATA instead.
- **HTTPS/SVCB records bypass quorum entirely**, proxied to a single upstream (SPEC.md §3) —
  Firefox uses HTTPS RR for ECH keys; quorum logic on this type silently disables ECH.
  is_blocked() only applies to A/AAAA.
- **Empty voter set is explicit pass-through, not fail-closed** (SPEC.md §3, §8.1) — if the user
  disables every provider, resolution goes through the unfiltered baseline resolver, and the UI
  must show this as a distinct state, not as a degraded/failure state.
- **GeoIP verdict is never cached alongside the quorum verdict** — it's a cheap local mmap lookup
  applied live on every read (cached or fresh) so a change to the blocked-country list takes effect
  immediately without cache invalidation logic (SPEC.md §3.5).
- **Rating filter (§5.3) can only BLOCK, never force-ALLOW.** A domain inside the allowed zones
  just continues through the normal pipeline (voter scope → quorum → GeoIP) rather than skipping
  it. This is a common implementation mistake per the spec's own regression-test note.
- Timeout handling is one of three configurable modes — `fail-open` (default), `fail-closed`,
  `degraded` — not a single hardcoded policy (SPEC.md §3.3).
- Default upstream preset on first run is **Security category only** (Quad9 Filtered + Cloudflare
  Malware); Ads/Adult are opt-in category toggles, not enabled by default.

### RFC conformance is step 0 of implementation

SPEC.md's phased plan mandates writing the RFC-conformance test table (§"Фазований план", Крок 0)
*before* any resolver code — one row per RFC requirement, with a failing test written before the
implementation that satisfies it. When implementing DNS wire-format, TTL, or negative-caching
behavior, check this table first; default to the cited RFC's behavior over intuition or copying
Pi-hole/AdGuard Home behavior (this is a stated cross-cutting principle, SPEC.md §"Наскрізні
вимоги").

### Privacy constraints that affect design choices throughout

- Domain names are **in-memory ring buffer only** by default (query log) — disk persistence is
  opt-in and must be encrypted via platform secure storage.
- Diagnostic/service logs (errors, timeouts) must never contain domain names.
- Fanning a query out to N upstream providers is a deliberate privacy/coverage tradeoff (more
  third parties see uncached browsing history, in exchange for better threat coverage) — this must
  stay user-visible in the UI, not buried.

## Current phase boundaries

Phase 1 (PoC) scope is explicitly minimal: 1 platform, 2 upstreams (Quad9 + AdGuard), manually
installed cert, override lists + in-memory log — but **no watchdog** (manual restart is acceptable
at PoC stage; §"Фазований план" explicitly defers `dnsqb-watcher` to Phase 3). Don't build ahead of
the current phase's scope without checking whether SPEC.md has already placed that feature in a
later phase for a stated reason (e.g. GeoIP and top-site voter exemption are deliberately deferred
past Phase 1 because they're independent of the core quorum hypothesis being validated first).
