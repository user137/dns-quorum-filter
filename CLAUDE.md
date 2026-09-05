# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

**Phase:** Фаза 2 (cert automation, Windows) **formally closed 2026-08-31** (SPEC.md §"Фазований
план" / TASKS.md §"Фаза 2"). **Фаза 3 (production hardening — `dnsqb-watcher`, MSIX packaging)
is next — a 9-batch execution plan (3.0–3.8) is in TASKS.md §"Фаза 3" ("План виконання Ф3",
2026-09-01). **T-101 done 2026-09-01** (pulled forward from Батч 3.7): `.github/workflows/
codeql.yml` — CodeQL SAST, `rust` / `build-mode: none` / `windows-latest`, on every push/PR;
alerts in the Security tab, triaged like clippy/audit findings (see the Commands section for the
`gh` read command).
**Батчі 3.0–3.3 done 2026-09-02 — watchdog complete, demonstrated end-to-end.** 3.0: SPEC.md §7.1
(9 реалізаційні рішення) + `diagrams/watchdog-{state,channels}.md`. 3.1: liveness primitives
(`instance` guard/pid, `frame`/`channel`, `pipe`, `heartbeat_file`, `GET /health`). 3.2: pure
decision core (`vote`, `backoff`, `budget`, `pid_check`, `spawn`, `state`, `transition`). 3.3:
assembly — `watchdog::loop_driver` (pure per-direction tick automaton, loop-level T-93/T-94),
`watchdog::launcher` (T-150 `plan_launch`), the three `dnsqb-service` heartbeat tasks +
`service→watcher` loop, `dnsqb-watcher`'s real `main` (idempotent launcher + `watcher→service`
loop, sole writer of `watchdog-state.json`), and T-95 (`/admin/status.watchdog` + tray).
**Батч 3.4 done 2026-09-03** (T-154/T-155/T-152, 8 commits, plan+advisor): T-154(a)
`connect_timeout` on `ReqwestDohClient` (probe-proven: `reqwest` 0.13 skips a blackholed first
resolved address without it) + T-154(b) `baseline_selector` (sticky Cloudflare→Quad9→Google
failover with auto-return, driven by the reachability prober's per-cycle `DoH` health check);
T-155 `DecisionSource::BaselineFallback` + `serve_baseline_when_filters_unreachable` toggle
(default OFF — DECISIONS.md 2026-09-03: OFF = today's behaviour, better-labelled, zero regress);
T-152 `reachability` module (3 independent `generate_204` markers, Offline only if all fail) +
offline fast path in `handle_query` (instant SERVFAIL, no fan-out/cache) + status-indicator
condition #3. Per-batch narrative → TASKS-DONE.md.
**Батч 3.5 — T-146 + T-96 done 2026-09-03** (7 code + 1 docs commit, plan+advisor): opt-in
encrypted persistence of the query log. `encrypted_file` (`XChaCha20Poly1305`, RustCrypto —
user decision, DECISIONS.md 2026-09-03), 32-byte key in the OS secret store (`key_store`, the
T-67 mechanism), `query-log.enc` format, `persist_query_log` config flag (**no admin toggle** —
hand-edit only), passive `/admin/ui` indicator.
**T-97 done 2026-09-03** (5 code + 1 docs commit, plan+advisor kickoff+closing): opt-in
encrypted persistence of the verdict cache. Same `encrypted_file` / `FileKind::Cache` / single
`persistence-key` as the log; `cache_persist_dto` stores an **absolute wall-clock deadline** (the
live `expires_at` is a monotonic `Instant` that resets on reboot) and drops an entry whose TTL
elapsed during downtime; **only `Verdict::Allow` is persisted** — `Block` is filtered at snapshot
(user decision: a `fail_closed` timeout-`Block` must not survive a restart / the watchdog's
auto-restart). `persist_cache` config flag (no admin route), `AdminStatusResponse.encrypted_persistence
{ query_log, cache }` (replaced the bare `query_log_persisted` bool — kept `AdminStatusResponse`
under `clippy::struct_excessive_bools`), passive `/admin/ui` line.
**Батч 3.6 (T-98 + T-99) done 2026-09-04, docs-only.** T-98 (research): Chrome DoH
enterprise-policy mechanism verified against the Chromium `policy_definitions` YAML —
`DnsOverHttpsMode` enum `off/automatic/secure` (Chrome 78+, `secure` = no silent native-resolver
fallback, `dynamic_refresh:true`), `DnsOverHttpsTemplates` (Chrome 80+, mandatory-non-empty under
`secure`, `{?dns}`⇒GET, a malformed template is silently ignored), registry
`HKLM\SOFTWARE\Policies\Google\Chrome` `REG_SZ`. Tiered write-up in SPEC.md §"Відкриті питання"
п.3. Gotcha: `chromeenterprise.google/policies/*` is a JS SPA (WebFetch sees only the shell) —
fetch the raw `chromium.googlesource.com/.../policy_definitions/*.yaml` instead. **T-99 closed
with no code** (kickoff AskUserQuestion, T-164 format): `secure` makes all Chrome resolution
hard-fail when `dnsqb-service` is down (Три Б user-safety), `HKLM\...\Policies` needs admin +
is machine-global (conflicts with "no persistent elevated privileges"), Chrome-only — same
conclusion T-134 reached for Firefox. Mechanism documented for a possible future phase, not
built. **Батч 3.7 (T-100/T-102/T-103) done 2026-09-04, CI-only** (plan+advisor). T-100:
`--locked` on every CI `cargo`; `.cargo/config.toml` `/Brepro` (MSVC triple only) +
`[profile.release] codegen-units = 1` (default 16 built `dnsqb-service` non-deterministically);
blocking `repro` job = two clean `--release` builds in **different absolute paths**, SHA-256
compared. T-102: `.github/workflows/release.yml` builds + signs the 3 binaries — **ephemeral
self-signed `test-signed`** by default (real cert optional via `CODESIGN_PFX` secret; production
trust = Microsoft Store re-signing the MSIX at publication, Батч 3.8); artifact name carries the
mode. T-103: `v*` tag → re-proves cross-path reproducibility → **draft** GitHub release with the
3 `.exe` + `SHA256SUMS`, published by a human. Also: `Swatinem/rust-cache` on the cargo jobs
(**not** `repro`/release — they must clean-build), `concurrency: cancel-in-progress` on all 3
workflows, `ci.yml`/`codeql.yml` `push: branches: ['**']` (not tags) + `paths-ignore` for
`**/*.md`/`diagrams/**`/`mockups/**` (a docs-only commit, and any tag push, triggers neither —
`release.yml` owns the tag path). **Version bumped `0.1.0` → `0.2.0`; `v0.2.0` tagged →
`release.yml` produced a DRAFT GitHub release (test-signed binaries + `SHA256SUMS`), left for a
human to publish.**
**Батч 3.8 (T-156 MSIX + T-70 local-state removal) done 2026-09-04 — Фаза 3 formally closed**
(plan+advisor kickoff+closing). T-156: `packaging/AppxManifest.template.xml` (sideload
placeholder identity, kickoff decision; `runFullTrust`; entry point + `windows.startupTask` both
`dnsqb-watcher.exe`, T-150's idempotent launcher) + `packaging/pack-msix.ps1` (stages binaries +
`assets/icon/`'s 3 MSIX PNGs + substituted manifest → `makeappx pack` → `signtool sign`, same
ephemeral-or-`CODESIGN_PFX` model as T-102, `Subject` = `-Publisher` exactly or signing fails) +
`release.yml`'s new `msix` job (attaches `.msix`+`.cer` to the tag draft release alongside the
raw `.exe`s). Verified empirically end-to-end on this machine (Windows SDK 10.0.26100.0, same as
CI) — pack+sign works against real `--release` binaries; **confirmed, not assumed:
`Cert:\CurrentUser\TrustedPeople` is NOT enough for `Add-AppxPackage` (`0x800B0109`) — needs
`Cert:\LocalMachine\Root`/`\TrustedPeople`, both requiring elevation.** T-70:
`local_state::remove_all` (new module) — MSIX has no uninstall-time code hook at all, so clearing
the trusted cert + 3 Credential Manager secrets is an in-app action (tray "Повністю видалити" +
`/admin/ui` danger-zone card + `POST /admin/uninstall-local-state`), per-artifact report
(`Removed`/`NotPresent`/`Failed`), never one collapsed bool. Also: `assets/gen-icon.py` +
`assets/icon/` — one drawing source for the app icon everywhere (MSIX tile, README wordmark, a
future Store listing/Linux icon), user-revised mid-batch from a low-contrast navy/cyan/white
funnel to a two-tone (Windows accent blue + white) wireframe hexagon with vertex dots.
**T-167 done 2026-09-04** (plan+advisor, 3 commits, TASKS-DONE.md): README rewritten for a lay
reader (build/run steps taken through to a browser-DoH-config step, honestly capped at the
still-unverified live browser→DoH pass; a new "Як працює фільтрація" section with the 8-step
SPEC.md §5.3 pipeline + a lightweight `mermaid` flowchart, embedded directly rather than as a
`diagrams/` file since it's a lay illustration, not a synced dev artifact); SECURITY.md's
dependency table compressed to a current-state snapshot (57065→19099 chars, ~66%, same
principle as this file's own Project State compression — every row's why-this-crate/`unsafe`-
location/accepted-risk fact checked to survive, none dropped). **T-168 done 2026-09-05**
(plan+advisor, 3 docs commits): `PERFORMANCE.md` (new) — critical-path complexity table +
`examples/load_test.rs` (new manual harness, not CI) run showing degradation is **smooth and
linear, zero failures** up to 3000 concurrent fresh connections / 2000 multiplexed streams;
`overrides::decision`'s O(n) at ~10k entries is +17% p50, not a risk. Design decision in
SPEC.md §1.1: bounded concurrency with **immediate reject** (not a deep queue), a generous
backstop sized from server-side numbers. **T-169 done 2026-09-05** (plan+advisor kickoff+closing,
5 commits): new `admission::ConnectionGate` (`tokio::sync::Semaphore` + `AtomicU64`, no
`Mutex`/`Arc<Mutex>`) — `main.rs`'s accept loop takes an `OwnedSemaphorePermit` before
`tokio::spawn`, and at the ceiling closes the TCP stream **before TLS** (`drop(stream)`, the
kickoff-AskUserQuestion decision). Paired with `tokio::time::timeout` around `acceptor.accept` +
`auto::Builder` http1 `header_read_timeout` / http2 keep-alive (a bare cap without those is
itself a slow-loris DoS). New `[limits]` table in `resolver_config.toml`
(`max_concurrent_connections` def 4096, `handshake_timeout_ms` 10000, `idle_timeout_ms` 30000;
`0` or `> 1_000_000` is a fatal load error). `AdminStats.rejected_connections` (cumulative) +
`active_connections` (live snapshot) on `GET /admin/status`. `[limits]` is not admin-mutable and
`apply_admin_reset` does **not** rebuild the gate — a `[limits]` change needs a service restart
(like `port`).
**Next** — Batches 3.9 + 3.10 close Phase 3 completely (plan in TASKS.md §"Фаза 3", "План
фінального закриття Ф3"): **3.9** = the three carried-forward Ф1 gates as honest verification, not
new features (T-170 `DEFAULT_PROVIDER_IDS` decision + change, T-171 re-measure T-66 quorum
coverage on a bigger sample, T-172 live "browser → local DoH" pass); **3.10** = T-173 version bump
`0.2.0` → `0.3.0` + `v0.3.0` tag → the existing `release.yml` produces a draft MSIX release for a
human to publish. T-51 / T-56 stay carried-forward backlog (blocked on out-of-MVP T-132 / T-134),
not part of the Phase 3 close.
Фаза 1 formally closed 2026-08-29; Крок 0 (Rust workspace, CI, RFC-conformance table T-1–T-19) done.
Target platform is Windows (DECISIONS.md, 2026-08-25 — SPEC.md left it open); macOS/Linux are
Фаза 6.

Carried into Фаза 3, not lost on the Ф2 close: **T-70** (packaged uninstaller must call
`trust_store::uninstall()` + `key_store::delete_secret`, blocked on T-156 MSIX packaging); the
**Ф1 metrics gate** — **metrics half closed T-171** (2026-09-05): re-measured on n=122 with the
T-170 default set, quorum gain over the best single provider (Quad9) was +1 domain / +0.8 pp —
hypothesis not confirmed, recorded, raised as a Ф4+ design question (DECISIONS.md, PERFORMANCE.md
"Quorum coverage"). **Verdict is provisional**: a same-day all-10-presets follow-up run found
`cleanbrowsing-{security,adult}` block via NXDOMAIN but are declared `NullIp` in `BUILTIN_PRESETS`
(66/124 NXDOMAIN, 18 Quad9 missed) → their blocks are uncounted; **T-174** fixes the signature
and re-measures. The live "browser → local DoH" pass is T-172.
**`DEFAULT_PROVIDER_IDS` decided in T-170** (2026-09-05,
DECISIONS.md): `quad9` + `cloudflare-malware` + `adguard` — the two §3.4/§3.5 Security-tier
voters plus AdGuard for ads out of the box.

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
rating filter, voter scope — are later phases, not built. Since Батч 3.3, `main.rs` also starts
three detached `#[cfg(windows)]` watchdog tasks (heartbeat pipe server, `service.hb` touch, the
in-memory `service→watcher` decision loop — §7.1 #7: it acts and logs but never persists, so that
direction's `GaveUp` is **not durable** — the restart budget resets on every service restart, a
symmetric un-fixable-without-§7.1-#7-violation counterpart to the watcher→service `restored` path).
Modules under `crates/dnsqb-service/src/`:

| Module | Responsibility |
|---|---|
| `admission` | T-169 — `ConnectionGate` (bounded-concurrency backstop, SPEC.md §1.1): `tokio::sync::Semaphore` (lock-free permits) + `AtomicU64` reject count, **no** `Mutex`/`Arc<Mutex>`. `try_admit() -> Option<OwnedSemaphorePermit>` (owned so it survives `tokio::spawn`; releases on `Drop`), `rejected_count()` (cumulative), `active()` (max − available, live). Lives on `AppState` (`connection_gate()`); `main.rs`'s accept loop calls `try_admit` before each `tokio::spawn`, `drop(stream)` (TCP-close before TLS) at the ceiling; `live_stats` reads both counters into `AdminStats` |
| `pipeline` | `handle_query` request flow (takes `UpstreamContext { timeout, baseline_url, serve_baseline_fallback, reachability }` — T-154/T-155/T-152 bundle); `invalidate_changed` (cache eviction on override-list reload). Offline (T-152) → `offline_servfail_with_meta` before cache read (instant SERVFAIL, no fan-out/cache, mode-independent). `outcome.filters_unreachable` (T-155) → `filters_unreachable_outcome` → `DecisionSource::BaselineFallback` (toggle on = baseline answer mode-invariant; off = mode's own verdict, relabelled), never cached |
| `quorum` | OR-logic `resolve(&[ProviderEntry], baseline_url)` over a runtime voter list (T-72/T-73, T-154); `evaluate(BlockSignature)` (3 heuristics: `NullIp` / `NxdomainVsBaseline` / `NullIpOrNxdomain`); early-return via `FuturesUnordered`; `VoterRecord { provider_id: String, .. }` / `VoterVerdict`. `QuorumOutcome` carries `filters_unreachable: bool` (every enabled voter `!Responded` — computed in `finalize_outcome` + early-block from raw `VoterOutcome`s, can coexist with a `Block`) and `baseline_answer: Option<Message>` |
| `baseline_selector` | T-154(b) pure: `BASELINE_CHAIN` (Cloudflare Unfiltered → Quad9 Unsecured → Google, §3.4); `BaselineSelector` — sticky failover after `SWITCH_THRESHOLD`=3 consecutive full failures, `should_retry_primary` + `RETRY_PRIMARY_AFTER`=300s auto-return with hysteresis; `record(now, url_used, BaselineHealth) -> Option<BaselineEvent>`. Reader = hot path (`current()`); writer = the reachability prober |
| `reachability` | T-152: `MARKERS` (3 independent `generate_204`-class — Google/Cloudflare/Apple); `verdict_from_probe_results` (raw Offline iff all fail), private `OfflineDebounce` — publishes `Offline` only after `OFFLINE_CONFIRM_CYCLES`=3 consecutive all-fail cycles (entry hysteresis; recovery not debounced), `next_probe_delay(previous, raw)` (idle 30s only when both Online, else recheck 3s — so a building outage still probes fast); `run_reachability_prober` (own `reqwest::Client`, publishes `NetworkReachability` on `AppState`, **also** drives `baseline_selector` via one real `DoH` sentinel probe per raw-Online cycle — a continuous heartbeat to the active baseline, acknowledged in the module-doc privacy note). Not wired into `/health` or watchdog channels |
| `cache` | `moka` per-entry-TTL cache; `CacheConfig`, `clamp_ttl`, `chain_cache_ttl`, `is_cacheable`, `invalidate_matching`, `clear`; T-97 added `snapshot()` (sync `moka::future::Cache::iter()`, best-effort) / `restore()` and `CacheKey::domain()`/`qtype()` accessors for `cache.enc` |
| `overrides` | allowlist/blocklist `load`/`save`/`decision`/`conflicts`; suffix-wildcard match; `InvalidEntry` (domain-redacting) |
| `upstream` | `ProviderSpec` / `ProviderEntry` / `Category` / `BlockSignature` + `BUILTIN_PRESETS` table (§3.4, T-72/T-73) + `builtin_preset` / `all_builtin_presets` / `validate_provider_url` (SSRF: `https` + non-loopback/private/link-local literal host) / `is_valid_provider_id`; `DohClient` trait + `ReqwestDohClient` (per-upstream HTTP/2 keep-alive + `connect_timeout` 500ms — T-154(a), restores multi-A failover for a blackholed address) |
| `timeout` | `TimeoutMode` (fail-open / fail-closed / degraded); `query_with_timeout` |
| `wire` | DoH wire codec; block (`0.0.0.0`/`::`) / NODATA / SERVFAIL / direct-answer construction; AD-bit passthrough |
| `query_log` | in-memory ring buffer (`parking_lot::RwLock`); `LogEntry`, `DecisionSource` (6 producible: +`BaselineFallback` T-155 — the one variant whose `voters` is **not** empty), `LogFilter` search, `clear`; `restore(entries, now)` (T-146 — seeds from `query-log.enc`, re-applies both the 1000/24h bounds) |
| `config` | `ResolverConfig` (TOML); `[providers]` / `[cache]` / `[geoip]` / `[limits]` (T-169 — `LimitsConfig`: `max_concurrent_connections` + `handshake_timeout_ms` + `idle_timeout_ms`, `Copy`, live type holds `Duration`s, `0`/`>1_000_000` = fatal load error) tables + `serve_baseline_when_filters_unreachable` bool (T-155, default `false`) + `persist_query_log` (T-146) + `persist_cache` (T-97) bools (default `false`, **no admin route** — each carried through every rewrite via `PersistTarget` cross-field-read); per-field validation, loud errors |
| `encrypted_file` | T-146 pure AEAD codec: `seal`/`open` over `XChaCha20Poly1305`; 6-byte cleartext header (`DQF1` / `FileKind` / version) is the AAD, validated **before** the AEAD open (`UnsupportedVersion` distinct from `Decrypt`); `EncryptedFileError` payload-free |
| `persist_dto` | T-146 serde mirrors of `LogEntry` (`SystemTime`↔u64 millis, `RecordType`↔u16, `error_kind` `&'static str` re-interned through a closed set); `PersistedFileV1` wrapper (struct, additive); `to_json`/`from_json` |
| `log_persist` | T-146: `persist_snapshot` (serialize→seal→`write_atomic`, testable core); `load_persisted_query_log` (startup — mint/read key, decrypt, seed; missing-key-with-file / corrupt → rename `.orphaned-<ts>` + empty, never overwrite); `run_query_log_persister` (60s + shutdown flush, thin impure shell). `paths::write_atomic` = temp + `sync_all` + `fs::rename` (Windows atomic-replace, scratch-probed). `rename_orphan` is `pub(crate)`, reused by `cache_persist` |
| `cache_persist_dto` | T-97 serde form of the verdict cache. `PersistedCacheEntry { domain, qtype: u16, expiry_millis: u64, verdict: PCacheVerdict }` — `expiry_millis` is an **absolute wall-clock** deadline (the live `CacheEntry.expires_at` is a monotonic `Instant`, unserialisable); `to_json(snapshot, now_wall, now_mono)` filters `Verdict::Block` + non-fresh + converts `Instant`→wall (clocks injected for tests); `from_json(plaintext, now_wall)` drops any entry whose deadline already passed. `PCacheVerdict` keeps `Block` representable (format-stable) though `to_json` never emits it. `IpAddr` kept un-mirrored (has its own serde impl) |
| `cache_persist` | T-97, sibling of `log_persist`: `persist_cache_snapshot` (→`seal(FileKind::Cache)`→`write_atomic`), `load_persisted_cache` (→`CacheInit { restore, flusher }`; independent `ciphertext_present` for `cache.enc`, shared `persistence-key`), `run_cache_persister` (60s + shutdown). `AppState::cache_snapshot`/`restore_cache` pass-throughs (lock dropped before `.await`) |
| `cert` / `paths` / `trust_store` / `cert_rotation` / `key_store` | self-signed leaf cert generation (T-48); `cert.pem` on disk, private key in the OS secret store via `key_store` (T-67 — Windows Credential Manager through `keyring`; entry name = `dns-quorum-filter`/`doh-tls-private-key:<sha1(app-data dir)[..8]>` so a scratch instance never collides). `key_store` now holds **three** secrets — +`persistence-key:<hash>` (T-146, `load_or_create_persistence_key` — 32-byte `XChaCha20Poly1305` key; **one** key seals **both** `query-log.enc` (T-146) and `cache.enc` (T-97), `FileKind` in the AAD keeps them distinct; `getrandom` failure → `KeyStoreError::Rng`, no fallback; a stored key that isn't 32 bytes → `MalformedKey`; `orphaned_ciphertext` flag when a file exists but no key does — the "created exactly once" invariant rests on `instance::acquire`). `paths::write_atomic` (T-146) lives here too; `cert::migrate_legacy_key_into_store` copies a pre-T-67 plaintext `key.pem` into the store once, and `discard_legacy_key_file` zero-and-unlinks it **only after** `tls` proves the stored key loads against `cert.pem` (so a mismatched plaintext key is never destroyed first); the T-50 `icacls` ACL helpers were removed in T-163 (nothing writes a plaintext secret to disk any more); `CurrentUser\Root` trust-store install/uninstall (T-49); `cert_rotation::rotate_certificate` (T-69) = ordered composition generate → `uninstall` (CN-exhaustive) → persist → `ensure_installed`, no new primitive, clear-before-persist forced by the shared CN, tray-only, needs a manual `dnsqb-service` restart to take effect |
| `tls` | `load_or_generate_server_config` (runs the one-time `key.pem` migration, then loads `cert.pem` + the stored key, else regenerates — `CertOrigin::{Loaded,GeneratedFirstRun,Replaced}`) → `rustls::ServerConfig` (always `builder_with_provider(aws_lc_rs::default_provider())`) |
| `local_state` | T-70 (Батч 3.8): `remove_all(app_data_dir: Option<&Path>) -> UninstallReport` — the in-app "prepare for removal" MSIX needs (no uninstall-time code hook). Calls `trust_store::uninstall()` + `key_store::delete_secret` for all 3 keyring entries; each of the 4 artifacts reports independently (`ArtifactOutcome::{Removed,NotPresent,Failed(&'static str)}`), never one collapsed bool. `remove_all`/its private `remove_cert` are **deliberately untested** — `remove_cert` always runs the real `trust_store::uninstall()` (a `CurrentUser\Root` sweep), the same real-external-resource line `trust_store`'s and `cert_rotation`'s own tests refuse to cross; `remove_secret` (the real Removed/NotPresent/Failed decision) is tested directly instead |
| `listener` | `bind_listener` / `BindError`; `127.0.0.1`-only; explicit error on port conflict, never a silent fallback |
| `dispatch` | route table (`ROUTES`), `serve` (generic over body type for testability), `resolve_doh_request`, `AppState<C>` (holds `in_flight: AtomicU64` **and** `gate: ConnectionGate`, T-169 — `live_stats` fills `AdminStats.{in_flight, rejected_connections, active_connections}` from both); `serve_health` (`GET /health`, T-86 — runs the local pipeline prefix for a sentinel domain, no upstream call); `read_watchdog_view(paths, now)` (T-95 — reads `watchdog-state.json`, projects to `Option<WatchdogStatusView>`, stale/absent/internal-state → `None`, `now` injectable) fills `AdminStatusResponse.watchdog` |
| `admin` / `admin_ui` | `/admin/*` JSON DTOs + `AdminClient` (incl. `AdminClient::health()` → `HealthResponse`); `WatchdogStatusView` (T-95: `RESTARTING` [incl. `BackoffWait`] / `GAVE_UP`, a 2-variant UI projection of the 7-variant `WatchdogState`, narrower than §7.1 #7 by design); embedded browser config page (`include_str!` HTML/CSS/JS, strict CSP, no `unsafe-inline`) |
| `watchdog/` (SPEC.md §7 — Батчі 3.1–3.3) | **Primitives (3.1):** `instance` (T-92: `Role` ∈ service/watcher/tray, `acquire` → `share_mode(0)` `<role>.lock` guard, `write_pid_file`/`read_pid_file`); `frame`/`channel` (T-84 pure: 20-byte `Frame`; `channel_status(misses)` → `Signal\|NoSignal` at `MISS_THRESHOLD`=3, no `Dead`); `pipe` (T-84 `#[cfg(windows)]` named-pipe; server `respond_once` + `recreate`, client `ping`); `heartbeat_file` (T-85: `touch`/`read` + pure `is_stale(now, mtime, threshold)`). **Decision core (3.2):** `vote` (T-87/T-88: two fixed-arity fns, never a slice — `vote_watcher_checks_service` 2-of-3, `vote_service_checks_watcher` unanimous → `Liveness`); `backoff` (T-90: `next_backoff` over `[1,2,4,8,16]s`, cap 16); `budget` (T-91: `RestartBudget::register_attempt(now)` → `{Allowed,GaveUp}`, 5/600s rolling per-target; `::restored(window, attempts)` from persisted fields — a watcher restart doesn't reset the count); `pid_check` (T-89: `verify_pid_alive(pid, expected_exe)` → `{Alive,Gone,IdentityMismatch}` via `sysinfo`, PID **+** exe identity); `spawn` (pure `resolve_sibling_path` rejects non-absolute; thin `spawn_sibling` → `NotFound`, never PATH/CWD; no `kill`); `state` (`WatchdogState` 7-variant + `WatchdogTarget` 2-variant + `WatchdogStateFile` §7.1 #7 + atomic `write`/`read`; `last_error: Option<WatchdogErrorLabel>` closed enum); `transition` (pure total automaton step, returns next state only). **Assembly (3.3):** `loop_driver` (pure `LoopDriver::{new,restored}` + `tick(now, &ChannelObs) -> TickOutcome{state, effects: Vec<Effect>}` — owns miss counters / `RestartBudget` / backoff deadline / spawn-once latch; `Direction::{WatcherToService, ServiceToWatcher}` a param; loop-level T-93/T-94 tests here); `launcher` (pure `plan_launch(Option<&PidFile>, Option<PidCheck>) -> {AlreadyRunning, Spawn}` — T-150 idempotency). The running I/O shells live in the two `main.rs` (`#[cfg(windows)]`, untested by the `dnsqb-service` main precedent). |
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
`/admin/config` — which carries `timeout_mode` + `serve_baseline_when_filters_unreachable` (T-155)),
`/admin/log[/clear]`; `POST /admin/uninstall-local-state` (T-70 — no body fields, never touches
`resolver_config.toml`);
`GET /admin/ui`, `/admin/ui/main.js`, `/admin/ui/style.css`. Also on the same listener but
**not** an admin route: `GET /health` (T-86, watchdog channel 3 — no CSRF gate, read-only,
`HealthResponse { active_providers, geoip }`; the 200 itself is the health signal). The MaxMind
creds are their own OS secret-store entry with a single writer (that one POST route), not part of
`resolver_config.toml` — no shared lock.
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
is unaffected). Also takes the `Tray` single-instance guard + writes `tray.pid` on startup
(T-150 — the watcher's launcher needs a `tray.pid` to detect it; a second instance exits
quietly). Replaced the deleted Tauri `dnsqb-ui` (T-149, DECISIONS.md). Tooltip states:
`Unreachable` / `ServiceRestarting` / `ServiceGaveUp` (T-95 — read from `watchdog-state.json` via
`status::watchdog_override`, checked **before** `/admin/status`, ranked above `NoActiveProvider` —
DECISIONS.md 2026-09-02) / `Offline` (T-152 — `from_response` returns it before `NoActiveProvider`
when `AdminStatusResponse.network == OFFLINE`; ranked below the watchdog states, above 0-voters —
DECISIONS.md 2026-09-03) / `NoActiveProvider` / `Filtering`; `Filtering` appends a degraded-upstream
suffix when `AdminStats.degraded_events > 0` (raw counts over the last 20 `QUORUM`/`BASELINE_FALLBACK`
log entries — T-56, narrowed; T-155 added `BASELINE_FALLBACK`).

`dnsqb-watcher` — the watchdog process (SPEC.md §7), real `main` since Батч 3.3.
`#[tokio::main(flavor = "current_thread")]` (§7.1 #9 — flavor, not features, keeps it
single-threaded: the `dnsqb-service` lib dep unifies `rt-multi-thread` in regardless). Startup:
`Watcher` guard + `watcher.pid`; **idempotent launcher (T-150)** — `ensure_sibling_running` for
`dnsqb-service` and `dnsqb-tray`, once, via `plan_launch` + `verify_pid_alive` + `spawn_sibling`
(tray is launcher-scope, never heartbeat-monitored). Then the `watcher→service` loop (5s tick:
IPC ping/pong channel 1, `service.hb`/`watcher.hb` channel 2, `GET /health` via cert-pinned
`AdminClient` channel 3; `LoopDriver` 2-of-3 vote; `spawn_sibling(Service)` on a confirmed-dead
service; **sole writer** of `watchdog-state.json`, rewritten every tick for `mtime` freshness).
`resume`s a <90s-old state file via `LoopDriver::restored`. Depends on `dnsqb-service` as a lib
(§7.1 #6).

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

**The GeoIP workstream (T-74–T-82) is complete.** Фаза 2 as a whole is **closed 2026-08-31** (see
the Project state phase line above for what carried into Фаза 3). **T-72/T-73 backend done**
(2026-08-31, plan+advisor, split into a backend commit + a `/admin/ui`-card commit) — `quorum` is
no longer hardcoded to two providers: runtime `[[providers]]` list, all 10 §3.4 presets +
custom-URL entry, 3
`BlockSignature` heuristics, 4 `/admin/providers/*` routes, `AdminConfigUpdate` loses `providers`,
`AdminStatusResponse.providers` → `active_providers`. **T-164** (ECS-enabled upstream preset,
ex-`ecs_option_for_upstream` stub) was **rejected 2026-08-31** — a live probe showed
`dns11.quad9.net` forwards the client's real /24 to every authoritative server with no option
from us, and a `127.0.0.1` resolver can't coarsen it. ECS stays a deliberate non-target (not a
gap): verified by reading, not a test — no code path constructs an ECS option, `quorum::resolve`
forwards the client `Message` unmodified, and `attach_edns` (the only OPT-writing helper) has no
production caller. SPEC §3.4 "Розглянуті й відхилені провайдери", TASKS-DONE.md T-164. The
second/third-platform work
(T-68/T-70 macOS halves, T-71, T-83) is now its own final **`## Фаза 6`** in TASKS.md / SPEC.md
— a planned target, deferred to last (no macOS access here), with a standing architectural
invariant that platform code stays behind a liftable seam (see "Current phase boundaries").

GeoIP design invariants (SPEC.md §3.5): the verdict is never cached — a cheap local lookup applied
live on every cached-or-fresh ALLOW, so a blocked-country-list change takes effect on the next
lookup with no invalidation logic. `geoip::blocking_country` (the filtering decision) takes
`blocked_countries`; `geoip::resolved_ip_country` (informational log metadata, T-161) deliberately
does **not** — structurally incapable of becoming a filter later. The allowlist branch and the
every-provider-disabled pass-through are exempt from GeoIP *filtering* but still get
`resolved_ip_country` annotation.

### Фаза 1 closure — open gaps (not numbered tasks; see SPEC.md's closure paragraph)

- No test anywhere exercises the real "browser → local DoH" leg — every existing confirmation is
  either DoH-client-level (`Invoke-WebRequest`) or Chrome automation against `/admin/ui`.
  **T-172 closes this** (Батч 3.9).
- ~~T-66's metrics did not confirm the quorum hypothesis (AdGuard 0/38, n=1)~~ — **T-171
  (2026-09-05) closed this gate with an honest record**: re-measured on n=122 with the T-170
  default set (`quad9` + `cloudflare-malware` + `adguard`), quorum caught +1 domain / +0.8 pp
  over the best single provider (Quad9). Hypothesis still not confirmed; Cloudflare Malware's
  blocks were near a subset of Quad9's (correlated feeds). Not a blocker — raised as a Ф4+ design
  question (DECISIONS.md 2026-09-05, PERFORMANCE.md "Quorum coverage (T-66 / T-171)").

### Known limitations in shipped code (no task number; the full open backlog is in TASKS.md)

- **Encrypted query-log persistence (T-146)** — best-effort scrub only (no defence vs VSS shadow
  copies / SSD wear-levelling, same honesty as `key_store::overwrite_with_zeros`); a hard crash
  loses ≤60s of the log tail (periodic full-snapshot rewrite, not append-only — deliberate); an
  orphaned `query-log.enc` (key gone) is renamed `.orphaned-<ts>` and **never** decrypted/
  recovered, a fresh key is minted (a query log is re-creatable — warn+proceed, unlike a TLS
  key); the `persistence-key` entry is not deleted on uninstall (folds into T-70, same as the
  TLS key). **Orphaned `.enc` files (`query-log.enc` / `cache.enc`) accumulate indefinitely** —
  `rename_orphan` never deletes (a key *might* resurface), but for a re-creatable store that
  recovery value is ~nil while each incident leaves a permanent undecryptable blob of
  browsing-derived data; no cleanup path exists yet.
- **Encrypted cache persistence (T-97)** — same scrub / ≤60s-crash-loss / orphan-rename / key-not-
  deleted-on-uninstall caveats as the query log (shared `persistence-key`). **Only `Verdict::Allow`
  is persisted** — `Block` is dropped at snapshot (so `fail_closed` timeout-blocks never cross a
  restart), meaning a fresh quorum `Block` costs one round-trip to re-derive after a restart. An
  entry whose **absolute wall-clock deadline** elapsed during downtime is dropped on restore, never
  served stale (RFC 8767 stale-if-error is still unconsumed — `should_serve_stale`). The restored
  entry's `ttl` is the *remaining* lifetime, not the original (diagnostic-only field). A
  `/admin/cache-config/apply` builds a fresh empty `Cache` (T-153) — the next flush overwrites
  `cache.enc` near-empty.
- **`fail_closed` timeout-Block is still cached in memory** for `block_verdict_ttl` — a network
  outage poisons the *in-memory* cache with blocks that outlive it. T-152's offline fast path does
  **not** write the cache, and T-97 does **not** persist `Block`, so a restart / watchdog restart
  still clears these; a retrofit of the pre-existing `fail_closed` branch is a separate task (Батч
  3.4 scoped it out).
- **`ProxyToSingleUpstream` (non-A/AAAA: HTTPS/SVCB/MX/TXT) has no offline fast path** — it falls
  through to its own per-query timeout while offline, not the instant SERVFAIL A/AAAA gets (T-152).
- **A `BASELINE_FALLBACK` ALLOW is not GeoIP-filtered** (T-155) — filtering already failed that
  round; `resolved_ip_country` (T-161) is still annotated. `BASELINE_FALLBACK` is also the one
  `DecisionSource` whose `LogEntry.voters` is deliberately non-empty (it carries the per-voter
  timeout record).
- **reachability markers / `BASELINE_CHAIN` / failover thresholds are not configurable** (T-152/
  T-154) — Ф3 defaults, §7.1 #8-style.
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
- **`cleanbrowsing-security` / `cleanbrowsing-adult` presets have the wrong `block_signature`
  (T-174, found 2026-09-05).** Both are declared `BlockSignature::NullIp` in `BUILTIN_PRESETS`,
  but from this vantage point both block via **NXDOMAIN** (T-171 all-presets run: 66/124 NXDOMAIN
  each, 18 not caught by Quad9). `is_blocked(NullIp, …)` can't see an NXDOMAIN block, so a user
  who enables either preset gets **none** of its blocks counted in `quorum::resolve`. Only
  Quad9/AdGuard were ever live-verified (DECISIONS.md 2026-08-25); the rest came from published
  provider docs. T-174 = live-verify + fix + re-measure T-171.
- **T-160** — `main.rs`'s `load_geoip_state` reads the ~8.3 MB `geoip.mmdb` synchronously at
  startup, unconditionally (even with an empty `blocked_countries`) — a one-time startup-latency
  cost, filed not fixed.
- **T-169** — the accept-loop backstop is built: `admission::ConnectionGate` cap +
  `handshake_timeout` (`tokio::time::timeout` around `acceptor.accept`) + `idle_timeout` (http1
  `header_read_timeout` / http2 keep-alive), all from the `[limits]` table. **Residual, filed not
  fixed:** there is **no separate, smaller cap on concurrent in-flight *quorum* resolutions** —
  the inbound-connection cap covers the primary vector, and the outbound fan-out ceiling
  (`concurrent queries × providers ≤ 10`) is bounded in time by `query_with_timeout` (2 s) +
  `UPSTREAM_CONNECT_TIMEOUT` (500 ms) but has no ceiling of its own (PERFORMANCE.md "Fan-out
  ceiling"). Also: `[limits]` is not admin-mutable and `apply_admin_reset` does not rebuild the
  gate, so a `[limits]` change needs a full service restart (same as `port`).
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
- **The status indicator (T-56, narrowed)** — watchdog state is built (T-95: tray
  `ServiceRestarting`/`ServiceGaveUp` + `/admin/status.watchdog`); browser-DoH-usage detection
  (indicator condition 1) is still unbuilt (blocked on T-134). The full single-indicator UI (all
  conditions as competing states, not a `Filtering` suffix) is still future.

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
- **A new `LogEntry` / DTO field is `None`/absent except for its owning `decision_source`(s)** —
  `voters` (`Quorum` **and** `BaselineFallback` — T-155: the latter *is* the per-voter timeout
  record), `geoip_country` (`Geoip` only).
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
  the TLS private key (T-67), the MaxMind account-id+license-key blob (T-163), and the
  `XChaCha20Poly1305` persistence key (T-146). `v1` is required
  (compile error without it); it also lists the Unix/Apple store crates target-gated — lockfile-only
  for windows-msvc, no `deny.toml` change. `unsafe` FFI is contained in
  `windows-native-keyring-store`, `#![forbid(unsafe_code)]` intact.
- `chacha20poly1305` (`default-features = false`, `features = ["alloc", "zeroize"]`) + `getrandom`
  (promoted transitive→direct, like `url` at T-72) — T-146's `encrypted_file` AEAD. RustCrypto,
  chosen over promoting `aws-lc-rs` (user decision 2026-09-03 — pure Rust, no C toolchain). 4 new
  crates (`chacha20poly1305`/`aead`/`poly1305`/`universal-hash`); `chacha20`/`cipher` 0.5/
  `crypto-common` 0.2 move dev-only→runtime (were via `proptest`'s `rand`); `cargo update -p
  chacha20` pins the tree off yanked 0.10.1 → non-yanked 0.10.2, `cargo audit` 12→11.
  `multiple-versions` ticks (`block-buffer` 0.10/0.12, `crypto-common` 0.1/0.2) — `warn`, gate
  green; no `deny.toml` change (all `MIT OR Apache-2.0`). `unsafe` SIMD contained in
  `chacha20`/`poly1305`, `#![forbid(unsafe_code)]` intact. SECURITY.md row.
- `sysinfo` (`default-features = false`, `features = ["system"]`) — `watchdog::pid_check::
  verify_pid_alive` (T-89): the recycled-PID guard §7 requires before a restart. Named by SPEC.md
  §7.1 #3. Pulls the transitive `winapi` 0.3.9 (via `ntapi`) + the `windows` 0.62 family —
  0 new advisories, no `deny.toml` change (licences already allowed), `multiple-versions` stays a
  warn; `unsafe` FFI contained in `ntapi`/`windows-*`, `#![forbid(unsafe_code)]` intact. Links
  into `dnsqb-service` though only `dnsqb-watcher` calls it (§7.1 #6). Full reasoning: SECURITY.md
  `sysinfo` row.
- `crates/dnsqb-tray`: `tray-icon` / `tao` / `rfd` (`default-features = false`) / `parking_lot`;
  depends on `dnsqb-service` as a library for `AdminClient`.
- Dev-only: `tempfile` (`overrides` load tests), `x509-parser` (`cert` DER assertions), `proptest`
  (`default-features = false`, `std` — no `fork`/`timeout` process-spawning tail).

### Commands (from repo root)

- `cargo build --workspace` — build all three crates. No `tauri-cli` / frontend build step of any
  kind — `dnsqb-tray` is a plain Rust binary, and `/admin/ui` is served from `include_str!`-embedded
  HTML/CSS/JS, no bundler. CI adds `--locked` to every `cargo` invocation (T-100) — run it that
  way locally too if you touched deps, so a stale-lock failure shows up before the push.
- Reproducible release build (T-100): `.cargo/config.toml` forces `/Brepro` on the MSVC triple and
  `Cargo.toml` sets `[profile.release] codegen-units = 1`; a `--release --workspace` build is
  byte-identical on rebuild. To reproduce the CI `repro` check locally, build `--release` twice in
  two differently-named dirs with `RUSTFLAGS="--remap-path-prefix=<dir>=src ..."` and compare
  `Get-FileHash` of the three `target/release/*.exe`. **Do not add rust-cache to a reproducibility
  build** — a restored `target/` can mask non-determinism.
- `cargo test --workspace --lib --bins` — unit tests. **`--bins` is required, not optional** —
  `dnsqb-tray` / `dnsqb-watcher` are `[[bin]]`-only crates with no `[lib]` target, so `--lib` alone
  never compiles or runs their `#[cfg(test)]` modules (caught when `dnsqb-tray/src/browser.rs`'s
  test turned out to have never run in CI). **`cargo test ... --bins` builds the *test-harness*
  exes, NOT the runnable `target/debug/<name>.exe`** — before a manual end-to-end smoke after a
  `main.rs` edit, run `cargo build --workspace` or you'll run a stale binary (cost real time in
  Батч 3.3: the watcher worked but the service showed no `service.hb` because its exe predated the
  watchdog wiring). And a *running* smoke process holds `target/debug/<name>.exe` open → the next
  `cargo build` fails with a link error; kill lingering `dnsqb-*` processes first.
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
conformance step and `coverage` (both `continue-on-error: true`). Since Батч 3.7: `ci.yml` also
has a blocking `repro` job (T-100, cross-path bit-identical release build), `Swatinem/rust-cache`
on the cargo jobs (not `repro`), `concurrency: cancel-in-progress`, and `paths-ignore` for
`**/*.md` / `diagrams/**` / `mockups/**` — **a docs-only commit runs no CI at all** (`ci.yml` and
`codeql.yml` both skip it), so don't wait on a CI run after a pure-docs push.

`.github/workflows/release.yml` (T-102/T-103/T-156) — `workflow_dispatch` builds + signs the 3
binaries (ephemeral `test-signed`, or strict with a `CODESIGN_PFX` secret), then a `msix` job
packs+signs a `.msix` via `packaging/pack-msix.ps1` (same signing model); a `v*` tag additionally
re-proves reproducibility and opens a **draft** GitHub release (3 `.exe` + `SHA256SUMS` +
`.msix`(+`.cer`)). No rust-cache anywhere in this workflow — every build is a clean build. To
exercise it without a real tag: `gh workflow run release.yml` (must be on `main`).

`packaging/pack-msix.ps1` — runnable standalone (`.\packaging\pack-msix.ps1 -BinDir
target\release -OutFile dist\dns-quorum-filter.msix`), needs the Windows SDK's `makeappx.exe`/
`signtool.exe` (`Windows Kits\10\bin\10.*\x64\`) — present on this dev machine as well as CI, so
it can be (and was, T-156) verified locally before ever pushing. `assets/gen-icon.py` (Pillow) —
regenerate `assets/icon/*.png` after editing it, never hand-edit a PNG; needs Segoe UI Bold
(`C:\Windows\Fonts\segoeuib.ttf`, present on any current Windows install) for `wordmark.png`.

`.github/workflows/codeql.yml` (T-101) is a separate workflow — CodeQL SAST, language `rust`,
`build-mode: none` (no cargo build), `runs-on: windows-latest` (cfg visibility for
`std::os::windows` code). It never fails the build on a finding — alerts land in the repo's
Security tab. Read them with `gh api repos/user137/dns-quorum-filter/code-scanning/alerts --jq
'.[] | {rule: .rule.id, sev: .rule.security_severity_level, path: .most_recent_instance.location.path}'`
— the `repo` scope already on the `gh` token covers code-scanning read+write on this public repo,
no `gh auth refresh` needed (verified 2026-09-01). Triage every finding in the same pass, same bar
as a clippy or audit finding.

First scan (`3703fe3`, 2026-09-01) surfaced 17 pre-existing findings, none introduced by T-101;
all resolved in **T-165** (`0` open now): the one real one (`examples/phase1_metrics.rs`
`danger_accept_invalid_certs(true)`) fixed by pinning `cert.pem`; 14× `rust/cleartext-logging`
fixed by restructuring `#[cfg(test)]` catch-all `other => panic!("{other:?}")` arms; 2×
(`trust_store.rs` 497/501, an assert printing a public cert thumbprint) dismissed via API as
`used in tests`. **T-146** added 6 more `used in tests` dismissals — `rust/hard-coded-cryptographic-value`
(critical) on fixed test keys in `#[cfg(test)]` modules: 2 in `encrypted_file.rs` (`const KEY = [7u8;32]`,
`let wrong = [8u8;32]`) and 4 in `log_persist.rs` (`let key = [3|5|9u8;32]` in the round-trip / overwrite
/ corrupt-file tests). A deterministic AEAD round-trip / wrong-key test needs a fixed key and it
never reaches production (real key = `key_store::load_or_create_persistence_key`).

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
  `Invoke-WebRequest -HttpVersion 2.0` for HTTP/2 (relevant here: `dns.quad9.net` requires it,
  and so does this project's own hyper `DoH` listener).
- **`std::fs::rename` on this Windows toolchain atomically replaces an existing destination**
  (`MOVEFILE_REPLACE_EXISTING`) and consumes the source — verified with a scratch probe before
  `paths::write_atomic` (T-146) relied on it. So the atomic-write pattern is just write-`<path>.tmp`
  → `sync_all` → `rename(tmp, path)`; **not** remove-then-rename (which reopens the torn-write
  window). `sync_all` the temp *before* the rename or a power loss can leave a renamed-but-empty
  file (same habit as `key_store::overwrite_with_zeros`).
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
- **`reqwest` 0.13 does multi-address connect but with no built-in per-address deadline unless
  `connect_timeout` is set (T-154).** Kickoff scratch probe (`reqwest::Client::builder()
  .resolve_to_addrs(host, &[bad, good])` then a real DoH GET, 2 runs): with a **fast-failing**
  first address (`127.0.0.1:9`, ECONNREFUSED) reqwest advances to the second and succeeds
  (~2s); with a **blackholed** first address (`192.0.2.1:443`, TEST-NET-1, packets dropped) it
  hangs on the first until the *outer* request timeout and never tries the second — **no
  failover** — *unless* `.connect_timeout(500ms)` is set, which restores failover for the
  blackhole shape too (~330–430ms). Production `ReqwestDohClient::new()` sets no per-query
  timeout of its own (that's `query_with_timeout`'s external `tokio::time::timeout`, 2s), so
  before T-154 a blackholed Quad9/Cloudflare primary IP just consumed the whole 2s and the
  secondary IP was never attempted. `UPSTREAM_CONNECT_TIMEOUT` (`upstream.rs`) now sits at
  500ms, provably `< TimeoutConfig::default().duration` (invariant test in that module).
- Boxing differently-shaped `async move { ... }` blocks into one `FuturesUnordered<Pin<Box<dyn
  Future<Output = T> + Send + 'a>>>` (T-30's tagged-future pattern) needs the borrowed generic
  type param itself bound `Sync`, not just `Send` — `&C` across an `.await` inside the box requires
  `C: Sync` or the compiler rejects the `Send`-future cast with a non-obvious error pointing at the
  `&` reference, not at `C`.
- `#[tokio::test(start_paused = true)]` (deterministic `tokio::time::sleep`/`timeout` tests, no real
  waiting) needs the default current-thread runtime — never add `flavor = "multi_thread"` to a
  paused-time test, it panics at runtime (`rt-multi-thread` being enabled for `main.rs`'s own needs
  doesn't carry over to test attributes, which pick their flavor independently).
- **A borrowed `tokio::sync::SemaphorePermit<'_>` cannot cross into `tokio::spawn` (T-169)** — it's
  tied to the `&Semaphore`, the spawned task needs `'static`. Use `Arc<Semaphore>` +
  `try_acquire_owned()` → `OwnedSemaphorePermit` (owned, `'static`, `add_permits(1)` on `Drop` —
  verified in vendored tokio 1.53.1). Put the `Arc` *inside* the wrapper type around the
  `Semaphore`, not a second `Arc` around the wrapper. `Semaphore::new` panics above
  `MAX_PERMITS` (`usize::MAX >> 3`) — unreachable from a `u32` on 64-bit, so a `u32`-typed cap
  makes `new` provably panic-free; a "huge value doesn't panic" test would be vacuous, put the
  loud upper bound in the config loader instead.
- **`hyper_util::server::conn::auto::Builder` has no top-level `.timer()` (verified vendored
  hyper-util 0.1.20)** — set it per protocol: `.http1().timer(TokioTimer::new())` and
  `.http2().timer(TokioTimer::new())` separately. `.http1().header_read_timeout(d)` **panics** if
  no http1 timer is set; the h2 idle equivalent is `.http2().keep_alive_interval(d)`
  (`header_read_timeout` "does not affect HTTP/2"). `.keep_alive_timeout(d)` (the PING-ACK
  deadline) is left at hyper's own 20s default in `main.rs` rather than tied to a `[limits]`
  field, so lowering the handshake deadline doesn't silently tighten PING-ACK too. A panic on the
  connection-serving path = a watchdog restart loop, so check this API before writing, not after.
  hyper 1.11.0 h2 server defaults (also vendored-verified): conn/stream flow-control windows
  1 MiB each (advertised *credit*, not resident memory — `adaptive_window` off), `max_send_buffer_size`
  400 KiB, `max_concurrent_streams` `Some(200)`; rustls 0.23.43 `DEFAULT_BUFFER_LIMIT` 64 KiB.
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
- **`moka::future::Cache::iter()` (0.12.16) is a *synchronous* method** (verified in the vendored
  `future/cache.rs` — no `.await`), yielding `(Arc<K>, V)` with `V` cloned. Its documented
  guarantees (no dup, won't yield a post-`iter()` insert, won't yield a removed entry) are enough
  for a best-effort snapshot but it **may** yield a logically-expired-but-not-yet-swept entry
  (eviction is lazy) — T-97's `Cache::snapshot` doesn't probe that: `cache_persist_dto`'s own
  `entry.is_fresh(Instant::now())` filter is strictly tighter than moka's `ttl + stale_grace`
  window, so a stale-but-present entry is dropped by that check regardless.
- **Persisting a `std::time::Instant` is meaningless** — it's monotonic and resets on reboot (T-97).
  `CacheEntry.expires_at` is persisted as an *absolute wall-clock* deadline (`SystemTime` → millis):
  snapshot does `now_wall + expires_at.saturating_duration_since(now_mono)`, restore does
  `deadline.duration_since(SystemTime::now())` and drops the entry on `Err`/zero (expired during
  downtime). Same shape as `persist_dto`'s `ts_millis`, but for a *deadline* not a timestamp.
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
- **CodeQL `rust/cleartext-logging` (T-101/T-165) taints a value by the *name* of the function
  that produced it, not by a real dataflow to a real sink.** Any `format!`/`panic!`/`assert!`
  interpolating a value returned from `load_secret` / `store_secret` / `local_cert_thumbprint`
  (and anything whose body calls those) fires — even a `#[cfg(test)]` catch-all `other =>
  panic!("{other:?}")` that sits *after* the arm which already destructured the only
  secret-carrying variant, and even `{}` on `Zeroizing::len()` (taint follows the projection).
  The fix that actually clears it: exhaustive arms (`Ok(None)` / `Ok(Some(_))` / `Err(err)`),
  formatting only the coarse thiserror `{err}` Display, never binding the value. A genuinely
  non-secret value that still trips the name heuristic (a *public* cert's SHA-1 thumbprint) is a
  real false positive — dismiss via `gh api -X PATCH .../code-scanning/alerts/<n> -f
  state=dismissed -f dismissed_reason="used in tests"`, don't churn code to dodge it. Expect this
  on every new secret-adjacent test (Батч 3.1 `key_store`/pipe work) — write the exhaustive match
  from the start.
- **A generic "fuzz every documented route" property test can turn a new admin route's real
  handler into a per-CI-run liability, not just a coverage win — check what the property's
  fixture actually satisfies before trusting "it'll just get covered automatically."**
  `serve_never_panics_on_arbitrary_input_for_any_documented_route` (T-58) builds a request for
  every `ROUTES` entry with a real `Content-Type: application/json` header on every non-GET
  route specifically so it reaches each handler's real body, not just its CSRF gate — which is
  exactly right for every route that existed when it was written (a `keyring` write, a cache
  rebuild, all fast and idempotent). Adding `POST /admin/uninstall-local-state` (T-70) without
  checking this meant a proptest case landing on it would run `local_state::remove_all` for
  real — spawning an actual `certutil.exe` subprocess and mutating whatever this project's CN
  has installed in `CurrentUser\Root` — on every `cargo test`, silently, since the handler never
  even inspects the arbitrary body once the gate passes. Caught by the test suite going from
  ~2s to a 60+-second hang immediately after adding the route, not by reading the property
  first. Fixed with a documented `FUZZ_EXCLUDED_ROUTES` allowlist-of-exclusions (one path so
  far) rather than weakening the property for every route; the excluded route's own two gates
  (wrong method, missing content-type — the paths that reject *before* the real handler runs)
  get their own direct tests instead, mirroring `serve_admin_shutdown`'s existing pair.
- **MSIX `.msix` signature Subject and `<Identity Publisher>` must match character for
  character, or `signtool sign` fails with a generic-looking error, not an obvious "these
  don't match."** `packaging/pack-msix.ps1` derives both from the one `-Publisher` parameter
  (never a manifest literal + a separate `New-SelfSignedCertificate -Subject` literal that
  happen to agree today) — confirmed by a real local pack+sign against both debug and
  `--release` binaries using the Windows SDK at `Windows Kits\10\bin\10.0.26100.0\x64\` (the
  same version `windows-latest` CI runners use), not assumed from documentation.
- **MSIX `<Identity Version>` is 4-part `Major.Minor.Build.Revision`, Revision always `0`** —
  `pack-msix.ps1` takes the crate's 3-part `Cargo.toml` version (or a `v*` git tag, cross-checked
  against it, `throw`ing on mismatch so a `.msix` can never carry a version different from the
  binaries packed inside it) and appends `.0`.
- **Sideloading a self-signed `.msix` needs the signing cert in `Cert:\LocalMachine\Root` or
  `\LocalMachine\TrustedPeople` — `Cert:\CurrentUser\TrustedPeople` is NOT enough.** Confirmed
  empirically (2026-09-04, this session, no admin access): importing the ephemeral test cert
  into `CurrentUser\TrustedPeople` and running `Add-AppxPackage` failed with `0x800B0109`
  ("root certificate ... not trusted by the trust provider"). Both `LocalMachine` locations need
  an elevated PowerShell session to write to — a real, if one-time and install-only, elevation
  cost that `packaging/README.md` and every release's notes now state explicitly rather than
  leaving a sideloader to discover it via a cryptic HRESULT.
- **A `gh` call inside a job that checks out multiple copies via `path: build-a`/`build-b`**
  (`release.yml`'s repro-then-release job) **needs `--repo $env:GITHUB_REPOSITORY` explicitly** —
  the job's own working directory has no `.git`, so `gh release create` fails "not a git
  repository" otherwise.

## Documentation map — who owns what

| File | Owns | Update when |
|---|---|---|
| `SPEC.md` | full design + reasoning: architecture, RFC table, phased plan, open questions | a design decision changes or a new one is made |
| `UI-SPEC.md` | GUI: screen inventory, per-screen field/type tables, DTOs for the admin HTTP channel (not Tauri — that channel was removed at T-149) — no rationale, links back to SPEC.md §8 by section number | a screen, field, or DTO changes; rationale changes go in SPEC.md instead |
| `diagrams/` | architecture + UI diagrams, each anchored to a SOURCES section list; ground-truth ritual in `diagrams/README.md` applies from here on | a diagrammed state/flow/DTO changes — see the ritual's trigger list |
| `CLAUDE.md` | agent-facing summary: commands, architecture at a glance, non-obvious gotchas | architecture/commands change |
| `TASKS.md` | open backlog — status only, no reasoning | a task starts or gets added |
| `TASKS-DONE.md` | completed tasks, moved out of `TASKS.md` on finish, same format + a one-line implementation note per task | a task finishes |
| `DECISIONS.md` | retroactive corrections to already-shipped decisions, with reasoning; overrides SPEC.md by date on conflict | a past decision gets revised |
| `SECURITY.md` | threat model summary, hard security constraints, dependency-vetting table | threat model changes or a dependency is added |
| `README.md` | human-facing project description | repo structure changes, or the project's phase/status badge changes |
| `CONFIGURATION.md` | operator-facing reference for both TOML config files (`resolver_config.toml`, `overrides.toml`) — fields, defaults, validation, examples | a config field is added, changed, or removed |
| `SERVICES.md` | what each binary does, how to run it, its logs and startup behavior | a binary's runtime behavior, ports, or file I/O changes |
| `PERFORMANCE.md` | critical-path complexity analysis, load-test methodology and measured results — not design reasoning (that's SPEC.md) | a hot-path complexity fact changes, or a load-test run produces new numbers |

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
- Default upstream set on first run (`DEFAULT_PROVIDER_IDS`, decided T-170 / DECISIONS.md
  2026-09-05) is **`quad9` + `cloudflare-malware` + `adguard`** — the two §3.4/§3.5 Security-tier
  voters plus AdGuard for ads out of the box. Adult stays an opt-in category toggle.

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

**Second/third desktop platform (macOS, Linux) is its own final phase — `## Фаза 6`** (moved
there 2026-08-31: no macOS build/test access in this environment). It is a *planned* target, not
"maybe someday" — so the standing architectural invariant is that platform-specific code sits
behind a boundary that can be lifted under `#[cfg(target_os)]` / a trait **without a rewrite**,
never hard-coupled to Windows. `key_store` (via `keyring`) already meets this; `trust_store` does
not yet (no trait, no `#[cfg(target_os)]`) — the port builds that boundary from scratch, named
ahead of time. When adding Windows-specific code (a spawned `certutil`/`rundll32`, a registry
call), keep the seam visible rather than inlining the assumption.
