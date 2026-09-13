# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

**Current phase:** Фаза 4 (rating filter «bubble», per-country top-N zone infra, personal learned
zone) fully closed 2026-09-11 — tag `v0.4.0` published as GitHub `latest` 2026-09-12 (moved once
mid-smoke-test to include the T-219 MSIX cert-trust fix, Батч 4.7.A, before publishing). Фаза 3
(production hardening — watchdog, MSIX packaging) closed 2026-09-06 (`v0.3.0`, no longer `latest`);
Фаза 2 (cert automation) closed 2026-08-31; Фаза 1 (PoC) closed 2026-08-29.

**Not started:** Фаза 5 (ccTLD block §5.2 + i18n T-151), Фаза 6 (macOS/Linux port — see "Current
phase boundaries" below for the architectural seam it needs). T-218 is open backlog, not
blocking (T-217 closed 2026-09-12).

Full batch-by-batch history (rationale, advisor catches, commit hashes, verification notes) lives
in `TASKS-DONE.md`; reversed/corrected decisions live in `DECISIONS.md`, git, and this file's
"Documentation map". This section is a current-state snapshot only — it does not repeat that
history.

**Maintaining this section:** it is a snapshot, not a log. A finished task updates the phase line,
the module table, and the workstream status, and adds a bullet to `KNOWN-LIMITATIONS.md`'s "Known
limitations in shipped code" *only* if it leaves a live limitation there. The task's own narrative
— rationale, advisor catches, verification notes — goes to `TASKS-DONE.md`, never here or there.
**This rule already failed once as prose alone** (file compressed 198k→62k chars on 2026-08-30
with this exact rule already written, regrew to 174k by 2026-09-11 anyway) —
`.github/workflows/claude-md-size.yml` now enforces a hard byte-size ceiling in CI on every push
that touches this file; if that check fails, move the new prose to its owner file, never raise the
number. **The two fastest-growing sections (`Known limitations` and the old `Rust/tooling
gotchas`) are now split into their own files** (`KNOWN-LIMITATIONS.md`, `RUST-GOTCHAS.md`,
2026-09-12) for exactly this reason — a further regrowth means finding the next section to split
out, not raising the ceiling.

### What's built

`dnsqb-service` — a real `hyper` + `rustls` DoH listener on `127.0.0.1`, resolving queries end to
end through the pipeline (allowlist → blocklist → cache → quorum) plus live GeoIP filtering
(SPEC.md §3.5 / §5.3 step 7) and the **rating filter «bubble» step 5** (§5.3, default OFF;
out-of-zone → BLOCK, in-zone → normal pipeline). The one intermediate SPEC.md §5.3 step still
unbuilt is the ccTLD block (§5.2, Фаза 5). (There is no "voter scope" step any more — §5.1 was
removed.) Startup also spawns three detached `#[cfg(windows)]` watchdog tasks (heartbeat pipe
server, `service.hb` touch, the in-memory `service→watcher` decision loop — §7.1 #7: it acts and
logs but never persists, so that direction's `GaveUp` is **not durable** — the restart budget
resets on every service restart, a symmetric un-fixable-without-§7.1-#7-violation counterpart to
the watcher→service `restored` path).

The whole startup/serve-until-shutdown sequence lives in `orchestrate::run` (a lib module, `pub
async fn run()`), not `main.rs` — `main.rs` is a 3-line shim (`dnsqb_service::run().await`).
**`orchestrate::run` is called only from `dnsqb-service`'s own `main.rs`** — `dnsqb-watcher` links
the same lib but must never call `run()` or its private `run_service_to_watcher_watchdog` (§7.1
#7's single-writer invariant depends on that boundary now being enforced by "who actually calls
this," not by two physically separate `main.rs` files).

Modules under `crates/dnsqb-service/src/`:

| Module | Responsibility |
|---|---|
| `orchestrate` | `pub async fn run()` — the whole startup + accept-loop-until-`/admin/shutdown` sequence. Owns `serve_until_shutdown` (connection-gate + handshake/idle timeouts), the config/overrides/cert/cache/query-log/GeoIP startup loads, and `spawn_watchdog_tasks`/`spawn_flag_watchers`/`spawn_public_http_tasks`. Called only from `dnsqb-service`'s own `main.rs` — see the §7.1 #7 boundary note above |
| `admission` | `ConnectionGate` (bounded-concurrency backstop, SPEC.md §1.1): `tokio::sync::Semaphore` (lock-free permits) + `AtomicU64` reject count, **no** `Mutex`/`Arc<Mutex>`. `try_admit() -> Option<OwnedSemaphorePermit>` (owned so it survives `tokio::spawn`; releases on `Drop`), `rejected_count()` (cumulative), `active()` (max − available, live). Lives on `AppState` (`connection_gate()`); the accept loop calls `try_admit` before each `tokio::spawn`, `drop(stream)` (TCP-close before TLS) at the ceiling; `live_stats` reads both counters into `AdminStats` |
| `pipeline` | `handle_query` request flow (takes `UpstreamContext { timeout, baseline_url, serve_baseline_fallback, reachability, filtering_paused, rating_filter }` bundle); `invalidate_changed` (cache eviction on override-list reload). Offline (T-152) → `offline_servfail_with_meta` before cache read. `outcome.filters_unreachable` (T-155) → `DecisionSource::BaselineFallback`, never cached. **Step 5 rating filter:** `rating_filter_step` after the cache read, before `resolve` — `RatingFilterView { lists, personal, removed }` snapshots (`personal` — the personal learned zone, checked as a second independent `zone_match` call on a `lists` miss); out-of-zone → `rating_filter_block_with_meta` (`DecisionSource::RatingFilter`, **not cached**); in-zone exact (hygiene-eligible on whichever `ZoneLists` matched) + quorum `Block` → `QueryLogMeta.zone_removal` (lazy-hygiene action signal, not a log field) |
| `quorum` | OR-logic `resolve(&[ProviderEntry], baseline_url)` over a runtime voter list (T-72/T-73, T-154); `evaluate(BlockSignature, &Message, &[SinkholeNet])` (3 heuristics `NullIp` / `NxdomainVsBaseline` / `NullIpOrNxdomain`, **+ T-175 sinkhole-prefix branch**: an A/AAAA answer inside a preset's `upstream::sinkhole_nets_for(id)` prefix (v4 or v6; IPv4-mapped AAAA unwrapped) → `Signal::NeedsBaseline`, composes with the signature); `is_blocked` / `known_signal` also carry the `&[SinkholeNet]` param; early-return via `FuturesUnordered`; `VoterRecord { provider_id: String, .. }` / `VoterVerdict`. `QuorumOutcome` carries `filters_unreachable: bool` (every enabled voter `!Responded` — computed in `finalize_outcome` + early-block from raw `VoterOutcome`s, can coexist with a `Block`) and `baseline_answer: Option<Message>` |
| `baseline_selector` | T-154(b) pure: `BASELINE_CHAIN` (Cloudflare Unfiltered → Quad9 Unsecured → Google, §3.4); `BaselineSelector` — sticky failover after `SWITCH_THRESHOLD`=3 consecutive full failures, `should_retry_primary` + `RETRY_PRIMARY_AFTER`=300s auto-return with hysteresis; `record(now, url_used, BaselineHealth) -> Option<BaselineEvent>`. Reader = hot path (`current()`); writer = the reachability prober |
| `reachability` | T-152: `MARKERS` (3 independent `generate_204`-class — Google/Cloudflare/Apple); `verdict_from_probe_results` (raw Offline iff all fail), private `OfflineDebounce` — publishes `Offline` only after `OFFLINE_CONFIRM_CYCLES`=3 consecutive all-fail cycles (entry hysteresis; recovery not debounced), `next_probe_delay(previous, raw)` (idle 30s only when both Online, else recheck 3s — so a building outage still probes fast); `run_reachability_prober` (own `reqwest::Client`, publishes `NetworkReachability` on `AppState`, **also** drives `baseline_selector` via one real `DoH` sentinel probe per raw-Online cycle — a continuous heartbeat to the active baseline, acknowledged in the module-doc privacy note). Not wired into `/health` or watchdog channels |
| `cache` | `moka` per-entry-TTL cache; `CacheConfig`, `clamp_ttl`, `chain_cache_ttl`, `is_cacheable`, `invalidate_matching`, `clear`; T-97 added `snapshot()` (sync `moka::future::Cache::iter()`, best-effort) / `restore()` and `CacheKey::domain()`/`qtype()` accessors for `cache.enc` |
| `overrides` | allowlist/blocklist `load`/`save`/`decision`/`conflicts`; suffix-wildcard match; `InvalidEntry` (domain-redacting) |
| `upstream` | `ProviderSpec` / `ProviderEntry` / `Category` / `BlockSignature` + `BUILTIN_PRESETS` table (§3.4, T-72/T-73) + `builtin_preset` / `all_builtin_presets` / `validate_provider_url` (SSRF: `https` + non-loopback/private/link-local literal host) / `is_valid_provider_id`; T-175 `SinkholeNet` (`IpAddr`+prefix, `v4()`/`v6()`, no `Default`, `contains` = XOR+`leading_zeros`) + `SINKHOLE_NETS` + `sinkhole_nets_for(id)` (builtin-only); `DohClient` trait + `ReqwestDohClient` (per-upstream HTTP/2 keep-alive + `connect_timeout` 500ms — T-154(a), restores multi-A failover for a blackholed address) |
| `timeout` | `TimeoutMode` (fail-open / fail-closed / degraded); `query_with_timeout` |
| `wire` | DoH wire codec; block (`0.0.0.0`/`::`) / NODATA / SERVFAIL / direct-answer construction; AD-bit passthrough |
| `query_log` | in-memory ring buffer (`parking_lot::RwLock`); `LogEntry`, `DecisionSource` (7 producible: +`BaselineFallback` T-155 — the one whose `voters` is **not** empty; +`RatingFilter` T-124), `LogFilter` search, `clear`; `restore(entries, now)` (T-146 — seeds from `query-log.enc`, re-applies both the 1000/24h bounds) |
| `rating_filter` | pure step-5 core (SPEC.md §5.3). `ZoneSourceKind` (`CountryTopN(cc)`/`Global`/`GovernmentTopN(cc)`/`SciEdu`/`Personal` — closed enum, all four kinds shipped), `ZoneSource { kind, registrables: HashSet }`, `ZoneLists(Vec<ZoneSource>)`. `zone_match(host, removed) -> Option<&str>` — one suffix walk, both the membership test and the exact-match identity for lazy hygiene; a hit on any suffix in the union = in zone. **No PSL** — the published lists are registrable-only, and `curate_topn` skips bare public suffixes (`overrides::suffix_matches` precedent). **Blanket-suffix entries:** a `GovernmentTopN`/`SciEdu` source can hold a whole registrar-restricted domain space (`gov.ua`, `gov`, `edu`, `int`) as one entry — the same PSL-free suffix walk then covers every subdomain automatically. `ZoneSourceKind::hygiene_eligible()` (`false` for these two, `true` for the CrUX-derived kinds **and** `Personal`) + `ZoneLists::is_hygiene_eligible()` gate lazy hygiene at **two** layers — `zone_match` itself only lets `removed` suppress a hygiene-eligible source's match (structural, not just caller discipline), and `pipeline::rating_filter_step`'s `exact` additionally requires eligibility — so a false-positive quorum block of the bare suffix itself can never evict the whole namespace it covers. **`Personal` deliberately lives in its own `AppState.rating_filter_personal_zone: Arc<ZoneLists>`, not folded into this module's own `ZoneLists`** — see the `pipeline` row above and the `personal_zone_*` rows below |
| `topn_download` | T-124 pure helpers — `TOPN_RAW_BASE` (`raw.githubusercontent.com/.../data/topn/`, the T-105 stable-URL contract), `AVAILABLE_TOPN_LISTS: &[&str]` (`ua`/`us`/`de`/`pl`/`gb`/`global` — the distribution contract; surfaced as `RatingFilterStatusView.available_lists` **and**, since T-127, gates config loading via `validate_rating_filter_lists`, so *removing* a code is a breaking change), `list_url`/`sha256_sidecar_url`, `parse_list` (skip `#`/blank, lowercase, dedup), `verify_sha256` (sha256sum-style first token, 64 hex; a malformed sidecar never matches). Mirrors `geoip_download` |
| `topn_updater` | `run_topn_updater` (`loop { refresh_all_lists; park_until_due }`, `TOPN_CHECK_INTERVAL` 24h, `Notify` wake on `/admin/reset` **and `POST /admin/rating-filter`**); `refresh_one_list` fetch→verify→`paths::write_atomic(<app-data>/topn/<list>.txt)`→`parse_list`→`ZoneSource`; failed list keeps last-known-good. `load_zone_from_disk` seeds the bubble at startup (empty on fresh install, like `load_geoip_state(None)`). **Always spawned by `main.rs` whenever an app-data dir exists** — not gated on `[rating_filter]` enabled+non-empty; `refresh_all_lists` re-reads the config snapshot each cycle and returns immediately while disabled (enabling via the route needs no restart). **No DNS.** Mirrors `geoip_updater` |
| `config` | `ResolverConfig` (TOML); `[providers]` / `[cache]` / `[geoip]` / `[limits]` (`LimitsConfig`: `max_concurrent_connections` + `handshake_timeout_ms` + `idle_timeout_ms`, `Copy`, live type holds `Duration`s, `0`/`>1_000_000` = fatal load error) tables + `serve_baseline_when_filters_unreachable` bool (default `false`) + `persist_query_log` + `persist_cache` bools (default `false`, **no admin route** — each carried through every rewrite via `PersistTarget` cross-field-read); per-field validation, loud errors. `validate_rating_filter_lists`: two ordered checks — shape (`InvalidRatingFilterList`, `"uka"`) then `topn_download::AVAILABLE_TOPN_LISTS` membership (`UnknownRatingFilterList`, `"fr"` — well-formed, no dataset); both fatal at load / `400` on the route, so `lists ⊆ available_lists` always holds. Removing a code from `AVAILABLE_TOPN_LISTS` is a breaking config change. **`[personal_zone]` — `PersonalZoneConfig`, `Copy`:** `enabled` + `frequency_window_days`/`frequency_top_n`/`regularity_window_days`/`regularity_min_days`, `validate_personal_zone` (window fields `1..=90` — `MAX_PERSONAL_ZONE_WINDOW_DAYS`, `frequency_top_n != 0`, `1 <= regularity_min_days <= regularity_window_days`). Also **no admin route**, but deliberately **not** carried through `PersistTarget` — every write site reads a live `AppState.personal_zone_config_snapshot()` instead (see the `dispatch` row below for why) |
| `encrypted_file` | T-146 pure AEAD codec: `seal`/`open` over `XChaCha20Poly1305`; 6-byte cleartext header (`DQF1` / `FileKind` / version) is the AAD, validated **before** the AEAD open (`UnsupportedVersion` distinct from `Decrypt`); `EncryptedFileError` payload-free |
| `persist_dto` | T-146 serde mirrors of `LogEntry` (`SystemTime`↔u64 millis, `RecordType`↔u16, `error_kind` `&'static str` re-interned through a closed set); `PersistedFileV1` wrapper (struct, additive); `to_json`/`from_json` |
| `log_persist` | T-146: `persist_snapshot` (serialize→seal→`write_atomic`, testable core); `load_persisted_query_log` (startup — mint/read key, decrypt, seed; missing-key-with-file / corrupt → rename `.orphaned-<ts>` + empty, never overwrite); `run_query_log_persister` (60s + shutdown flush, thin impure shell). `paths::write_atomic` = temp + `sync_all` + `fs::rename` (Windows atomic-replace, scratch-probed). `rename_orphan` is `pub(crate)`, reused by `cache_persist` |
| `cache_persist_dto` | T-97 serde form of the verdict cache. `PersistedCacheEntry { domain, qtype: u16, expiry_millis: u64, verdict: PCacheVerdict }` — `expiry_millis` is an **absolute wall-clock** deadline (the live `CacheEntry.expires_at` is a monotonic `Instant`, unserialisable); `to_json(snapshot, now_wall, now_mono)` filters `Verdict::Block` + non-fresh + converts `Instant`→wall (clocks injected for tests); `from_json(plaintext, now_wall)` drops any entry whose deadline already passed. `PCacheVerdict` keeps `Block` representable (format-stable) though `to_json` never emits it. `IpAddr` kept un-mirrored (has its own serde impl) |
| `cache_persist` | T-97, sibling of `log_persist`: `persist_cache_snapshot` (→`seal(FileKind::Cache)`→`write_atomic`), `load_persisted_cache` (→`CacheInit { restore, flusher }`; independent `ciphertext_present` for `cache.enc`, shared `persistence-key`), `run_cache_persister` (60s + shutdown). `AppState::cache_snapshot`/`restore_cache` pass-throughs (lock dropped before `.await`) |
| `zone_removal_persist` | another `log_persist` sibling: `zone-removals.enc`, shared `persistence-key` (operational state of an already-opted-in feature, not new personal disclosure — see `personal_zone_persist`'s row for the contrast). Gated on `[rating_filter].enabled`, re-checked every flush tick (not just startup) so toggling it off stops new flushes without a restart |
| `personal_zone_stats` | pure core (no I/O). `DayIndex` (days-since-epoch, saturating both directions — never panics on a clock jump or a stale restored snapshot); `PersonalZoneStats` — per-domain fixed-length daily-count ring (`window_len_from_config` = `max(frequency_window_days, regularity_window_days)`), `MAX_TRACKED_DOMAINS = 2000` provable cap with LRU-ish eviction by `last_visited`. `record_visit` is the hot-path entry (`rotate_day` first, `saturating_add`, no allocation on an already-tracked hostname). `derive_qualifying_domains` — the SPEC.md §5.1.1 frequency-top-N **union** regularity-X-of-Y criteria. Records are queried *hostnames*, not registrables (no PSL) |
| `personal_zone_persist` | `log_persist` sibling but sealed with its own, separate `personal-zone-key` (not the shared `persistence-key` — higher privacy tier). One task does rotate+republish+persist every cycle (no separate "did the day change" branch — recomputing is cheap at `MAX_TRACKED_DOMAINS` scale). `AppState.rating_filter_personal_zone: Arc<ZoneLists>` is fully independent of `rating_filter_zone` (different writers/cadences — see `rating_filter`'s own row) |
| `cert` / `paths` / `trust_store` / `cert_rotation` / `key_store` | self-signed leaf cert generation; `cert.pem` on disk, private key in the OS secret store via `key_store` (Windows Credential Manager through `keyring`; entry name = `dns-quorum-filter`/`doh-tls-private-key:<sha1(app-data dir)[..8]>` so a scratch instance never collides). `key_store` holds **four** secrets — `persistence-key:<hash>` (`load_or_create_persistence_key` — 32-byte `XChaCha20Poly1305` key; seals `query-log.enc`, `cache.enc`, **and** `zone-removals.enc`, `FileKind` in the AAD keeps them distinct; `getrandom` failure → `KeyStoreError::Rng`, no fallback; a stored key that isn't 32 bytes → `MalformedKey`; `orphaned_ciphertext` flag when a file exists but no key does — the "created exactly once" invariant rests on `instance::acquire`), `personal-zone-key:<hash>` (`load_or_create_personal_zone_key` — a **deliberately separate** key sealing only `personal-zone.enc`, higher privacy tier than the three sharing `persistence-key`; both public functions share one private `load_or_create_symmetric_key` mint-or-read core). `paths::write_atomic` lives here too; `cert::migrate_legacy_key_into_store` copies a pre-existing plaintext `key.pem` into the store once, and `discard_legacy_key_file` zero-and-unlinks it **only after** `tls` proves the stored key loads against `cert.pem` (so a mismatched plaintext key is never destroyed first — no plaintext-secret-write code path exists any more, see the gotchas section's `icacls` entry); `CurrentUser\Root` trust-store install/uninstall + read-only `trust_store::is_trusted(cert_path)` (shared `trusted_state` core with `ensure_installed`, `certutil -dump`/`-store` only, no route, called directly by the tray icon's trust-watch thread; **all `certutil` spawns go through `certutil_command` with `CREATE_NO_WINDOW`** — else the background poll flashes a console window); `cert_rotation::rotate_certificate` = ordered composition generate → `uninstall` (CN-exhaustive) → persist → `ensure_installed`, clear-before-persist forced by the shared CN, tray-only, needs a manual `dnsqb-service` restart to take effect |
| `tls` | `load_or_generate_server_config` (runs the one-time `key.pem` migration, then loads `cert.pem` + the stored key, else regenerates — `CertOrigin::{Loaded,GeneratedFirstRun,Replaced}`) → `rustls::ServerConfig` (always `builder_with_provider(aws_lc_rs::default_provider())`) |
| `local_state` | `remove_all(app_data_dir: Option<&Path>) -> UninstallReport` — the in-app "prepare for removal" MSIX needs (no uninstall-time code hook). Calls `trust_store::uninstall()` + `key_store::delete_secret` for all 3 keyring entries; each of the 4 artifacts reports independently (`ArtifactOutcome::{Removed,NotPresent,Failed(&'static str)}`), never one collapsed bool. `remove_all`/its private `remove_cert` are **deliberately untested** — `remove_cert` always runs the real `trust_store::uninstall()` (a `CurrentUser\Root` sweep), the same real-external-resource line `trust_store`'s and `cert_rotation`'s own tests refuse to cross; `remove_secret` (the real Removed/NotPresent/Failed decision) is tested directly instead |
| `listener` | `bind_listener` / `BindError`; `127.0.0.1`-only; explicit error on port conflict, never a silent fallback |
| `logging` | `init_logging(role, app_data_dir)` — all 3 binaries call it once → `%LOCALAPPDATA%\dns-quorum-filter\logs\<role>.log`. Dependency-free `tracing_subscriber::fmt().with_writer(Arc<File>)` (no `tracing-appender`), fixed INFO, no `env-filter`; startup rotation to `.log.old` at 5 MiB. Debug build also writes stdout. Exists because T-181 removed the console — the file is the only diagnostic |
| `lifecycle` | `stop.flag` (pause) / `quit.flag` (exit — watcher stops the service + exits). `set_/clear_/…_flag(app_data_dir)`; presence *is* the signal, contents unread. **Separate files, not `watchdog-state.json`** (§7.1 #7 single-writer kept). `dnsqb-watcher::main` clears both on startup → a fresh app launch lifts a pause. `stop.flag` is read by `dnsqb-service` itself (`pause_watch`, below) — a pause keeps the service **up** serving the unfiltered baseline; the watcher no longer freezes or special-cases it (DECISIONS.md) |
| `pause_watch` | T-193: `run_pause_watcher(app_data, state)` — detached 1 s poll of `lifecycle::stop.flag` → `AppState::filtering_paused` (`RwLock<bool>`, `Copy`, no `Arc` — mirrors `reachability`). `handle_query` snapshots it into `UpstreamContext.filtering_paused` and shares the `!ProviderEntry::any_enabled` branch: paused ⇒ baseline pass-through, never cached, `DecisionSource::Quorum` + empty voters. Providers stay *enabled* (resume = zero config change). Overrides + offline fast path still win above it. Same "detached loop publishes a `Copy` value to `AppState`" shape as `reachability`; loop itself untested by precedent |
| `dispatch` | route table (`ROUTES`), `serve` (generic over body type for testability), `resolve_doh_request`, `AppState<C>` (holds `in_flight: AtomicU64` **and** `gate: ConnectionGate` — `live_stats` fills `AdminStats.{in_flight, rejected_connections, active_connections}` from both); `serve_health` (`GET /health` — runs the local pipeline prefix for a sentinel domain, no upstream call); `read_watchdog_view(paths, now)` (reads `watchdog-state.json`, projects to `Option<WatchdogStatusView>`, stale/absent/internal-state → `None`, `now` injectable) fills `AdminStatusResponse.watchdog`. `POST /admin/rating-filter` → `serve_admin_rating_filter` → `apply_rating_filter_change` (holds `persist_lock` across validate→swap→cache-rebuild-if-still-on→persist; `wake_rating_filter_refresh`; response built after the guard drops). `rating_filter_is_active(&RatingFilterConfig, &ZoneLists) -> bool` = `enabled && !zone.is_empty()` — the **single** authority, called by both `resolve_doh_request` (pipeline gate) and `rating_filter_status_view` (the 3 `AdminStatusResponse` builders), so the badge and the pipeline can never disagree. **Deliberately takes only the downloaded `ZoneLists`, never the personal one** — the personal zone widens an already-active bubble, never activates one alone (an earlier draft that also checked the personal zone's emptiness here would let an `enabled=true`, empty-`lists` config get silently activated by personal-zone entries alone). **Not** in `FUZZ_EXCLUDED_ROUTES` (handler touches no external resource). `record_personal_visit`/`restore_personal_zone`/`rotate_and_republish_personal_zone`/`restore_rating_filter_removed` on `AppState` — see `personal_zone_stats`/`personal_zone_persist`/`zone_removal_persist`'s own rows. Every `ResolverConfig`-literal write site (the 4 non-`/admin/rating-filter` config routes) reads a **live** `personal_zone_config_snapshot()`, not a `PersistTarget` echo — the same live-read fix (T-217, 2026-09-12) was later applied to the `rating_filter` field's own sites, which used to read a stale `PersistTarget` snapshot instead |
| `admin` / `admin_ui` | `/admin/*` JSON DTOs + `AdminClient` (incl. `AdminClient::health()` → `HealthResponse`, `set_category_enabled`); `WatchdogStatusView` (`RESTARTING` [incl. `BackoffWait`] / `GAVE_UP`, a 2-variant UI projection of the 7-variant `WatchdogState`, narrower than §7.1 #7 by design); embedded browser config page (`include_str!` HTML/CSS/JS, strict CSP, no `unsafe-inline`). Basic view (hero protection status + master/category toggles + browser-setup card, fan-out/pass-through notices kept in basic) + a native `<details>` "Розширені" wrapping the technical cards (timeout mode, per-provider, cache, geoip, rating-filter, danger-zone). `RatingFilterStatusView`/`ZoneListStatusView`/`RatingFilterConfigUpdate` DTOs + `AdminClient::set_rating_filter`; `#rating-filter-body` card (own fetch/render off `GET /admin/status`, not the 2s poll — the zone combobox is a free-text input; `renderRatingFilterBadge` from `render()` *is* on the poll) + `#rating-filter-badge` slot. Mockup: `mockups/gui-dashboard.html`; UI-SPEC.md §2.1/§3.6. The `/admin/ui` hero's decisive priority ladder is **server-side** — `AdminStatusResponse.hero_state: HeroStateView` (8 variants) computed by pure `admin::compute_hero_state(watchdog, network, paused, has_active_provider, cert)` (called from both status builders, like `rating_filter_is_active`); `cert` is `Option<CertTrustView>` — `None` "not yet polled" → `Protected`, never a fabricated `CertUnknown`. `ProvidersResponse` += `category_states: Vec<CategoryFilterView>` (Off/Partial/On fold) + `master_switch_targets: Vec<Category>` (categories with ≥1 configured voter — the master-switch adult-opt-in guard). `main.js` is pure render (`HERO_PRESENTATION` map + `heroPresentation()`; `SERVICE_UNREACHABLE` synthesised client-side on a failed fetch — the one state the server can't self-report). Decisive assertions live in `admin::hero_and_category_tests` (real Rust tests), not `MAIN_JS.contains(...)`. **Authority boundary: `hero_state` drives the `/admin/ui` hero only — `dnsqb-tray/status.rs::from_response` keeps its own deliberately different ranking (Paused above the watchdog states); do not unify the tray onto this field.** The `/admin/*` DTO is versioned — `pub const ADMIN_DTO_SCHEMA_VERSION: u32` + `AdminStatusResponse.schema_version` (`#[serde(default)]` → `0` from a pre-versioning service); **every additive field carries `#[serde(default)]`** (with a `Default`/`#[default]` on its type — safe zero: `network`→`ONLINE`, `hero_state`→`PROTECTED`, `rating_filter`→off, …) so a newer consumer decoding an older service's response falls back instead of erroring; the load-bearing Ф1 fields (`active_providers`/`timeout_mode`/`timeout_ms`/`port`/`stats`/`persisted`) stay strict. `AdminClient::{status,apply,reset}` `tracing::warn!` on a version mismatch, never fail. **When you add an `AdminStatusResponse` field: bump the const AND add `#[serde(default)]`.** |
| `watchdog/` (SPEC.md §7) | **Primitives:** `instance` (T-92: `Role` ∈ service/watcher/tray, `acquire` → `share_mode(0)` `<role>.lock` guard, `write_pid_file`/`read_pid_file`); `frame`/`channel` (T-84 pure: 20-byte `Frame`; `channel_status(misses)` → `Signal\|NoSignal` at `MISS_THRESHOLD`=3, no `Dead`); `pipe` (T-84 `#[cfg(windows)]` named-pipe; server `respond_once` + `recreate`, client `ping`); `heartbeat_file` (T-85: `touch`/`read` + pure `is_stale(now, mtime, threshold)`). **Decision core (3.2):** `vote` (T-87/T-88: two fixed-arity fns, never a slice — `vote_watcher_checks_service` 2-of-3, `vote_service_checks_watcher` unanimous → `Liveness`); `backoff` (T-90: `next_backoff` over `[1,2,4,8,16]s`, cap 16); `budget` (T-91: `RestartBudget::register_attempt(now)` → `{Allowed,GaveUp}`, 5/600s rolling per-target; `::restored(window, attempts)` from persisted fields — a watcher restart doesn't reset the count); `pid_check` (T-89: `verify_pid_alive(pid, expected_exe)` → `{Alive,Gone,IdentityMismatch}` via `sysinfo`, PID **+** exe identity); `spawn` (pure `resolve_sibling_path` rejects non-absolute; thin `spawn_sibling` → `NotFound`, never PATH/CWD; no `kill`); `state` (`WatchdogState` 7-variant + `WatchdogTarget` 2-variant + `WatchdogStateFile` §7.1 #7 + atomic `write`/`read`; `last_error: Option<WatchdogErrorLabel>` closed enum); `transition` (pure total automaton step, returns next state only). **Assembly:** `loop_driver` (pure `LoopDriver::{new,restored}` + `tick(now, &ChannelObs) -> TickOutcome{state, effects: Vec<Effect>}` — owns miss counters / `RestartBudget` / backoff deadline / spawn-once latch; `Direction::{WatcherToService, ServiceToWatcher}` a param); `launcher` (pure `plan_launch(Option<&PidFile>, Option<PidCheck>) -> {AlreadyRunning, Spawn}` idempotency; the impure shell `ensure_sibling_running(app_data, role)` = read pid file → `verify_pid_alive` → `plan_launch` → `spawn_sibling`, re-exported from `lib.rs`, called by both `dnsqb-watcher` and the `dnsqb-tray` safety net). The running I/O shells live in the two `main.rs` (`#[cfg(windows)]`, untested by the `dnsqb-service` main precedent). |
| `geoip` / `geoip_credentials` / `geoip_download` / `geoip_updater` | `GeoipReader` country lookup — `country()` tries the nested `["country","iso_code"]` path (DB-IP/GeoLite2) then falls back to a flat `["country_code"]` field (T-226(б)). `GeoipSource` = `UserCountry` (`sapics/ip-location-db`, default since T-226(б) 2026-09-12, PDDL, no registration) or `Maxmind` (opt-in, Basic auth, `.tar.gz` extract — T-80). **`DbIpLite`, the former default, is not selectable by any production code path any more** — no config field or route constructs it (`load_geoip_source` and its two `dispatch.rs` mirrors all fall back to `UserCountry`) — kept in the enum only as a one-line revert path, not a live option. `geoip_credentials::{save,load,clear}` (T-163) store the MaxMind account-id+license-key JSON blob in the OS secret store (`key_store::maxmind_credentials_entry`), not a file; `migrate_legacy_credentials_file` folds a pre-T-163 plaintext `geoip_maxmind.toml` in once and unlinks it (delete-after-store is safe here — a credential is re-typeable, unlike the TLS key). `geoip_updater::check_maxmind_credentials` = one status-only authed probe (10s timeout) for the save-time check; `MaxmindHealth` (`health_after_refresh`, pure) tracks whether the stored key is still accepted at the 24h background refresh. `GeoipSource` lives on `AppState` (`RwLock<Arc<_>>`); `run_geoip_updater` re-snapshots it each cycle and parks on `sleep`-or-`Notify` so a creds change is picked up with no restart. Bounded download + integrity gate (hard-fail sha256 for `user-country` — a confirmed real sidecar, unlike DB-IP's/MaxMind's opportunistic ones) + atomic swap |

Admin channel — same loopback TLS port as `/dns-query`, `application/json` CSRF gate on every
write route, the full set enumerated in `dispatch::ROUTES` (a path/method not in that table can
never reach a handler): `GET /admin/status`; `POST /admin/config`, `/admin/reset`,
`/admin/shutdown`; `GET|POST /admin/overrides[/add|/remove]`, `/admin/cache-config[/apply]`,
`/admin/geoip[/add|/remove]`, `GET|POST /admin/geoip/maxmind` + `POST /admin/geoip/maxmind/clear`
(MaxMind creds → OS secret store; POST stores then runs a save-time probe → `check`, and updates
the live `GeoipSource` + wakes the updater; `refresh_health` on the view flags a key that started
failing later), `GET /admin/providers`
+ `POST /admin/providers/{add,remove,set-enabled,set-category-enabled}` (provider list edited
here, **not** `/admin/config` — which carries `timeout_mode` +
`serve_baseline_when_filters_unreachable`. `set-category-enabled` flips every voter in one
`Category` atomically, one `resolver_config.toml` write; turning on an empty `ADULT_CONTENT` adds
`opendns-familyshield` in the same txn, `EMPTY_ADULT_CATEGORY_DEFAULT_PRESET`, DECISIONS.md),
`/admin/log[/clear]`; `POST /admin/rating-filter` (`RatingFilterConfigUpdate { enabled, lists }`,
full replace; shares `persist_lock`; validates `lists` shape + `AVAILABLE_TOPN_LISTS` membership →
`400`; wakes `run_topn_updater`; rebuilds the verdict cache when it leaves the filter on; **not**
in `FUZZ_EXCLUDED_ROUTES`); `POST /admin/uninstall-local-state` (no body fields, never touches
`resolver_config.toml`); `GET /admin/cert-status` (`CertStatusResponse { trusted: CertTrustView }`,
three-state `TRUSTED`/`NOT_TRUSTED`/`UNKNOWN`; read-only, no CSRF gate — a pure read of
`AppState.cert_trust` (`RwLock<Option<CertTrustView>>` — `None` "never checked" ≠ `Some(Unknown)`,
collapses to `UNKNOWN` on the wire), a cache kept warm by the detached `cert_watch::run_cert_trust_watch`
60 s poll (`spawn_blocking(is_trusted)` on `<app-data>/cert.pem`); `/admin/install-cert` →
`Trusted` and `/admin/uninstall-local-state` → `NotTrusted` poke it synchronously; spawns no
`certutil` per call → **not** in `FUZZ_EXCLUDED_ROUTES`) + `POST /admin/install-cert`
(`ensure_installed` via `spawn_blocking`, `InstallCertResponse { outcome }`; mutates
`CurrentUser\Root` like `/admin/uninstall-local-state`; **stays** in `FUZZ_EXCLUDED_ROUTES` — mutating);
`GET /admin/ui`, `/admin/ui/main.js`, `/admin/ui/style.css`. Also on the same listener but
**not** an admin route: `GET /health` (watchdog channel 3 — no CSRF gate, read-only,
`HealthResponse { active_providers, geoip }`; the 200 itself is the health signal). The MaxMind
creds are their own OS secret-store entry with a single writer (that one POST route), not part of
`resolver_config.toml` — no shared lock.

**Every route that re-serializes `resolver_config.toml` shares `state.persist_lock` and reads the
other fields' live values before saving** — skipping this (writing one field from a stale
in-memory copy of the rest) is this project's single most recurring bug class: reading a field
live but not holding the lock across the read+write, or vice versa, silently discards a
concurrent write to an unrelated field. Related: "A failed disk save must surface `persisted:
false`" under "Recurring patterns" below is the client-visible symptom of the same lock
discipline lapsing.

`dnsqb-tray` — tray icon (`tray-icon` / `tao` / `rfd`), polls `/admin/status` on its own OS thread.
Menu (lifecycle group at the bottom): "Відкрити налаштування" (browser → `/admin/ui`) · "Скинути
кеш і лог" (soft `/admin/reset`) · "Про програму" · "Майстер налаштування" (manual re-entry to the
first-run wizard) · cert group ("Встановити"/"Видалити"/"Перевипустити сертифікат") · "Повністю
видалити" (clears cert+secrets, shows the report, writes `stop.flag`+`quit.flag`, spawns a
detached hidden `powershell` (`self_uninstall.rs`) that waits for every DNS-QF process to exit
then wipes all of `%LOCALAPPDATA%\dns-quorum-filter`, opens `ms-settings:appsfeatures` via
`explorer.exe`, then sets `QUIT_REQUESTED` so the event loop exits) ·
**"Призупинити ↔ Відновити фільтрацію"** (label flips on `stop.flag`; pause = `set_stop_flag`
**only** (no `/admin/shutdown`) behind a confirm dialog — the service stays up and serves the
unfiltered baseline via `pause_watch`; resume = `clear_stop_flag` +
`ensure_sibling_running(Service)` (idempotent no-op unless both siblings died mid-pause))
· **"Відновити нагляд"** (`ensure_sibling_running(Watcher)` — the only manual recovery for a dead
watcher) · **"Сховати іконку"** (exits the tray only) · **"Вийти з DNS Quorum Filter"** (confirm
dialog → `set_stop_flag` + `set_quit_flag` + `ControlFlow::Exit`; the watcher's next tick sees
`quit.flag`, stops the service and exits). A rotation needs a manual `dnsqb-service` restart
before the new cert is served. Also takes the `Tray` single-instance guard + writes `tray.pid` on
startup, and runs `ensure_sibling_running(Watcher)` as a safety net if launched standalone.

Tray runtime icon: four colour blobs `crates/dnsqb-tray/icons/tray-32-{green,amber,grey,red}-rgba.bin`
(`gen-icon.py`'s `make_tray_glyph(size, colour)`, GitHub Primer palette). `status::icon_colour(TrayStatus,
cert_trusted) -> IconColour` picks one:
🟢 `Filtering` (incl. a partial degraded count — a recovered blip is not an alarm) · 🟡
`Filtering` when **every** recent quorum query degraded (`degraded_events == degraded_window`),
`ServiceRestarting`, `Offline` · ⚪ `Paused`,
`NoActiveProvider` · 🔴 `Unreachable`, `ServiceGaveUp`, **and `Filtering` when the cert isn't
trusted** (override — flips `Filtering` **only**; `NoActiveProvider`/`Paused`/`Offline`/watchdog
stay their row colour, SPEC §3/§8.1 "pass-through ≠ failure"). The cert issue reaches those other
states as a `status::cert_warning` tooltip suffix (`compose_tooltip`), not a red glyph.
`cert_trusted` = read-only `trust_store::is_trusted(cert.pem)` polled by a **dedicated thread**
(`status::spawn_trust_watch` — `certutil` is blocking, off the 2s poll loop; the displayed flag
seeds `true` so "unknown" ≠ "untrusted", but the poll *cadence* (`next_delay`) keys on a
**confirmed `Ok(true)`** — an `Err` first poll before `cert.pem` exists takes the 2→5→15→60→300s
back-off ladder, not the 300s slow branch, or a fresh install shows green for 5 min; cert menu
items call `request_recheck()`). `refresh_tray` commits `last_colour` only on `set_icon` success.

**First-run onboarding:** `onboarding` module — pure `should_offer_onboarding(cert_confirmed,
cert_trusted, seen)` (fires only on a **confirmed** untrusted reading — `TrustState.is_confirmed()`,
set on the first `Ok(_)`; `cert.pem` is absent when the tray starts on a fresh install) +
`onboarding.seen` marker file in app-data (NOT `lifecycle.rs` — that's cleared on startup; this
must survive launches). `maybe_offer_onboarding` (once-per-process latch, called each event-loop
tick) → `run_setup_wizard` (own `std::thread`, `rfd` Yes/No; on Yes reuses `spawn_cert_action` →
`ensure_installed` → marker + open `/admin/ui` **only on success**). Same wizard on the "Майстер
налаштування" menu item.

**Tooltip states:** `Unreachable` / `ServiceRestarting` / `ServiceGaveUp` (read from
`watchdog-state.json` via `status::watchdog_override`, checked **before** `/admin/status`, ranked
above `NoActiveProvider`) / `Paused` (read straight from `stop.flag` in the poll thread, ranked
**above** the watchdog/admin states: while paused the watchdog file goes stale by design and the
service is deliberately down, so without this a pause reads as a misleading `Unreachable`) /
`Offline` (`from_response` returns it before `NoActiveProvider` when
`AdminStatusResponse.network == OFFLINE`; ranked below the watchdog states, above 0-voters) /
`NoActiveProvider` / `Filtering`; `Filtering` appends a degraded-upstream tooltip suffix when
`AdminStats.degraded_events > 0` (raw counts over the last 20 `QUORUM`/`BASELINE_FALLBACK` log
entries). **The tray *icon* only goes amber on `degraded_events == degraded_window` — a partial
count is a recovered blip, tooltip only.** `TrayStatus::Filtering` also carries
`rating_filter_active: bool` (from `AdminStatusResponse.rating_filter.active`); `compose_tooltip`
appends "— рейтинг-фільтр «бульбашка» активний" **after** the degraded suffix, **only when
`active`** (`enabled` but no list gets no tray suffix — the `/admin/ui` card's own notice covers
it). The icon colour is untouched by this — the bubble is a scope choice, not a health signal
(same "pass-through ≠ failure" rule as `NoActiveProvider`).

`dnsqb-watcher` — the watchdog process (SPEC.md §7), real `main`.
`#[tokio::main(flavor = "current_thread")]` (§7.1 #9 — flavor, not features, keeps it
single-threaded: the `dnsqb-service` lib dep unifies `rt-multi-thread` in regardless).
`windows_subsystem = "windows"` under `not(debug_assertions)` — the MSIX entry point, so a
console-subsystem build made the Start-menu tile open a terminal whose close killed the group.
Startup: `dnsqb-watcher::main` **clears both `stop.flag` / `quit.flag`** (a fresh launch is a
clean slate, so an app restart also lifts a pause); `Watcher` guard + `watcher.pid`; **idempotent
launcher** — `ensure_sibling_running(Tray)` **first** (icon in ~0.2 s), then
`ensure_sibling_running(Service)`, once each; a second watcher instance (re-clicked tile) hits
`AlreadyRunning` → `ensure_sibling_running(Tray)` + `exit(0)` ("click the tile again = show the
icon"), clearing only `quit.flag`. Then the `watcher→service` loop (5s tick: IPC ping/pong channel
1, `service.hb`/`watcher.hb` channel 2, `GET /health` via cert-pinned `AdminClient` channel 3;
`LoopDriver` 2-of-3 vote; `spawn_sibling(Service)` on a confirmed-dead service; **sole writer** of
`watchdog-state.json`, rewritten every tick for `mtime` freshness). The loop checks `quit.flag`
(→ stop service, `exit(0)`). **A pause keeps the service up** (it reads `stop.flag` itself via
`pause_watch` and serves the unfiltered baseline, not killed by the watcher), so the normal tick
sees a healthy service and is a no-op; a genuine crash mid-pause respawns (the new service
re-reads `stop.flag`). Children are spawned detached (`DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB`
via safe `creation_flags`, fallback to `DETACHED_PROCESS` alone on `ERROR_ACCESS_DENIED`).
`resume`s a <90s-old state file via `LoopDriver::restored`. Depends on `dnsqb-service` as a lib
(§7.1 #6).

### GeoIP workstream (Фаза 2)

**Complete, closed 2026-08-31.** T-74–T-82 (reader, background updater, pipeline wiring, admin
routes/UI, MaxMind opt-in source + OS-secret-store creds) — full per-task history in
`TASKS-DONE.md`. Runtime provider list is no longer hardcoded to two (T-72/T-73: 10 §3.4 presets +
custom-URL entry, 3 `BlockSignature` heuristics, 4 `/admin/providers/*` routes). **T-164**
(ECS-enabled upstream) was **rejected** — Quad9 forwards the client's real /24 regardless, a
`127.0.0.1` resolver can't coarsen it; rationale in SPEC.md §3.4 "Розглянуті й відхилені
провайдери". Second/third-platform work (macOS/Linux halves) is `## Фаза 6` in TASKS.md/SPEC.md —
planned, deferred, with the standing seam requirement in "Current phase boundaries" below.
**T-226(б) (2026-09-12, DECISIONS.md):** default GeoIP source changed to `sapics/ip-location-db`'s
`user-country` (PDDL, no registration) — DB-IP Lite kept, not removed.

GeoIP design invariants (SPEC.md §3.5): the verdict is never cached — a cheap local lookup applied
live on every cached-or-fresh ALLOW, so a blocked-country-list change takes effect on the next
lookup with no invalidation logic. `geoip::blocking_country` (the filtering decision) takes
`blocked_countries`; `geoip::resolved_ip_country` (informational log metadata, T-161) deliberately
does **not** — structurally incapable of becoming a filter later. The allowlist branch and the
every-provider-disabled pass-through are exempt from GeoIP *filtering* but still get
`resolved_ip_country` annotation.

### Фаза 1 closure — open gaps (not numbered tasks; see SPEC.md's closure paragraph)

Both open gaps from Ф1's closure are resolved; full methodology, raw output paths, and re-measure
numbers are in `TASKS-DONE.md` (T-172, T-174, T-175) — kept only as one-liners here:

- Live "browser → local DoH" test — **closed by T-172 (2026-09-06)**, verified via
  chrome-devtools MCP against a real Chrome `secure` DoH config. Procedure in `README.md`
  ("Перевірка: браузер → локальний DoH").
- Quorum-hypothesis metrics — **closed by confirmation, T-174/T-175 (2026-09-05/06)**: quorum
  **89.2 %** vs. best single voter **82.9 %** (`dns4eu-protective`), +6.3 pp. Hypothesis
  confirmed (DECISIONS.md 2026-09-05, PERFORMANCE.md).

### Known limitations in shipped code

Moved to [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) — this is the fastest-growing part of
`CLAUDE.md`, one bullet per newly-found live limitation, and was pushing the file toward its CI
size ceiling (`.github/workflows/claude-md-size.yml`). Read it before assuming a feature works
end to end; add a new bullet there, not here, only if a finished task leaves a live limitation
behind (narrative still goes to `TASKS-DONE.md`, never either of these files).

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
  — T-146's `encrypted_file` AEAD. RustCrypto, chosen over `aws-lc-rs` (user decision 2026-09-03 —
  pure Rust, no C toolchain). Full vetting/rationale: SECURITY.md row.
- `sysinfo` (`default-features = false`, `features = ["system"]`) — `watchdog::pid_check::
  verify_pid_alive` (T-89): the recycled-PID guard §7 requires before a restart (SPEC.md §7.1 #3).
  Links into `dnsqb-service` though only `dnsqb-watcher` calls it (§7.1 #6). Full vetting/rationale:
  SECURITY.md `sysinfo` row.
- `winreg` (T-227, `[target.'cfg(windows)'.dependencies]`) — `install_region::detect_system_region`
  reads `HKCU\Control Panel\International\Geo`'s `Name` value to suggest a matching rating-filter
  zone; chosen over `GetUserDefaultGeoName` directly (that Win32 call is `unsafe fn`, incompatible
  with this project's `forbid(unsafe_code)`) and over `sys-locale` (wraps UI display language, not
  region — wrong signal). Full vetting/rationale: SECURITY.md `winreg` row.
- `crates/dnsqb-tray`: `tray-icon` / `tao` / `rfd` (`default-features = false`) / `parking_lot` /
  `softbuffer` (T-229, `default-features = false` — its default features are Linux-only windowing
  backends); depends on `dnsqb-service` as a library for `AdminClient`.
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
  test turned out to have never run in CI). **`--lib --bins` also runs no `tests/` integration
  binary** — that is a third target class; each needs its own `cargo test --test <name>` line in
  CI (`conformance` and `admin_client` are the two wired in — T-201's `tests/admin_client.rs`
  would not have run without adding its line). **`cargo test ... --bins` builds the *test-harness*
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
- `cargo test --workspace --doc` — doctest gate, required, and **now has teeth** (T-207, Батч RV):
  8 runnable `# Examples` on pure leaf functions of the `lib.rs` re-export surface
  (`normalize_domain`, `min_rrset_ttl`, `negative_cache_ttl`, `should_serve_stale`, `next_backoff`,
  `channel_status`, `ZoneLists::zone_match`, `SinkholeNet::contains`). The `min_rrset_ttl` /
  `negative_cache_ttl` examples construct `hickory_proto` `Record`/`SOA` values — the one place a
  doctest depends on a transitive dep's constructor API. `--lib --bins` does **not** run doctests
  — run `cargo test --workspace --doc --locked` before a push that touches a `pub` re-export's
  doc comment.
- `cargo run --example sinkhole_probe` — T-175 recalibrator (live, not CI): each sinkhole-preset
  canary must still resolve inside its `SINKHOLE_NETS` prefix (A + AAAA), the provider's own site
  must not; non-zero exit if a prefix looks stale. **Run before a release** — a hard-coded prefix
  silently under-counts a voter if the provider rotates its block IP. `cargo test -p dnsqb-service
  --lib -- --ignored` also runs it as `#[ignore]`d live-verify tests (`quorum::tests::live_sinkhole_*`,
  plus `upstream`'s live-Quad9 test).
- `cargo run --example curate_topn -- lists=ua,global n=1000` — T-107 Фаза 4 curation tool
  (**no DNS** — one HTTP GET per list, seconds). Fetches a CrUX top bucket (per-country from
  `InternetHealthReport/crux-top-lists-country`, or `global` from `zakird/crux-top-lists`),
  normalises origin→registrable via a bundled pinned PSL (`examples/public_suffix_list.dat`,
  MPL-2.0), writes `data/topn/<list>.txt` + `.txt.sha256` (stable paths, `#` provenance header) —
  the **raw** popular set, no content filtering. T-108 hygiene is lazy client-side (Батч 4.3): an
  in-zone domain quorum blocks is removed from the local zone set — a curation-time bulk scan
  (1000 DoH queries per resolver per regen) risks the address being rate-limited, and quorum runs
  anyway (DECISIONS.md 2026-09-09). Normally run via `.github/workflows/topn-curate.yml`
  (`workflow_dispatch`) → artifact → human PR. Example `#[cfg(test)]` modules run in CI via
  `cargo test --workspace --examples`.

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
regenerate `assets/icon/*.png` + `app.ico` + `assets/icon/wordmark.png` **and** the four
`crates/dnsqb-tray/icons/tray-32-{green,amber,grey,red}-rgba.bin` blobs (T-191 — the tray's
runtime `Icon::from_rgba` per-status glyphs, `make_tray_glyph(size, colour)`; replaced T-183's
single `tray-32-rgba.bin`) after editing it, never hand-edit a PNG/`.bin`; needs Segoe UI Bold
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

## Rust/tooling gotchas

Moved to [RUST-GOTCHAS.md](RUST-GOTCHAS.md) — it was the single largest contributor to this
file regrowing past its CI size ceiling (`.github/workflows/claude-md-size.yml`). Read it
before touching wire-format/TTL/cache/persistence/watchdog/MSIX-packaging code; add a new
entry there, not here, on the same trigger CLAUDE.md's own maintenance rule already states.

## Documentation map — who owns what

| File | Owns | Update when |
|---|---|---|
| `SPEC.md` | full design + reasoning: architecture, RFC table, phased plan, open questions | a design decision changes or a new one is made |
| `UI-SPEC.md` | GUI: screen inventory, per-screen field/type tables, DTOs for the admin HTTP channel (not Tauri — that channel was removed at T-149) — no rationale, links back to SPEC.md §8 by section number | a screen, field, or DTO changes; rationale changes go in SPEC.md instead |
| `diagrams/` | architecture + UI diagrams, each anchored to a SOURCES section list; ground-truth ritual in `diagrams/README.md` applies from here on | a diagrammed state/flow/DTO changes — see the ritual's trigger list |
| `CLAUDE.md` | agent-facing summary: commands, architecture at a glance | architecture/commands change |
| `RUST-GOTCHAS.md` | non-obvious Rust/tooling gotchas learned by doing — split out of `CLAUDE.md` once it became that file's single largest section | a new empirically-verified gotcha is worth not re-deriving next time |
| `KNOWN-LIMITATIONS.md` | live limitations in shipped code, no task number unless noted — split out of `CLAUDE.md`'s `Project state` once it became the fastest-growing section | a finished task leaves a live limitation behind (narrative still goes to `TASKS-DONE.md`) |
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
5. Rating filter (5.3, opt-in, default-OFF; T-124 BUILT) → BLOCK (not cached) if domain outside
                       every active zone (curated per-country top-N ∪ global ∪ [gov/edu/personal
                       — 4.2/4.5] minus lazy-hygiene removals); in-zone → proceed unchanged,
                       NEVER force-ALLOW. Runtime host→registrable = suffix-walk, no PSL
6. Quorum           → query the enabled voter set, OR-logic
7. GeoIP (3.5)      → applied live to cached or fresh ALLOW responses, never cached itself
```

There is **no "voter scope" step** — §5.1 (top-sites excluded from Ads/Adult voters) was removed
2026-09-07 (T-179, DECISIONS.md); the top-sites mechanism is now only the rating-filter "bubble"
(step 5), which never narrows the voter set. This pipeline was revised several times in SPEC.md
(top-sites: bypass → voter-scope → removed; rating filter: step 0 → late local step; moved Фаза 5
→ Фаза 4) — treat the §5.3 diagram as current, the §3.5/§5 ones as superseded context.

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
- **Rating filter «bubble» (§5.3, T-124 BUILT) can only BLOCK, never force-ALLOW.** A domain inside
  the allowed zones just continues through the normal pipeline (quorum → GeoIP) rather than skipping
  it. Out-of-zone → BLOCK, quorum never runs, **not cached**. Opt-in, default-OFF (mandatory, not
  a judgment). §5.1 (a separate always-on top-N voter-scope exemption) was removed — the bubble is
  the only top-sites mechanism (T-179). Runtime host→registrable is a **suffix walk over the zone
  set, not a PSL** (the published lists are already registrable-only). Lazy hygiene (T-108): a
  fresh quorum block of an *exact* in-zone registrable evicts it from an **in-memory** removal
  overlay (own lock, separate from the zone `Arc`); a subdomain block evicts nothing. Overlay
  persistence is Батч 4.5.
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
later phase for a stated reason (e.g. GeoIP and the rating-filter «bubble» are deliberately deferred
past Phase 1 because they're independent of the core quorum hypothesis being validated first).

**Second/third desktop platform (macOS, Linux) is its own final phase — `## Фаза 6`** (moved
there 2026-08-31: no macOS build/test access in this environment). It is a *planned* target, not
"maybe someday" — so the standing architectural invariant is that platform-specific code sits
behind a boundary that can be lifted under `#[cfg(target_os)]` / a trait **without a rewrite**,
never hard-coupled to Windows. `key_store` (via `keyring`) already meets this; `trust_store` does
not yet (no trait, no `#[cfg(target_os)]`) — the port builds that boundary from scratch, named
ahead of time. When adding Windows-specific code (a spawned `certutil`/`rundll32`, a registry
call), keep the seam visible rather than inlining the assumption.
