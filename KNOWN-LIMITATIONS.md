# Known limitations in shipped code

No task number unless noted; the full open backlog with task numbers is in TASKS.md. Referenced
from CLAUDE.md's "Known limitations" pointer -- this file exists for the same reason
RUST-GOTCHAS.md does: it is the part of CLAUDE.md that grows fastest, one bullet per
newly-found live limitation, and was pushing the file toward its CI size ceiling
(.github/workflows/claude-md-size.yml). Same maintenance rule as CLAUDE.md's own "Project
state" section: a finished task adds a bullet here only if it leaves a live limitation behind --
the task's own narrative (rationale, advisor catches, verification notes) goes to
TASKS-DONE.md, never here.

- **Rating filter (T-124)** — ~~(a) enable-needs-restart~~ / ~~(b) already-cached domains outlive
  a new bubble~~ **both closed in Батч 4.4** (T-127: `run_topn_updater` always spawns; the enable
  route rebuilds the verdict cache). ~~(c) The lazy-hygiene removal overlay is in-memory only~~
  **closed in Батч 4.5** (T-108: `zone_removal_persist.rs`, `zone-removals.enc`, shared
  `persistence-key`, gated on `[rating_filter].enabled`). (d) The `#rating-filter-body` card's
  zone-count line reads `RatingFilterStatusView.loaded` (per-list, never a cross-source sum — a
  domain in both a country list and `global` would double-count, and since Батч 4.5 the personal
  source's own count is included the same way); a card shows "—" for a picked code with no loaded
  list yet. Not a bug — a stated choice, same "never a fake 0/0" discipline as T-66. (e) No
  `/admin/ui` button to clear the learned personal zone (Батч 4.5, T-138) — same stated gap as
  T-96/T-97's encrypted stores, clearable only via full uninstall (T-70). (f) A `[personal_zone]`
  window-length change (`frequency_window_days`/`regularity_window_days`) only fully applies after
  a restart — a live config reload (`/admin/reset`) picks up the new thresholds but
  `PersonalZoneStats`'s ring stays sized to whatever `window_len` it was constructed with; a
  *smaller* window is correctly capped at derive time, a *larger* one is under-served until
  `from_persisted` rebuilds it with the new size on the next process start. **A separate, deeper
  gap on the same table (T-221):** the *other* thresholds (`frequency_top_n`/`regularity_min_days`)
  aren't read from the restart-time TOML at all at derive time — `rotate_and_republish_personal_zone`
  reads them from a live `AppState` snapshot that starts at compiled defaults and is never
  initialized from `resolver_config.toml` at startup, only by `/admin/reset` (or 2 other admin
  routes). A config-file-only `[personal_zone]` change (no admin route exists for this table) needs
  one `/admin/reset` call to take effect at all, restart or not.
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
- ~~`cleanbrowsing-{security,adult}` have the wrong `block_signature`~~ — **fixed T-174**
  (2026-09-05): both were `NullIp` but block via NXDOMAIN; now `NullIpOrNxdomain`, live-verified.
- ~~`adguard-family` / `opendns-familyshield` / `dns4eu-{protective,child}` may block via a
  provider-specific sinkhole IP no `BlockSignature` recognises~~ — **resolved T-175 (2026-09-06)**.
  `quorum::evaluate` / `is_blocked` / `known_signal` gained a `&[SinkholeNet]` param; `upstream::
  sinkhole_nets_for(id)` returns a per-preset **network prefix** (RDAP-verified owner, not a
  vendor block-page doc): `adguard`/`adguard-family` `94.140.14.0/24`, `opendns-familyshield`
  `146.112.61.104/29`, `dns4eu-{protective,child}` `51.15.69.11/32` + native-v6
  `2001:bc8:…:3ec9/128` (both exact — Scaleway general hosting, no widening). `is_sinkhole_ip`
  matches **A and AAAA** (IPv4-mapped `::ffff:a.b.c.d` unwrapped to the v4 prefix — OpenDNS does
  this; `adguard*` returned NODATA on AAAA, no v6 entry). An answer in the prefix →
  `Signal::NeedsBaseline` (block only if baseline resolved `NoError`); composes with the existing
  signature. `adguard` (shipped default) also blocks some malware this way — quorum now counts it.
  Latent bug fixed en route: pre-T-175 a `NullIp`-signature voter returning a sinkhole IP was
  `NotBlocked`, so `representative_allow_answer` could forward the block-page IP to the browser as
  a real answer; now excluded (routes to the existing Allow/`answer: None` path).
  **Residual brittleness (Три Б):** the table is hard-coded — a provider moving its block IP to a
  different prefix silently under-counts that voter (false negative, never a wrong block). No
  passive alarm (the "0-in-prefix" predicate isn't computable — CDN variance dominates). Mitigation
  = `examples/sinkhole_probe.rs`, now a **recalibrator** (canary domain must land in the prefix,
  provider's own site must not; queries A + AAAA) — run before a release. DNS4EU's `/32` /
  `/128` rely entirely on it. Plus two `#[ignore]`d live smoke tests in `quorum.rs`
  (`live_sinkhole_presets_block_their_canary_through_the_prefix` /
  `..._do_not_block_a_normal_domain`) covering the 3 presets with a stable public canary
  (`internetbadguys.com`, `pornhub.com`) — `cargo test --lib -- --ignored`.
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
- **`trust_store::uninstall()` can never return `Ok(())` against the real store (T-220, found
  2026-09-12, not fixed).** `NOT_FOUND_EXIT_CODE = 17` (T-49) doesn't match the real, untruncated
  `certutil -store` empty-result exit code (`-2146893807`/`0x80090011` — `17` was only ever the
  POSIX-shell-truncated value). `confirmed_thumbprints_for_common_name`, the sole way
  `uninstall_loop` confirms the store is empty, therefore hits `ListFailed` on every call —
  affecting `cert_rotation::rotate_certificate` (live-reproduced: tray "Перевипустити сертифікат"
  fails even when the old cert really is gone) and `local_state::remove_all`'s cert artifact
  (always reports `Failed`). Not MSIX-specific, predates v0.4.0. Needs its own plan+advisor cycle
  before fixing — full record TASKS.md T-220.
- **`[personal_zone].enabled = true` in `resolver_config.toml` has no effect at process startup
  (T-221, found 2026-09-12, not fixed).** `AppState::new` hardcodes `personal_zone_config` to
  `PersonalZoneConfig::default()` (`enabled: false`); `restore_personal_zone` (called once at
  startup) only seeds `stats`/`zone`, never `config` — no startup code path calls
  `update_personal_zone_config`, only three `/admin/*` write routes do. The feature is inert from
  boot until then (`record_personal_visit`'s gate reads the same stuck flag, so visits aren't
  recorded either), not merely unpersisted — `personal-zone.enc` never appearing is a symptom, and
  `AdminStatusResponse.rating_filter.personal_zone_enabled` reads `false` right after boot even
  with the TOML set `true` (one-HTTP-call symptom, a natural regression-test anchor).
  `POST /admin/reset` is a live (undocumented) workaround: confirmed live — it calls
  `update_personal_zone_config` + wakes the flusher, the field flips to `true`, `personal-zone.enc`
  appears within seconds, and only *post-reset* queries get recorded (verified: 2 queries sent
  before the reset recorded nothing, 2 sent after showed up as `loaded: [{list:"personal",
  domains:2}]`). Needs its own plan+advisor cycle before fixing — full record TASKS.md T-221.
- **`self_uninstall.rs`'s app-data wipe helper is a no-op on the packaged MSIX build (T-222,
  found 2026-09-12, not fixed)** — same virtualization gap as T-219, in a subsystem T-219's fix
  never touched. Full record TASKS.md T-222.
- **The stored TLS private key (T-67) is never removed on uninstall yet** — `key_store::
  delete_secret` is no longer `#[cfg(test)]` (T-163 gave it a real caller — the creds-clear route)
  but nothing calls it for the *TLS key* entry on uninstall. A left-behind
  key in Windows Credential Manager after the app is removed is the same class of security bug as
  a left-behind trusted cert (SECURITY.md). Calling it for the TLS-key entry on uninstall is
  folded into **T-70** (the packaged uninstaller). Also `key_store::overwrite_with_zeros` before
  unlinking a migrated plaintext file is a best-effort scrub only — no defence against VSS shadow
  copies or SSD wear-levelling.
- **Fuzz coverage (T-58, widened since)** — `overrides::parse_pattern`, `wire::decode_wire_message`,
  a dedicated `/admin/config` POST-body pass, **and**
  `dispatch::serve_never_panics_on_arbitrary_input_for_any_documented_route`: a proptest driven by
  `ROUTES` itself, so every route not in `FUZZ_EXCLUDED_ROUTES` is exercised — each route's GET
  query pair and each non-GET body, **`/dns-query` POST included** (`application/dns-message` +
  arbitrary bytes; the `decode`-branch reachability is pinned by a temporary `panic!()` per that
  test's comment). Still outside the fuzz surface: the two excluded mutating routes
  (`/admin/uninstall-local-state`, `/admin/install-cert` — real `certutil` / trust-store mutation;
  method + content-type gate tests only) and the upstream/quorum response-decode path (the property
  runs against a benign mock client).
- **The status indicator (T-56, narrowed)** — watchdog state is built (T-95: tray
  `ServiceRestarting`/`ServiceGaveUp` + `/admin/status.watchdog`); browser-DoH-usage detection
  (indicator condition 1) is still unbuilt (blocked on T-134). The full single-indicator UI (all
  conditions as competing states, not a `Filtering` suffix) is still future.
- **`user-country`'s GeoIP download URL has no fallback candidate (T-226(б), 2026-09-12)** —
  unlike DB-IP's two calendar-month URLs, `sapics/ip-location-db` publishes only one rolling
  release asset for this file, and its own README already records renaming its distribution once
  (June 2026). If the asset is ever renamed again, every refresh attempt fails forever; the
  existing "keep last-known-good + `tracing::warn!`" behavior absorbs it silently — the only
  user-visible signal is an aging `database_built_at_ms` on the GeoIP card, nothing louder.

