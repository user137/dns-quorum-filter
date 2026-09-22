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
  `from_persisted` rebuilds it with the new size on the next process start. (The separate,
  deeper T-221 gap this bullet used to describe — `[personal_zone].enabled` and the other
  thresholds not reaching the live gate at startup at all — is fixed; see TASKS-DONE.md.)
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
- **`[blocklist_bundles]` can stay actively blocking on a stale, non-empty set** (T-218, Батч
  7.4) — `enabled = true` with `sources = Some([])` (or a config edit that shrinks `sources` to an
  empty explicit list) makes `refresh_all_sources` return before touching the bundle, same as
  `enabled = false`; `blocklist_bundles_is_active` only checks `config.enabled`, not whether
  `sources` is now empty, so a *previously* populated bundle keeps blocking every query
  indefinitely. Same already-accepted class of staleness as `[rating_filter]`/
  `topn_updater::refresh_all_lists` (an emptied `lists` doesn't clear the zone either), but a
  larger blast radius here (up to ~5.5M hashed entries, not a curated top-N list). **The
  `#blocklist-bundles-body` card now renders this state (Батч 7.4 частина 3, 2026-09-17)** — an
  all-unchecked selection shows an explicit "лишається чинним, не очищується автоматично" notice
  instead of a silent Fork-B "loading" lie, so an operator reading `/admin/ui` is no longer blind
  to it either; the underlying staleness itself is still unfixed — the card explains the state, it
  doesn't clear it.
- **Partial runtime integrity check on the 7 fetched blocklist sources** (T-218 Фаза 7, T-233,
  narrowed 2026-09-17, extended same day, PSL filter added 2026-09-18). `blocklist_download::validate_hashes`
  gates each source on a parse-success ratio (`MIN_PARSE_SUCCESS_RATIO` = 0.5) and an exact-match
  canary-domain check (`BLOCKLIST_CANARY_DOMAINS`, ≥2 hits rejects); `delta_verdict` additionally
  gates on the entry count vs. the last successful cycle's count (persisted in a new
  `<id>.count` file next to `<id>.txt`, `MAX_COUNT_GROWTH_MULTIPLIER` = 5× /
  `MIN_COUNT_RETENTION_DIVISOR` = 5, skipped below `MIN_COUNT_BASELINE` = 5000 entries or past a
  7-day `DELTA_CHECK_GRACE_PERIOD` since the last success). All three run **before** the fetched
  body ever reaches disk — a rejected cycle falls back to last-known-good exactly like a network
  failure, and never poisons that fallback or the delta baseline (T-233's own closing-review
  catch, part 1: the write used to happen before the hash/validate step). **Ingestion also drops
  any candidate that is itself, in its entirety, an ICANN-section public suffix** (`co.uk`,
  `pl.ua`, …) via `public_suffix::Psl::is_public_suffix`, so a single such line no longer blocks
  the whole legitimate namespace under it — measured against the real ~4.1M lines across all
  eight sources (2026-09-17): 4 ICANN-section hits total, none in `hagezi-hoster`/`hagezi-dyndns`
  (whose 468/8 bare PRIVATE-section entries are their intended purpose and are deliberately left
  unfiltered — DECISIONS.md has the full measurement). Still open:
  - **None of the checks catches injecting a small number of legitimate domains into a
    large list** — T-233's own stated primary threat model. Ratio is unaffected (the injected
    lines are valid domains); canary only catches the 12 specific compiled-in domains; delta is
    unaffected at any realistic injection volume (1,000 domains into `hagezi-nrd`'s measured
    3,181,194 entries is a 0.03% shift, far inside any threshold wide enough to tolerate that
    source's own day-to-day registration churn); the PSL filter only catches a *single whole
    public suffix as one entry*, not a handful of ordinary-looking registrable domains. This is a
    structural gap across all four gates, not a bug in any one of them — closing it needs a much
    larger, continuously maintained canary set (or an equivalent reputation signal), nothing
    already planned.
  - **The canary gate is per-source, not per-bundle** — a source with fewer than 2 injected
    canaries (or a different injected domain per source) passes even though the combined
    multi-source bundle could still accumulate several. Deliberate (per-source is what makes
    last-known-good fallback work at all), but a real limit worth knowing before relying on the
    canary check as a cross-source guarantee.
  - **The two smallest real sources get no delta protection** — `hagezi-hoster`/`hagezi-dyndns`
    (1,251/1,547 entries measured 2026-09-17) sit below `MIN_COUNT_BASELINE`, so `delta_verdict`
    skips them unconditionally; there is no per-source-calibrated threshold, only the one global
    floor (no multi-day history exists yet to calibrate anything tighter).
  - **The PSL filter doesn't consult PSL exception rules** (e.g. `!city.kawasaki.jp`) —
    `is_public_suffix` can treat a string as a public suffix when an exception rule would actually
    make it registrable. The failure direction is under-filtering (one fewer real block-target
    line kept), never over-blocking, so this is accepted rather than reproducing
    `Psl::registrable`'s full exception walk on the ingestion hot path (`public_suffix.rs`'s own
    doc on `is_public_suffix` has the detail).
  - **A source frozen on a rejected/failed cycle ages silently** — same accepted posture as
    `user-country` GeoIP's own bullet below: the only operator-visible signal is
    `last_error`/an aging `last_updated` on the `#blocklist-bundles-body` card, no escalation after
    N consecutive rejections.
  - **Resource exhaustion (large `Vec<u64>` within `MAX_BLOCKLIST_BYTES`)** — mitigated by T-232's
    `spawn_blocking` move (CPU cost hits the blocking pool, not the async worker), not eliminated.
  See T-233 in `TASKS-DONE.md` (closed 2026-09-18, all three planned parts shipped) for the full
  threat-model writeup; the one remaining structural gap (small-domain injection) is tracked as
  T-234 in `TASKS.md`'s backlog.
- **i18n locale dictionaries (T-236, Батч 5.4) — 35 of 37 are machine-translated, not natively reviewed; the whole `/admin/ui` key set (~330 keys after Батч 5.4), not just the T-236 pilot.**
  `uk`/`en` predate T-236 (Батч 5.2) and were reviewed then; the other 35 `ui/i18n/*.json` files
  were translated by Claude with a self-review pass covering structural correctness only (glossary
  consistency, JSON validity, the measured `Intl.PluralRules` category shape) — not idiomatic
  quality or register, which only a native speaker can confirm. See `ui/i18n/GLOSSARY.md`'s own
  closing note. Also: `ar`/`he`/`ur` (RTL) get a correct `document.dir` but not a mirrored
  flex/grid layout — text reads right-to-left correctly, but component layout (the locale
  switcher, cards, buttons) stays left-to-right-oriented; full RTL mirroring via CSS logical
  properties is unscoped future work.
  **Verified in a real browser 2026-09-22** (T-238 smoke test, `chrome-devtools` MCP, live
  `setLocale()` across all 37 locales, both collapsed and expanded "Розширені" view): 0 raw
  `a.b.c` keys, 0 unsubstituted `{token}`s, `#advanced-settings`'s open state survives a locale
  switch. **One real regression found this way, filed and fixed as T-240 (`TASKS-DONE.md`,
  2026-09-23)**: the custom DoH-provider add-form (`customProviderForm()`) caches its whole DOM
  node to protect in-progress typed input (T-47) and, as a side effect, never re-translated on a
  later `setLocale()` — the one render path in the whole batch a fresh-module-per-locale `node vm`
  smoke structurally cannot reach, exactly as anticipated below. Fixed by
  `retranslateCustomProviderForm()`; **the fix itself was not re-verified in a real browser**
  (T-240's own closing note, TASKS-DONE.md) — a native Windows cert-trust confirmation dialog
  blocked automating a scratch instance. RTL mirroring, the first-visit browser-setup auto-open
  label, and the tray/CLI (Батч 5.5/5.6) remain unexercised by this pass.
  Translated browser-menu labels in `browserSetup.*` are quoted in English on purpose.

