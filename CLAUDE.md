# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

Фаза 2, seventh GeoIP slice (T-78 — TASKS-DONE.md, one commit): the last remaining row of
`#geoip-body` (T-77) — `GeoipCountriesResponse` gained `database_loaded: bool` and
`database_built_at_ms: Option<u64>`, rendered as three always-visible text lines (never a banner,
same "always-on warning is functionally identical to no warning" reasoning already recorded for
T-56/T-57) instead of a single date field. Below the plan+advisor threshold (additive DTO field,
no new route/lock/state machine), so no Plan mode — a lighter `advisor` consult before writing any
code still caught a real design gap: `GeoipState` (T-75) has three reachable combinations —
`reader: None` (no database loaded, `GeoIP` filtering isn't happening regardless of
`blocked_countries`), `reader: Some` + a known build time, and `reader: Some` with `build_time()`
returning `None` — and a lone `Option<u64>` field couldn't distinguish the first from the third,
the same Три-Б "the user sees an absent date and assumes filtering is on" shape this project keeps
catching. Fixed by adding `database_loaded` as its own field rather than overloading the
`Option`. `admin::unix_millis` (already used for `LogEntryView.timestamp_ms`) widened to
`pub(crate)` and reused rather than duplicated. `database_built_at_ms` is the database's own
**build date** (`GeoipReader::build_time`'s embedded `build_epoch`), never a refresh-poll
timestamp — the same T-75 gotcha already in this file about why `SystemTime::now()` would be a
misleading, always-"today" value here; the UI label says "Дата збірки бази" (build date), not
"дата оновлення" (update date), for the same reason. 3 new `dispatch.rs` tests, one per
`GeoipState` combination — a new `state_with_geoip_database` test helper (since the existing
`state_with`'s `GeoipState::default()` can only ever exercise the "no database" branch) plus the
already-vendored `GeoIP2-Country-Test.mmdb` fixture. **Live-verified against the real binary, and
more thoroughly than planned**: copied the vendored fixture into a scratch `%LOCALAPPDATA%`,
started a real `dnsqb-service.exe` against it — `geoip_updater::run_geoip_updater` (T-75, runs
immediately at startup) **successfully downloaded a real, current DB-IP Lite database** (the file
grew from the 19,492-byte test fixture to 8,284,207 bytes, with a plausible recent
`database_built_at_ms`), unlike every prior session in this project (T-75/T-76/T-79 all recorded
`db-ip.com` as DNS-blocked in this dev sandbox) — this session's sandbox could actually reach it.
`GET /admin/geoip` against the running service returned `database_loaded: true` with the real
downloaded database's own build time, the first time this project's live verification has covered
the whole `geoip_updater` → `AppState::geoip` → `GET /admin/geoip` path against a genuine
network-fetched database rather than only the vendored fixture — named honestly as a one-off
environmental difference, not evidence the DNS block is gone for good. Both live queries landed
*after* the refresh completed (the "GeoIP database refreshed" log line preceded both requests), so
the fixture's own build time was never actually observed through this DTO live — that stays
covered only by `geoip.rs`'s pre-existing `build_time_reports_a_plausible_past_date_not_the_
current_moment` unit test, not overclaimed as a live result here. Chrome browser automation
was still unavailable this slice (`tabs_context_mcp`: "extension is not connected") — the actual
click-through and the three text lines' visibility are **not** verified, same T-77-precedent
fallback to a direct HTTPS round-trip (confirmed the rebuilt `main.js`/`style.css` were actually
served, both before and after the live query). Diagram ground-truth ritual run:
`diagrams/ui-dto-model.md`'s `GeoipCountriesResponse` class and its own prose section updated
(the real two-field shape vs. the draft's single `DateTime`, with the Три-Б reason named
explicitly); `diagrams/ui-navigation.md`'s GeoIP node **actually checked this time** (not silently
skipped, the way T-76/T-79 both left it) — its own third bullet already correctly named T-78, no
edit needed. `UI-SPEC.md` §3.5 marks the third row done with a note on the real DTO shape.
`SERVICES.md`'s `/admin/geoip` paragraph gained a sentence on the two new response fields.
`CONFIGURATION.md` checked, not edited — no TOML field changed, T-78 only adds response fields, a
deliberate non-edit rather than a symmetry-driven one. **New backlog item found while verifying
live and put directly to the user's question, not silently acted on**: `main.rs`'s
`load_geoip_state` reads the on-disk `geoip.mmdb` synchronously before the listener starts
accepting connections, unconditionally (even with an empty `blocked_countries`) — a real, if
one-time, startup-latency cost now empirically sized (8.3MB) rather than theoretical; per-query
behavior was already correct (the whole file is read once into memory, `maxminddb`'s `mmap`
feature deliberately left off per this crate's `#![forbid(unsafe_code)]` posture, never re-read
from disk per lookup). Filed as **T-160** (TASKS.md backlog), not designed or implemented this
slice.

Фаза 2, sixth GeoIP slice (T-77 — TASKS-DONE.md, three commits — two planned per the T-153 split,
plus one from a real advisor review of the already-committed result, not the plan): the first
live-write path for
`[geoip] blocked_countries` — new `GET /admin/geoip`/`POST /admin/geoip/add`/`POST
/admin/geoip/remove` plus a `#geoip-body` card on `/admin/ui`, matching the T-47 overrides-card
shape. Plan mode + a real advisor review of the plan before implementing (this repo's global
CLAUDE.md Agent Discipline rule, a genuine new admin-write surface) caught two real bugs before
any code existed: (1) the plan's first draft would have shown a permanently-visible CDN
over-blocking warning banner — flagged as the same "always-on warning is functionally identical
to no warning" trap already recorded for T-56, doubly so since T-57's own permanent notice was
later reversed at the user's explicit request (DECISIONS.md); fixed with a two-click confirm flow
(first "Додати" click arms the warning and requires "Підтвердити додавання"/"Скасувати", nothing
sent until the second click) so the warning is a genuine per-addition event, not a fixture. (2)
the plan's remove route validated/normalized the country code only on add — since the stored list
is always uppercase, a lowercase remove request would have silently no-op'd against it, looking
like a broken button with no error; fixed by routing remove through the same
`config::validate_country_code` (now `pub(crate)`) as add, both empirically confirmed as real
regressions (reverted each fix, watched the corresponding test fail, restored). Design decisions
made explicitly: new routes share `state.persist_lock` with `/admin/config`/`/admin/cache-config/
apply` (not an independent lock, since all three write the same `resolver_config.toml` — the same
cross-field-read discipline already fixed four times in this project, T-57/T-139/T-149/T-47, now
extended a fifth); no cache-invalidation call on change, unlike overrides — a `GeoIP` verdict is
never cached at all (SPEC.md §3.5), so a list change takes effect on the very next lookup with no
invalidation logic needed. `AppState::update_geoip_countries` (T-76) stays the single writer,
shared with `apply_admin_reset`, rather than the new routes touching the `RwLock` directly. 11 new
`dispatch.rs` tests, including two cross-field regressions (an unrelated geoip add must not wipe
`providers`/`timeout_mode`/`[cache]`, and vice versa — mirrors the existing T-76 tests one
direction over), both empirically confirmed against a reverted fix. Live-verified against the
real binary via direct HTTP round-trips (Chrome browser automation wasn't connected in this
environment) — add/remove/persist-to-disk/lowercase-normalization/invalid-code-400 all confirmed
against a running `dnsqb-service.exe` and its real `resolver_config.toml`; the actual browser
click-through and warning-banner visibility are **not** verified this slice, named honestly
rather than glossed over.

**Third commit — the closing advisor review of the actual committed diff (not a repeat of the
pre-implementation plan check) found a real bug the first two commits missed**: `renderGeoip`'s
`!data.persisted` warning branch could never fire — both `submitAdd` and the remove button
discarded the `POST` response and called `refreshGeoip()` (a re-`GET`, which always reports the
live state's own `persisted: true`), the same failure class this project has fixed four times
before (T-57/T-139/T-149/T-47) — a failed disk save would leave the user seeing the country tag
appear with zero indication it wouldn't survive a restart. Fixed by rendering the `POST` response
directly (`renderGeoip(await addGeoipCountry(code))`), the same pattern
`renderCacheConfig(await applyCacheConfig(update))` already uses one section above in the same
file — deliberately **not** applied to `#overrides-body`, which has the identical latent bug from
T-47's own add-then-refresh shape, named as a pre-existing gap outside this task's scope rather
than silently fixed in passing. Same review added two small `CONFIGURATION.md` clarifications:
the fatal-load-error enumeration didn't name an invalid country code (`ConfigError::
InvalidCountryCode` also exits 1), and the intro paragraph's live-write-path list predated the
cache-config/geoip routes.

Found while researching, folded into this task: `CONFIGURATION.md` had
zero mentions of `[geoip]`/`blocked_countries` at all — a pre-existing gap from T-76, now fixed
with a full section mirroring `[cache]`'s own shape. Diagram ground-truth ritual run: `ui-dto-
model.md` gained the new `GeoipCountriesResponse`/`GeoipCountryRequest` DTO pair and re-marked the
draft `GeoIPConfig` class as a draft, not a real DTO; `ui-navigation.md`'s GeoIP screen-inventory
node was actually re-checked this time (not silently skipped the way T-76/T-79 both left it) —
its existing text already named T-77 correctly for both bullets it now covers, so no edit was
needed there. Next in the Ф2 plan order: T-78 (UI: last-database-update indicator), then T-80/T-81.

Фаза 2, fifth GeoIP slice (T-82 — TASKS-DONE.md, docs-only, no commit-worthy code): closed without
new code, the same T-60 precedent — both properties T-82's own line names (OR across multiple IPs,
nop on an empty blocked-country list) already had dedicated `geoip.rs` unit tests, written for
T-76/T-79 and never credited to this line. Confirmed via `git log -S`, not assumed:
`blocking_country_is_some_when_a_non_first_ip_matches_a_blocked_country` and
`blocking_country_is_none_on_an_empty_blocked_list_even_for_a_matching_ip` both predate this pass
(commit `7790433`, T-76); the second, stronger two-country OR test
(`blocking_country_reports_the_first_matching_ips_country_when_two_ips_match_different_countries`)
predates it too (commit `5a5a894`, T-79). All three confirmed green and unedited since their
introducing commit. Deliberately **not** claimed to cover pipeline-level properties (cache-hit vs.
fresh-quorum-Allow) — T-82's own line names the GeoIP filter's unit level, already covered
separately by `pipeline.rs`'s own T-76/T-79 tests. Next in the Ф2 plan order: T-77 (UI: blocked-
country list, over-blocking warning).

Фаза 2, fourth GeoIP slice (T-79 — TASKS-DONE.md, one commit): fills in the one field T-76's own
closing note left as a stated gap — `query_log::LogEntry`/`pipeline::QueryLogMeta` gain
`geoip_country: Option<String>` (`Some` only when `decision_source == Geoip`, `None` otherwise,
the same "empty/absent except for one source" rule `voters` already follows one field over), and
`admin::LogEntryView::from_entry` now clones it through instead of hardcoding `None`. The one real
design decision was widening `geoip::blocks_any` itself, not adding a second lookup alongside it:
renamed to `blocking_country`, return type changed from `bool` to `Option<String>` — `find_map`
over `ips` in caller-supplied order, first IP whose looked-up country is in `blocked_countries`
wins (SPEC.md never names an ordering beyond OR, so this is the natural reading of the function's
own iteration order, now pinned by a dedicated two-country test rather than left implicit). Every
caller updated: `cache_hit_response_with_meta`'s and `handle_allow`'s own `if geoip::blocks_any(...)`
checks became `if let Some(country) = geoip::blocking_country(...)`. **Advisor-caught before
implementing**: the first draft of `handle_allow`'s `GeoIP`-block signal was a plain
`AllowResult::GeoipBlocked(Message, String)` tuple, threaded through `quorum_allow_response_with_meta`'s
existing 4-tuple match as a 5th positional element — flagged as exactly the shape rust.md's own
"Make Illegal States Unrepresentable" rule warns against: a future 6th field would silently land at
the wrong tuple position rather than fail to compile. Fixed with a named struct variant
(`GeoipBlocked { response: Message, country: String }`), matched by field name. A second
advisor-directed check, done *before* writing any code rather than assumed: grepped
`query_log::LogFilter`/`matches_filter` and `dispatch::parse_log_query` for any enumeration of
`LogEntry`'s field set or `DecisionSource`'s variants that a new `Option<String>` field could
silently break — confirmed neither exists (SPEC.md §6's own log-search paragraph names exactly
three facets — domain substring, decision, voter — `geoip_country` isn't one of them this phase),
so this stayed a clean 5-file change (`geoip.rs`/`pipeline.rs`/`query_log.rs`/`dispatch.rs`/
`admin.rs`), not a sixth. New tests: `geoip.rs`'s five existing `blocks_any` tests renamed and
reshaped to assert `Option<String>` instead of `bool` (including one now proving the returned code
is the *database's* casing, not an echo of the configured entry's casing — the one way the old
plain-bool version could pass while silently sourcing the value from the wrong place), plus a new
test with two `ips` matching two different blocked countries in reversed list order, proving IP
order (not list order or alphabetical) decides which country is reported — this needed a second
known-country fixture address (`81.2.69.160` → `GB`, the same `GeoIP2-Country-Test.mmdb` address
`maxminddb`'s own upstream `test_within` uses against this file, empirically confirmed against the
real vendored fixture via `cargo test` before committing to the assertion, per this project's own
"verify before trusting an assumed value" discipline — not guessed from the address alone).
`pipeline.rs`'s six existing `GeoIP` tests gained `meta.geoip_country` assertions (`Some("SE")` on
every `DecisionSource::Geoip` branch, `None` everywhere else, including the post-country-removal
cache-hit half of the "removing a country unblocks immediately" test). `admin.rs` gained a new test
proving `LogEntryView::from_entry` threads a real `Some("SE")` through unchanged (the existing
"always None" test was re-scoped to a `Blocklist`-source entry, which genuinely never carries a
country regardless of phase, rather than deleted). `dispatch.rs` gained one new full-stack test
(`serve_admin_log_reports_the_real_geoip_country_for_a_geoip_sourced_entry`) proving the value
survives the real HTTP `GET /admin/log` JSON round-trip, not just the direct `LogEntryView::from_entry`
unit test — and its own pre-existing `/admin/reset` fixture test updated for the renamed function
(`assert!(blocks_any(...))` → `assert_eq!(blocking_country(...), Some("SE".to_string()))`). Full
local gate green (349 lib tests, +3 new — the two-country `geoip.rs` test, the `admin.rs` DTO test,
and the `dispatch.rs` HTTP round-trip test; clippy/fmt/doc/doctest/conformance all unaffected and
clean; `cargo deny check` clean, only the same pre-existing informational advisories T-75/T-76
already recorded). Manually smoke-tested the real binary: started with the same kind of mixed-case
`[geoip]` config T-76 used, confirmed `GET /admin/log`/`GET /admin/status` both respond healthily
(no runtime panic from the new field threading), then a clean `/admin/shutdown`. **Not verified
live** (same underlying blocker T-75/T-76 both already named, not a new one): an actual
`GeoIP`-blocked real-world DNS query producing a real `geoip_country` in the log end to end — this
sandbox's DNS block on `db-ip.com` (T-75's own finding) means no real database can be downloaded
here at all, so a live block is unreachable regardless of domain choice, not merely inconvenient to
pick a domain for. Stays covered by the vendored-fixture unit/integration tests above, named as a
real gap rather than glossed over.
Diagram ground-truth ritual run (triggered — `LogEntryView.geoip_country` moved from
always-placeholder to genuinely producible): `diagrams/ui-dto-model.md`'s `GET /admin/log`
paragraph updated in place, no new SOURCES section needed (the field's shape was already declared,
only its real-vs-placeholder status changed). **Not in this slice**: the UI (T-77/T-78/T-81),
advanced MaxMind mode (T-80), closing property-style tests (T-82, next in the Ф2 plan order).

Фаза 2, third GeoIP slice (T-76 — TASKS-DONE.md, one commit): wires the already-built
`geoip::blocks_any` (new, pure OR-across-multiple-IPs decision over `GeoipReader::country`, T-74)
into `pipeline.rs` at SPEC.md §3.5's two named hook points — `cache_hit_response_with_meta` (a
cached `Allow` replay) and `handle_allow`'s return path (a fresh quorum `Allow`, after
`extract_ips`). Both apply live and never cache the `GeoIP` verdict itself — a quorum `Allow` is
cached unchanged even when `GeoIP` blocks that particular response, proven by a test that reads the
cache entry back after a `GeoIP` block and asserts `Verdict::Allow`, not `Block`. **Named, not
hidden, side effect (advisor-caught on the closing review)**: a fresh quorum `Allow` that `GeoIP`
then blocks logs `voters: Vec::new()` — real voter telemetry from a quorum resolution that
genuinely ran (timeouts and errors included) never reaches the log. Consistent with `LogEntry.
voters`'s already-documented "empty except for `Quorum`" rule, not a bug, but it has a real
consequence for T-56's degraded-upstream signal: `admin::degraded_counts` filters on `decision_
source == Quorum`, so those samples drop out of the degradation window entirely. Not fixed this
slice — a stated limitation, not a silent gap. New config surface
needed before any UI exists (same backend-before-UI precedent as T-153/T-47/T-52):
`config::GeoipConfig { blocked_countries: Vec<String> }`, a new `[geoip]` TOML table, empty by
default (SPEC.md §3.5's own opt-in default); `ResolverConfig::load` validates each code (exactly
two ASCII letters) and normalizes to uppercase, a malformed code is a loud `ConfigError::
InvalidCountryCode`, never a silent no-op. `AppState` gained a separate `geoip_countries:
RwLock<Arc<Vec<String>>>` field — deliberately **not** folded into the existing `GeoipState {
reader, updated_at }` (T-75): the two are swapped by different triggers (`geoip_updater`'s
background refresh vs. config load/`/admin/reset`/T-77's future admin route), and merging them
would let a database refresh silently wipe the user's country list, or vice versa. A new
`AppState::new` parameter `GeoipInit { database, blocked_countries }` bundles both at construction
only, immediately split into the two independent fields — keeps the constructor under
`clippy::too_many_arguments` (same structural-fix precedent as T-147/T-148, never `#[allow(...)]`).
The same threshold hit `pipeline::handle_query` (7 params + `geoip` = 8); fixed with new
`pipeline::CacheContext<'a> { cache, config }` (replacing two params with one) and `pipeline::
GeoipFilter<'a> { reader, blocked_countries }`, both local to `pipeline.rs` rather than reusing
`dispatch::CacheState` (would invert the `dispatch` → `pipeline` dependency direction). `handle_allow`
now returns a new `AllowResult { Answer, GeoipBlocked }`, not a bare `Message` — otherwise
`handle_query`'s `decision_from_response` call (whose own doc comment says it's never valid where
`Block` is reachable) would misclassify a `GeoIP`-block-shaped `NoError` response as `Allowed`; the
`Allow` branch was pulled into a new `quorum_allow_response_with_meta` helper for `clippy::
too_many_lines` (same "extract, don't `#[allow]`" precedent). New `query_log::DecisionSource::Geoip`
(a fifth, now-real value — `admin::DecisionSourceView::GeoIp` already existed as a T-74/T-75-era
DTO placeholder, now genuinely mapped; `geoip_country` itself stays `None` until T-79, the next task
in this workstream). **SPEC-silent choice, stated explicitly rather than picked silently**: the
allowlist branch is exempt from `GeoIP` (SPEC.md §3.5's own pipeline snippet says so), and the
every-provider-disabled pass-through is *also* exempt, by the same "no filtering at all" reasoning
T-41 already documented for that branch (both share `resolve_via_baseline`) — this is the user's
call to reverse later (that language predates `GeoIP`), not a hidden default.

**Advisor review of the plan before implementing caught two real bugs**: (1) the first draft hooked
`extract_ips` inside the `is_cacheable(ttl)` branch, which would skip `GeoIP` entirely for a TTL-0
answer — fixed by hoisting `extract_ips` onto the return path, outside the cacheability check. (2)
`blocks_any`'s comparison was first drafted as plain `==`, documented as relying on `blocked_
countries` arriving already-uppercased from `ResolverConfig::load`. **The closing review before
commit found that precondition false, not just risky**: `AppState::update_geoip_countries` (and
T-77's future admin write route) write into the same field with no normalization at all — the
"correct by an invariant enforced elsewhere" shape global CLAUDE.md's bounds-safety rule names
explicitly. Fixed structurally with `eq_ignore_ascii_case`, correct regardless of which writer
populated the field; the test that had locked in the old, fragile `==` behavior was rewritten to
prove the property that actually holds instead. **The same closing review found three more real
gaps, all closed in this commit**: (3) neither of the two admin routes that re-serialize
`ResolverConfig` to disk (`POST /admin/config`, `POST /admin/cache-config/apply`) read the current
`geoip_countries` before saving — the same "an unrelated write silently drops a sibling field"
shape this project has now fixed four times (T-57/T-139/T-149/T-47), extending `persist_lock`'s
cross-field-read discipline to `geoip_countries`; both routes got a regression test, empirically
confirmed by reverting the fix and watching the test fail before restoring it. (4) `/admin/reset`
never reloaded `[geoip]` at all — fixed via a new `AppState::update_geoip_countries`, called under
the already-held `persist_lock`; its test uses a real loaded `GeoipReader` (the same vendored
`GeoIP2-Country-Test.mmdb` fixture `geoip.rs`/`pipeline.rs`'s own tests use) rather than
`GeoipState::default()`, which would make the test vacuous (`blocks_any` always `false` regardless
of whether the reload worked). (5) the two hook points handed out different block TTLs for the same
kind of decision — the fresh path used `cache_config.block_verdict_ttl`, the cache-hit path used the
*Allow* entry's own remaining TTL, with no rationale (the `GeoIP` verdict isn't cached, so
inheriting an unrelated entry's remaining lifetime was accidental, not designed) — fixed to
`block_verdict_ttl` in both places; unfixed, removing a country from the list would leave the
browser holding a stale `0.0.0.0` for up to the old entry's remainder. Checked, not assumed: the
embedded web UI (`admin_ui.rs`) has zero references to `decision_source` or a log screen (grepped
the whole file) — the already-documented T-46/T-54 gap (DTO ready, no UI consumer yet), nothing to
reconcile this slice. Tests: 3 new in `geoip.rs` (nop-on-empty asserts the real IP, not just the
response code — the same trap `pipeline.rs`'s own `label_with_a_literal_dot...` test already
documents; OR when the *second*, not first, IP matches; case-insensitivity), 5 new in `config.rs`
(`[geoip]` table default/normalization/rejection cases), 6 new in `pipeline.rs` (nop via real IP; OR
with a non-first matching IP; a cached `Allow` survives a `GeoIP` block **and** unblocks with no
network call the moment the country is removed — one test proving both halves of SPEC.md §3.5's own
claim; the cache-hit path tested directly, not just transitively via a prior quorum call; both
exempt branches), 3 new in `dispatch.rs` (two cross-field-persist regressions, one reset-reload,
the reset test using the real fixture reader as noted above). Manually smoke-tested the real binary:
a `resolver_config.toml` with `[geoip]\nblocked_countries = ["SE", "de"]` (deliberately mixed case)
against a temp `%LOCALAPPDATA%` — the process started and stayed alive, not exit-1; stopped
manually. **Not verified live** (same class of gap as T-75): an actual DNS query through a real
`GeoIP` block end to end — `db-ip.com`'s DNS-blocked-sandbox limitation (T-75's own note) means no
real database can be downloaded here either, so this is covered by the vendored-fixture unit tests
above, named as a real gap rather than glossed over. Full local gate green (346 lib tests, +19 new;
clippy/fmt/doc/doctest all clean; RFC-conformance untouched; `cargo deny check` clean, only the same
pre-existing informational advisories as T-75). Diagram ground-truth ritual run (triggered —
`decision_source` gained a fifth real-producible value): `diagrams/ui-dto-model.md` updated once;
`ui-navigation.md`'s GeoIP screen-inventory node checked, unaffected (describes the still-unbuilt
T-77/T-78 UI, not touched this slice). **Not in this slice**: `geoip_country` in the log (T-79,
next), the UI (T-77/T-78), advanced mode (T-80), UI attribution (T-81), closing property-style
tests (T-82).

Фаза 2, second GeoIP slice (T-75 — TASKS-DONE.md, one commit): the background updater that keeps
the local `GeoIP` database current — new `geoip_download.rs` (pure: DB-IP Lite candidate-URL
construction via a hand-rolled civil-calendar date algorithm, no new date dependency; bounded gzip
decompression) and `geoip_updater.rs` (network fetch/verify/atomic-swap + an infinite background
loop, this crate's first standing background task and first outbound call to a new third party).
`AppState` gained a `GeoipState { reader: Option<Arc<GeoipReader>>, updated_at }` slice
(`RwLock<Arc<_>>`, mirroring `CacheState`/`OverridesState`'s snapshot-read shape), swapped only by
`AppState::update_geoip` after a downloaded database is validated and durably written to disk — a
failed refresh never clears an already-loaded database (SPEC.md's own user-safety framing: stale
beats silently unfiltered). **Real environment blocker, same class as the earlier macOS one,
surfaced to the user rather than guessed past**: `db-ip.com`/`download.db-ip.com` are unreachable
from this dev sandbox (DNS-blocked — confirmed via both `curl` and `WebFetch`, while an unrelated
domain resolves fine) — **not a permanent property of every session**: T-78 (2026-08-30) recorded
`db-ip.com` as actually reachable in that session's sandbox, a real live download succeeded; don't
treat this line as still-current without re-checking, only as the state observed at T-75's own
time of writing. So whether DB-IP publishes a machine-readable checksum sidecar next to the
`.mmdb.gz` file (their download *page* only shows an MD5/SHA1 as HTML text) couldn't be confirmed
before writing this code — and SPEC.md §3.5 calls integrity verification "not optional." Put to the
user via `AskUserQuestion`; chosen: a **defensive fallback** — try a `.sha1` sidecar opportunistically
and hard-fail on a mismatch, but when the sidecar is absent (404 or any fetch failure), fall back to
a still-real integrity gate that needs nothing extra from `db-ip.com`: TLS (transport integrity +
CA-validated origin identity), the gzip trailer's own CRC32/ISIZE (`flate2` validates this
automatically when the stream is read to its real EOF — the size cap is therefore an unconditional
reject, never a silent CRC-skipping truncation), a structural `MaxMind`-DB parse
(`GeoipReader::from_bytes`, new alongside `open`), and a loose `database_type` sanity check. A
`#[ignore]`d live test (`geoip_updater::tests::fetch_and_verify_against_live_db_ip`, same "manual,
not CI-gated" precedent as `upstream.rs`'s live-Quad9 test) is where whoever first has real
`db-ip.com` connectivity should confirm which path actually fires and fold that back into
`geoip_updater.rs`'s own module doc comment. **Advisor-caught before implementing**: the first
framing called the sidecar "same-origin, adds ~nothing" — wrong, `db-ip.com` (the page) and
`download.db-ip.com` (the artifact) are different hosts, so a found sidecar is a genuine cross-host
consistency check, not a self-referential one; and the gzip CRC32/ISIZE trailer is a free, already-
present integrity check the first draft hadn't counted at all. Two more findings recorded but not
acted on here (T-81's scope): DB-IP Lite's actual current license is **CC BY 4.0**, not CC BY-SA 4.0
as SPEC.md previously stated, and their page separately requires a link back to db-ip.com on any
page displaying results — both confirmed via live web search, not training-data memory, and
appended to SPEC.md §3.5 as a note rather than rewriting the original paragraph. New dependencies:
`flate2` (pure-Rust `miniz_oxide` backend, no `unsafe`, no C toolchain — keeps `#![forbid(unsafe_code)]`
intact the same way `maxminddb`'s feature choice does) and `sha1` (RustCrypto — SHA-1 chosen only
because that's what `db-ip.com`'s page is confirmed to publish, not for collision resistance; the
threat model here is cross-host consistency, not a resourced adversary). `reqwest` gained the
`stream` feature for `Response::bytes_stream()` — download size is bounded chunk-by-chunk as bytes
arrive, not checked against a spoofable `Content-Length` after the fact. Date math (which calendar
month DB-IP's URL should name, with a previous-month fallback for early-in-the-month publish lag)
is Howard Hinnant's `civil_from_days` algorithm, hand-implemented — deliberately no new date crate
for one calculation. **Closing advisor review before commit caught three more real bugs, all fixed
in this same slice, not deferred:** (1) `fetch_checksum_sidecar`'s first draft trusted any `2xx`
body as a real checksum — a server answering a missing sidecar path with `200` + an HTML error page
(not a proper `404`) would have its first "word" (`<!doctype`) compared as if it were a digest,
always mismatch, and hard-fail every refresh forever via `ChecksumMismatch` with no working
fallback — the exact "silently worse than no filtering, no signal to the user" Три Б shape. Fixed
with `looks_like_sha1_hex` (40 hex chars) gating whether a fetched token is even treated as a
checksum, restoring "absent" vs. "present but wrong" as the only two real outcomes. (2) The new
`reqwest::Client` in `main.rs` had no timeout anywhere on this path — a stalled connection would
park `run_geoip_updater`'s loop indefinitely (it never reaches its own `sleep`), silently killing
the feature until a process restart — the same "promoted to an unbounded path, needs a timeout"
gotcha already recorded in this file for `pipeline::resolve_via_baseline` at T-41, now hit on a
brand-new outbound path instead of rediscovered later. Fixed with `tokio::time::timeout` wrapping
each candidate attempt (`GEOIP_FETCH_TIMEOUT`, 120s), mirroring `query_with_timeout`'s own
established shape rather than reaching for `reqwest`'s own per-request timeout (whose semantics
against a still-open `bytes_stream()` weren't worth relying on unverified). (3) `updated_at` was
first set from `SystemTime::now()` (the refresh's own poll time) — since this task polls on a fixed
24h schedule regardless of whether `db-ip.com` actually published anything new, T-78's future "last
updated" indicator would always read as "today," true but useless for showing real staleness. Fixed
by reading the database's own embedded `build_epoch` instead (`maxminddb::Metadata::build_time`,
confirmed present by reading the vendored source) — a new `GeoipReader::build_time` (`pub`, mirrors
`database_type`'s existing internal accessor) used both here and by `main.rs`'s startup-load path,
which had the same wrong-quantity bug via file mtime. Full local gate green (327 lib tests,
clippy/fmt/doc all `-D warnings`, `cargo deny check`/`cargo audit` both clean, only pre-existing
informational advisories). Diagram ground-truth ritual checked, untriggered — `GeoipState` is an
internal `AppState` slice, no `admin.rs` DTO/UI state/flow changed this slice. **Not in this
slice**: pipeline wiring (T-76), `DecisionSource::Geoip`/`geoip_country` internal types (T-79), any
UI (T-77/T-78/T-81), advanced MaxMind mode (T-80).

Фаза 2, first slice (T-74 — TASKS-DONE.md, one commit): `geoip.rs`, a standalone `GeoipReader::open`/
`country` — pure `IpAddr → Option<ISO country code>` lookup over a caller-supplied `MaxMind`-format
database path (SPEC.md §3.5), the first primitive in the Ф2 execution plan's GeoIP workstream
(TASKS.md's Ф2 plan block). New direct dependency `maxminddb` 0.30.3 (+`ipnetwork` 0.21.1,
`default-features = false` — the `mmap`/`simdutf8`/`unsafe-str-decode` features all opt-in and left
off, keeping this crate's `#![forbid(unsafe_code)]` posture intact without needing an exception for
this dependency, confirmed by reading the vendored `reader.rs` before relying on it). Reads via
`decode_path(&path!["country", "iso_code"])` rather than the crate's typed `geoip2::Country` struct
— that path is the layout both DB-IP Lite (T-75's future default) and MaxMind GeoLite2 (T-80's
future advanced mode) share, so this reader doesn't need to know which produced the file it's
pointed at. A lookup-level error (confirmed empirically: an IPv6 address against this crate's
IPv4-only test fixture) collapses into the same `None` as a genuine not-found, documented on
`country()`'s own doc comment — this is a live per-query filter (SPEC.md §3.5's "порожній список
країн — nop, не помилка" framing), not a fallible pipeline step. Test fixture risk (advisor-caught
during Ф2 planning — `maxminddb` is reader-only, can't hand-author a valid `MMDB` file) resolved by
vendoring `GeoIP2-Country-Test.mmdb` directly from `maxmind/MaxMind-DB`'s own `test-data/`
(Apache-2.0/MIT dual-licensed, not a git submodule — `tests/fixtures/geoip/README.md` records
provenance), reusing that repo's own known-good `89.160.20.112 → SE` assertion as ground truth
rather than trusting the vendored file's contents unverified. `SECURITY.md` gained the dependency-
vetting row. Diagram ground-truth ritual checked, untriggered — no `admin.rs` DTO/state/flow changed
this slice (T-74 is internal-only; the pipeline wiring that will actually produce a `GeoIP` decision
is T-76/T-79, not yet done). **Not in this slice**: the DB-IP Lite download/integrity-check/atomic-
swap mechanism (T-75), pipeline wiring at either of the two located hook points (T-76), and the
internal `DecisionSource::Geoip`/`LogEntry.geoip_country` fields (T-79, though the `admin.rs` DTO
side already exists and is waiting, pinned by tests to stay inert until T-79 lands).

**Фаза 1 formally closed 2026-08-29** (SPEC.md §"Фазований план", TASKS.md's own closure-plan
record, docs-only) — every bullet in SPEC.md's original Ф1 scope is done; the two backlog lines
still open under the Ф1 heading (T-51's Firefox half, T-56's full indicator) were never part of
that original bullet list and are both blocked on named out-of-MVP work (T-132, T-134), so neither
blocks the closure. **Closing-advisor review of this closure note itself (before commit) caught
two real, unblocked gaps the first draft had silently overclaimed past**: (1) no test anywhere in
this repo has ever exercised the actual "browser → local DoH" leg SPEC.md's own Ф1 "Ціль" line
names first — every existing confirmation is either DoH-client-level (`Invoke-WebRequest`, T-143/
T-148) or Chrome automation against `/admin/ui` (a different page); Chrome trusting the cert
(T-49/T-51) is the prerequisite, not the pass itself. (2) T-66's metrics — the explicit gate
SPEC.md sets before investing in Ф2 — didn't confirm the quorum hypothesis on its one sample
(AdGuard 0/38). Neither is a numbered task, both are open decisions before Ф2 starts for real; see
SPEC.md's own closure paragraph for the full wording. Next active phase is Фаза 2, not yet started.

Крок 0 done (SPEC.md §"Фазований план"): Rust workspace, CI, and the RFC-conformance test table
(T-1–T-19) are in place. Phase 1 target platform is Windows (DECISIONS.md, 2026-08-25 — SPEC.md
itself left this open).

Фаза 1, twenty-seventh slice (T-56, narrowed — TASKS.md, one commit): per the Ф1 closure plan's own
step 5, added a "деградований апстрім" signal to `dnsqb-tray`'s tooltip, derived from the existing
`QueryLog` window — the plan's own narrower scope, not the full `diagrams/ui-status-indicator.md`
draft (no browser-DoH-usage check, no watchdog state, Фаза 3 doesn't exist yet). New
`admin::AdminStats` fields `degraded_window`/`degraded_events` (computed by a new private
`degraded_counts`, wired into `compute_stats`): among the most recent `DEGRADED_LOOKBACK` (20)
*quorum-decided* log entries (only `DecisionSource::Quorum` entries carry voters at all, T-147 —
counted before taking the last N, not diluting it with allowlist/blocklist/cache entries that can
never carry a voter), `degraded_window` is how many were actually available and `degraded_events`
is the subset with at least one `VoterVerdict::Timeout`/`Error`. **Advisor review of the plan caught
the one design choice the whole feature lives or dies on**: a first draft collapsed this into a
single `degraded: bool`, "any Timeout/Error in the last 20" — flagged as the noisiest possible
definition, since under `TimeoutMode::FailOpen` (the default) a single slow provider on a single
query is routine internet weather, not degradation, and would leave the tooltip reading "degraded"
almost permanently — an always-on warning being functionally identical to no warning, the same axis
SPEC.md §8.1 already guards for the "0 voters" state. Fixed by exposing raw counts instead of an
invented threshold — the same "backend returns counts, the caller renders the label" split
`AdminStats::blocked`/`total` already use (T-139's `main.js` bands them client-side) — the tray only
appends a suffix (`"N/M останніх апстрім-запитів мали тайм-аут/помилку"`) when `degraded_events >
0`, letting the reader judge severity from the raw numbers rather than a collapsed always-on flag.
A second advisor catch: the first-draft integration test asserted only `degraded_events >= 1`, which
could pass for the wrong reason if the mocked voters actually landed on `Canceled` instead of
`Timeout` (both filtering providers share one `MockResponse::Pending`, and `Canceled` is what T-30's
early-return path produces for a voter that's still eligible but never waited on) — fixed by first
asserting the actual recorded `VoterRecord.verdict == VoterVerdict::Timeout`, the fourth instance of
this crate's own "a passing test that doesn't prove its own named property" gotcha, and by tightening
both `degraded_window`/`degraded_events` to exact equality (`== 1`, not `>= 1` — exactly one query
was logged, so the counts are fully known). **Checked empirically, not just reasoned about**:
temporarily flipped the `Timeout` assertion to `Canceled` and reran — failed with `[Timeout,
Timeout]` (no Block signal ever arises in this fixture, so nothing triggers T-30's cancellation path;
both voters genuinely run out `query_with_timeout`'s own timeout), confirming the real assertion
proves what it claims rather than passing by coincidence; reverted before commit.
`TrayStatus::Filtering` gained the same two fields, threaded through from `AdminStatusResponse`;
`NoActiveProvider`/`Unreachable` are untouched (no voters run in either state — a stale nonzero
`degraded_events` from before providers were disabled must never leak into a state that implies "no
filtering is happening", documented on the field's own doc comment). Tested at three levels: pure
`degraded_counts` unit tests in `admin.rs` (in-window vs. just-outside-the-20-entry-boundary,
non-`Quorum` entries excluded from the window rather than diluting it, an all-healthy window staying
zero), one real `dispatch.rs` integration test proving the actual production wiring
(`resolve_doh_request` → `pipeline::handle_query` → `quorum::resolve` → `query_with_timeout` → a
real logged `Timeout` voter → `compute_stats`) under `#[tokio::test(start_paused = true)]` with a
never-resolving `MockResponse::Pending` (new variant on the existing `MockClient`, converted from a
plain `fn` returning `std::future::ready(...)` to a genuine `async fn` — `quorum.rs`'s own
`MockDohClient` already established this exact shape against the same `DohClient` trait), and new
`dnsqb-tray/src/status.rs` unit tests (`#[cfg(test)]` added to that file for the first time) proving
`TrayStatus::from_response`/`tooltip()` thread the counts through correctly. **A real pre-existing
CI gap found and fixed in the same pass**: `dnsqb-tray`/`dnsqb-watcher` are `[[bin]]`-only crates
with no `[lib]` target, so CI's `cargo test --workspace --lib` had never once compiled or run
`dnsqb-tray`'s own `#[cfg(test)]` modules — `browser.rs`'s existing test (predating this task)
had been silently unexercised by CI the whole time, only caught while adding this slice's own
`status.rs` tests and noticing they didn't appear in local `--lib` output either. Fixed by adding
`--bins` to the CI command (`.github/workflows/ci.yml`) and to CLAUDE.md's own Commands section —
not itself part of T-56's scope, but the new tests this slice adds would otherwise have joined
`browser.rs`'s in never actually running anywhere. TASKS.md's own T-56 line updated in place
(deliberately **not** moved to TASKS-DONE.md — same "narrowed, not closed" precedent already used
for T-51 above it in the same closure plan) — still open: browser-DoH-usage detection (blocked on
T-134's own named gap, no domain→fixed-IP canary mechanism exists yet), watchdog state (Фаза 3),
and the full richer indicator for the web UI or a dedicated screen. Diagram ground-truth ritual run
(triggered — `AdminStats` gained two DTO fields): `diagrams/ui-dto-model.md` updated (new fields on
the `AdminStats` class, the `dnsqb-tray` tooltip section's `Filtering` shape corrected, one new
section explaining the window/raw-counts design); `diagrams/ui-status-indicator.md` got one new
paragraph noting this narrowed subset shipped, without rewriting the diagram's own full future
target (conditions 1/4 stay undesigned). `SERVICES.md`'s `dnsqb-tray` "Live-статус" paragraph
updated to describe the new fields — still three top-level tooltip states, not a fourth.

Фаза 1, twenty-sixth slice done (T-153 — TASKS-DONE.md, **two commits**, advisor-recommended split
given the size — backend fully green standalone before the UI card landed, same split precedent as
T-52/T-149): `cache::CacheConfig`'s five fields (`clamp_min`/`clamp_max`/`block_verdict_ttl`/
`stale_grace`/`max_capacity`, SPEC.md §4.1) gained the same "TOML-start + live admin-channel write"
path `providers`/`timeout_mode` already had (T-52/T-144) — a new `[cache]` table in
`resolver_config.toml` plus a **separate** `GET /admin/cache-config`/`POST /admin/cache-config/apply`
route (not folded into `AdminConfigUpdate` — an ordinary provider/timeout toggle must never carry
and thereby flush the cache config as a side effect). **Key finding verified by reading vendored
source before designing anything on top of it**: `moka::future::Cache` has no live setter for
`max_capacity`/its `Expiry` policy (`Cache::policy()` is a read-only snapshot, `moka` 0.12.16) — a
cache-config change therefore always rebuilds a whole new `Cache` and swaps it in, never patches
one field in place. New `dispatch::CacheState { cache, config }`, `AppState.cache` retyped to
`RwLock<Arc<CacheState>>` (same snapshot-read shape already used for `overrides`). **Advisor review
of the plan caught two real bugs before any code existed**: (1) `cache::clamp_ttl`'s `Duration::
clamp(min, max)` panics unconditionally (release included) if `min > max` — relying on boundary
validation alone to prevent that would be exactly the "safe only by a hand-traced cross-module
invariant" anti-pattern global CLAUDE.md's bounds-safety rule forbids; fixed structurally
(`.max(min).min(max)`, never panics regardless of caller discipline), empirically confirmed both
ways (reverted to `.clamp()`, watched the new test panic with `assertion failed: min <= max`;
restored, 260/260 green). (2) One validating constructor owned by `cache.rs`
(`CacheConfig::from_secs`/`to_secs()`), not duplicated in `config.rs` and `dispatch.rs` separately —
both callers go through the same `clamp_min <= clamp_max` check `clamp_ttl` depends on structurally
holding. **A third bug, also advisor-caught**: `/admin/config` and the new cache-config route now
write into the *same* `resolver_config.toml` — two independent locks guarding that one file would
reproduce the exact disk-vs-live divergence T-58's `persist_lock` already exists to prevent, one
level up. Fixed by sharing `persist_lock` between both routes, each `save()` snapshotting the
*other* field's live value too so the file always reflects both. **`apply_admin_reset` also had to
start acquiring `persist_lock`** (the mirror-image gap of T-47's `overrides_persist_lock` catch, one
field over) — empirically confirmed via revert-and-loop (1/20 failures reverted, a narrower window
than T-58's 16/20 since this handler does far less work between the two lock acquisitions it would
otherwise race on; 20/20 restored) — and reset now rebuilds the cache via `Cache::new(&config.cache)`
instead of a plain `clear()`, strictly safer against a racing query (finishes against the orphaned
`Arc`-cloned old instance rather than racing a live mutation). **A fourth catch**: the first-draft
flush test ("insert, apply, assert `cache.get` is `None`") would pass vacuously against any
brand-new empty `Cache` — replaced with a real property test via `resolve_doh_request` against a
`MockClient` call counter, proving the second identical query actually re-queries upstream after an
apply, not just that the swap happened. UI card ("Кеш", a standalone section — T-153's own text left
this open, decided explicitly since no "Розширені" section exists yet to fold it into) mirrors T-47's
overrides card exactly: outside the 2s-polled `#app-body`, own fetch/render cycle, client-side
mirror of the server's `clamp_min <= clamp_max` check (belt-and-suspenders, not a replacement).
Manually verified against the running binary (both commits): GET/POST round-trip, persistence to
disk, inverted range → 400, missing Content-Type → 415, a real DoH query still resolves after the
cache swap, clean graceful shutdown; live Chrome pass on the UI card confirmed persisted values
load on open, edit+apply round-trips through the real backend and persists to disk (checked by
reading the file), and the client-side validator blocks an invalid submission without touching the
server, console clean throughout. `CONFIGURATION.md`/`UI-SPEC.md`/`diagrams/ui-dto-model.md`
updated (new `[cache]` table docs including the "this flushes the cache" warning, new DTO classes
`CacheConfigView`/`CacheConfigUpdate`).

Фаза 1, twenty-fifth slice done (T-47 — TASKS-DONE.md, one commit): the override-list editor on
`/admin/ui` (allowlist/blocklist, add/remove, conflict highlighting) — the first real write path
for `overrides.toml`, which previously had only `load()` (T-37) and no route exposing it to any
client. This also removes the `save()` blocker T-46 shared with this task; T-46 itself stays open,
now blocked only on the still-missing log screen/route (T-54). Plan-mode + advisor review of the
plan *before* implementing (not just after) caught a real gap before any code existed: `OverrideLists`
only ever holds successfully-*parsed* entries — a naive `save()` serializing just those would
silently delete any pre-existing typo'd line from disk the moment an unrelated `add` fires,
`InvalidEntry.raw`'s own doc comment had already named this exact future caller. Fixed structurally:
new `dispatch::OverridesState { lists: OverrideLists, invalid: Vec<InvalidEntry> }` (`pub`, same
"bundle what's always swapped together" reasoning as `PersistPaths`, and the same
`clippy::too_many_arguments` fix T-147/T-148 already established) replaces `AppState.overrides:
RwLock<Arc<OverrideLists>>` with `RwLock<Arc<OverridesState>>`; `OverrideLists::save(path, invalid)`
takes the invalid lines as an explicit parameter and writes them back verbatim. Verified empirically,
not just by unit test: hand-wrote a malformed `overrides.toml` line, loaded it via a real
`POST /admin/reset`, added a new domain through the actual running `/admin/ui` in Chrome, and
confirmed the malformed line survived on disk alongside the new entry. Two more advisor catches on
the same plan review: the serialize-error variant (`OverrideError::Serialize`) is payload-free,
mirroring the already-established `Parse` variant, rather than assuming (unverified) that
`toml::ser::Error` doesn't echo its input the way the deserialize side was empirically proven to;
and `save()` checks the serialized size against `MAX_OVERRIDES_FILE_SIZE` before writing, closing
a gap where a UI-grown list could write a file `load()` would then refuse to read back. New
`OverrideLists::with_entry_added`/`with_entry_removed` (pure, reuse the existing `parse_pattern`,
return a new value rather than mutating) and three new routes (`GET /admin/overrides`,
`POST /admin/overrides/add`/`remove`, added to both `ROUTES` and T-59's `EXPECTED_ADMIN_ROUTES`
snapshot test) with their own `overrides_persist_lock` (deliberately separate from the existing
`persist_lock`, an independent resource with its own file). **A second advisor catch on the
concurrency test itself**: T-58's own concurrent-write test only proves disk matches live state —
the weaker property here, since two concurrent adds without a lock would both read the same base
list and the second swap would silently discard the first (a genuine lost update, not just a
disk/memory mismatch, since both would still consistently show the losing state). The new test
asserts the stronger property (all N concurrent adds present in both live state and on disk) and
was empirically confirmed as a real regression test the same way T-58's was: 20/20 failures with
the lock reverted, 20/20 passes with it restored. New DTOs `OverrideDomainView`/
`OverrideListsResponse` in `admin.rs` — a genuine projection (split by list, `list` tag redundant
once split), not a reuse of the internal `OverrideEntry` type, leaving T-53's open DTO-duplication
question exactly as unresolved as before. UI (`index.html`/`main.js`/`style.css`): the new section
lives outside `#app-body` (which the 2s status poll fully replaces) specifically so a free-text
"add domain" input never loses in-progress typing to an unrelated timer tick; list rows render via
`document.createElement`/`textContent`, not the string-interpolated `innerHTML` pattern the rest of
the page uses — `admin_ui.rs`'s own module doc comment had already flagged this exact gap for a
future domain-rendering screen, closed here rather than deferred again. Live Chrome verification:
add/add-conflicting/remove all confirmed via real clicks and screenshots, console clean, disk state
checked after each step. **Not verified this slice**: a full live DoH round-trip proving cache
invalidation (the mechanism is proven via a real `Cache` instance in a dispatch-level unit test
instead — a live round-trip would need hand-built DNS wire bytes, named as a real gap, not hidden).
CONFIGURATION.md/UI-SPEC.md/`diagrams/ui-dto-model.md` updated to match (ground-truth ritual run,
one diagram touched, four new DTO classes added). **A second, closing advisor review of the
finished diff (before commit) caught two more real gaps**, neither visible to any gate or test that
already existed: `apply_admin_reset` wrote `state.overrides` without taking `overrides_persist_lock`
at all, so a concurrent `/admin/reset` and `POST /admin/overrides/add` could interleave into the
same lost-update shape the add/add concurrency test had already fixed, just between two different
routes — fixed by having reset take the same lock across its own reload-then-commit sequence, both
locks' doc comments updated so the next reader doesn't re-derive the old (now wrong) "reset takes no
lock" conclusion from `persist_lock`'s comment. Relatedly, `apply_overrides_change` re-read
`state.overrides` after writing it (`after = Arc::clone(&state.overrides.read())`) instead of using
the value it had just computed — redundant under the lock, but a latent bug if any future writer
ever bypassed it; fixed by keeping `after` as a local value. Second: `OverrideListsResponse` had no
`persisted` field, so a save failure (permissions, disk full, no path configured) live-applied
silently with no way for the caller to know it wouldn't survive a restart — the exact "add a
blocklist rule, restart, filtering is silently gone" failure class this project has fixed three
times before without ever writing it down as a pattern (T-57, T-149, T-139). Fixed the same way
`apply_admin_config` already does it (`persisted: bool`, set from the real save result), plus one
`main.js` warning line rendered when it's `false`.

Поза фазами, T-54 checked against its own premise (TASKS.md annotation, docs-only, no code,
separate commit from T-134 above — a close and a non-close annotation don't belong in one commit,
this repo's own `git log -S` habit of mining history for "was this already done?" depends on that):
found genuinely still open, not narrowable-to-closed like T-55/T-59/T-60 were — those found
existing behavior to credit, this one has nothing built to credit. Confirmed via grep:
`query_log.rs`'s types (`Decision`/`DecisionSource`/`LogEntry`/`VoterVerdict`) carry zero
`Serialize`/`Deserialize` derives, and `dispatch::ROUTES` has no log-exposing route at all — only
`/admin/status`/`/admin/config`/`/admin/reset`/`/admin/shutdown`/`/admin/ui*`. T-54's own "mirror to
a TS discriminated union" framing is also stale post-T-149 (no TS frontend exists) — but that's
already covered generically by the existing T-149 blockquote at the top of SPEC.md §8, so no
further SPEC.md/diagram edit was needed, just the TASKS.md annotation. T-54 stays open, blocked on
a log-exposing endpoint/screen (adjacent to T-46/T-47's scope) that doesn't exist yet.

Поза фазами, T-134 done (TASKS-DONE.md, docs-only, no code): investigated a technical mitigation
for silent browser DoH fallback (SPEC.md §"Відкриті питання" п.10), the same "research, not
implementation" precedent as T-14/T-141. An advisor review before starting split what looked like
one batchable pair (T-133+T-134) into a real one and a false one: T-133 asks for a literal legal
determination ("юридична перевірка" of Quad9/AdGuard ToS) — a research pass, however sourced,
can't produce that, so closing it under this task's number would be a false close on exactly the
axis this project is strictest about; T-133 stays untouched, open. T-134 was reframed as missing
design input for T-56 (the open state-indicator task), not standalone research. Two
live-WebSearch-confirmed findings, dated 2026-08-28 since 2026 currency isn't verifiable from
training data (same discipline as T-66/T-141): (1) Firefox has a direct analog of the Chrome-only
enterprise policy SPEC.md's п.10 already named — the `DNSOverHTTPS` policy (`Locked` +
`network.trr.mode`/`network.trr.uri`, mode 3 = TRR-only) mirrors Chrome's `DnsOverHttpsMode=secure`,
same admin-level-privilege caveat. (2) For the actually-useful, non-enterprise half T-56 needs: no
passive signal on `dnsqb-service`'s own side (log-window silence) can distinguish "browser silently
fell back" from "user is idle" — fundamentally ambiguous server-side. The one technique found with
real precedent (the DNS-leak-test-page class other DoH providers use) is an active client-side
canary probe from `/admin/ui` — a hostname only correctly resolvable through `dnsqb-service`'s own
resolver, fetched by the served page's own JS — plausible because Chrome's ordinary page-level DNS
resolution (not just navigation) does route through a configured custom DoH provider, confirmed via
WebSearch, not assumed. **A second closing-advisor-review pass caught the write-up naming a
non-existent primitive**: the first draft said the canary domain would come from "an override entry
mapped to a fixed synthetic IP" — checked, not assumed, and false — `overrides::OverrideLists::
decision` only returns a binary `Option<ListKind>` (Allow/Block), and `wire::build_block_response`
hardcodes `0.0.0.0`/`::`; nothing in the pipeline can bind an arbitrary domain to an arbitrary fixed
IP today. Fixed by naming the missing primitive explicitly instead of asserting a ready path — a
new, undesigned route/mechanism, not an override-list extension. Also explicitly **not verified
empirically** this pass (needs a scratch probe before being trusted, this project's standing bar)
and Firefox's own TRR behavior at page-fetch level wasn't separately confirmed. Firefox's own
reverse-canary domain (`use-application-dns.net`) was checked and deliberately not reused — it
tests whether the *network* blocks DoH via the native resolver, the opposite direction from what
T-56 needs. T-98 (Chrome policy doc verification) explicitly not absorbed — stays Phase 3. SPEC.md's
п.10 gained one appended paragraph (not rewritten); T-56 (TASKS.md) now points at the canary-probe
candidate as unverified design input naming a missing primitive, not a ready plan.

Поза фазами, T-139 done (TASKS-DONE.md, one commit, docs+static-asset only, no Rust code): closed
the remaining scope of a task already narrowed once before (T-52's dashboard already covers
processed/blocked/in-flight counts) — a blocked-percentage stat on `/admin/ui`, purely derived
client-side (`main.js`'s `blockedPercentLabel`) from the already-returned `status.stats.blocked`/
`.total`, no new backend field. **Advisor-caught before commit, same failure class as T-57's
baseline undercount**: the first draft guarded only `total === 0` (→ "—", not `NaN`/a false `0%`)
but a plain `Math.round` still misrepresents the far more common case — a real filter's steady-state
block rate is often well under 1% of a full log window, so `blocked > 0` could still round display
to a misleading `0%` (and the mirror case, `blocked < total` rounding up to a misleading `100%`).
Fixed with explicit `<1%`/`>99%` bands instead of rounding through either edge. Second catch: the
new fourth stat cell had no `flex-wrap` on `.stat-row`, a real narrow-window overflow risk — fixed
with one CSS property. Verified two ways: a `node`-run unit pass over nine boundary cases for
`blockedPercentLabel` (0/0, 0/4, 1/1, 1/100, 1/101, 99/100, 100/101, 3/1000, 997/1000, all correct),
plus a live Chrome pass against a real running `dnsqb-service` (a real blocked-domain DoH query via
a temporary `overrides.toml` + `POST /admin/reset`, confirming `—`/`0%`/`25%` render correctly on
live data). The wrap fix itself was verified via forced-width DOM geometry
(`getBoundingClientRect`, 4 cells → 2 rows, zero horizontal overflow at 360px) rather than a
screenshot of an actually-narrowed OS window — `resize_window` didn't change the real viewport in
this environment, named honestly rather than skipped. `UI-SPEC.md` §3.1's draft row annotated (not
rewritten) to note the real shape differs (`AdminStats`, not a standalone "today" `u32`, percentage
computed by the client). Diagram ritual checked (`ui-dto-model.md`'s SOURCES) — unaffected, no DTO
field changed. No new Rust code, types, or tests.

Фаза 1, twenty-fourth slice done (T-57 — TASKS-DONE.md, one commit, docs+static-asset only, no
Rust code): the explicit, non-hidden quorum-privacy notice SPEC.md §8/"Відкриті питання" п.4
requires on the admin UI. New `.notice.info` block on `/admin/ui` (`main.js`'s
`privacyNoticeHtml`), computed live from the already-returned `status.providers` — no new
backend field or endpoint. **Real undercount bug in the first draft, caught by closing advisor
review before commit, not by any test**: the count only summed the two toggleable filtering
providers (`quad9`/`adguard`), missing that `quorum::resolve` pushes an *unconditional*
`Slot::Baseline` future (right after the two `if enabled.*` blocks) for every quorum-applicable,
uncached lookup — `upstream::BASELINE_DOH_URL` (hardcoded Cloudflare, not yet admin-configurable)
is queried regardless of which filtering providers are toggled, so the true third-party count is
always "enabled filtering providers + 1," never just the filtering providers. A privacy
disclosure that understates real exposure is wrong in the one direction that's never acceptable.
Fixed: `total = filtering.length + 1`, baseline always named in the list. Second consequence,
also advisor-caught: the "both providers off" state previously showed *no* privacy notice at all
(count was 0, notice suppressed) — but that's exactly the state where baseline alone sees 100% of
new-domain traffic, the one state with zero disclosure. That state doesn't even go through
`quorum::resolve` — `pipeline::handle_query`'s every-provider-disabled branch short-circuits
straight to `resolve_via_baseline` (`pipeline.rs`, a separate call site that also always queries
`BASELINE_DOH_URL`, same conclusion via a different function than the one named above). Fixed by
extending the existing `.notice.warn` text itself ("...йдуть напряму через baseline-резолвер
(Cloudflare), який усе одно бачить кожен новий домен...") rather than stacking a second box — the
two notices stay
**mutually exclusive**, now for the right reason (each names who sees traffic in that specific
state, via whichever banner is showing). Verified with two full live-browser passes (Chrome
automation, real toggle clicks on the running `/admin/ui`, all three provider-count states
screenshotted) — once for the (already-corrected) single-provider-grammar issue, once again after
the baseline-undercount fix, both before commit — the CLAUDE.md-named "if you can't test the UI,
say so explicitly" gap doesn't apply here since T-149's web UI (unlike the deleted Tauri one) is
genuinely browser-testable, and this slice is the first one to actually do it. `style.css`'s
`.notice.warn`/new `.notice.info` now share their common properties via one `.notice` base
selector instead of duplicating them — a small in-scope tidy of the exact block this slice was
already editing. No new Rust types, endpoints, or tests — all logic lives in the static JS
`admin_ui.rs` already serves via `include_str!`; the existing header/CSP tests on that module
don't depend on file contents and needed no changes. Diagram ground-truth ritual checked
(`diagrams/ui-dto-model.md`'s SOURCES includes §8) — not affected, no DTO type/field changed,
only static text over the already-existing `AdminStatusResponse.providers`.

**Reversed 2026-08-28 (DECISIONS.md)**: the notice itself (`privacyNoticeHtml`, `.notice.info`)
was removed at the user's explicit request — the paragraph above stays as the historical record
of what was built and why at the time, not rewritten. `.notice.warn` (both-providers-off warning)
is unaffected.

Фаза 1, twenty-third slice (T-58, narrowed but not closed — TASKS.md, one commit): a scoping pass
over T-58's four-category admin-channel test requirement (SPEC.md §8.1) surfaced two real bugs, not
just missing tests, and fixed both. (1) `overrides::OverrideLists::load`/`config::ResolverConfig::
load` had no file-size bound — every other input boundary in this crate is explicitly capped before
allocating (`dispatch::MAX_MESSAGE_SIZE`, `MAX_ADMIN_BODY_SIZE`), but these two file loaders weren't,
and both are reachable live via `POST /admin/reset` (T-149), not just at startup — SPEC.md §8.1's
"malformed/huge override file" misuse example, now closed. Advisor-caught before implementing: the
first draft checked `fs::metadata(path)?.len()` before `read_to_string` — measures one thing,
allocates another, real TOCTOU. Fixed with a bounded read (`File::open` + `.take(MAX + 1).
read_to_string(...)`, checked against the actual bytes read, not a separately-measured length) —
`overrides::MAX_OVERRIDES_FILE_SIZE` (10 MiB, generous for a hand-edited domain list) and `config::
MAX_CONFIG_FILE_SIZE` (64 KiB, four scalar fields — a deliberately separate, much smaller constant,
not a shared one covering two files three orders of magnitude apart) with their own `OverrideError::
TooLarge`/`ConfigError::TooLarge` variants. (2) `dispatch::apply_admin_config`'s disk persist
(`ResolverConfig::save`, a plain non-atomic `fs::write`) happens *after* the `runtime` write lock is
released — two near-simultaneous `POST /admin/config` calls (e.g. two quick UI clicks) could persist
to disk in the opposite order from their in-memory writes, leaving the file not matching live state:
SPEC.md §8.1's "rapid toggle race" misuse example, real not hypothetical. Fixed with a new
`AppState::persist_lock` (`parking_lot::Mutex<()>`, invariant documented on the field: always
acquired before `runtime`, never after), held across the whole write-then-persist sequence but not
across the disk write via `runtime` itself (so a concurrent admin config write's disk I/O never
blocks `resolve_doh_request`'s per-query `state.runtime.read()`). **Advisor-flagged and then
empirically resolved, not assumed either way**: a naive concurrency test proving this exact race
would very likely pass on both fixed and unfixed code (the same vacuous-test shape this file's
gotchas section already documents three times — `IsCa::NoCa`, the `icacls` denylist, T-59's `ROUTES`
fix) unless actually watched failing first. Checked, not assumed: with `persist_lock` temporarily
reverted, `concurrent_admin_config_posts_leave_disk_matching_live_settings` (3 real OS threads,
`flavor = "multi_thread"`, looped 20×) failed 16/20 runs; with the fix restored, 20/20 passed — a
genuine, empirically-confirmed regression test, documented as such in the test's own comment rather
than left to look like an untested aspiration. First real `proptest` usage in the workspace (named in
the planned-stack table since Крок 0, never wired up before this slice) — `default-features = false,
features = ["std"]`, confirmed via `cargo tree -f "{p} {f}" -p proptest` to exclude the default
`fork`/`timeout` features' process-spawning tail (`rusty-fork`, `wait-timeout`, `quick-error`), per
advisor review. Three property tests at the channel's actual untrusted-input parsing boundaries:
`overrides::parse_pattern` (arbitrary strings never panic; a parsed domain never contains `*` — a
regression-shaped property tied directly to this file's own documented `Name::from_utf8` wildcard-
label gotcha), `dispatch::wire_bytes_from_get` (arbitrary GET query strings never panic, RFC 8484
§4.1.1), and `dispatch::serve` end to end against arbitrary `/admin/config` POST bodies (proves the
whole CSRF-gate→body-limit→JSON-decode→live-apply path is panic-free, not just the JSON decoder in
isolation). **Deliberately not claimed exhaustive** — T-58 stays open in TASKS.md, narrowed: SPEC.md
§8.1's third misuse example (allow+block override conflict) is covered separately, elsewhere, not by
this slice; fuzzing covers only these three boundaries, not every admin route or `/dns-query`'s own
POST body, named as a remaining gap rather than silently implied done.

Фаза 1, twenty-second slice done (T-60 — TASKS-DONE.md, docs-only, no commit-worthy code): closed
without new code, the third such case after T-55/T-59 — the two tests SPEC.md §8.1 requires
("окремий рядок... не лише в тестах UI-каналу") already existed, written for other tasks and never
credited to this line. Quorum-level: `pipeline::tests::
voters_disabled_yields_pass_through_via_baseline_without_consulting_quorum` (T-41). Channel-level:
`dispatch::tests::serve_admin_config_disabling_both_providers_is_pass_through_not_fail_closed`
(T-52, commit `f2906c9`) — a real `POST /admin/config` with both providers false, then a real
`/dns-query` resolving via baseline pass-through with the quorum mock set to panic on any call.
Both confirmed via `git log -S` to predate this pass, not edited into shape now. Deliberately not
claimed as covering all of SPEC.md §8.1's misuse category — three other named examples (override
conflict, malformed/huge override file, rapid toggle race) stay open, and the `/admin/status`
distinct-state requirement in the same §8.1 paragraph is T-56's line, not T-60's.

Фаза 1, twenty-first slice done (T-55 + T-59 — TASKS-DONE.md, one commit): T-55 closed with no new
code — `admin_ui::respond`'s CSP (`default-src 'self'; frame-ancestors 'none'`, no inline
script/style) already satisfies it as a side effect of T-149's architecture, already proven by
`admin_ui::tests::serve_html_returns_ok_with_a_strict_csp_header`. T-59's own first draft (a
hardcoded path list swept against `serve()`'s behavior) passed while proving nothing about route
*addition* — confirmed empirically (a throwaway unlisted `match` arm added to `serve()` left the
test green), advisor-caught before commit, not by the test itself. Real fix is structural, not a
stronger assertion: new `dispatch::ROUTES` (`&[(&str, &[Method])]`) is the actual table `serve()`
dispatches from — checked before the handler-selection `match`, so an unlisted path/method can
never reach a handler regardless of what arm the `match` grows — plus a test asserting that live
table against an independent hand-written copy (`serve_matches_the_documented_admin_route_
allowlist`) and a second proving the table is actually enforced, not just declared
(`serve_enforces_the_route_table_it_matched_above`). Re-verified empirically both ways (added-route
→ red, reverted → green) before committing. Side effect: the four private `serve_admin_*` handlers
lost their now-unreachable inner method checks (single call site, `ROUTES` already gates it —
CLAUDE.md's own "no validation for scenarios that can't happen" rule); `admin_ui::serve_html/js/css`
keep theirs (`pub(crate)`, independently tested, bypass `serve()` entirely). `HEAD` deliberately
left out of the negative-method sweep — RFC 7231 §4.3.2's "SHOULD support HEAD wherever GET is
supported" is a decision this project hasn't made yet, and freezing 405-for-HEAD as tested behavior
would make it by omission. T-53 narrowed in TASKS.md, not closed — the allowlist half is now
structurally real, the DTO half ("not directly exposing internal backend structs") is still open.
New generalized gotcha recorded below (third instance of "a passing test that doesn't prove its own
named property" — see `IsCa::NoCa`/`icacls` denylist entries — first one fixed by making the
property into data the test reads, not a stronger assertion).

Фаза 1, twentieth slice done (T-149 — TASKS-DONE.md, **three commits**): replaced T-52's Tauri
desktop UI (`dnsqb-ui`) with a lightweight tray icon (`crates/dnsqb-tray`, `tray-icon`/`tao`/`rfd`,
not Tauri) plus a browser-based config page `dnsqb-service` serves itself at `GET /admin/ui`. User
asked (Ukrainian) whether the add-on could run headless with a tray icon instead of a desktop
window; SPEC.md's own "Відкриті питання" п.13 had already named this exact question as needing a
plan-mode + advisor review before implementing, which this slice carried out. Three explicit
user decisions via `AskUserQuestion`: (1) tray "Restart" = soft reset over the admin channel
(clear cache+log, re-read both TOML configs from disk) — not an OS process kill/relaunch, full
process supervision stays `dnsqb-watcher`'s job (Фаза 3). (2) The tray menu splits **"Close"**
(exits the tray only, `dnsqb-service` keeps running) from a separate, confirm-gated **"Stop
filtering"** (calls the new `POST /admin/shutdown`) — advisor-caught before implementation: a
single combined "Close" button would leave zero on-screen indication that filtering silently
stopped (SPEC.md "Відкриті питання" п.10), the same Три-Б user-safety class already caught twice
before (T-148, T-52's CSRF fix); the split itself came from the user's own follow-up question
about who launches `dnsqb-service` if the tray doesn't own it as a child process. (3) `dnsqb-ui`
is deleted entirely, no parallel Tauri build kept — recorded as a DECISIONS.md reversal of T-52.
Autostart (who launches `dnsqb-service` for a mouse-only user with no terminal) was scoped out as
a new, separately tracked **T-150** (installer registers a Startup shortcut/Run key, Фаза 2/3),
chosen via `AskUserQuestion` over building it into this slice.

**Commit 1 — `dnsqb-service` additive, minimal new attack surface**: `AppState.overrides` became
`RwLock<Arc<OverrideLists>>` (was a bare `RwLock<OverrideLists>`) so a read can `Arc::clone` and
hold no lock across `.await`; a new `AtomicU64` in-flight counter with an RAII `InFlightGuard`
(not manual inc/dec at ~9 return points, same footgun class already named for T-147); `AdminStats`
gained `in_flight`; `PersistTarget` gained `paths: Option<PersistPaths>` (one struct with `config`
+ `overrides` fields always set together, not two independent `Option<PathBuf>` — advisor-caught,
illegal-state-unrepresentable, since `main.rs` always resolves both paths from one
`app_data_dir()` call). New `POST /admin/reset` (`content_type_is_json` CSRF gate, same as
`/admin/config`): prepare-then-commit — loads both config files into locals first, only mutates
`state.runtime`/`state.overrides`/clears cache+log if both loads succeed; swaps `overrides` before
`cache.clear()`, not after (advisor-caught ordering — the reverse leaves a window where a
concurrent query repopulates the cache from stale overrides). New embedded web UI at `GET
/admin/ui` (+ `/admin/ui/main.js`, `/admin/ui/style.css`), `include_str!`-compiled in, no runtime
file I/O — new `admin_ui.rs` module, ported from `dnsqb-ui/ui/*`'s layout/labels but CSS moved to
its own file so CSP can be `default-src 'self'; frame-ancestors 'none'` with no `unsafe-inline`
from the start (T-55's goal for the now-deleted Tauri UI, met differently here — `frame-ancestors`
is required separately from `default-src`, advisor-caught, since `default-src` doesn't cover
framing and an untrusted cert accidentally blocking iframing today is not the same as blocking it
on purpose once T-49 installs the cert). Fully green standalone.

**Commit 2 — `/admin/shutdown` + graceful shutdown + new `dnsqb-tray` crate**: `hyper-util` gained
the `server-graceful` feature (`GracefulShutdown`, API verified by reading vendored source, not
memory — `.watcher()`'s non-`Clone` `Watcher` exists specifically to avoid a race, per its own
source comment); `tokio` gained `sync` for `watch::channel(bool)`, chosen over `Notify`
specifically to avoid an unverified ambiguity worth a scratch probe when an unambiguous primitive
was equally viable. `AppState` gained `shutdown_tx: watch::Sender<bool>` + `pub fn
shutdown_handle()`; new `POST /admin/shutdown` (same CSRF gate) sends `true` and returns 200 — the
response is written by the already-spawned per-connection task, independent of the accept loop the
signal stops, so no ordering/sleep hack is needed; a `send()` failure (all receivers already
dropped, reachable if a second shutdown call lands mid-drain) still returns 200 with a one-line WHY
comment, not a silent `let _ =`. `main.rs`'s accept loop is now `serve_until_shutdown`:
`tokio::select!` between `listener.accept()` and `shutdown_rx.changed()`, then `drop(listener)` and
`graceful.shutdown()` under a 5s timeout — never `std::process::exit()`, which would kill
`/admin/shutdown`'s own response mid-flight. New crate `crates/dnsqb-tray` (`tray-icon` 0.21.3 +
`tao` 0.31.1 + `rfd` 0.15.4, Крок 0 empirically probed first, scratch project deleted before
commit): `tao`'s `EventLoop::run` owns the calling thread forever, so admin-channel polling runs on
a separate OS thread with its own single-threaded `tokio` runtime (`status.rs`); `muda`'s
`MenuEvent` queue isn't wired into `tao`'s event delivery on Windows, drained via `.try_recv()` on
a 100ms `ControlFlow::WaitUntil` tick. Three honestly-distinguished tray states (`Unreachable`,
`NoActiveProvider`, `Filtering{in_flight,blocked,total}`) — `Unreachable` also covers "cert.pem
doesn't exist yet" (first run, before `dnsqb-service` has ever started) so the tray never stays
permanently dead; `status.rs` lazily rebuilds `Option<AdminClient>` only after a failed poll (not
every poll — advisor-caught, same "promoted to all-traffic path needs re-audit" gotcha class
already in this file for T-39→T-41, since rebuilding a TLS-pinned client 30×/minute is a different
cost class than the old Tauri UI's build-once-per-user-click). Browser opened via
`rundll32.exe url.dll,FileProtocolHandler`, absolute `%SystemRoot%\System32\` path, no new
open/opener crate — same absolute-path-for-spawned-processes precedent as `cert.rs`'s `icacls`
call. Icon shipped as a compiled-in 32×32 RGBA buffer (Python/Pillow-generated once from the old
`.ico`, command documented in a code comment since the source file is deleted in commit 3) via
`Icon::from_rgba`, not a runtime `.ico` file read.

**Commit 3 — architectural reversal**: `crates/dnsqb-ui` deleted entirely (`git rm -r`).
DECISIONS.md records the T-52 reversal. SPEC.md: tech-stack UI row updated; comms-matrix row 4
(Tauri webview↔Rust IPC) struck through in place rather than deleted/renumbered (grepped first —
nothing else in the repo cites rows by number, and struck-in-place matches this file's own "never
silently deprecate" rule better than a renumber with unbounded blast radius); row 12 split into
12a (tray↔service: `/admin/reset`, `/admin/shutdown`) and 12b (browser↔service: `/admin/ui` +
existing `/admin/status`/`/admin/config`); "Відкриті питання" п.13 marked resolved, pointing at
DECISIONS.md. UI-SPEC.md §5's Tauri-command table gets a superseded-header note, not a rewrite —
it stays a draft for screens T-149 didn't touch. SECURITY.md: Tauri IPC threat bullet replaced with
an admin-HTTP-channel bullet; `tauri`/`tauri-build` rows removed, `tray-icon`/`tao`/`rfd` rows
added with real versions. SERVICES.md: `dnsqb-ui` section replaced by a `dnsqb-tray` section
(cross-referencing the commit-2 write-up above); admin-channel section gained `/admin/reset` and
`/admin/shutdown`. CONFIGURATION.md and README.md's stack table updated to match. TASKS.md: T-150
added; T-53/T-55/T-56/T-58/T-59/T-139 annotated where their Tauri-IPC referent no longer exists
(T-55's CSP goal already met differently, T-53/T-59's allowlist/snapshot goal now maps to
`dispatch.rs`'s route table, already test-covered). `deny.toml`: `MPL-2.0`/`Zlib` and all 5
`unic-*` RUSTSEC ignores removed **one at a time with `cargo deny check` after each** (per the
plan's explicit instruction, not a bulk removal) — all confirmed genuinely no longer needed;
`[graph] targets = ["x86_64-pc-windows-msvc"]` restriction kept (independently correct for a
Windows-only Ф1 project, not Tauri-specific — its comment reworded to say so instead of crediting
Tauri alone). Closing advisor review before this commit caught two misses: CLAUDE.md's own
operational sections (Commands, "Planned stack" table, Runtime-dependencies paragraph) still named
`dnsqb-ui`/Tauri — fixed in place, this paragraph included; `diagrams/ui-dto-model.md` still cited
SPEC.md's old, now-renamed "row 12" — fixed to "rows 12a/12b". Діаграма ground-truth ritual run
(triggered — `AdminStats.in_flight` at commit 1, SPEC.md §0/§8 renumbered at commit 3):
`ui-dto-model.md` updated twice (new `in_flight` field + explanatory paragraph at commit 1; the
row-12→12a/12b reference fixed at commit 3); `ui-navigation.md`/`ui-status-indicator.md` checked
against their SOURCES §8/§8.1 citations both times — both are screen-inventory/condition-table
diagrams describing UI-technology-agnostic requirements, unaffected by the Tauri→tray/web swap.
Звірка діаграм: прогнано, зачеплено 1 діаграму (`ui-dto-model.md`), оновлено 2 рази, GAP: 0.
`cargo audit`'s advisory count dropped 17→11 (Tauri's own advisories gone) but still lists
gtk/glib informationally — `tray-icon`/`muda`/`tao`'s own Linux-only cfg'd deps resolve into
`Cargo.lock` without compiling here, same shape Tauri had, already excluded from `cargo deny`'s
evaluation by the kept `[graph] targets` restriction; `cargo audit` itself doesn't respect that
restriction, so this is expected, not a regression. **Not in this slice**: T-150 (autostart) —
separate, still-open task; T-56 (status indicator)/T-57 (quorum privacy notice) stay open, now
targeting the tray/web UI instead of a Tauri window; a real visual click-through check of
`/admin/ui` via Chrome browser automation (the CLAUDE.md-named gap T-52 left, "if you can't test
the UI, say so explicitly") — genuinely possible now (unlike a native Tauri window) but not yet
done this slice.

Фаза 1, seventeenth slice done (T-147 — TASKS-DONE.md, one commit): `query_log::QueryLog` finally
has a producer — `dispatch::resolve_doh_request` pushes a `LogEntry` after every `pipeline::
handle_query` call that returns a decision (allowlist/blocklist/cache-hit/quorum). Found while
scoping T-52: the dashboard stat and T-44/T-45/T-46 all needed real log data that didn't exist yet.
Turned out bigger than "call `push()`" — four real design gaps, three resolved by reasoned default
and documented, one (a documented-DTO reversal) put to the user: (1) **`Decision::Failed`** — a
third variant, since `handle_query` demonstrably produces SERVFAIL on several paths and the old
2-value enum would have logged those as `Allowed`; user chose to add it over silently skipping those
paths (DECISIONS.md, same reversal class as T-145). (2) An early-return `Block` can leave one voter
`Responded` but undecidable (its signal needed baseline, baseline got canceled too) — logged as
`Canceled`, documented on `quorum::voter_record`. (3) Non-A/AAAA proxied queries aren't logged this
slice — `handle_query` never sees the actual proxied response, named as an open gap. (4)
`VoterVerdict`/`VoterRecord` moved from `query_log.rs` to `quorum.rs` — which providers vote is
quorum's domain, not the log's; `query_log.rs`'s own comment about excluding `quorum::Slot::Baseline`
moved with the types, re-exported from `lib.rs` either way. `QuorumOutcome` gained `voters:
Vec<VoterRecord>`, computed via new `quorum::voter_record`/`voter_records` reusing `known_signal`
(same "one predicate, no drift" discipline already documented there) — a compiler-required
`Some(Signal::NeedsBaseline)` match arm (never actually reachable at runtime, but `known_signal`'s
declared return type doesn't rule it out) folds into `Canceled` too, commented as such rather than
`unreachable!()` (forbidden, rust.md). `pipeline::handle_query` now returns `(PipelineOutcome,
Option<QueryLogMeta>)` — deliberately not a new `&QueryLog` parameter threaded through every one of
its ~9 return points (advisor-caught: a forgotten future return point would silently drop a log
entry); `dispatch::resolve_doh_request` is the single push site, already bracketing the whole request
for timing and already seeing both the `Response` and proxy paths. `QueryLogMeta.domain` is a
separately normalized copy (`trim_end_matches('.').to_ascii_lowercase()`), not the same `domain`
`handle_query` itself uses for `overrides.decision`/`CacheKey::new` (that one is deliberately the
untransformed `to_ascii()` form, to round-trip cleanly through those calls' own internal
`normalize_domain`) — a test caught this mismatch (expected "example.com", got "example.com.")
before the closing review did. `handle_query` tripped `clippy::too_many_lines` (109/100) after the
new branches; fixed by extracting three small pure helpers (`baseline_passthrough_with_meta`,
`blocklist_response_with_meta`, `cache_hit_response_with_meta`), not `#[allow(...)]`.
`resolve_doh_request` tripped `clippy::too_many_arguments` (8/7); fixed by taking `&AppState<C>`
instead of its seven individual fields — a genuine simplification (all seven were already `AppState`
fields), not a lint workaround. **Not in this slice**: the non-A/AAAA proxy path stays unlogged
(named gap above); T-148 (real per-provider config) and T-52 (Tauri UI) are separate, still-open
tasks — T-52 remains blocked on T-148.

Фаза 1, eighteenth slice done (T-148 — TASKS-DONE.md, one commit): replaced `pipeline::Voters`
(the T-41 all-or-nothing switch) with `quorum::EnabledProviders { quad9: bool, adguard: bool }` — a
real per-provider toggle `quorum::resolve` actually honors, the exact gap `config.rs`'s own doc
comment had named since T-144 ("persisting a per-provider toggle the resolver can't yet act on
would repeat T-41's own `Voters` design note"). This is what unblocked T-52. `EnabledProviders`
lives in `quorum.rs` (which providers vote is quorum's domain, T-147 precedent) and
`config::ResolverConfig` reuses it directly as `providers` (nested `[providers]` TOML table) rather
than a parallel config-only copy — a second type could drift from what `resolve()` actually
honors, T-41's lesson applied to itself. **Advisor-caught trap before implementation, not a
test**: naively defaulting a disabled provider's missing outcome to `VoterOutcome::TimedOut` (the
existing "never arrived" fallback) would make `fail_closed` mode treat "administratively disabled"
the same as "unresponsive" and silently BLOCK every query the moment one provider is turned off —
worse than no filtering at all (Три Б, user safety). Fixed by keeping a disabled provider's
outcome `None` all the way through `resolve()` (no future is even pushed for it into the
`FuturesUnordered`; the `.unwrap_or(TimedOut)` collapse only applies when that provider is
enabled) — `combine`/`representative_allow_answer`/`voter_records` all take `Option<&VoterOutcome>`
for quad9/adguard and treat `None` as "doesn't participate", reusing `known_signal`'s existing
`outcome?` early-return with no new special-casing. New `VoterVerdict::Disabled` — distinct from
`Canceled` (still eligible, just not waited on) and `Timeout` (asked, never answered);
`voter_record()` checks `enabled` before any outcome logic so the two never collapse. **Second real
bug, also advisor-caught before implementation**: `query_log::LogFilter::voter`'s existing filter
checked only provider *presence* in `voters`, not verdict — once `Disabled` became a possible
value, filtering by voter would start matching entries where that provider never actually voted,
contradicting the facet's own documented "participation" intent. Fixed by excluding
`VoterVerdict::Disabled` explicitly in `matches_filter`, new test mirroring the existing
`search_voter_facet_excludes_entries_with_no_voters_even_if_that_provider_would_have_blocked`.
`resolve()` tripped `clippy::too_many_lines` (114/100) after the new branches; fixed by extracting
`finalize_outcome` (the post-loop verdict/answer/voters assembly), not `#[allow(...)]`, same
precedent as T-147's helper extraction. Hard cutover in `resolver_config.toml`, no dual-field
shim — a file still using the old flat `voters_enabled` key now fails to parse
(`ConfigError::Toml`, unknown field), same precedent as T-145's TOML migration; no `DECISIONS.md`
entry needed (SPEC.md never committed to this field's exact shape, nothing to reverse). Manually
confirmed on the running binary: `resolver_config.toml` with `[providers]\nquad9 = false\nadguard =
true` starts the service and a real DoH GET for `example.com` returns 200 (resolved via AdGuard +
baseline, Quad9 never queried). New tests: `quorum.rs` — a disabled provider's URL is never
queried (panics if it is), the fail-closed regression named above (Quad9 disabled, AdGuard +
baseline both `Allow` → verdict must stay `Allow`, not falsely `Block`), and
`representative_allow_answer` with a disabled provider and no usable answer elsewhere;
`pipeline.rs` — one provider disabled still runs real quorum, not the every-provider-disabled
pass-through; `config.rs` — partial `[providers]` table, a typo'd nested key, the old flat
`voters_enabled` key now a loud error; `query_log.rs` — the new voter-facet regression test.
Closing advisor review caught two more real gaps before commit: (1) `pipeline.rs`'s new
single-provider-disabled test only asserted `meta.voters.len() == 2`, which would pass even if
`handle_query` silently dropped `Disabled` on the way from `QuorumOutcome` into `QueryLogMeta` —
strengthened to assert Quad9's own record actually carries `VoterVerdict::Disabled` (grepped every
`.voters` reader in the crate first to confirm `query_log.rs`'s `matches_filter` is the only
participation-counting one, so nothing else double-counts). (2) `resolve()` is `pub`, and nothing
at the type level stops a caller from passing `EnabledProviders { quad9: false, adguard: false }`
directly to it — it would return a well-formed `Allow` sourced from baseline with both voters
`Disabled`, indistinguishable from a real filtered `Allow` and cacheable, the T-41 lesson recurring
one level up. The one shipped caller (`handle_query`) never reaches this (its own `any_enabled()`
gate runs first), so this is documented as a real but unenforced precondition on `resolve()`'s own
doc comment, not fixed with a newtype — over-engineering for two providers. Checked before
committing, not skipped: `grep`'d SPEC.md/UI-SPEC.md for `voters_enabled`/prior committed
per-provider config shape — no hit, so unlike T-145 this isn't a SPEC.md reversal (T-144's own doc
comment named the gap as future work, never a settled shape); SPEC.md §3.4's "checkbox per
category, not per provider" line is about the *future Ads/Adult category UI*, not Phase 1's single
Security category's two providers, so it doesn't conflict with a per-provider backend toggle for
those two. Діаграма ground-truth ritual run (triggered — `VoterVerdict` gained an enum variant):
`diagrams/ui-dto-model.md`'s `VoterStatus` DTO union updated with the new `Disabled` variant and a
new resolved-discrepancy paragraph (its existing `ProviderConfig.enabled: bool` field already
anticipated this exact toggle, so no conflict found) — `ui-navigation.md`/`ui-status-indicator.md`
checked, not affected. Звірка діаграм: прогнано, зачеплено 1 діаграму (`ui-dto-model.md`), оновлено
1, GAP: 0.
**Not in this slice**: category toggling beyond the two Phase-1 providers (Ads/Adult etc.,
UI-SPEC.md §3.4) — needs upstream presets `upstream::Provider` doesn't have; the Tauri UI itself
(T-52), now genuinely unblocked but still not built.

Фаза 1, nineteenth slice done (T-52 — TASKS-DONE.md, **two commits**, advisor-recommended split
given the size — backend control-plane fully green on its own before the new Tauri crate's much
larger dependency tail landed): the project's first real UI, a minimal Tauri window with the three
Ф1 controls SPEC.md §8 names (provider toggles, timeout mode, blocked-stat). **Real architectural
gap found before this could even be scoped**: `dnsqb-service` and any future UI are separate
long-running processes (SERVICES.md) with no channel between them — `config.rs` only had
startup-time `load()`, `query_log::QueryLog` was in-memory-only with no external reader. Asked the
user (AskUserQuestion) which architecture to build; chosen: a **full live control-plane** — toggles/
timeout-mode apply to the running resolver immediately, no restart, and the stat panel shows real
live numbers. Plan-mode + advisor review of the plan (before any code) caught one thing that
blocked and several real refinements, all folded into the plan before implementation started — most
consequentially: the whole admin-channel TLS design rested on an unverified assumption
(`reqwest::Certificate::from_pem` + `.add_root_certificate()` validating against `cert.rs`'s
`IsCa::ExplicitNoCa` self-signed leaf, `cA=FALSE`) — confirmed **empirically** via a throwaway
scratch probe (real `tokio-rustls` server + pinned `reqwest` client, deleted before commit) before
building anything on top of it. Green — real TLS validation, not disabled cert checking.

**Commit 1 — backend control-plane** (`crates/dnsqb-service`): new `admin.rs` — `AdminStatusResponse`/
`AdminStats`/`AdminConfigUpdate` JSON DTOs, `compute_stats` (from `QueryLog::snapshot`, no new
storage), `AdminClient`/`AdminClientError` (a `reqwest::Client` pinned to the service's own
`cert.pem`, deliberately kept out of `dnsqb-ui`'s own dependency graph entirely — no cross-crate
`reqwest` version coupling). `quorum::EnabledProviders` gained `Serialize`. `config::ResolverConfig::
save()` — this file's first writer ever; a stated, documented tradeoff, not a silent one: it
overwrites the whole file from struct fields, destroying any hand-written comments T-145 chose TOML
specifically to preserve, and — advisor-sharpened — a pending, not-yet-restarted-into hand-edit to
`port`/`timeout_ms` gets silently reverted by the next UI toggle click too (CONFIGURATION.md now
says both explicitly). `dispatch::AppState<C>` — **one** `RwLock<RuntimeSettings>` (providers+timeout
together, not two separate locks — advisor-caught: two locks would let a query observe new
providers paired with a stale timeout mid-update), plus `PersistTarget { port, config_path }`;
`AppState::new`'s param count held at 7 (not 9) via these two cohesive bundles, the same structural
`too_many_arguments` fix T-147/T-148 already established, not `#[allow(...)]`. New routes
`GET /admin/status`/`POST /admin/config` on the *same* loopback TLS port `/dns-query` already uses —
no new listener, the same pattern already named for the future `/health` (T-86).

**Real CSRF gap, caught by advisor review of the finished diff before commit, not a test**:
`POST /admin/config` initially had no `Content-Type` check — a `text/plain` (or missing)
`Content-Type` is a CORS *simple* request (no preflight), so any page the browser happened to be
rendering could have silently disabled filtering machine-wide the moment `cert.pem` is trust-store-
installed (T-49). Fixed with `content_type_is_json` mirroring the existing `content_type_is_dns_message`
gate — `application/json` isn't a simple type, forcing a preflight that this route never answers, so
the real request never fires. DNS rebinding (the obvious next worry on a loopback admin channel) was
already closed independently by the leaf cert's narrow SAN set (`IP:127.0.0.1`/`IP:::1`/
`DNS:localhost`, T-48), not by this fix — documented in `content_type_is_json`'s own comment so it
isn't re-litigated later. Verified live against the running binary: a `text/plain` POST → 415, a
real `application/json` POST live-applies and persists, and the persisted value **survives a
restart** (confirmed by actually restarting the service and re-reading `/admin/status`). 201 tests,
full gate green, CI confirmed (all 6 jobs).

**Commit 2 — `crates/dnsqb-ui`**: new Tauri v2 workspace member, vanilla HTML/CSS/JS frontend (no
npm/bundler — `tauri.conf.json`'s `withGlobalTauri: true`, no `beforeDevCommand`/`beforeBuildCommand`,
so plain `cargo build -p dnsqb-ui` — what CI runs — needs no `tauri-cli`). One panel, no sidebar/nav
(other screens are separate future tasks): provider toggles, timeout-mode radios, a stat panel
honestly labeled "current log window" rather than "today" (same honesty correction T-66 already made
relabeling cache buckets "miss/hit" instead of "cold/warm" — the ring buffer isn't a calendar-day
count). Three thin Tauri commands (`get_status`/`set_providers`/`set_timeout_mode`) wrapping
`AdminClient`, returning a typed `UiError` (not a bare `String`) so the frontend can render "service
unreachable" honestly instead of a fake `0`/`0` stat. A one-line warning renders when both providers
are off (Три Б — a one-click-reachable unfiltered state needs *some* on-screen indication even before
T-56's real status indicator exists).

Two real build obstacles, both resolved empirically: (1) Windows requires `icons/icon.ico` even for
plain `cargo build` (`tauri-build` always generates a Windows resource file) — generated a minimal
valid 32×32 ICO with a small Python/`struct` script, not hand-authored bytes. (2) `cargo deny check`
against the full Tauri tree genuinely failed three ways at once, confirming the advisor's own
"budget this, it's bigger than the UI" warning: a wildcard path-dependency (`dnsqb-service` needed an
explicit `version` field), two new licenses needing real vetting (`MPL-2.0` — weak, file-level
copyleft, doesn't propagate to an unmodified dependency; `Zlib` — permissive), and five `unmaintained`
advisories on the `unic-*` crate family (via `urlpattern`, no safe upgrade available per the
advisories' own text) — added as an explicit, ID-specific `ignore` list, not a blanket
unmaintained-check disable. Separately, the entire GTK/Linux-only tail (unmaintained gtk-rs bindings,
an extra Apache-2.0-variant license) disappeared on its own once `deny.toml` gained
`[graph] targets = ["x86_64-pc-windows-msvc"]` — the actually-correct fix for a Windows-only Ф1
project, not licensing code that never compiles here.

Manual verification, with an honestly-named limit: launched `dnsqb-ui.exe` next to a live
`dnsqb-service` — the process starts, doesn't crash, and spawns a real `msedgewebview2.exe` process
tree (confirmed via `Get-CimInstance Win32_Process`), proving the webview actually rendered something
rather than failing silently. **Not verified**: the actual visual render or click-through interaction
— no screenshot/browser-automation tool exists in this environment for a native Tauri window; every
layer below the webview (the admin channel, `AdminClient`, both Tauri commands) is already covered by
commit 1's tests and live manual confirmation. Named as a real gap, not glossed over (CLAUDE.md: "if
you can't test the UI, say so explicitly rather than claiming success").

SPEC.md/UI-SPEC.md/diagrams updated, not left to silently drift: SPEC.md §0 gained communication-
matrix row 12 ("UI ↔ `dnsqb-service`, адмін-канал") plus a §8 paragraph distinguishing the two
different "UI↔backend" channels (webview↔Tauri-core vs. Tauri-core↔separate `dnsqb-service`) the
previous edition never separated. UI-SPEC.md §5's draft Tauri-command table is annotated where T-52's
real implementation diverged (`set_category_enabled` → `set_providers`, with the reason — Ф1 has 2
providers, not categories, T-148; `get_status`/`set_timeout_mode` now return the wider
`AdminStatusResponse`, not a standalone `ResolverSettings`). Diagram ritual run: 1 diagram touched
(`ui-dto-model.md` — new `AdminStatusResponse`/`AdminStats`/`EnabledProviders` classes plus a
discrepancy paragraph against the draft `ResolverSettings`), `ui-navigation.md`/`ui-status-indicator.md`
checked, unaffected. T-139 narrowed, not silently duplicated — its processed/blocked counters are now
covered by `dnsqb-ui`'s dashboard; only the percentage display remains open.

**Not in this slice**: T-53 (formal audited command allowlist), T-54 (tagged-enum DTOs for the rest
of the channel), T-55 (CSP without `unsafe-inline` — the current CSP still allows `style-src
'unsafe-inline'` for the inline `<style>` block), T-56 (status indicator), T-57 (quorum privacy
notice), T-58/59/60 (4-category IPC channel tests) — all separate, still-open tasks; `port`/
`timeout_ms` aren't admin-editable this slice (only `providers`/`timeout_mode`) — changing the port
needs a listener re-bind, out of scope for a live-apply call.

Поза фазами, T-141 done (TASKS-DONE.md, one commit, docs only — no code): investigated whether
HTTP/3 upstream support is worth building now, same "research, not implementation" precedent as
T-14 (ECH). Client-side stack is the decisive blocker: `reqwest` 0.13.4's `http3` feature is
explicitly unstable (`compile_error!` unless `RUSTFLAGS='--cfg reqwest_unstable'` is set — confirmed
by reading `reqwest-0.13.4/src/lib.rs:252`, not assumed), and pulls in `h3` 0.0.8/`h3-quinn` 0.0.10
(both pre-1.0); `RUSTFLAGS` isn't a local build quirk here — it's process-wide, would need setting in
every `.github/workflows/ci.yml` job. Provider side (checked via live `WebSearch`/`WebFetch`, not
training-data memory — 2026 currency isn't otherwise verifiable): Quad9 enabled DoH3/DoQ in March
2026 on the same `dns.quad9.net/dns-query` endpoint, coexisting with HTTP/2 (not replacing it,
negotiated via `Alt-Svc`/DDR/SVCB) — doesn't disturb this project's existing strict-HTTP/2
requirement for Quad9 (gotchas below); AdGuard modernized similarly; Cloudflare (this project's
baseline resolver) had no confirmed public DoH3 data found this pass. Deliberately **not**
re-checked a second time: Cloudflare specifically and AdGuard's current DoH3 (not just DoQ) status —
the client-side gate decides the outcome either way, so that second check is deferred to whenever
`reqwest` drops the `reqwest_unstable` gate. Decision: don't implement now; the future feature's
shape (per-upstream try-HTTP/3-then-fall-back-to-HTTP/2, decided per resolver) is named in one
sentence in SPEC.md §3.6, not designed — no speculative design for a feature that can't compile
today. New SPEC.md §3.6 paragraph, no DECISIONS.md entry (SPEC.md never previously claimed anything
about HTTP/3, so there's nothing to reverse).

Фаза 1, sixteenth slice done (T-44 + T-45 — TASKS-DONE.md, **one commit for both** — both tasks
touch only `query_log.rs`, no interactive staging to split them after the fact, and the user asked
this session to batch a few small tasks under a single plan+advisor review pass rather than one
review cycle per task). `QueryLog::clear()` (T-44) — a one-line wrapper over
`entries.write().clear()`, same pattern as `Cache::clear` (T-137). `QueryLog::search(now,
&LogFilter)` (T-45) — new `LogFilter<'a>` with three independently-optional fields
(`domain_contains`, `decision`, `voter`), combined with AND, not a bespoke enum per facet
combination (rust.md "Make Illegal States Unrepresentable"); facet semantics were checked against
SPEC.md §6 (lines 923-925) and `UI-SPEC.md` §3.2 (lines 77-79) *before* implementing, not invented
from TASKS.md's one-line parenthetical alone — both sources independently confirm a case-insensitive
domain substring filter plus an `{ALL,BLOCKED,ALLOWED}` facet, and the already-drafted Tauri command
signatures (`UI-SPEC.md` lines 182-183, `clear_log()`/`get_log(filter)`) line up with this shape
one-to-one, no contradiction found. `search`/`snapshot` now share one private `age_filtered_entries`
helper (one `retain` pass under one write-lock acquisition, then `filter().cloned()`) — the age bound
is enforced in exactly one place regardless of which public method a caller uses (advisor-caught on
closing review: the naive `search` calling `snapshot` then filtering would clone the whole buffer and
discard most of it). The `voter` facet is deliberately about provider *participation* in `voters`,
not verdict ("blocked by X") — a SPEC-silent choice, documented in `LogFilter`'s own doc comment,
same pattern as `VoterRecord`'s own note — with a **documented consequence** (advisor-caught on plan
review): `voters` is empty for every non-`Quorum` `decision_source`, so filtering by voter can never
surface a domain that provider once blocked but is now cache-served — the same ambiguity class
already recorded in T-66's entry for AdGuard, pinned here with its own dedicated unit test
(`search_voter_facet_excludes_entries_with_no_voters_even_if_that_provider_would_have_blocked`)
rather than left implicit. Substring matching lowercases **both** sides (`to_ascii_lowercase()`, not
just the needle) — the first draft lowered only the needle, relying on the convention that
`normalize_domain` always lowercases stored domains before they reach the log, a convention no type
or producer actually enforces yet (`LogEntry` still has no live producer) — caught immediately by the
test itself, not by review. `diagrams/ui-dto-model.md` was checked (ground-truth ritual) — `LogFilter`
is a backend query parameter, not a `LogEntry` DTO field, so the diagram needs no change. No Tauri
command consumer yet (T-53 doesn't exist) — same "module ready, wiring later" pattern as every prior
slice.

Фаза 1, thirteenth slice done (T-143 — TASKS-DONE.md, one commit): `main.rs` is no longer a
stub — a real `hyper` TCP accept loop + `rustls`/`tokio-rustls` TLS termination + `DoH` GET/POST →
`pipeline::handle_query` request dispatch (plus T-25's non-A/AAAA proxying) now resolves queries
end to end, manually confirmed against the running binary (`Invoke-WebRequest -HttpVersion 2.0
-SkipCertificateCheck`: GET and POST both 200 with a correctly encoded `application/dns-message`
answer, wrong path 404, wrong method 405). New `dispatch.rs` module: `wire_bytes_from_get`/
`content_type_is_dns_message` (`pub(crate)`, RFC 8484 §4.1.1/RFC 7231, unit-tested directly),
`resolve_doh_request` (`pub(crate)`, decode → `handle_query` → `pipeline::proxy_to_single_upstream`
on `ProxyToSingleUpstream` → encode), and `pub` `AppState<C: DohClient + Sync>` + `serve` — `serve`
is deliberately generic over the request body type (`B: Body<Data = Bytes>`), not hardcoded to
`hyper::body::Incoming` (which only a live connection can construct), specifically so it's
unit-testable with `http_body_util::Full` instead of needing a real socket. Routing: exact-match
`/dns-query` only (SPEC.md §1 line 84), 404 otherwise — leaves `/health` (T-86, Фаза 3) free on the
same port without colliding; POST body size is bounded via `http_body_util::Limited::new(body,
MAX_MESSAGE_SIZE)` wrapped **before** `.collect()`, not after (a post-collection length check
bounds nothing — advisor review of the plan caught the first draft doing this backwards, violating
SPEC.md §8.1's "ліміт розміру, не необмежена алокація"). `tls::build_server_config` now sets
`alpn_protocols` (`h2` then `http/1.1`) — advisor review of the plan: an unset ALPN offer doesn't
guarantee predictable HTTP/2 negotiation. `paths::app_data_dir`/`PathsError` are `pub` as of this
slice (were `pub(crate)`) — `main.rs` is a separate crate (the `[[bin]]` target) and is the first
genuine external-crate consumer, needing a real path to resolve `overrides.json`'s location. Seven
new direct dependencies (`hyper`, `hyper-util`, `tokio-rustls`, `http`, `http-body-util`, `bytes`,
`tracing-subscriber` — SECURITY.md rows added for each); `tracing_subscriber::fmt::init()` is the
first real subscriber this project has ever wired, so every existing `tracing::` call site starts
emitting for the first time — audited (grep, not assumed) before enabling it, none interpolates a
domain name. At the time of this slice, port `8443` and `Voters::Enabled` were MVP hardcoded
defaults (no config UI yet — T-52) — **superseded by T-144** (see the fourteenth-slice paragraph
below), which made both a real persisted config. **Not yet in
this slice**: `query_log::LogEntry` still has no producer; graceful shutdown/signal handling (no
watcher yet, Фаза 3); T-49 (manual trust-store install) and T-51 (empirical CT-policy check) are
now genuinely unblocked (a real listener exists to connect to) but not themselves done.

Фаза 1, T-66 done (TASKS-DONE.md, one commit): the phased-plan's own named Фаза 1 validation
deliverable — measuring whether "quorum beats a single provider" actually holds, plus a cache
latency sanity check — is done as a standalone `examples/phase1_metrics.rs` benchmark, not a change
to any production code path. Malicious-domain source (decided with the user, not invented from
training-data memory of what's "currently" on a blocklist, which would be unverifiable and possibly
stale): the live abuse.ch URLhaus recent-URLs CSV feed, no Auth-Key needed. Two real findings from
an actual run, not fabricated: (1) a real methodology bug caught by advisor review of the plan
before writing code — a fixed well-known-domain list (`example.com` etc.) would have been useless
for latency measurement, since those domains are so heavily cached *upstream* that a "cold" query
would still land in ~10ms regardless of this service's own cache state; fixed by reusing the same
URLhaus-derived sample for both halves of the benchmark (genuinely uncached anywhere, differs every
run) and relabeling the buckets honestly as "local cache miss"/"local cache hit", not "cold"/"warm".
(2) A real bug in the benchmark tool itself, caught empirically during the actual run (not by any
static check): `hickory_proto::op::Message::query()` leaves `recursion_desired` at its default
`false`, which made Cloudflare's baseline resolver SERVFAIL on 39/40 sampled domains — looked at
first like "most of these fresh malware domains are already dead," until a debug trace showed
definitely-live domains failing identically; root-caused by reading `hickory-proto`'s own source,
fixed by setting `message.metadata.recursion_desired = true` explicitly (CLAUDE.md gotchas has the
full writeup, including why this never affected any shipped code path — confirmed by reading
`pipeline::resolve_via_baseline`/`quorum::resolve`, which always forward the original incoming query
object, never build a fresh one for an outgoing upstream call). A closing advisor review of the diff
caught a third thing before commit: an AdGuard 0% rate is ambiguous by response code alone —
AdGuard's own block signal is an explicit `0.0.0.0`/`::` *answer*, still rcode `NoError`, so "AdGuard
blocked nothing" and "AdGuard blocked everything but `is_blocked` missed it" look identical in an
rcode-only trace. Checked with a one-off run logging raw AdGuard answer records: every one of the 38
carried genuine, routable IPs, no null-IP anywhere — confirming the 0% figure is a real finding, not
a masked bug in the shipped `is_blocked`/`evaluate` logic. Real numbers from the corrected run (one
sample, one point in time — not a controlled multi-run study): 38/40 domains resolvable (baseline
`NoError`); Quad9 alone caught 22/38 (57.9%, via NXDOMAIN — an upper bound under `is_blocked`'s
`NeedsBaseline` semantic, not an unambiguous explicit signal, per the example's own module doc
comment); AdGuard alone caught 0/38 in this sample (verified, not assumed); quorum (OR) therefore
matched Quad9's
own rate exactly, and the "exactly one provider blocked" count was 22/38 — meaning this particular
sample didn't demonstrate AdGuard adding incremental catches over Quad9 alone, an honest finding
worth recording as-is rather than silently omitted for looking unflattering to the two-provider
design; local cache hit vs miss showed the expected two-orders-of-magnitude win (mean ~2.9ms hit vs
~156ms miss), directly validating SPEC.md §4's caching rationale. The tool is deliberately **not**
wired into CI (non-deterministic live-threat-feed content and live third-party calls, same
"manual, not automated" precedent as the existing `#[ignore]`d live-Quad9 test) and the fetched
domain list itself is never committed anywhere in this repo — only these interpreted numbers are.

Фаза 1, fifteenth slice done (T-145 — TASKS-DONE.md, one commit): config-file format switched
from JSON to TOML for both `config.rs`'s `ResolverConfig` (T-144) and `overrides.rs`'s
`OverrideLists` (T-37) — user asked, mid-session, for a hand-editable format "like `ssh_config`/
`my.cnf`" and whether something beats plain JSON; TOML was recommended and implemented (comment
support is the actual gap JSON has vs. that style; the swap is close to mechanical on top of the
existing serde-based `ResolverConfigFile`/`OverrideListsFile` pattern — `toml::from_str` in place of
`serde_json::from_str`, same struct shapes, same `#[serde(default, deny_unknown_fields)]`
attributes). **This is a genuine SPEC.md reversal, not just a code change** — SPEC.md named JSON
explicitly (comms-matrix row, §1's override-storage line), both now edited to say TOML, with a
`DECISIONS.md` entry recording the switch (same precedent as T-20's block-response-format
correction). Hard cutover, no dual-format loader: `resolver_config.json`/`overrides.json` are no
longer read at all, file names become `resolver_config.toml`/`overrides.toml`. Two things an
`advisor` review of the plan caught before implementing: (1) `toml::de::Error`'s `Display`/`Debug`
both render an annotated snippet of the offending input line (unlike `serde_json::Error`'s generic
"expected value at line N"), confirmed empirically via a scratch probe — since `overrides.toml` is
nothing but domain names, wrapping that error type the same way `config.rs` does would newly leak a
domain into the service diagnostic log the moment `main.rs` logs it, the same failure class already
recorded for `InvalidReason`/`ProtoError` in this file's own gotchas. Fixed by making
`overrides::OverrideError`'s parse variant (`Parse`) carry **no payload at all** — a fixed message,
structurally incapable of carrying a domain — while `config::ConfigError::Toml(toml::de::Error)`
keeps its payload, since `resolver_config.toml` carries no domains and the rich snippet is a genuine
UX win there. A new regression test (`overrides.rs`'s
`load_error_display_never_contains_the_raw_toml_input`) formats the error with a sentinel domain
embedded in malformed input and asserts the sentinel is absent, mirroring the existing
`InvalidEntry`-redaction test. (2) A hard cutover alone would make an already-populated
`overrides.json` silently invisible on upgrade — `load()` sees no `.toml` file, returns empty, and
the caller only warned on `Err`, never on merely-missing. A user with a real blocklist would go
silently unfiltered, the Три Б user-safety failure mode by name. Fixed with a small `main.rs` helper
(`warn_if_legacy_json_sibling_exists`), called before both `load_overrides`/`load_resolver_config`'s
real `load()` calls — if the new `.toml` path is missing but the old `.json` sibling exists,
`tracing::warn!`s the two file *paths* (never contents) so the operator notices the format changed
instead of silently losing their config. Not a compatibility shim — the old file is still never
read, only its *presence* is detected and reported. Manually confirmed on the running binary: a
`resolver_config.toml` port override still works exactly as T-144's own JSON version did; a
malformed `.toml` still exits 1 with an explicit (now TOML-snippet) error, not a silent fallback; a
leftover `overrides.json` with no `overrides.toml` sibling produces exactly the new warning log line
and nothing else. New direct dependency `toml` 1.1.4 (+ `toml_parser`/`toml_writer`/
`toml_datetime`/`serde_spanned`/`winnow`, all `MIT`/`MIT OR Apache-2.0`, already-allowed licenses,
SECURITY.md row added) — default features (`display`, `parse`, `serde`, `std`) are sufficient, no
`cargo tree` feature drift found for the crates it shares with the existing dependency graph (none
— this is a genuinely new leaf in the tree). `timeout.rs`'s existing `TimeoutMode` JSON round-trip
test is intentionally left as JSON, not converted to TOML — `toml::to_string` has no bare-scalar
document root to serialize a lone enum variant into, and the snake_case variant-name string it
proves is identical in both formats regardless (only the test's own comment was reworded to stop
claiming it proves `config.rs`'s literal on-disk shape, which is no longer JSON). T-146
(config-driven persisted query log) stays explicitly out of scope — separate task, blocked on the
encrypted-storage mechanism SPEC.md's privacy constraints require (T-96).

Фаза 1, fourteenth slice done (T-144 — TASKS-DONE.md, one commit): `main.rs`'s three MVP-hardcoded
constants (port, timeout mode/duration, `Voters::Enabled`) are now a real persisted
`ResolverConfig` — new module `config.rs`, mirroring `overrides.rs`'s own load pattern closely
(`ResolverConfigFile`/`ConfigError`/`ResolverConfig::load`: missing file → `Ok(default())`,
malformed file → `Err`, struct-level `#[serde(default, deny_unknown_fields)]` so an absent key
defaults per-field but a typo'd key fails loudly). Deliberately **not** a per-provider/category
config (UI-SPEC.md §3.4's Security/Ads/Adult toggles) — checked `quorum::resolve` (`quorum.rs`)
first: it hardcodes querying both `Provider::Quad9` and `Provider::AdGuard` unconditionally, no
parameter anywhere for "which providers to query," and `upstream::Provider` only has those two
variants (matching Фаза 1's explicit "2 upstreams" scope) against SPEC.md's much longer preset
table — persisting a per-provider toggle the resolver can't act on would repeat T-41's own `Voters`
lesson (a config subset nothing downstream honors is a footgun), so only `voters_enabled` (the one
toggle already wired since T-41) is persisted; per-provider toggling is a named, open gap for
whoever scopes T-52's config surface for real. Unlike `overrides.json`'s own load errors (non-fatal,
falls back to empty), a malformed `resolver_config.json` is **fatal** at startup — SPEC.md §1's
"never a silent port fallback" rule means silently substituting the default port for a corrupted
file would be exactly the forbidden behavior, one step removed. `port == 0`/`timeout_ms == 0` are
rejected explicitly at load (`ConfigError::ZeroPort`/`ZeroTimeout`, not silently clamped — a `0`ms
timeout would SERVFAIL every query instantly with no obvious cause, Три Б user safety, advisor
review of the plan). A *privileged* port (1-1023) is deliberately left unhandled for now — a bind
failure there is still loud (`BindError::Other`), just not specifically diagnosed as "needs
elevation"; noted in `config.rs`'s own doc comment as worth revisiting once T-53 exposes
`set_doh_port(port)` from the UI. `timeout::TimeoutMode` gained `Serialize`/`Deserialize`
(`#[serde(rename_all = "snake_case")]`) rather than a parallel config-only copy of the same three
variants. `main.rs` now resolves `app_data_dir()` once and joins two file paths off it
(`overrides.json`, `resolver_config.json`) instead of resolving it twice. **Manually confirmed on
the running binary**: a `resolver_config.json` with `port: 9443` actually changed which port the
listener bound (confirmed with a real `DoH` query against 9443), and a structurally-invalid file
exits with code 1 and an explicit error, not a silent fallback. **Not yet in this slice**:
per-provider/category toggles, `save()`/live-reload, the Tauri scaffold and commands themselves
(T-52/T-53) that would actually let a user change any of this without hand-editing JSON.

Фаза 1, twelfth slice done (T-142 — TASKS-DONE.md, one commit): `tls::load_or_generate_server_config`
— builds a `rustls::ServerConfig` from the cert/key T-48/T-50 generate and persist, making the
"load-existing-vs-regenerate" decision T-50 explicitly left open for "the future listener-wiring
caller." New `tls.rs` module, three functions layered the same way every prior slice in this crate
has been: `server_config_from_certified_key` (pure, builds from an in-memory freshly-generated
`CertifiedKey`, no filesystem), `load_server_config_from_dir` (pure, parameterized by directory —
mirrors `paths.rs`'s own pure/impure split for testability), and the real `pub`
`load_or_generate_server_config` orchestrator (tries the load path first, falls back to
generate+persist on any failure, `tracing::warn!`s specifically when an *existing* cert couldn't be
used — as opposed to `tracing::info!` on an ordinary first run — since silently replacing a corrupt
cert could invalidate a user's T-49 manual trust-store install without them noticing). Not directly
unit-tested itself — same "hardcoded real app-data path, untested by design" precedent as
`paths::app_data_dir`/`cert::write_cert_and_key_to_app_data`; the two pure functions above carry
the actual coverage, including a deliberately-mismatched-cert-and-key negative test proving
`rustls`'s `SubjectPublicKeyInfo` check is actually exercised, not just "the happy path returns
`Ok`." New direct dependencies: `rustls` 0.23 only (`default-features = false, features =
["aws_lc_rs", "std", "tls12"]` — confirmed via `cargo tree -f "{p} {f}" -p rustls` that this is the
*exact* feature set `reqwest` already activates, adding nothing new to the build). Deliberately
**not** `pem` as a second new dependency — `rustls::pki_types::pem::PemObject::from_pem_slice` (via
the `rustls::pki_types` re-export, confirmed in `rustls`'s own `lib.rs`) reads the PEM tag itself
(`"PRIVATE KEY"`/`"RSA PRIVATE KEY"`/`"EC PRIVATE KEY"` → the correctly tagged `PrivateKeyDer`
variant) rather than this project assuming a fixed encoding, and it's already available given
`rustls`'s `std` feature — one fewer dependency, one fewer place two PEM parsers could disagree.
Every `ServerConfig` is built via `ServerConfig::builder_with_provider(aws_lc_rs::
default_provider())`, never the plain `ServerConfig::builder()` — see the gotchas section below,
this was a real correction during the closing advisor review, not a first-draft decision. At the
time of this slice, `main.rs` was still an untouched stub — the actual `hyper` TCP accept loop,
TLS termination, and DoH GET/POST → `pipeline::handle_query` request dispatch (plus T-25's
non-A/AAAA passthrough) were a separate, larger, not-yet-numbered next task. **Superseded by
T-143** (see the thirteenth-slice paragraph above) — that task is now done.

Фаза 1, eleventh slice done (T-50 — TASKS.md, one commit): `cert::write_cert_and_key_to_app_data`
— disk persistence for T-48's cert/key, SPEC.md §2's explicitly named MVP fallback ("якщо secure
storage складно — файл з правами `600`, зафіксований як технічний борг"). Writes `cert.pem`/
`key.pem` to `%LOCALAPPDATA%\dns-quorum-filter\` (new `paths.rs` module, `pub(crate)`, split into a
pure `resolve_app_data_dir` and a thin `app_data_dir` wrapper so the LOCALAPPDATA-missing case is
unit-testable without mutating the real process environment — `std::env::set_var` is `unsafe fn`
on this toolchain regardless of edition, which would conflict with `#![forbid(unsafe_code)]`).
`key.pem`'s ACL is restricted to the current user only via `icacls.exe`, spawned by absolute path
(`%SystemRoot%\System32\icacls.exe`) with a bare `%USERNAME%` grant — confirmed empirically (not
assumed) that `icacls` resolves an unqualified account name against the local machine first, so no
`%USERDOMAIN%` lookup is needed. Restriction is **two `icacls` phases, not one** — see the gotchas
section below for why a single `/inheritance:r /grant:r` pass looked sufficient on the dev machine
but left extra grants in place on CI, caught only once CI actually ran (not by any local test).
Advisor review of the plan caught a real TOCTOU gap in the first draft (write key bytes, then
restrict the ACL) — fixed to create the file empty, restrict its ACL, *then* write the key bytes,
so the private key is never on disk under the parent directory's wider inherited ACL even briefly;
confirmed empirically that a truncate-in-place write preserves an already-set ACL rather than
resetting it. The derived PEM text is wrapped in `zeroize::Zeroizing`
and the source `KeyPair` gets an explicit `.zeroize()` call after writing (new direct `zeroize`
dependency; `rcgen`'s own `zeroize` feature, now enabled, only wipes the `KeyPair`'s internal DER
bytes, not a PEM `String` derived from it) — documented as best-effort in-memory hygiene, not a
guarantee, with no test claiming to prove memory was wiped (advisor review: the only observable
effect would prove `rcgen`'s implementation, not this module's code). The function unconditionally
overwrites both files on every call — deciding whether to load an existing cert instead is left to
the future listener-wiring caller, stated explicitly rather than silently assumed. **Not yet in
this slice**: trust-store installation (T-49), certificate rotation (T-69), platform secure storage
(T-67, Фаза 2), and the load-existing-vs-regenerate decision itself (real `main.rs` listener
wiring, still a stub at the time). **Both since superseded**: the load-vs-regenerate decision by
T-142, the listener wiring itself by T-143 (see the paragraphs above).

Фаза 1, tenth slice done (T-48 — TASKS.md, one commit): `cert::generate_self_signed_cert` — the
local `DoH` listener's self-signed leaf certificate (SPEC.md §2), generation only. SAN
`IP:127.0.0.1`, `IP:::1`, `DNS:localhost` via `rcgen::CertificateParams::new` (the same
classification `generate_simple_self_signed` uses internally — verified empirically via a scratch
probe, not assumed from docs, that IP literals become typed `GeneralName::IPAddress` entries, not
`DNSName` strings). Not a CA via `IsCa::ExplicitNoCa`, not the plain `NoCa` default — advisor
review of the diff caught that `NoCa` omits the `BasicConstraints` extension entirely, so a test
asserting "not a CA" against it would pass regardless of this cert's actual bytes;
`ExplicitNoCa` encodes `cA=FALSE` explicitly, and the test now asserts that field, not just
`x509_parser`'s no-extension-means-false default. Explicit `DistinguishedName` (CN =
`"dns-quorum-filter local DoH"`) instead of rcgen's placeholder CN — same review pass: T-49's
manual trust-store import and T-69/T-70's find-and-remove-on-rotation/uninstall all need a human
(or future automation) to recognize this cert in the OS store, which a placeholder CN wouldn't
support. Explicit 100-year validity window (`2020-01-01`..`2120-01-01`), overriding rcgen's own
unexamined raw default (`1975`..`4096`) — absolute dates chosen deliberately (not
`SystemTime::now()`, though that would work without any new dependency — also verified
empirically) so this module's own tests assert an exact timestamp; stated as provisional pending
T-51's empirical Chrome/Firefox CT-policy check, not a settled number. **Not yet in this slice**
(same "primitive ready, wiring later" pattern as every prior module): writing the cert/key to disk
(T-50, explicit private-key-file tech debt), trust-store installation (T-49, manual/human step),
certificate rotation (T-69, Фаза 3), or wiring into a real `hyper` + TLS listener (`main.rs` was
still a stub at the time — **superseded by T-143**, see the paragraphs above).

Фаза 1, ninth slice done (T-42/T-43 — TASKS.md, one commit): `query_log::QueryLog` — the in-memory
ring buffer query log (SPEC.md §6, §6.1), a `VecDeque<LogEntry>` behind `parking_lot::RwLock` (new
direct dependency, SECURITY.md), bounded independently by entry count (evict-oldest-after-push,
provable post-condition per global CLAUDE.md's bounds-safety rule — not an `if len >= max` guard
before push) and age (`retain`-on-read, no background sweep task, per SPEC.md §6.1). `LogEntry` is
the internal backend record — narrower than the eventual Tauri DTO of the same name
(`diagrams/ui-dto-model.md`, `UI-SPEC.md`): only the four `decision_source` values Phase 1 can
actually produce (`ALLOWLIST`/`BLOCKLIST`/`CACHE`/`QUORUM`), no `voter_scope`/`geoip_country` field
at all (those are T-109/T-79, later phases) — the DTO widening is T-53/T-54 scope, not this
module's. `voters: Vec<VoterRecord>` deliberately carries only `Provider`'s two filtering-voter
variants, not `quorum::Slot`'s three (baseline never casts an OR-logic vote, SPEC.md §3.1) — a
SPEC-silent choice, flagged in the module's own doc comment rather than picked silently. No live
producer yet either (nothing in `pipeline::handle_query` builds/pushes a `LogEntry`), same
"backend primitive ready, wiring later" pattern as every module below.

Фаза 1, eighth slice done (T-137 — TASKS.md, one commit): `Cache::clear()` — manual one-click
full-cache clear (SPEC.md §4, analogous to T-44's planned log-clear button), a thin wrapper over
`moka::future::Cache::invalidate_all` (no predicate needed, unlike `invalidate_matching` — `moka`
just stamps the current time as the invalidation cutoff). No live caller yet either (no Tauri
command exists — T-53), same "backend primitive ready, UI wiring later" pattern as T-40's
`invalidate_matching`/`invalidate_changed`.

Фаза 1, seventh slice done (T-41 — TASKS.md, one commit): `pipeline::handle_query` gains a
`Voters` parameter — SPEC.md §3/§8.1's explicit pass-through when the user has disabled every
quorum provider, on top of the sixth slice's (T-40) cache invalidation on an override-list reload
and the fifth slice's (T-39) end-to-end request pipeline — allowlist → blocklist → cache → quorum
(SPEC.md §5 steps 1-3+5). `dnsqb-service`'s `lib.rs` now re-exports from ten of its eleven
modules — `cache`
(`CacheKey`/`CacheEntry`/`Verdict`/`CacheConfig`/`Cache`, `clamp_ttl`, `chain_cache_ttl`,
`is_cacheable`, T-32/T-34/T-36; `Cache::invalidate_matching`, T-40 — one `moka`
`invalidate_entries_if` predicate per whole batch of changed domains, not one per domain, since
`moka` re-applies every live predicate on every `get()` until its own maintenance task sweeps it
away; `Cache::clear`, T-137), `overrides` (`OverrideLists::decision`/`conflicts`/`load`,
`OverrideEntry`/`ListKind`/`InvalidEntry`/`InvalidReason`/`OverrideError`, T-37;
`changed_entries`, T-40 — `pub(crate)`, symmetric diff between two `OverrideLists` snapshots, no
reader outside `pipeline::invalidate_changed` yet), `pipeline` (`handle_query`/`PipelineOutcome`,
T-39; `invalidate_changed`, T-40 — the reload-event counterpart to `handle_query`'s per-query
flow; `Voters { Enabled, Disabled }` new this slice — deliberately not `&[Provider]`, see the
gotchas section below), `wire` (`DoH` wire codec, block/NODATA/
SERVFAIL/direct-answer response construction, AD-bit passthrough), `upstream` (`Provider` enum,
`DohClient` trait + `ReqwestDohClient` with per-upstream HTTP/2 keep-alive, T-31), `timeout`
(`TimeoutMode`/`TimeoutConfig`, `VoterOutcome`, `query_with_timeout`, T-27), `quorum` (`is_blocked`
per-provider signature table, `requires_quorum`, OR-logic `resolve()` returning `QuorumOutcome
{verdict, answer}` — T-39 extended it to carry the real Allow answer, not just a verdict, SPEC.md
§5 step 5's "get ALLOW + IP" bundled as one action — with early-return/cancellation via
`FuturesUnordered`, T-30), `listener` (`bind_listener`/`BindError`, `127.0.0.1`-only), `query_log`
(`QueryLog`/`LogEntry`/`Decision`/`DecisionSource`/`VoterRecord`/`VoterVerdict`, T-42/T-43 — see
the ninth-slice paragraph above), `cert` (`generate_self_signed_cert`/`CertError`, T-48;
`write_cert_and_key_to_app_data`/`CertFiles`, T-50 — see the tenth/eleventh-slice paragraphs
above). The eleventh module, `paths` (T-50), stays crate-private — `pub(crate)`, no `pub use` —
since only `cert.rs` needs it so far. `lib.rs`'s own `min_rrset_ttl`/`negative_cache_ttl`/
`normalize_domain` are implemented (T-33/T-35/T-38, no longer `todo!()`).

`pipeline::handle_query` is the first real consumer of `cache.rs`/`overrides.rs`/`quorum.rs`
together — it branches a `CacheEntry` between positive-answer (`chain_cache_ttl`) and genuine
NXDOMAIN/NODATA (`negative_cache_ttl`, from an authority-section SOA `pipeline.rs`'s own
`find_soa` now extracts) TTL sources. `pipeline::invalidate_changed(before, after)` (T-40) is a
second, separate entry point — not per-query, but per override-list reload: it diffs two
`OverrideLists` snapshots (`overrides::changed_entries`) and evicts every affected domain's cache
entries in one `Cache::invalidate_matching` call. Needed because `handle_query`'s fixed
overrides-before-cache order means a domain under an active override rule can never get a *new*
cache entry — the only entry that can go stale is one written *before* the rule existed, so
invalidating at rule-*add* time (not just removal) is what actually closes the gap; see
`invalidate_changed`'s own doc comment for the full argument. `Voters::Disabled` (T-41) short-
circuits `handle_query` straight to the already-existing `resolve_via_baseline` helper (the same
one the allowlist branch uses) — one baseline query, no filtering, not cached (same reasoning as
the allowlist/blocklist branches: a cached pass-through record would be indistinguishable from a
genuinely-filtered `Allow` once a provider is re-enabled). A blocklist match still short-circuits
above the `Voters::Disabled` check regardless of voter state — disabling third-party voters never
disables the user's own override rules. **Not yet in this slice**: voter scope (SPEC.md
§5.3-конвеєр крок 4, top-N-per-country, Фаза 4) and GeoIP (крок 6, Фаза 2) — both later phases by
design; RFC 8767 stale-if-error wired into the live pipeline (`should_serve_stale` stays an
unconsumed predicate — deferred per advisor review, see the gotchas section below for why); UI
warning on an allowlist/blocklist conflict (`OverrideLists::conflicts()` is ready, no UI consumer
yet — T-47/T-52); `overrides.rs` still has **no file-write path** (`save()` — deliberately deferred
to T-46/T-47, when a UI writer exists; SPEC.md §5 calls the file "редагований і вручну", manually
text-edited, until then) — so nothing calls `invalidate_changed` yet either, same pattern as
`handle_query` itself before the real listener exists; no real per-provider toggle config exists
yet either (T-52), so nothing calls `handle_query` with `Voters::Disabled` yet. `query_log::QueryLog`
(T-42/T-43) exists but has no live producer either — `handle_query` doesn't build or push a
`LogEntry` yet, that wiring is a later task. The self-signed leaf certificate exists and is
persisted to disk (`cert::generate_self_signed_cert` + `write_cert_and_key_to_app_data`,
T-48/T-50), the load-existing-vs-regenerate decision those left open is made
(`tls::load_or_generate_server_config`, T-142, produces a real `rustls::ServerConfig`), and as of
T-143 there's a real `hyper` TCP accept loop + TLS termination + `dispatch::serve` request
dispatch — `main.rs` is no longer a stub, manually confirmed resolving real queries end to end
(see the thirteenth-slice paragraph above). Trust-store install (T-49) and the empirical CT-policy
check (T-51) are now genuinely unblocked — a real listener exists to connect to — but not
themselves done yet. `dnsqb-watcher` is still
a stub binary (`todo!()` body); it's Фаза 3 scope (SPEC.md §7).

Runtime dependencies: `hickory-proto`, `tokio` (`rt-multi-thread`/`macros`/`net`/`sync`/`time` —
`sync` added T-149 for `tokio::sync::watch`, `main.rs`'s `/admin/shutdown` signal; `test-util`
in `[dev-dependencies]` for `tokio::time::pause`/`advance` in timeout tests), `reqwest`
(`default-features = false`, `rustls`/`http2`/`json`/`stream` — `json` added T-52 for
`admin::AdminClient`'s `Response::json()`/`RequestBuilder::json()`; `stream` added T-75 for
`Response::bytes_stream()`, `geoip_updater::fetch_bounded`'s chunk-by-chunk size-bounded download
(pulls in `tokio-util`; `wasm-streams` too, but `cfg`'d to `wasm32`, outside this project's
Windows-only `cargo deny` graph restriction); `cargo deny check` clean both times, no new license
entries; still no `native-tls`), `thiserror`, `base64`,
`futures-util` (`FuturesUnordered`/`StreamExt` only, not the full `futures` crate — T-30), `tracing`
(diagnostic logging, T-29; `SPEC.md`'s "Технічний стек" table doesn't name a logging crate, `tracing`
is the tokio-ecosystem de-facto default), `tracing-subscriber` (T-143 — `main.rs`'s
`tracing_subscriber::fmt::init()`, the first real subscriber this project has wired; every existing
`tracing::` call site was grepped and confirmed not to interpolate a domain name before this was
enabled — RUSTSEC-2025-0055 against this crate doesn't cover the version resolved here, re-checked
via `cargo audit`, see SECURITY.md),
`moka` (`default-features = false`, feature `future` only — concurrent per-entry-TTL cache, T-32),
`maxminddb` (+`ipnetwork`, `default-features = false` — GeoIP country lookup, T-74, Фаза 2; `mmap`/
`simdutf8`/`unsafe-str-decode` all opt-in and left off, keeping this crate's `#![forbid(unsafe_code)]`
posture without an exception for this dependency),
`serde` (`derive` feature) + `serde_json` (introduced T-37 for the override-list file's on-disk
shape; that use moved to `toml` at T-145, but `serde_json` stays direct — `timeout.rs`'s
`TimeoutMode` round-trip test still exercises it deliberately, per the fifteenth-slice paragraph
above, and it's also what `admin.rs`'s JSON DTOs and `admin_ui.rs`'s embedded web UI need
regardless), `toml` (T-145 —
default features `display`/`parse`/`serde`/`std`; `config.rs`'s `ResolverConfig`/`overrides.rs`'s
`OverrideLists` on-disk format, replacing `serde_json` there for comment support and
`ssh_config`/`my.cnf`-style hand-editability, DECISIONS.md), `parking_lot` (`query_log.rs`'s ring buffer lock, T-42 — SPEC.md §6.1's
explicit choice over `tokio::sync::RwLock`, since no critical section here ever holds the lock
across an `.await`), `rcgen` (`default-features = false`, features `aws_lc_rs`/`pem`/`zeroize` —
not the default `ring`, to match `reqwest`/`rustls`'s already-chosen crypto backend; SPEC.md §2's
self-signed leaf certificate, T-48; `pem`/`zeroize` added at T-50 for PEM encoding and key-wipe
support), `zeroize` (T-50 — wraps the derived private-key PEM text in `Zeroizing<String>` and
zeroizes the source `KeyPair` after writing; default features only, `alloc` not `std`), `rustls`
(T-142 — `default-features = false`, features `aws_lc_rs`/`std`/`tls12` only, confirmed via `cargo
tree -f "{p} {f}" -p rustls` to be the exact feature set `reqwest` already activates; builds the
local `DoH` listener's `rustls::ServerConfig` in `tls::load_or_generate_server_config`, always via
`builder_with_provider(aws_lc_rs::default_provider())`, never the plain `ServerConfig::builder()`
— see `tls.rs`'s own module doc comment), `hyper` (T-143 — `server` feature added to the
`client, http1, http2` set `reqwest` already activated; `dispatch.rs`/`main.rs`'s TCP accept loop
and request handling), `hyper-util` (T-143 — `default-features = false`, features `http1`/`http2`/
`server`/`server-auto`/`tokio`; `hyper_util::server::conn::auto::Builder` negotiates HTTP/1.1 vs
HTTP/2 per connection; `server-graceful` added T-149 — `hyper_util::server::graceful::
GracefulShutdown`, `main.rs`'s `serve_until_shutdown` drains in-flight connections after
`/admin/shutdown` fires, 5s timeout), `tokio-rustls` (T-143 — `default-features = false`, feature `tls12` only,
`aws-lc-rs` resolves in automatically via this workspace's already-active `rustls` feature choice,
confirmed via `cargo tree`; TLS termination on each accepted connection), `http` (T-143 — default
features, `StatusCode`/`Method`/`Request`/`Response`/`header` types `dispatch.rs` names directly),
`http-body-util` (T-143 — default features; `Full<Bytes>` for every response body,
`Limited::new(body, MAX_MESSAGE_SIZE)` wrapped **before** `.collect()` for every POST request body
— see the thirteenth-slice paragraph above for why that ordering matters), `bytes` (T-143 —
default features, the `Bytes` buffer type those response/request bodies are built from) — vetting
rows for each are in SECURITY.md. `crates/dnsqb-tray` (T-149, new crate, replacing `dnsqb-ui`'s
Tauri dependency tail) adds `tray-icon` 0.21.3 (tray icon + `muda`-backed menu, consumed only via
`tray_icon::menu::*`'s re-export — no direct `muda` dependency), `tao` 0.31.1 (the event loop
`tray-icon` requires — `EventLoop::run` owns the calling thread; `status.rs`'s admin-channel
polling runs on a separate OS thread with its own `tokio::runtime::Builder::new_current_thread()`
runtime), `rfd` 0.15.4 (`default-features = false`; native confirm dialog for "Stop filtering"),
`parking_lot` (`status.rs`'s `Arc<RwLock<TrayStatus>>`), and depends on `dnsqb-service` itself as
a library (for `AdminClient`) — all license-clean (`MIT OR Apache-2.0`/`MIT`), `cargo deny check`
confirmed at T-149 (2026-08-27). `[dev-dependencies]` also gained `tempfile` (T-37, `overrides.rs`'s
`load()` tests only — never shipped in a binary) and `x509-parser` (T-48, `cert.rs`'s tests only —
decodes the real DER `rcgen` produces to assert SAN/`is_ca`/validity empirically rather than
trusting `rcgen`'s docs; T-50 also uses its `pem` module to prove `Certificate::pem()` round-trips
to the same DER), and `proptest` (T-58 — first real use of the planned-stack's own named fuzz/
property-test crate; `default-features = false, features = ["std"]`, deliberately excluding the
default `fork`/`timeout` features' process-spawning dependency tail). `deny.toml`'s license allowlist also covers `CDLA-Permissive-2.0`
(webpki-root-certs' CA-data license) and `ISC` (rustls' crypto backend and `rustls-webpki`), both
added several batches ago; `futures-util`/`tracing`/`moka`/`serde`/`serde_json`/`tempfile`/
`parking_lot`/`rcgen`/`x509-parser`/`zeroize`/`rustls`/`hyper`/`hyper-util`/`tokio-rustls`/`http`/
`http-body-util`/`bytes`/`tracing-subscriber`/`toml` didn't need new allowlist entries (`rcgen`/
`x509-parser`/`zeroize` are all `MIT OR Apache-2.0`, already allowed; `rustls` is `Apache-2.0 OR
ISC OR MIT`, `ISC` already allowed for this same TLS stack; the `hyper` family/`http`/
`http-body-util`/`bytes`/`tracing-subscriber` are all plain `MIT`, already allowed) — `cargo deny
check` confirmed clean at T-142 (2026-08-26) and again at T-143 (2026-08-26). `flate2`
(`default-features = false, features = ["miniz_oxide"]` — the crate's own pure-Rust, no-`unsafe`
default backend, no C toolchain; T-75, `geoip_download::decompress_bounded`'s bounded gzip
decompression of a downloaded `GeoIP` database) and `sha1` (RustCrypto, T-75,
`geoip_updater::sha1_hex` — verifies an opportunistic `.sha1` checksum sidecar; SHA-1 chosen to
match what `db-ip.com`'s download page actually publishes, not for collision resistance) both
resolve to already-allowed licenses (`MIT OR Apache-2.0`), no new `deny.toml` entries — `cargo deny
check` confirmed clean at T-75 (2026-08-29); introduces a second `cpufeatures` version alongside the
one `chacha20`/`rand` already pull in (`multiple-versions = "warn"`, not `deny`, so this doesn't
fail the gate).

Commands (from repo root):
- `cargo build --workspace` — build all three crates (`dnsqb-service`, `dnsqb-watcher`, and
  `dnsqb-tray` as of T-149, replacing T-52's Tauri-based `dnsqb-ui` — see DECISIONS.md). No
  `tauri-cli`/frontend build step of any kind — `dnsqb-tray` is a plain Rust binary
  (`tray-icon`/`tao`/`rfd`), and the browser-based config page (`/admin/ui`) is served directly
  by `dnsqb-service` from `include_str!`-embedded HTML/CSS/JS, no bundler.
- `cargo test --workspace --lib --bins` — unit tests (`is_blocked`/quorum, T-61/T-62; `#[tokio::test]`
  for the async quorum cases). **`--bins` is required, not optional** — `dnsqb-tray`/`dnsqb-watcher`
  are `[[bin]]`-only crates with no `[lib]` target, so `--lib` alone silently never compiles or runs
  their own `#[cfg(test)]` modules (`dnsqb-tray/src/browser.rs`'s test predates this fix and had been
  silently unexercised by CI the whole time; caught while adding T-56's `status.rs` tests — the CI
  command itself was still the old `--lib`-only form).
- `cargo test --test conformance -p dnsqb-service` — RFC-conformance tests; green
  (`#[ignore]`d ones stay green, un-`#[ignore]`d ones must actually pass; count of each changes as
  Фаза 1 tasks land — check `TASKS.md` or run `-- --ignored` below for the current red-board size,
  don't trust a hardcoded number here).
- `cargo test --test conformance -p dnsqb-service -- --ignored` — the same tests without the
  ignore filter; intentionally red until each cited Фаза 1 task lands (this is the informational
  red-board step in CI, not a merge gate).
- `cargo clippy --workspace --all-targets -- -D warnings` — lint gate, required, not advisory
  (`dnsqb-service`'s `lib.rs`/`main.rs` and `dnsqb-watcher`'s `main.rs` also carry
  `#![warn(clippy::pedantic)]` + `#![deny(clippy::unwrap_used, clippy::expect_used)]`, per
  `~/.claude/rules/rust.md`).
- `cargo fmt --all -- --check` — format gate.
- `cargo audit` / `cargo deny check` — dependency vetting, required (SECURITY.md, `deny.toml`).
- `cargo llvm-cov --workspace --lib --lcov --output-path lcov.info` — coverage report, published as
  a CI artifact, non-blocking at the MVP stage (T-19).
- `cargo doc --workspace --no-deps --document-private-items` with `RUSTDOCFLAGS=-D warnings` —
  rustdoc gate, required, not advisory. `lib.rs` carries `#![allow(rustdoc::private_intra_doc_links)]`
  (this crate is never published, its docs are always built with `--document-private-items`, and
  its doc comments routinely cross-reference private helpers on purpose) — don't add a second
  one-off `#[allow(...)]` next to a broken link instead of fixing the link itself.
- `cargo test --workspace --doc` — doctest gate, also required. As of this check-in there are
  **zero** doctests anywhere in the workspace (confirmed via `grep -rn '/// *```' crates`, 0
  hits) — `~/.claude/rules/rust.md`'s "key functions must include code examples" is not yet met
  anywhere; this step exists so the day the first doctest is added, it's actually run, not just
  compiled by the `docs` step above.

All of the above run in `.github/workflows/ci.yml` on every push/PR, except the `--ignored`
conformance step and `coverage` (both `continue-on-error: true`).

**Check the actual CI run after every push — local-green is not CI-green, especially for
OS-permission/environment-dependent code.** `gh run list --branch main --limit 5` to find the
run; `gh run watch <run-id> --exit-status` to wait on it; `gh run view <run-id> --log-failed` to
read a failure. Confirmed the hard way: an `icacls`-based ACL fix (T-50) passed the full local
gate on a Windows 11 Pro dev box but failed on the `windows-latest` CI runner, which has
different default file ACLs.

**`SPEC.md` is the source of truth for all design decisions.** Read it before proposing any
architectural change — most non-obvious choices in this project are already deliberated there with
explicit reasoning (search the file for the relevant section number rather than re-deriving a
decision from scratch).

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
  this environment — `cd` inside the same command string, don't rely on a prior call's `cd`.
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
