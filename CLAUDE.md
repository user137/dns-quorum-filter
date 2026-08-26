# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

Крок 0 done (SPEC.md §"Фазований план"): Rust workspace, CI, and the RFC-conformance test table
(T-1–T-19) are in place. Phase 1 target platform is Windows (DECISIONS.md, 2026-08-25 — SPEC.md
itself left this open).

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

Runtime dependencies: `hickory-proto`, `tokio` (`rt-multi-thread`/`macros`/`net`/`time`; `test-util`
in `[dev-dependencies]` for `tokio::time::pause`/`advance` in timeout tests), `reqwest`
(`default-features = false`, `rustls`/`http2` only — no `native-tls`), `thiserror`, `base64`,
`futures-util` (`FuturesUnordered`/`StreamExt` only, not the full `futures` crate — T-30), `tracing`
(diagnostic logging, T-29; `SPEC.md`'s "Технічний стек" table doesn't name a logging crate, `tracing`
is the tokio-ecosystem de-facto default), `tracing-subscriber` (T-143 — `main.rs`'s
`tracing_subscriber::fmt::init()`, the first real subscriber this project has wired; every existing
`tracing::` call site was grepped and confirmed not to interpolate a domain name before this was
enabled — RUSTSEC-2025-0055 against this crate doesn't cover the version resolved here, re-checked
via `cargo audit`, see SECURITY.md),
`moka` (`default-features = false`, feature `future` only — concurrent per-entry-TTL cache, T-32),
`serde` (`derive` feature) + `serde_json` (introduced T-37 for the override-list file's on-disk
shape; that use moved to `toml` at T-145, but `serde_json` stays direct — `timeout.rs`'s
`TimeoutMode` round-trip test still exercises it deliberately, per the fifteenth-slice paragraph
above, and it's also the dependency T-53's Tauri DTO layer will need regardless), `toml` (T-145 —
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
HTTP/2 per connection), `tokio-rustls` (T-143 — `default-features = false`, feature `tls12` only,
`aws-lc-rs` resolves in automatically via this workspace's already-active `rustls` feature choice,
confirmed via `cargo tree`; TLS termination on each accepted connection), `http` (T-143 — default
features, `StatusCode`/`Method`/`Request`/`Response`/`header` types `dispatch.rs` names directly),
`http-body-util` (T-143 — default features; `Full<Bytes>` for every response body,
`Limited::new(body, MAX_MESSAGE_SIZE)` wrapped **before** `.collect()` for every POST request body
— see the thirteenth-slice paragraph above for why that ordering matters), `bytes` (T-143 —
default features, the `Bytes` buffer type those response/request bodies are built from) — vetting
rows for each are in SECURITY.md. `[dev-dependencies]` also gained `tempfile` (T-37, `overrides.rs`'s
`load()` tests only — never shipped in a binary) and `x509-parser` (T-48, `cert.rs`'s tests only —
decodes the real DER `rcgen` produces to assert SAN/`is_ca`/validity empirically rather than
trusting `rcgen`'s docs; T-50 also uses its `pem` module to prove `Certificate::pem()` round-trips
to the same DER). `deny.toml`'s license allowlist also covers `CDLA-Permissive-2.0`
(webpki-root-certs' CA-data license) and `ISC` (rustls' crypto backend and `rustls-webpki`), both
added several batches ago; `futures-util`/`tracing`/`moka`/`serde`/`serde_json`/`tempfile`/
`parking_lot`/`rcgen`/`x509-parser`/`zeroize`/`rustls`/`hyper`/`hyper-util`/`tokio-rustls`/`http`/
`http-body-util`/`bytes`/`tracing-subscriber`/`toml` didn't need new allowlist entries (`rcgen`/
`x509-parser`/`zeroize` are all `MIT OR Apache-2.0`, already allowed; `rustls` is `Apache-2.0 OR
ISC OR MIT`, `ISC` already allowed for this same TLS stack; the `hyper` family/`http`/
`http-body-util`/`bytes`/`tracing-subscriber` are all plain `MIT`, already allowed) — `cargo deny
check` confirmed clean at T-142 (2026-08-26) and again at T-143 (2026-08-26).

Commands (from repo root):
- `cargo build --workspace` — build both crates.
- `cargo test --workspace --lib` — unit tests (`is_blocked`/quorum, T-61/T-62; `#[tokio::test]` for
  the async quorum cases).
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

## Rust/tooling gotchas (learned by doing, T-20–T-145 batches)

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
| `README.md` | human-facing project description | repo structure changes |

Don't duplicate a fact across files — link to the owner instead. `SPEC.md` stays the deep source of
truth; the other files summarize or track state, they don't re-derive it.

## Development practices for this project

(Adapted from a personal cross-project practices file — see it only if a point below turns out to
need more detail than fits here.)

- **Test-first, where a unit is isolatable.** SPEC.md §8.1 already instantiates this for the Tauri
  IPC boundary specifically (smoke / exploit / misuse / fuzz, four categories, not one "smoke"
  test) — apply the same discipline (write the failing test before the implementation) to the
  resolver, cache, and override-list logic too, not just the UI channel. A bug fix gets a
  regression test written first, reproducing the bug, before the fix.
- **Три Б (three safety legs) — check all three, not just "is this correct."** This project already
  embodies all three without naming them; naming them is useful as a completeness check when adding
  new logic:
  - *User safety* — does a failure mode leave the user worse off than no filtering at all, and will
    they notice? (Already why silent DoH fallback bypassing quorum is flagged as an open risk in
    SPEC.md, and why the watchdog "must **notify**, not silently self-heal.")
  - *Software safety* — is the code safe against adversarial/malformed input, provably from the line
    itself? Two concrete input boundaries in this project: DNS wire format from upstream providers
    (why `hickory-dns`, not a hand-rolled parser) and the Tauri IPC channel from the webview
    (SPEC.md §8.1's exploit/misuse/fuzz categories exist exactly for this leg).
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
| UI | Tauri |
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
