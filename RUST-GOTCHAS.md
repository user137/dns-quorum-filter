# Rust/tooling gotchas

Learned by doing, across many task batches (T-20 onward). Referenced from `CLAUDE.md`'s
"Rust/tooling gotchas" pointer — this file exists because that section kept being the
single largest contributor to `CLAUDE.md` regrowing past its CI size ceiling
(`.github/workflows/claude-md-size.yml`). Same maintenance rule as `CLAUDE.md` itself:
a new entry here on the same trigger (a real, empirically-verified gotcha worth not
re-deriving), never narrative that belongs in `TASKS-DONE.md`/`DECISIONS.md` instead.

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
- **The `icacls` ACL helpers (T-50: `write_user_restricted_file` / `restrict_to_current_user` /
  `other_principals` / `icacls_path`) were deleted in T-163** — nothing writes a plaintext secret
  to disk any more, so the tool-specific `icacls` lessons that lived here (bare-`%USERNAME%`
  resolution, ACE-count assertions, the single-pass-vs-two-phase restriction gap, principal-suffix
  matching) no longer apply to any live code path; full detail in git history / `TASKS-DONE.md`
  T-163 if that pattern ever recurs. The one lesson from this code that generalizes beyond `icacls`
  itself — local-machine verification isn't CI verification — is kept live under "Check the actual
  CI run after every push" in the Commands section above, not restated here.
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
- **Guarding an `Effect` in the impure shell is too late when the pure step that produced it
  already mutated its own state as a side effect of producing it.** T-185's first cut suppressed
  respawn during a deliberate pause by matching `Effect::Spawn if stop_flag_is_set(..)` in
  `dnsqb-watcher`'s loop — but `LoopDriver::tick` (`loop_driver.rs`) calls
  `RestartBudget::register_attempt(now)` itself whenever it sees `Restarting`, and `transition`
  (`S::GaveUp => S::GaveUp`) is terminal, so a pause longer than the 5/600s budget drove the
  automaton into a `GaveUp` that stuck against a healthy service after resume — until the watcher
  process itself was restarted. Fix at the time: skip the *whole* `tick()` while paused, not just
  the effect. **T-193 removed the pause-freeze entirely** — the root cause was that the pause path
  *killed the service* (`/admin/shutdown`); once a pause keeps the service up (it reads `stop.flag`
  itself now), the tick sees a healthy service, never reaches `Restarting`, and the whole problem
  dissolves. The *general* lesson stands: a property that a pure step can violate as a side effect
  of running must be enforced at the point that step runs, not inspected in the shell afterward —
  same family as the `Limited::new`-after-`.collect()` entry above. Caught by the closing advisor
  of Батч 3.12, not by any gate (`fmt`/`clippy`/tests all green — no test exercised a multi-cycle
  pause).
- **A "changed?" guard that gates a fallible side effect must commit the new value only when the
  effect actually succeeded** (T-191, `dnsqb-tray`'s `refresh_tray`). The tooltip guard commits
  `last_status`/`last_trusted` unconditionally — a missed `set_tooltip` is cosmetic and self-heals
  on the next change. But `set_icon` commits `last_colour` **only on `Ok`**: commit it after a
  failed call and `colour != *last_colour` reads equal forever, pinning the wrong colour for the
  process lifetime. Also: a boolean input that seeds a warning state (here `cert_trusted` for the
  red override) seeds to the *safe* value (`true` — "trusted until proven otherwise"), so
  "unknown" / a transient `certutil` failure never reads as "broken"; and the poll for it runs on
  its own `std::thread`, not the async status loop, because `certutil` is a blocking subprocess.
- **A console-subsystem subprocess spawned from a GUI (`windows_subsystem = "windows"`) process
  flashes a console window unless `.creation_flags(CREATE_NO_WINDOW)` is set** (T-194,
  `trust_store::certutil_command`). Harmless when the spawn is a rare explicit user action; once a
  background poll (T-191's trust-watch, 2 `certutil` spawns per tick) does it every few seconds it
  becomes a visible defect. `CREATE_NO_WINDOW` (`0x0800_0000`) still captures stdout/stderr through
  the pipes. It is **ignored when paired with `DETACHED_PROCESS`** — a child that must *outlive*
  the app (T-195's `self_uninstall` cleaner) uses `DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB`
  with the raw-OS-error-5 fallback, mirroring `watchdog::spawn::spawn_detached` (T-182): the MSIX
  process tree is job-contained, so `DETACHED_PROCESS` alone lets the job kill the helper with the
  tray.
- **A process cannot delete its own open app-data directory, and `tao`'s `event_loop.run` never
  returns** (T-195). The tray holds `tray.lock` (`share_mode(0)`) for its whole life and there is
  no post-`run` cleanup point to drop the guard. "Повністю видалити" therefore hands the wipe to a
  **detached, job-broken-out** `powershell` helper that waits up to 20 s for every DNS-QF process
  to exit, then — only if they are actually gone (else it `exit`s, since deleting
  `stop.flag`/`quit.flag` under a live watcher would leave it respawning the service into a
  directory being erased) — loops `Remove-Item` until the dir is gone.
  `build_wipe_script` fences the target: under `%LOCALAPPDATA%` **and** final component exactly
  `dns-quorum-filter`.
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
- **Sideloading a self-signed `.msix`: the signing cert must be in `Cert:\LocalMachine\TrustedPeople`
  specifically** (elevation required). `Cert:\CurrentUser\...` → `0x800B0109` ("root ... not
  trusted"); a cert in no store `Add-AppxPackage` checks → `0x800B010A` (`CERT_E_CHAINING`);
  `\LocalMachine\Root` alone satisfies chain-to-root but **not** AppX publisher trust, so it's
  insufficient by itself (T-178 — the v0.3.0 draft's notes originally said "`Root` or
  `TrustedPeople`" and a downloader hit `0x800B010A`). `packaging/Trust-TestCert.ps1` (copied next
  to the `.msix` by `pack-msix.ps1`, shipped as a release asset) self-elevates and writes via the
  `X509Store` API — more reliable than `Import-Certificate` into that store. `pack-msix.ps1` also
  forces a CryptoAPI RSA key (`-Provider "Microsoft Strong Cryptographic Provider"`) on the
  ephemeral cert: SignTool can't sign an MSIX with a CNG key cleanly. Both fixes ported from
  sister project **pakko** (`C:\Users\Pa\Projects\windows-archiver-wrapper`,
  `github.com/pakkoapp-oss/pakko` — its `scripts/Setup-DevCert.ps1`, `docs/DECISIONS.md`), which
  hit the same wall first.
- **MSIX per-package `%LOCALAPPDATA%` file virtualization does not extend to a spawned
  unpackaged child process** — `certutil.exe` handed the packaged app's own logical `cert_path`
  sees it as missing (`ERROR_FILE_NOT_FOUND`), even though the packaged process's own `std::fs`
  reads/writes that same path fine; confirmed release-blocking on a live v0.4.0 MSIX
  2026-09-12, fixed (pure-Rust SHA-1 thumbprint for reads, a `%SystemRoot%\Temp` staged copy for
  the one `-addstore` write) — full root-cause chain and fix verification in `TASKS-DONE.md`'s
  T-219 entry, don't re-derive it. `certutil -store`/`-delstore` (no file-path arg — `uninstall`'s
  code path) were **not** affected.
- **A POSIX shell truncates a spawned process's exit code to its low byte; `std::process::
  ExitStatus::code()` on a compiled Windows binary does not** — `trust_store::NOT_FOUND_EXIT_CODE`
  (T-49) was set to `17` from a manual `certutil -store` no-match check run through a shell, but
  the real, untruncated Windows exit code for that same result is `-2146893807`/`0x80090011`
  (`NTE_NOT_FOUND`) — `17` is exactly its low byte (`-2146893807 mod 256`). Every downstream
  comparison against the shell-observed value silently never matched the real one; fixed and full
  story in `TASKS-DONE.md`'s T-220 entry, don't re-derive it. General lesson: never transcribe a
  subprocess exit code observed via a shell (`$?`/`echo %ERRORLEVEL%`) directly into Rust constants
  meant to match `ExitStatus::code()` — read it from a real `std::process::Output` (or, for a
  regression test, a real spawn against a value guaranteed to hit that branch — a synthetic
  `ExitStatus` built from the same wrong constant would prove nothing).
- **The `windows` MCP server's `ui_click` (UIA element-name-based) can report success while a
  native Win32 dialog (an `rfd` message box, a CryptUI confirmation) never receives the click** —
  observed twice 2026-09-12, dialog stayed open after a "successful" click. `autoit`'s
  `controlClick` (Windows-message-based, straight into the button's control handle, no screen
  coordinates/UIA) worked every time on the same dialogs — prefer it for native Win32 dialogs
  (message boxes, CryptUI, TaskDialogs); reserve `windows`'s UIA tools for actual UIA-aware app UI.
- **A `gh` call inside a job that checks out multiple copies via `path: build-a`/`build-b`**
  (`release.yml`'s repro-then-release job) **needs `--repo $env:GITHUB_REPOSITORY` explicitly** —
  the job's own working directory has no `.git`, so `gh release create` fails "not a git
  repository" otherwise.
- **No `whois` / `dig` on this box — use RDAP over HTTPS via `WebFetch`** for "who owns this IP /
  what CIDR": `https://rdap.arin.net/registry/ip/<ip>` 303-redirects to the owning RIR
  (`rdap.db.ripe.net/ip/<ip>` for RIPE) — refetch the redirect URL; JSON has
  `startAddress`/`endAddress`/`name`/org. T-175 pinned sinkhole prefixes to each provider's
  registered netblock this way, not a vendor block-page doc.
- **CIDR "is this IP in this prefix" on a serve/hot path: `(ip.to_bits() ^ net.to_bits())
  .leading_zeros() >= prefix`** — no shift, so no `<< 32` / `<< 128` overflow panic to reason
  about (a panic on the query path = a watchdog restart loop). `to_bits` is stable for `Ipv4Addr`
  (`u32`) and `Ipv6Addr` (`u128`) on 1.98; `SinkholeNet` (T-175) uses this, and the `1..=32` /
  `1..=128` prefix invariant makes "match everything" unrepresentable (no `Default`). **An AAAA
  answer can be IPv4-mapped (`::ffff:a.b.c.d`)** — `Ipv6Addr::to_ipv4_mapped()` unwraps it
  (OpenDNS FamilyShield returns its block IP that way for AAAA); `requires_quorum` admits AAAA, so
  answer-address logic must cover both, not just A.
- **Arbitrary IP fixtures in tests must use reserved doc ranges** — RFC 5737 (`192.0.2.0/24` /
  `198.51.100.0/24` / `203.0.113.0/24`) for v4, RFC 3849 (`2001:db8::/32`) for v6 — never a
  plausible real address. T-175 flipped 3 `quorum::resolve` tests Allow→Block because their
  `94.140.14.14` fixture (AdGuard's real resolver IP, picked as "an AdGuard-ish answer") matched a
  new `94.140.14.0/24` sinkhole prefix — the "test passes for the wrong reason" family.

