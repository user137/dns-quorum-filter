# PERFORMANCE.md

Complexity of the request pipeline's critical paths (SPEC.md §5.3), and where this service's
resource usage is bounded today versus where it isn't. Companion to `SECURITY.md` (threat model)
and `SPEC.md` (design decisions) — this file is measurement and analysis, not reasoning about
what to build; the resource-exhaustion safeguard decision itself lives in SPEC.md.

T-168 (TASKS-DONE.md) produced this file. Read it alongside `examples/load_test.rs`, the harness
that produced the numbers in the "Measured" section below.

## Threat framing

This DoH listener binds only `127.0.0.1` (`listener::bind_listener`) — nothing here is
internet-facing DDoS resistance. The actual risk is **resource exhaustion from a local client**:
not necessarily a browser. Any process configured to use this service as its DoH resolver — a
browser, a stub resolver, a script, another local service — can open connections and send
queries. A single misbehaving or simply high-volume local client is the threat this analysis is
about, not a coordinated attack.

## Per-query pipeline complexity

| Step (SPEC.md §5.3) | Complexity | Bound |
|---|---|---|
| 1. Allowlist | O(n) linear scan, `OverrideLists::decision` | n = allowlist entries |
| 2. Blocklist | O(n) linear scan, same function, same pass | n = blocklist entries |
| 3. ccTLD block | not implemented (Фаза 4+, TASKS.md T-115) | — |
| 4. Cache | O(1) amortized, `moka` concurrent hash map lookup | bounded by `max_capacity` (10 000) |
| 5. Rating filter | not implemented (Фаза 4+) | — |
| 6. Voter scope | not implemented (Фаза 4+) | — |
| 7. Quorum | O(k) parallel fan-out, `FuturesUnordered` | k = enabled providers, ≤10 (SPEC.md §3.4) |
| 8. GeoIP | O(1) effectively — bounded-depth binary lookup over the IP address's bit prefix, `maxminddb` mmap read | independent of blocked-country-list size |

Steps 1 and 2 run on **every** query, cache hit or miss (they're upstream of the cache in the
pipeline). `overrides::decision` (`overrides.rs:298`) calls `self.entries.iter().any(...)` once
per list — two full scans in the worst case (no match in either list).

**n's actual ceiling**: `overrides::MAX_OVERRIDES_FILE_SIZE` caps the serialized TOML file at
10 MiB (`overrides.rs:177`). The on-disk format is a flat string array
(`allowlist = ["a.com", "b.com", ...]`, `overrides.rs`'s `OverrideListsFile::save`) — at roughly
10 bytes per short-domain entry (quotes + comma + a few characters), the file format could in
theory hold on the order of 10⁶ entries before hitting the size cap. No code path enforces a
smaller practical limit; a real operator's list is expected to be in the thousands, but nothing
currently prevents growing it far beyond that. See "Measured" below for what this actually costs
in latency at a representative large size.

## Connection-level complexity — the part that isn't in the table above

The per-query costs above are all bounded by existing constants. What is **not** bounded today
is the number of concurrent connections and, downstream of quorum fan-out, the number of
concurrent outbound sockets:

- **Accept loop**: `main.rs`'s `serve_until_shutdown` (`main.rs:551-579`) calls `tokio::spawn`
  once per accepted TCP connection, unconditionally. No cap exists on how many connections (and
  therefore tasks) can be in flight at once.
- **Per-connection stream limit — verified, not assumed**: no code in `main.rs`/`dispatch.rs`
  calls `.http2().max_concurrent_streams(...)` on the `hyper_util::server::conn::auto::Builder`
  used to serve each connection. Reading `hyper` 1.11.0's own source
  (`hyper-1.11.0/src/proto/h2/server.rs:69`) shows its h2 server config defaults to
  `max_concurrent_streams: Some(200)` — this is **hyper's** default, not h2's (h2's own
  `Builder`, used standalone, defaults to `None`, meaning no limit). So: **one connection is
  capped at 200 concurrent HTTP/2 streams; the number of connections is not capped at all.**
- **Outbound fan-out amplification**: `quorum::resolve` (`quorum.rs:624`) opens one outbound
  `reqwest` connection per enabled provider per query (`FuturesUnordered`, ≤10 providers,
  SPEC.md §3.4). Concurrent in-flight queries multiply this directly — see "Fan-out ceiling
  (computed)" below.

**Memory is largely already bounded** (`MAX_MESSAGE_SIZE` = 65 535 bytes per DoH message,
`MAX_ADMIN_BODY_SIZE` for admin routes, `moka`'s `max_capacity` = 10 000 cache entries,
`query_log`'s 1000-entries/24h ring buffer). **What is not bounded is task count, connection
count, and outbound socket count** — that is the actual resource-exhaustion risk this file is
about, not per-query memory.

### Memory per connection (cost model — first-order, for sizing the cap)

The concurrency cap (SPEC.md §1.1, T-169) is a backstop against pathological *accumulation* of
held connections, so its size wants a second check alongside the T-168 latency curve: **how much
resident memory does one held connection actually cost?** The per-connection heap cost, from the
locked dependency versions:

| Layer | What it holds | Size (verified from vendored source) |
|---|---|---|
| `rustls` 0.23.43 `ServerConnection` | `sendable_tls` (outgoing encrypted queue) + `sendable_plaintext` (decrypted, awaiting app read), each `ChunkVecBuffer` capped at `DEFAULT_BUFFER_LIMIT`; plus the record deframer input | ≤ 64 KiB + ≤ 64 KiB cap (only fills under backpressure); deframer ≈ one TLS record, ≤ ~18 KiB |
| `hyper` 1.11.0 h2 server conn | HPACK tables, framing bookkeeping, `max_send_buffer_size` | send buffer ≤ 400 KiB (fills only if the client stalls reads); tables/bookkeeping ~tens of KiB |
| h2 flow-control windows | `initial_conn_window_size` / `initial_stream_window_size` = **1 MiB each** (`adaptive_window` off) | **advertised credit, not resident memory** — h2 holds only bytes actually received and not yet drained |
| tokio task | the spawned `serve_connection` future state machine | ~a few KiB heap |
| `TcpStream` + fd | kernel socket buffers (not process heap) + 1 fd | ~1 KiB process-side |

The 1 MiB h2 windows are the scary-looking number and the misleading one: they are the *credit*
the client may spend, not memory the server pre-allocates. What actually caps a stream's resident
receive buffer is the app draining it — `dispatch::serve` wraps every request body in
`Limited::new(_, MAX_MESSAGE_SIZE)` (65 535) and `.collect()`s it promptly, so a single in-flight
stream holds at most ~64 KiB of body regardless of the window advertisement.

**First-order estimate:**

- **Idle held connection** (TCP open, mid-handshake or connected-idle, no request in flight — the
  slow-loris shape): rustls deframer + partial handshake state + the tokio task future + socket
  bookkeeping ≈ **~10–30 KiB**. The 64 KiB rustls buffers and 400 KiB h2 send buffer are empty in
  this state.
- **Connection actively serving one DoH request**: **+ ~64–150 KiB transient** (the collected
  body up to `MAX_MESSAGE_SIZE`, plus rustls plaintext/TLS buffers if the peer backpressures),
  released as soon as the response is flushed.

**Budget check (the second sizing input):**

```
max_concurrent_connections  ≲  connection_memory_budget / per_idle_connection_cost
```

At a deliberately generous 256 MiB budget for held-connection memory and ~32 KiB per idle
connection, that is on the order of **~8 000**; at ~64 KiB, ~4 000. This is the same order of
magnitude the T-168 latency curve points to (smooth to 3 000, no failures, "tens of MB transient
at the 3 000 peak, released after") — the two checks agree, which is what a backstop cap wants.

**Measured (T-169 slow-loris mode).** The T-168 per-ramp RSS delta can't isolate this (its
connections open and close *within* a level — allocator high-water, not concurrent-connection
cost; two of its deltas are negative). T-169's `examples/load_test.rs` slow-loris mode instead
holds ~50 stalled **pre-handshake** sockets open (TCP established, no ClientHello) and samples
RSS with the gate full: across two runs on the Windows 11 dev box the RSS rise per held
connection was **~4–10 KiB** — at or below the low end of the estimate above, as expected for a
connection stalled *before* the TLS handshake (rustls hasn't allocated its 64 KiB buffers and h2
hasn't started). The RSS-delta method is noisy (the probe requests allocate too), so treat this
as "single-digit KiB per idle stalled connection", not a precise figure. Either way the budget
check and the T-168 latency curve agree on the order of magnitude: a few thousand held
connections is a comfortable backstop, not a memory wall.

The same smoke also proves the **pre-handshake reaper** end to end: a normal client is served
while stalled sockets are held below the ceiling; at the ceiling it is refused in ~15–17 ms
(fast TCP close, not a timeout); and with the stalled sockets still held open it recovers once
the server's `handshake_timeout` elapses (so the `tokio::time::timeout` around `acceptor.accept`,
not our FIN, freed the permits). The **post-handshake idle reaper** (`header_read_timeout` for
HTTP/1, `keep_alive_interval` for HTTP/2 — the peer that completes TLS then sends nothing) is
wired from the same `[limits].idle_timeout_ms` and verified against the vendored `hyper-util`
0.1.20 API (`header_read_timeout` panics without a per-protocol timer; both are set), but its
runtime behaviour is not separately observed by this smoke.

### Fan-out ceiling (computed, not measured)

Deliberately **not** exercised with real concurrent traffic against live upstreams — Quad9/
AdGuard's ToS for high-volume automated queries hasn't been reviewed (TASKS.md T-133), and a live
run would be non-deterministic besides. The ceiling is arithmetic instead:

```
outbound sockets  ≈  concurrent in-flight queries × enabled providers (≤10)
```

bounded in time by `query_with_timeout` (2s outer timeout) and `UPSTREAM_CONNECT_TIMEOUT` (500ms
per-address connect deadline) — every such socket resolves (success, error, or timeout) within
that window, so this isn't unbounded *growth*, but the peak concurrent count during a burst scales
linearly with concurrent in-flight queries and has no ceiling of its own today.

## Measured

Methodology and harness: `examples/load_test.rs` (`cargo run --example load_test`, not run in
CI — a manual tool, same category as `examples/phase1_metrics.rs`). Every query in the run hits a
synthetic blocklisted domain, so **no upstream call ever fires** — this measures the
accept-loop / TLS / hyper / `overrides::decision` layer only, not quorum fan-out. Before the
ramps the harness decodes one response and asserts it is an actual `0.0.0.0` NULL-block (a bare
HTTP 200 isn't enough — a DoH SERVFAIL is also 200), so the numbers provably belong to the
blocklist path, not to a failing quorum or T-152's offline fast path.

Two runs on this Windows 11 dev box (debug build, scratch `dnsqb-service` instance, 2026-09-05).
The two shapes:

- **Many connections × 1 request** — a fresh `reqwest::Client` (fresh TLS handshake) per
  request, modeling N independent local DoH clients.
- **One shared client × many requests** — one `reqwest::Client` reused, relying on reqwest/hyper
  HTTP/2 connection reuse. How many TCP connections its pool actually opens is not observed from
  the client side — past the 200-streams-per-connection cap it may open more rather than queue.
  So this is a shared-client path, not "one connection".

**Curve 1 — one blocklist entry (`n=1`).**

| shape | concurrency | success | p50 (run 1 / run 2) |
|---|---|---|---|
| many connections × 1 request | 50 | 50/50 | 115 ms / 109 ms |
| | 200 | 200/200 | 466 ms / 480 ms |
| | 1000 | 1000/1000 | 2.42 s / 2.29 s |
| | 3000 | 3000/3000 | 7.68 s / 7.15 s |
| one shared client × many requests | 200 | 200/200 | 67 ms / 54 ms |
| | 500 | 500/500 | 149 ms / 144 ms |
| | 2000 | 2000/2000 | 518 ms / 433 ms |

**Curve 2 — `n≈10 000` blocklist entries, fixed concurrency 200, same target and path.**

| shape | p50 at n=1 → n≈10 000 (run 1 / run 2) |
|---|---|
| many connections × 1 request | 466→544 ms (+17 %) / 480→470 ms (≈0) |
| one shared client × many requests | 67→285 ms (~4×) / 54→225 ms (~4×) |

### What the numbers say

- **Degradation is smooth and predictable, not a cliff.** Latency rises roughly linearly with
  concurrency (~2.4 ms of p50 per concurrent fresh connection; ~0.25 ms per shared-client
  request). **Zero failed requests** at any level, both runs — 3000 concurrent fresh TLS
  handshakes and 2000 concurrent shared-client requests all completed. No errors, no timeouts, no
  crash. RSS stayed bounded (tens of MB transient at the 3000 peak, released after).
- The unbounded `tokio::spawn`-per-connection accept loop **did not fall over** at any level a
  busy-but-well-behaved local client reaches. The practical ceiling on this machine is throughput
  (one accept loop, serialized TLS handshake cost), which just makes requests slower — it is not
  a resource wall that produces failure.
- **`overrides::decision`'s O(n) scan is only visible on the cheap path.** On the shared-client
  shape (no per-request handshake cost) a pathological ~10 000-entry list roughly quadruples p50
  (~55 ms → ~225 ms), consistently across both runs. On the many-connections shape the same scan
  is lost in TLS-handshake noise — one run showed +17 %, the other ≈0. Either way it stays
  sub-second and 100 % success. A realistic list (hundreds to low thousands) makes it negligible;
  it is not a stability risk at any size `MAX_OVERRIDES_FILE_SIZE` permits.
- **This run does not exercise**: connections opened and held without completing a request
  (slow-loris shape — the residual risk SPEC.md §1.1 calls out), the outbound-socket
  amplification (no upstream calls by design), or concurrency far beyond 3000. So "will it
  eventually exhaust resources" is: yes in principle — nothing caps connections, tasks, or
  in-flight requests, and nothing time-bounds a stalled TLS handshake — but not at any level a
  single well-behaved client produces.

The design decision this feeds — a generous bounded-concurrency backstop against pathological
accumulation, sized from these server-side numbers rather than a throughput percentile —
is in `SPEC.md` §1.1, and its implementation is a separate task (TASKS.md T-169).

## Quorum coverage (T-66 / T-171 / T-174)

Not a latency measurement — this is the efficacy question the whole OR-logic design rests on:
**does querying several filtering providers and blocking on any one "block" vote catch more
malicious domains than the best single provider would alone?**

> **Current answer: yes, confirmed (T-174, 2026-09-05) — +15.9 pp over the best single Security
> provider on n = 126.** The T-66 and T-171 measurements below read as "not confirmed" because a
> block-signature bug (fixed in T-174) hid two of the four Security providers. Read the "Resolution
> — T-174" subsection at the end for the up-to-date result; the T-171 material is kept for the
> record of how it was found.

Harness: `examples/phase1_metrics.rs` (`cargo run --example phase1_metrics`, manual, not CI).
It pulls the live abuse.ch URLhaus `csv_recent` feed, keeps the domain-name hosts whose baseline
(Cloudflare `1.1.1.1`) lookup returns `NoError` (so a churned/dead URLhaus entry isn't counted as
a provider miss), and asks each voter of the shipped default set for an A record, classifying the
answer through that preset's own `BlockSignature`.

**T-171 run — 2026-09-05, shipped T-170 default set (`quad9` + `cloudflare-malware` + `adguard`),
`SAMPLE_CAP = 150`.** After the baseline-`NoError` filter and 4 transient Quad9 request failures,
**n = 122**.

| voter | blocked | rate | signal |
|---|---|---|---|
| Quad9 Filtered | 73/122 | 59.8 % | `NXDOMAIN` vs baseline-`NoError` (`NeedsBaseline` path — an **upper bound** under `is_blocked`'s semantic: some of these are genuine non-existence, not an active Quad9 block) |
| Cloudflare Malware | 43/122 | 35.2 % | explicit `0.0.0.0`/`::` answer |
| AdGuard Default | 0/122 | 0.0 % | explicit `0.0.0.0`/`::` answer — none seen |
| **Quorum (OR of all three)** | **74/122** | **60.7 %** | — |
| **delta over best single (Quad9)** | **+1/122** | **+0.8 pp** | one domain Cloudflare caught that Quad9 did not (`#84` in the run's per-domain trace) |

### What the numbers say

- **The quorum hypothesis is _not_ confirmed on this sample** — and now on a sample ~3× the size
  of T-66's (n = 122 vs n = 38). The OR of three providers caught **exactly one** malicious
  domain that simply running Quad9 alone would have missed. +0.8 pp is within sampling noise.
- **Cloudflare Malware's blocks are very nearly a subset of Quad9's.** The per-domain trace shows
  `quad9=true cloudflare=true` for almost every Cloudflare hit; `quad9=false cloudflare=true`
  happens once in 122. Two Security-tier feeds here are highly correlated, not independent — which
  is exactly what erodes an OR-quorum's value.
- **AdGuard 0/122 again** (T-66 saw 0/38). Expected and not a defect: AdGuard is in the shipped
  default for **ads/trackers** (T-170), and its ads blocklist does not overlap a live *malware*
  URL feed. A one-off raw-answer check in T-66 confirmed AdGuard returned genuine routable IPs
  for every domain, so this is a real 0 %, not an unrecognised null-IP.
- **Quad9's 59.8 % is an upper bound**, not a floor — it counts every "baseline resolved,
  Quad9 `NXDOMAIN`" as a block, and URLhaus domains churn fast.

### Verdict and disposition

**One run, one record** (T-171 rule — no re-measuring with a different sample/set to chase a
confirming number). The T-171 run's number was honest and negative: **+0.8 pp**.

**That number was wrong-for-a-reason, not wrong-by-noise.** The follow-up and T-174 (below)
established that two of the four Security presets had a broken block signature, so T-171 measured
a two-provider quorum, not a four-provider one. With the signature fixed, the same measurement
methodology on a comparable sample gives **+15.9 pp** — the OR-quorum hypothesis holds. See
"Resolution — T-174" below; the up-to-date verdict lives there.

### Follow-up run — all 10 built-in presets (2026-09-05, user-requested)

`phase1_metrics.rs` was extended to measure **every** preset in `all_builtin_presets()`, not
just the shipped default set, and re-run (n = 124 after the baseline-`NoError` filter + 4
transient Quad9 skips):

| preset | category | blocked | note |
|---|---|---|---|
| `quad9` | Security | 73/124 (58.9 %) | NXDOMAIN vs baseline (upper bound) |
| `cloudflare-malware` | Security | 43/124 (34.7 %) | `0.0.0.0` answer |
| `cleanbrowsing-security` | Security | **0/124 counted** | **returned NXDOMAIN 66/124 — see below** |
| `dns4eu-protective` | Security | 0/124 | genuine `NoError` — did not block these |
| `adguard` | AdsTrackers | 0/124 | genuine `NoError` (ads list, not a malware feed) |
| `cloudflare-family` | AdultContent | 45/124 (36.3 %) | `0.0.0.0` answer — Cloudflare Family (1.1.1.3) also filters malware |
| `adguard-family` | AdultContent | 0/124 | genuine `NoError` |
| `cleanbrowsing-adult` | AdultContent | **0/124 counted** | **returned NXDOMAIN 66/124 — see below** |
| `opendns-familyshield` | AdultContent | 0/124 | genuine `NoError` (signature is `NxdomainVsBaseline` — a real 0, not a mismatch) |
| `dns4eu-child` | AdultContent | 0/124 | genuine `NoError` |

- **Quorum (OR of all 10):** 75/124 (60.5 %) — **+2 domains / +1.6 pp** over the best single (Quad9).
- **Quorum (OR of the 4 Security-tier):** 74/124 (59.7 %) — **+1 / +0.8 pp** over Quad9.
- The one domain OR-of-10 gains over OR-of-Security is `cloudflare-family` (an adult filter that
  also does malware). Every other Adult preset added nothing to a malware feed, as expected.

**Bug found: the CleanBrowsing presets have the wrong `block_signature`.**
`cleanbrowsing-security` and `cleanbrowsing-adult` are declared `BlockSignature::NullIp` in
`upstream::BUILTIN_PRESETS`, but from this vantage point both **block via NXDOMAIN** — each
returned NXDOMAIN for 66 of 124 domains (baseline resolved all 124 fine), including **18 that
Quad9 did not flag**. `is_blocked(NullIp, …)` cannot see an NXDOMAIN block, so a user who enables
either preset today gets **none** of its blocks counted in `quorum::resolve`. This is exactly the
class of gap CLAUDE.md's own note anticipates — "лише Quad9/AdGuard live-звірені; решта — з
опублікованої поведінки провайдера". Filed as **T-174** (live-verify + fix the CleanBrowsing
signatures). The harness now prints a `[!] signature=NullIp but returned NXDOMAIN …` marker so
this can't hide on a future run.

**Effect on the T-171 verdict: it was provisional — and T-174 overturned it (below).**

### Resolution — T-174 (CleanBrowsing signature fixed, hypothesis CONFIRMED)

T-174 changed `cleanbrowsing-security` / `cleanbrowsing-adult` from `BlockSignature::NullIp` to
`NullIpOrNxdomain` (live-verified via this harness: 67/126 malware + 10/10 adult blocked via
NXDOMAIN, baseline resolved all). `phase1_metrics.rs` also gained an `ads` corpus (18 fixed
ad/tracker hosts) and an `adult` corpus (10 fixed high-traffic adult sites) so the AdsTrackers
and AdultContent presets get exercised at all.

Re-run with the fix, malware corpus n = 126:

| preset | rate | | preset | rate |
|---|---|---|---|---|
| `quad9` | 73/126 (57.9 %) | | `cloudflare-family` | 45/126 (35.7 %) |
| `cloudflare-malware` | 43/126 (34.1 %) | | `cleanbrowsing-adult` | 67/126 (53.2 %) |
| **`cleanbrowsing-security`** | **67/126 (53.2 %)** | | others (5) | 0/126 |

- **Quorum (OR of the 4 Security-tier): 93/126 (73.8 %) — +20 domains / +15.9 pp over the best
  single provider (Quad9).**
- Quorum (OR of all 10): 94/126 (74.6 %) — +21 / +16.7 pp.
- **19 malware domains were blocked *only* by CleanBrowsing** (neither Quad9 nor Cloudflare
  Malware) — that is the OR-quorum's gain, made of real independent coverage. The T-171
  "correlated feeds, quorum adds nothing" reading was an artifact of the signature bug hiding
  CleanBrowsing entirely.

**Verdict: the OR-quorum hypothesis is confirmed on n = 126** — a good single Security provider
(Quad9, ~58 %) is beaten by ~16 pp when the OR runs over all four working Security feeds. Ф1
metrics gate #1 is now closed *by confirmation*, not just by an honest negative record.

Other corpora (both n < 20 — indicative): **ads** — `adguard` and `adguard-family` each 9/14
(64 %) via `0.0.0.0`, confirming AdGuard delivers ad blocking (the T-170 default's reason for
shipping it). **adult** — `cloudflare-family` and `cleanbrowsing-adult` each 10/10; but
`adguard-family`, `opendns-familyshield`, `dns4eu-child` caught **0/10 with 0 NXDOMAIN** — they
appear to block via a provider-specific sinkhole/redirect IP that no current `BlockSignature`
(`NullIp` / `NxdomainVsBaseline` / `NullIpOrNxdomain`) recognises. Filed as **T-175** (needs a
new `SinkholeIp` signature variant); lower priority — those are secondary Adult presets, not the
shipped default.
