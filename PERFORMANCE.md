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
holds ~50 stalled pre-handshake sockets open and samples RSS with the gate full: across two runs
on the Windows 11 dev box the RSS rise per held connection was **~4–10 KiB** — at or below the
low end of the estimate above, as expected for a connection stalled *before* the TLS handshake
(rustls hasn't allocated its 64 KiB buffers and h2 hasn't started). The RSS-delta method is
noisy (the probe requests allocate too), so treat this as "single-digit KiB per idle stalled
connection", not a precise figure. Either way the budget check and the T-168 latency curve agree
on the order of magnitude: a few thousand held connections is a comfortable backstop, not a
memory wall.

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
