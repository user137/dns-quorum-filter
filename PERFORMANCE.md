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
CI — a manual tool, same category as `examples/phase1_metrics.rs`). Results land here once the
harness (added next) has actually been run — see TASKS-DONE.md's T-168 entry for the full
numbers and the design decision they feed, which lives in `SPEC.md` (this file documents what's
true today, not what to build).
