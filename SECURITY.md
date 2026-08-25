# Security

Threat model summary, hard constraints, and dependency-vetting table. Full reasoning behind each
item lives in `SPEC.md` — this file tracks the current state, `SPEC.md` explains why.

## Threat model (summary — see SPEC.md §"Наскрізні вимоги", §2, §8.1 for full reasoning)

- **Local DoH cert compromise** — the largest single attack surface in the project. Mitigated by
  using a single self-signed leaf certificate on `127.0.0.1` (never a local CA): a compromised
  private key spoofs localhost only, not arbitrary domains. See SPEC.md §2.
- **Tauri IPC boundary (webview → Rust backend)** — treated as untrusted input (XSS in the UI,
  compromised render, or dev error can all produce an arbitrary IPC call). Covered by four test
  categories, not one "smoke" test: correctness, exploit (path traversal, allowlist bypass,
  oversized payload), misuse (contradictory input, malformed manually-edited override file),
  fuzz (no `unwrap()`/`panic!` on arbitrary byte input at the boundary). See SPEC.md §8.1.
- **Upstream DoH providers and DNS wire format** — parsed via `hickory-dns`, not a hand-rolled
  parser, specifically because this is historically the highest-CVE-density code class in C-based
  DNS software.
- **GeoIP / top-sites data feeds** — binary blobs that influence blocking decisions; atomic
  replacement is gated on TLS + checksum verification before swapping in a new file (SPEC.md §3.5).
- **Browser silent DoH-fallback** — open, not fully closed: if `dnsqb-service` errors or times out,
  the browser may silently fall back to system DNS, bypassing quorum entirely with no built-in
  mitigation in the current design (SPEC.md, Відкриті питання, п.10).

## Hard constraints (see SPEC.md §"Наскрізні вимоги" for the full list)

- Listens only on `127.0.0.1` — never `0.0.0.0`, no network listener beyond loopback.
- `#![forbid(unsafe_code)]` in every crate where possible; any `unsafe` needs an explicit
  justification comment.
- Domain names live only in the in-memory ring buffer by default; disk persistence of the query log
  is opt-in and must be encrypted via platform secure storage. Diagnostic/service logs never contain
  domain names.
- Elevated privileges only once, for the one-time trust-store install/uninstall step — the main
  process runs as a normal user, never with standing elevated privileges.
- CI must run `cargo audit` (known CVEs) and `cargo deny` (license/duplicate checks) as required
  steps, not optional ones.
- Reproducible builds / signed release binaries — the app installs a trusted certificate into the
  system, so binary trust is as security-critical as the certificate itself.

## Dependency vetting

When a crate is added, add a row here **before merging**, not after:

| Crate | Maintainer | Reproducible build? | Independent audit / reputation | CVE history | Notes |
|---|---|---|---|---|---|
| `hickory-proto` 0.26.1 | `hickory-dns` project (formerly `trust-dns`); maintainers include Dirkjan Ochtman (also rustls, RustSec core team), divergentdave, marcus0x62 | Standard `cargo`/`crates.io` build, no vendored binaries | First formal security audit funded/performed by Ferrous Systems; production use includes Let's Encrypt's recursive resolver and (per public reporting) Google Pixel | Past DNSSEC-validation CVEs (e.g. CVE-2025-25188, unbounded-loop/memory-exhaustion class), fixed in later releases; `cargo audit` run clean against 0.26.1 at time of adding (2026-08-25) — re-verify on every `cargo audit` CI run, don't treat this row as a standing guarantee | Chosen per SPEC.md "Технічний стек" specifically to avoid hand-rolling a DNS wire-format parser (highest-CVE-density code class in C-based DNS software); only the `-proto` sub-crate is used in Крок 0 (wire-format types for conformance-test fixtures), not the full resolver |
| `tokio` 1.53.1 | `tokio-rs` org, founding maintainer Carl Lerche; foundational async runtime for a large fraction of the Rust async ecosystem, backed by multiple large-org sponsors | Standard `cargo`/`crates.io` build, no vendored binaries | De facto standard async runtime; formal `security@tokio.rs` disclosure process, advisories coordinated through GitHub/RustSec | Historical advisories cluster in `io-util`/channel APIs and legacy 0.1-era sibling crates (`tokio-reactor`, `tokio-timer`, both unmaintained, not depended on here); `cargo audit` run clean against 1.53.1 at time of adding (2026-08-25, T-20–T-26 batch) — re-verify on every CI run | Async runtime for concurrent upstream queries (SPEC.md "Технічний стек"); features limited to `rt-multi-thread`, `macros`, `net`, `time` — no `full` |
| `reqwest` 0.13.4 | Sean McArthur (`seanmonstar`); widely used, foundational Rust HTTP client | Standard `cargo`/`crates.io` build, no vendored binaries; TLS backend (`rustls`) itself audited independently (see rustls project) | Most widely depended-on Rust HTTP client; `rustls`-backed builds avoid the system OpenSSL dependency the "Технічний стек" section explicitly rules out | `cargo audit` run clean against 0.13.4 and its `rustls`/`aws-lc-rs` TLS stack at time of adding (2026-08-25) — re-verify on every CI run | `default-features = false`, features `rustls` + `http2` only — no `native-tls`, no `blocking`. Pulled `aws-lc-rs`/`aws-lc-sys` as the `rustls` crypto backend and `webpki-root-certs`/`rustls-platform-verifier` for trust-store validation, each vetted via `cargo deny`'s license check (`deny.toml`), not this table, since none is a direct dependency this project chose |

Planned crates and the reasoning for choosing each are listed in `SPEC.md` §"Технічний стек" and
`CLAUDE.md` §"Planned stack" — that's a design-time rationale, not a substitute for this vetting
table once a specific version is actually pinned.
