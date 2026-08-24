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

No dependencies are added to a `Cargo.toml` yet (pre-implementation). When a crate is added, add a
row here **before merging**, not after:

| Crate | Maintainer | Reproducible build? | Independent audit / reputation | CVE history | Notes |
|---|---|---|---|---|---|
| | | | | | |

Planned crates and the reasoning for choosing each are listed in `SPEC.md` §"Технічний стек" and
`CLAUDE.md` §"Planned stack" — that's a design-time rationale, not a substitute for this vetting
table once a specific version is actually pinned.
