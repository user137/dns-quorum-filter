# Curated availability-zone lists (`data/topn/`)

These files are the source of the Фаза 4 **rating-filter «bubble»** (SPEC.md
§5.3). A domain **in** any active list continues through the normal pipeline;
a domain **outside every** active list is **blocked**. The filter is opt-in
and default-off; a user selects which lists apply (their own country, extra
countries, `global`) — the zone is the union of those.

## Files

| File | Contents |
|---|---|
| `<cc>.txt` | Top-traffic registrable domains of country `<cc>` (ISO 3166-1 alpha-2). |
| `global.txt` | Worldwide top-traffic registrable domains. |
| `gov-<cc>.txt` | Government domain/suffix for country `<cc>` (Батч 4.2 — see below). |
| `edu.txt` | Global science/education/non-profit zone (Батч 4.2 — see below). |
| `<name>.txt.sha256` | `sha256sum`-format checksum sidecar for `<name>.txt`. |

Format: **one entry per line, sorted, lowercase**. Lines starting with `#`
(a provenance header) and blank lines are ignored by the client. URLs are
stable — content changes, paths don't; the client fetches `<name>.txt` +
`<name>.txt.sha256` and atomic-swaps on a checksum change (the same
mechanism as the GeoIP database).

An entry is not always a single site — see "Government & science/education
zones" below for the blanket-suffix case, where one entry covers an entire
domain space.

## Government & science/education zones (`gov-<cc>.txt`, `edu.txt` — Батч 4.2)

**These files are hand-curated, not CrUX-derived** — the "Data source and
attribution" section below (CrUX, CC BY 4.0, the PSL) does not apply to
them; they carry their own `source:`/`criterion:` header instead. No
automated candidate-scanning tool exists for these — the lists are short
enough that a maintainer curates them directly (see
`ZONES-CHANGELOG.md` for the audit trail of what was added, why, and against
what source it was verified).

**Government (`gov-<cc>.txt`, T-122).** Each file holds one *domain/suffix*
whose registration a registrar restricts by policy to legitimate government
bodies of that country (`gov.ua`, `gov.pl`, `gov.uk`, bare `gov` for the
US). Because [`ZoneLists::zone_match`](../../crates/dnsqb-service/src/rating_filter.rs)
is a pure suffix walk with no PSL, that single entry automatically covers
every present and future subdomain — no per-ministry enumeration, and no
editorial judgment about which specific site is "really" official (the
registrar's own restricted-registration policy is the inclusion criterion,
not this project's opinion). **`de` is a stated gap**: Germany has no single
unified government-domain convention (agencies use a mix of `bund.de` and
independent domains) — SPEC.md §5.3 names this variance explicitly, and this
batch did not attempt to guess a substitute.

Because a `gov-<cc>` entry is a whole namespace behind one line, it is
**not** subject to T-108 lazy hygiene (`ZoneSourceKind::hygiene_eligible`) —
a false-positive quorum block of the bare suffix itself must never evict the
entire zone it covers. The `/admin/ui` zone card shows "весь простір"
instead of a domain count for these — a "1" would read as broken.

**Science/education (`edu.txt`, T-123).** One global (not per-country) list
mixing (a) registrar-restricted academic/international TLDs and SLDs (`edu`,
`ac.uk`, `edu.ua`, `int` — same blanket-suffix reasoning as above) and (b) a
short list of individually-named, globally-recognized research/standards
bodies — the SPEC.md §5.3 examples (PubMed/NIH, NASA) plus similarly neutral
peers (arXiv, DOI, ORCID, IETF, W3C, IEEE, the UN). Deliberately narrow: this
is not an attempt to rank or enumerate every legitimate institution
worldwide (SPEC.md names that exact risk — "чому є NASA, а нема аналогічної
установи іншої країни"), only entries with an objective inclusion criterion.
No restricted academic SLD is included for `de`/`pl` — not verified with
confidence this batch, a stated gap alongside the `gov-de` one.

## Data source and attribution

Popularity data is from the **Chrome UX Report (CrUX)**, published by
**Google** to BigQuery and mirrored on GitHub:

- per-country: [`InternetHealthReport/crux-top-lists-country`](https://github.com/InternetHealthReport/crux-top-lists-country)
- global: [`zakird/crux-top-lists`](https://github.com/zakird/crux-top-lists)

CrUX data is licensed **[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)**
(© Google). See the [CrUX methodology](https://developer.chrome.com/docs/crux/methodology).
`rank` in the source is a magnitude bucket (`1000` / `10000` / `100000` /
`1000000`), not an ordinal position; order within a bucket is random.

**Changes made to the source data** (CC BY 4.0 §3(a)): origins are
normalised to their registrable domain and deduplicated; only the top
(`1000`) bucket is kept, capped at N rows. **No content filtering is done
here** — a list is the raw popular set. Dropping a domain that a
Security/Adult resolver blocks is a lazy runtime job in the client (T-108):
an in-zone domain still goes through the normal quorum pipeline, and if
quorum blocks it the client removes it from its local zone set. Each file's
`#` header records the counts.

The `origin → registrable` step uses the **Public Suffix List**
(`crates/dnsqb-service/examples/public_suffix_list.dat`, from
[`publicsuffix/list`](https://github.com/publicsuffix/list),
**[MPL-2.0](https://mozilla.org/MPL/2.0/)**, pinned commit in the tool's
source).

This is the repository-side attribution required because these derived
files are distributed here. The running app carries its own attribution in
the `/admin/ui` credits footer.

## Regenerating

`.github/workflows/topn-curate.yml` (`workflow_dispatch`) runs the curation
tool for the requested lists in one job and uploads the results as an
artifact; a maintainer reviews the diff and commits it. Locally:

```
cargo run --release --example curate_topn -- lists=ua,global n=1000
```

Fast — one HTTP GET per list, no DNS. See the tool's module doc.

**`gov-<cc>.txt`/`edu.txt` have no tool** — edit the `.txt` by hand, add a row to
`ZONES-CHANGELOG.md`, then recompute the sidecar (the client's `verify_sha256`
silently keeps the last-known-good file and logs a warn on any mismatch — a
forgotten sidecar update means the new content never actually ships):

```
sha256sum data/topn/gov-ua.txt | awk '{print $1"  gov-ua.txt"}' > data/topn/gov-ua.txt.sha256
```
