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
| `<name>.txt.sha256` | `sha256sum`-format checksum sidecar for `<name>.txt`. |

Format: **one registrable domain per line, sorted, lowercase**. Lines
starting with `#` (a provenance header) and blank lines are ignored by the
client. URLs are stable — content changes, paths don't; the client fetches
`<name>.txt` + `<name>.txt.sha256` and atomic-swaps on a checksum change
(the same mechanism as the GeoIP database).

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
tool and uploads the results as an artifact; a maintainer reviews the diff
and commits it. Locally:

```
cargo run --release --example curate_topn -- lists=ua,global n=1000
```

Fast — one HTTP GET per list, no DNS. See the tool's module doc.
