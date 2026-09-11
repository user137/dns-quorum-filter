# Zone changelog — hand-curated lists

Audit trail for `gov-<cc>.txt` and `edu.txt` (SPEC.md §5.3: "публічним і
версійованим, щоб рішення курації були простежувані"). The CrUX-derived
`<cc>.txt`/`global.txt` files are **not** covered here — their provenance is
each file's own `#` header + `.github/workflows/topn-curate.yml`'s run
history. This file only tracks entries a human/editorial decision put in,
not an algorithm.

Each entry below names: what was added, why, and what was checked to
verify the inclusion criterion (registrar-restricted TLD/SLD policy, or an
individually-named canonical source) — not the target domain's own content,
which this project never claims to police.

## 2026-09-11 — Батч 4.2 (T-122, T-123)

Initial seed. Criterion for every entry: either (a) a domain/suffix whose
*registration* is restricted by the registrar's own policy to a legitimate
class of holder (government, academic, international-treaty), verified
against that registrar/registry's published policy — not this project's
judgment about a specific site — or (b) an individually-named body already
called out as a canonical example in SPEC.md §5.3, extended with a small
number of similarly neutral, globally-recognized peers.

| List | Entry | Criterion | Verified against |
|---|---|---|---|
| `gov-ua` | `gov.ua` | (a) restricted to Ukrainian government bodies, special procedure + letter of authority | [101domain](https://www.101domain.com/gov_ua.htm), [NIC.UA](https://support.nic.ua/en-us/article/326-how-to-register-gov-ua-and-edu-ua-domains) |
| `gov-pl` | `gov.pl` | (a) restricted to entitled Polish government entities, registered directly by NASK | [101domain](https://www.101domain.com/gov_pl.htm), [NASK](https://www.dns.pl/en/history) |
| `gov-gb` | `gov.uk` | (a) restricted UK public-sector second-level namespace | widely documented UK government domain-name policy |
| `gov-us` | `gov` | (a) DotGov Act 2021 — TLD restricted to US federal/state/local/tribal government, managed by CISA | widely documented `.gov` registry policy (Wikipedia `.gov`, CISA dotgov program) |
| `edu` | `edu` | (a) US, accredited postsecondary institutions only (Educause) | widely documented `.edu` eligibility policy |
| `edu` | `ac.uk` | (a) UK academic/research institutions only, via Jisc, naming-committee approval | [Jisc](https://community.jisc.ac.uk/library/janet-services-documentation/eligibility-policy) |
| `edu` | `edu.ua` | (a) Ukrainian higher-education institutions only, level III+ accreditation | [NIC.UA](https://support.nic.ua/en-us/article/326-how-to-register-gov-ua-and-edu-ua-domains) |
| `edu` | `int` | (a) organizations founded by an international treaty between governments, IANA policy | widely documented `.int` eligibility policy |
| `edu` | `nasa.gov`, `nih.gov` (PubMed) | (b) SPEC.md §5.3's own named examples | — |
| `edu` | `arxiv.org` | (b) open-access research preprint repository (Cornell University) | — |
| `edu` | `doi.org` | (b) persistent identifier resolver for published research (DOI Foundation) | — |
| `edu` | `orcid.org` | (b) researcher identifier registry (nonprofit) | — |
| `edu` | `ietf.org`, `w3.org` | (b) Internet/Web standards bodies | — |
| `edu` | `ieee.org` | (b) engineering professional/standards body | — |
| `edu` | `un.org` | (b) United Nations | — |

**Known gaps, not attempted this batch:** `gov-de` (no single unified German
government-domain convention — SPEC.md §5.3 names this variance explicitly);
a restricted academic SLD for `de`/`pl` in `edu.txt` (not verified with
confidence this session).

**Process note:** no formal PR-template/CODEOWNERS gate is in place for this
file — the repository is single-maintainer. A future contributor proposing
a change should still follow this table's shape: entry, criterion, source
checked.
