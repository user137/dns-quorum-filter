"""Check every store-listing/<locale>.json against the Partner Center limits (STORE-LISTING.md)."""
import json
import pathlib
import sys

KEYS = {"shortTitle", "shortDescription", "description", "features", "searchTerms"}
NAME = "DNS Quorum Filter"
here = pathlib.Path(__file__).resolve().parent
ui_locales = {p.stem for p in (here.parent.parent / "crates/dnsqb-service/ui/i18n").glob("*.json")}
errors = []
seen = set()
for path in sorted(here.glob("*.json")):
    loc = path.stem
    seen.add(loc)
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        errors.append(f"{loc}: unreadable: {err}")
        continue
    if set(d) != KEYS:
        errors.append(f"{loc}: keys {sorted(set(d) ^ KEYS)}")
        continue
    def limit(field, text, n):
        if not isinstance(text, str) or not text.strip():
            errors.append(f"{loc}: {field} empty or not text")
        elif len(text) > n:
            errors.append(f"{loc}: {field} {len(text)} > {n}")
    limit("shortTitle", d["shortTitle"], 50)
    limit("shortDescription", d["shortDescription"], 270)
    limit("description", d["description"], 10000)
    if NAME not in d["description"]:
        errors.append(f"{loc}: description lacks the untranslated name")
    if not isinstance(d["features"], list) or not 1 <= len(d["features"]) <= 20:
        errors.append(f"{loc}: features count")
    else:
        for i, f in enumerate(d["features"]):
            limit(f"features[{i}]", f, 200)
    if not isinstance(d["searchTerms"], list) or not 1 <= len(d["searchTerms"]) <= 7:
        errors.append(f"{loc}: searchTerms count")
    else:
        for i, s in enumerate(d["searchTerms"]):
            limit(f"searchTerms[{i}]", s, 30)
for loc in sorted(ui_locales - seen):
    errors.append(f"{loc}: missing")
for loc in sorted(seen - ui_locales):
    errors.append(f"{loc}: not an interface locale")
print("\n".join(errors) or f"ok: {len(seen)} locales")
sys.exit(1 if errors else 0)
