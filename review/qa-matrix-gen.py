"""Merge review/qa_matrix_rows.py into the table section of review/QA-MATRIX.md.

Rows are keyed by ID. Columns from the data file (Поверхня..Виконавець) are
refreshed on every run; Вердикт / Доказ / Баг/задача already present in the
markdown are kept. Rows that disappeared from the data file stay in the table
with a "ВИДАЛЕНО З ДЖЕРЕЛА" marker instead of being dropped.

Usage: python review/qa-matrix-gen.py
"""
import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = ROOT / "review" / "QA-MATRIX.md"
BEGIN = "<!-- MATRIX:BEGIN -->"
END = "<!-- MATRIX:END -->"
HEADER = ["ID", "Поверхня", "Точка", "Категорія", "Кроки", "Очікувано",
          "Наявне автопокриття", "Виконавець", "Вердикт", "Доказ", "Баг/задача"]
CAT = {"HP": "Happy path", "SB": "Security & Boundary", "MF": "Misuse & Fool",
       "EP": "Error path", "CR": "Concurrency/Recovery"}
WHO = {"AUTO": "MCP-AUTO", "PART": "MCP-PARTIAL", "USER": "USER-MANUAL", "CODE": "CODE-ONLY"}
SURF_ORDER = "AEBCDFHIG"


def load_rows():
    spec = importlib.util.spec_from_file_location("rows", ROOT / "review" / "qa_matrix_rows.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ROWS


def test_index():
    names = set()
    for path in (ROOT / "crates").rglob("*.rs"):
        names.update(re.findall(r"\bfn\s+(\w+)\s*[<(]", path.read_text(encoding="utf-8")))
    smoke = (ROOT / "crates" / "dnsqb-service" / "ui" / "smoke.js").read_text(encoding="utf-8")
    smoke_calls = set(re.findall(r'^\s*\["([^"]+)",', smoke, re.M))
    return names, smoke_calls


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def parse_existing(text):
    if BEGIN not in text:
        return {}
    body = text.split(BEGIN, 1)[1].split(END, 1)[0]
    kept = {}
    for line in body.splitlines():
        if not line.startswith("| ") or line.startswith("| ID ") or line.startswith("|---"):
            continue
        # cell() escapes on write, so unescape here or every run adds a backslash.
        parts = [re.sub(r"\\+\|", "|", p.strip()) for p in re.split(r"(?<!\\)\|", line)[1:-1]]
        if len(parts) == len(HEADER):
            kept[parts[0]] = parts
    return kept


def main():
    rows = load_rows()
    ids = [r["id"] for r in rows]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        sys.exit(f"duplicate IDs: {sorted(dupes)}")
    fn_names, smoke_calls = test_index()
    missing = []
    text = MATRIX.read_text(encoding="utf-8")
    existing = parse_existing(text)

    out_rows = []
    for r in sorted(rows, key=lambda r: SURF_ORDER.index(r["surf"])):
        cov_parts = []
        for c in r["cov"]:
            if c.startswith("~"):
                cov_parts.append(c[1:])
            elif c.startswith("smoke.js:"):
                if c.split(":", 1)[1] not in smoke_calls:
                    missing.append((r["id"], c))
                cov_parts.append(f"`{c}`")
            else:
                if c not in fn_names:
                    missing.append((r["id"], c))
                cov_parts.append(f"`{c}`")
        cov = ", ".join(cov_parts) if cov_parts else "НЕМАЄ"
        old = existing.get(r["id"])
        verdict, evidence, bug = (old[8], old[9], old[10]) if old else ("—", "", r["bug"])
        if old and not bug and r["bug"]:
            bug = r["bug"]
        out_rows.append([r["id"], r["surf"], r["point"], CAT[r["cat"]], r["steps"], r["expect"],
                         cov, WHO[r["who"]], verdict, evidence, bug])
    for old_id, old in existing.items():
        if old_id not in ids:
            old = list(old)
            old[10] = (old[10] + " ВИДАЛЕНО З ДЖЕРЕЛА").strip()
            out_rows.append(old)

    lines = ["| " + " | ".join(HEADER) + " |", "|" + "---|" * len(HEADER)]
    lines += ["| " + " | ".join(cell(c) for c in row) + " |" for row in out_rows]
    table = BEGIN + "\n" + "\n".join(lines) + "\n" + END
    if BEGIN in text:
        pre = text.split(BEGIN, 1)[0]
        post = text.split(END, 1)[1]
        text = pre + table + post
    else:
        text = text.rstrip() + "\n\n" + table + "\n"
    MATRIX.write_text(text, encoding="utf-8")

    by_surf = {}
    for row in out_rows:
        by_surf.setdefault(row[1], [0, 0, 0])
        by_surf[row[1]][0] += 1
        by_surf[row[1]][1] += row[6] == "НЕМАЄ"
        by_surf[row[1]][2] += row[7] == "USER-MANUAL"
    print(f"rows={len(out_rows)}")
    for s in SURF_ORDER:
        if s in by_surf:
            t, n, u = by_surf[s]
            print(f"  {s}: rows={t} no-autocoverage={n} user-manual={u}")
    if missing:
        print("UNKNOWN coverage references:")
        for rid, c in missing:
            print(f"  {rid}: {c}")
        sys.exit(1)


if __name__ == "__main__":
    main()
