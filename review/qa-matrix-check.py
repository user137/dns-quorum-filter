"""Completeness check for review/QA-MATRIX.md against the source (QA-PROMPT.md Фаза 1).

(1) every path x method in dispatch.rs ROUTES / I18N_ROUTES is in the matrix;
(2) every id= in ui/index.html and every fieldHelp.* key is in the matrix;
(3) every *_ID menu constant of dnsqb-tray is in the matrix;
(4) every field documented in CONFIGURATION.md is in the matrix.
Exit code 1 on any gap. Usage: python review/qa-matrix-check.py
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SVC = ROOT / "crates" / "dnsqb-service"


def read(p):
    return p.read_text(encoding="utf-8")


matrix = read(pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "review" / "QA-MATRIX.md")
table = matrix.split("<!-- MATRIX:BEGIN -->", 1)[1].split("<!-- MATRIX:END -->", 1)[0]
gaps = {}


def need(check, item, present):
    if not present:
        gaps.setdefault(check, []).append(item)


# (1) routes
dispatch = read(SVC / "src" / "dispatch.rs")
consts = dict(re.findall(r'const (\w+_PATH): &str = "([^"]+)";', dispatch))
routes_block = dispatch.split("const ROUTES:", 1)[1].split("];", 1)[0]
pairs = []
for const, methods in re.findall(r"\((\w+_PATH), &\[([^\]]+)\]\)", routes_block):
    for m in re.findall(r"Method::(\w+)", methods):
        pairs.append((m, consts[const]))
i18n_codes = re.findall(r'"([a-zA-Z-]+)"', dispatch.split("\ni18n_routes!(", 1)[1].split(");", 1)[0])
# A route counts only when it is the Точка (point) of some row -- a path merely mentioned in
# another row's steps/expectation text is not coverage.
points = set()
for line in table.splitlines():
    if line.startswith("| ") and not line.startswith("| ID ") and not line.startswith("|---"):
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]
        m_ = re.match(r"((?:GET|POST)(?:\\\|(?:GET|POST))*) (\S+)$", cells[2])
        if m_:
            for meth in m_.group(1).split("\\|"):
                points.add((meth, m_.group(2)))
point_text = "\n".join(
    [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]][2]
    for line in table.splitlines()
    if line.startswith("| ") and not line.startswith("| ID ") and not line.startswith("|---"))
for m, path in pairs:
    need("1-routes", f"{m} {path}", (m, path) in points)
for code in i18n_codes:
    need("1-routes", f"GET /admin/ui/i18n/{code}.json",
         re.search(rf"(?<![\w-]){re.escape(code)}(?![\w-])", table.split("A-i18n-HP", 1)[1].split("\n", 1)[0]))
counts = (len(re.findall(r"\(\w+_PATH, &\[", routes_block)), len(pairs), len(i18n_codes))

# (2) ids + fieldHelp
html = read(SVC / "ui" / "index.html")
for i in re.findall(r'id="([^"]+)"', html):
    need("2-ui", f"#{i}", re.search(rf"#{re.escape(i)}(?![\w-])", point_text))
uk = json.loads(read(SVC / "ui" / "i18n" / "uk.json"))
for k in uk:
    if k.startswith("fieldHelp."):
        need("2-ui", k, k in point_text)

# (3) tray menu ids
tray = read(ROOT / "crates" / "dnsqb-tray" / "src" / "main.rs")
menu_ids = re.findall(r"const (\w+_ID): &str", tray)
for c in menu_ids:
    need("3-tray", c, re.search(rf"\b{c}\b", point_text))
with_id = len(re.findall(r"MenuItem::with_id\(", tray))

# (4) CONFIGURATION.md fields
conf = read(ROOT / "CONFIGURATION.md")
section = conf.split("## `resolver_config.toml`", 1)[1].split("## Курований топ-N", 1)[0]
table_name = ""
fields = []
for line in section.splitlines():
    h = re.match(r"###+ `\[+(\w+)\]+`", line)
    if h:
        table_name = h.group(1)
    elif line.startswith("## MaxMind"):
        table_name = "maxmind"
    elif line.startswith("## `overrides.toml`"):
        table_name = "overrides"
    elif line.startswith("### "):
        table_name = "-"
    m = re.match(r"\| `([a-z_]+)` \|", line)
    if m and table_name != "-":
        name = m.group(1)
        full = name if not table_name else f"{table_name}.{name}"
        if line.startswith("| `[") or "вкладена таблиця" in line or "масив таблиць" in line:
            continue
        fields.append(full)
for f in fields:
    need("4-config", f, f"`{f}`" in point_text)

# (5) four mandatory categories per point (QA-PROMPT.md Фаза 1) -- a point is the Точка column.
# Scenario/limitation/state rows and cross-cutting A-tls/A-unknown-path are not points.
REQUIRED = {"Happy path", "Security & Boundary", "Misuse & Fool", "Error path"}
per_point = {}
for line in table.splitlines():
    if not line.startswith("| ") or line.startswith("| ID ") or line.startswith("|---"):
        continue
    cells = [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]
    if re.match(r"(KL-|DIAG-|H-file-|A-routes-unused|A-dto-|A-tls|A-unknown-path)", cells[0]):
        continue
    point = re.sub(r"-(HP|SB|MF|EP|CR)\d*$", "", cells[0])
    per_point.setdefault(point, set()).add(cells[3])
for point, cats in sorted(per_point.items()):
    for cat in sorted(REQUIRED - cats):
        need("5-categories", f"{point} :: {cat}", False)

print(f"ROUTES entries={counts[0]} path x method={counts[1]} I18N locales={counts[2]} "
      f"index.html ids={len(re.findall(r'id=\"', html))} tray *_ID={len(menu_ids)} "
      f"MenuItem::with_id={with_id} config fields={len(fields)}")
for check in ("1-routes", "2-ui", "3-tray", "4-config", "5-categories"):
    items = gaps.get(check, [])
    print(f"{check}: {'OK' if not items else str(len(items)) + ' missing'}")
    for item in items:
        print(f"    {item}")
sys.exit(1 if gaps else 0)
