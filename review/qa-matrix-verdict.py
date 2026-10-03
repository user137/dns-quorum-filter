"""Record a verdict in review/QA-MATRIX.md by row ID (Phase 2).

Usage: python review/qa-matrix-verdict.py <ID> <VERDICT> "<evidence>" ["<bug/task>"]
VERDICT: PASS / FAIL / BLOCKED / NOT RUN / USER-MANUAL / N/A-IN-BUILD.
Several rows at once: pass a JSON file instead -- [{"id":..,"verdict":..,"evidence":..,"bug":..}].
"""
import json
import pathlib
import re
import sys

MATRIX = pathlib.Path(__file__).resolve().parent / "QA-MATRIX.md"
VERDICTS = {"PASS", "FAIL", "BLOCKED", "NOT RUN", "USER-MANUAL", "N/A-IN-BUILD"}


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def apply(lines, rid, verdict, evidence, bug):
    if verdict not in VERDICTS:
        sys.exit(f"unknown verdict {verdict!r}")
    for i, line in enumerate(lines):
        if line.startswith(f"| {rid} |"):
            cells = [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]
            cells[8], cells[9] = verdict, cell(evidence)
            if bug is not None:
                cells[10] = cell(bug)
            lines[i] = "| " + " | ".join(cells) + " |"
            return
    sys.exit(f"row {rid} not found")


def main():
    lines = MATRIX.read_text(encoding="utf-8").split("\n")
    if len(sys.argv) == 2:
        items = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    else:
        items = [dict(id=sys.argv[1], verdict=sys.argv[2], evidence=sys.argv[3],
                      bug=sys.argv[4] if len(sys.argv) > 4 else None)]
    for it in items:
        apply(lines, it["id"], it["verdict"], it["evidence"], it.get("bug"))
    MATRIX.write_text("\n".join(lines), encoding="utf-8")
    print(f"updated {len(items)} row(s)")


if __name__ == "__main__":
    main()
