"""Summarise the real-CVE repair runs (results/realcve/*.jsonl) into a markdown table.

  python -m aegisbench.realcve.summarize > aegisbench/results/realcve/summary.md

Two gate versions were run, in this order:
  v1  exploit and variants within 1 s; urllib3's own parse_url test URLs (test/test_util.py) unchanged;
  v2  v1 plus seven long legitimate URLs (long paths, queries, signatures, userinfo, fragments), added after all
      three patches v1 accepted turned out to be length caps.
Every accepted patch is re-checked after the fact on the long legitimate URLs, and inspected by AST for an added
length or count cap (a comparison against len(...) or .count(...) that the original module does not have).
"""
from __future__ import annotations

import ast
import json
import statistics as st
import tempfile
from pathlib import Path

from aegisbench.realcve import cves
from aegisbench.summarize_deep import wilson

R = Path(__file__).resolve().parents[1] / "results" / "realcve"
URL_PY = cves.VENDOR / "urllib3-1.26.4" / "src" / "urllib3" / "util" / "url.py"


def caps(src: str) -> int:
    """Comparisons whose operand is len(...) or x.count(...)."""
    n = 0
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Compare):
            for side in [node.left] + node.comparators:
                if isinstance(side, ast.Call) and ((isinstance(side.func, ast.Name) and side.func.id == "len")
                                                   or (isinstance(side.func, ast.Attribute) and side.func.attr == "count")):
                    n += 1
    return n


def keeps_long(patch: str) -> bool:
    from aegisbench.realcve import repair_urllib3 as r
    f = Path(tempfile.mkdtemp()) / "url.py"
    f.write_text(patch)
    gold, now = r.run(URL_PY, r.LONG_LEGIT), r.run(f, r.LONG_LEGIT)
    return now is not None and all(a["result"] == b["result"] and b["s"] <= r.SLOW_S for a, b in zip(gold, now))


# Inputs that stay under a 100-'@' cap but are long (probes for capped patches).
PROBES = ["https://" + "@" * 100 + "a" * 30000 + ":a", "https://" + ("a" * 300 + "@") * 100 + ":a",
          "https://" + "@" * 100 + ":" * 30000, "https://" + "a" * 40000 + ":a", "https://" + "@" * 99 + "%" * 20000]


def probe_max(patch: str) -> float:
    from aegisbench.realcve import repair_urllib3 as r
    f = Path(tempfile.mkdtemp()) / "url.py"
    f.write_text(patch)
    out = r.run(f, PROBES)
    return max(x["s"] for x in out) if out else float("inf")


def row(name: str, path: Path) -> tuple[str, str]:
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    base = caps(URL_PY.read_text())
    acc = [(r, next(c for c in r["candidates"] if c.get("gate_ok"))) for r in rows if r["verified"]]
    k, n = len(acc), len(rows)
    lo, hi = wilson(k, n)
    keep = sum(keeps_long(c["patch"]) for _, c in acc)
    capped = sum(caps(c["patch"]) > base for _, c in acc)
    hl = sum(r.get("heldout_live", 0) for r, _ in acc)
    hs = sum(r.get("heldout_safe", 0) for r, _ in acc)
    heal = [r["heal_s"] for r, _ in acc]
    cands = [c for r in rows for c in r["candidates"]]
    gated = [c for c in cands if "gate_ok" in c]
    probe = max((probe_max(c["patch"]) for _, c in acc), default=None)
    line = (f"| {name} | {n} | {k}/{n} [{lo}, {hi}] | {keep}/{k} | {capped}/{k} | {hs}/{hl} | "
            f"{'n/a' if probe is None else f'{probe:.2f} s'} | "
            f"{st.median(r['tokens_in'] for r in rows):,.0f} | {(str(round(st.median(heal))) + ' s') if heal else 'n/a'} |")
    note = (f"{name}: {len(cands)} candidates; unparseable {sum(1 for c in cands if 'error' in c)}; JSON repaired by the "
            f"harness {sum(1 for c in cands if c.get('json_repaired'))}; rejected before the gate {sum(1 for c in cands if 'reject' in c)}; "
            f"reached the gate {len(gated)}: passed {sum(1 for c in gated if c['gate_ok'])}, attack still slower than 1 s "
            f"{sum(1 for c in gated if c.get('attack_s') is None or max(c['attack_s']) > 1.0)}, legitimate results changed "
            f"{sum(1 for c in gated if (c.get('legit_changed') or 0) > 0)}.")
    return line, note


def main() -> None:
    sets = [("gate v1 (test URLs)", R / "urllib3_redos_gate_v1.jsonl"), ("gate v2 (+ long URLs)", R / "urllib3_redos.jsonl")]
    sets = [(n, p) for n, p in sets if p.exists()]
    first = json.loads((R / "urllib3_redos_gate_v1.jsonl").read_text().splitlines()[0])
    print("# Real CVE repair: CVE-2021-33503 (urllib3 1.26.4, ReDoS in parse_url)\n")
    print(f"Gemma 4 E4B as the repair model, local Apple M5, 5 trials of up to 4 candidates per gate version. Context: slice + BM25 "
          f"(alert text) within 5% of the package ({', '.join(first['context_files'])}). Exploit: a 12,010-character URL "
          f"that takes 2.5 to 3.1 s to parse. Gate v1 legitimate inputs: {first['legit_cases']} URLs from urllib3's tests; "
          "v2 adds 7 long legitimate URLs (3,021 to 11,020 characters).\n")
    print("| Gate | Trials | Accepted [95% CI] | Accepted and keeps long legitimate URLs | Accepted patch adds a length/count cap | "
          "Held-out blocked | Slowest long probe under the cap | Median prompt tokens | Median time to fix |")
    print("|---|---|---|---|---|---|---|---|---|")
    notes = []
    for name, p in sets:
        line, note = row(name, p)
        print(line)
        notes.append(note)
    print("\n" + "\n".join(f"- {n}" for n in notes))
    print("\nLong probes: five inputs of 20,000 to 40,000 characters with at most 100 '@' (they parse in at most "
          "0.11 s on the vulnerable code too); the column reports the slowest parse over all accepted patches.")
    print("\nThe strict-JSON first attempt (urllib3_redos_strict_json_trial1.jsonl) had 3 of 4 candidates unparseable, "
          "which is why the harness repairs unescaped backslashes in JSON strings.")


if __name__ == "__main__":
    main()
