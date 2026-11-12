"""Label every verified fix as a root-cause fix or a path-specific guard (offline, from the logs).

  python -m aegisbench.rootcause --out aegisbench/results/rootcause.md

The sink of a task is the set of top-level definitions in the vulnerable module that the reference fix
changes (AST comparison of vulnerable vs. reference module). An accepted patch is
  root-cause verified        if it changes at least one sink definition (its AST differs from the vulnerable one);
  path-specific guard        otherwise: the gate passed, but the vulnerable code is untouched and stays
                             reachable from other callers.
The gate cannot tell the two apart; this label is computed after the fact and reported next to the gate.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

from aegisbench.tasks import TASKS, reference_fix

R = Path(__file__).parent / "results"
TASK = {t["id"]: t for t in TASKS}


def defs(src: str) -> dict[str, str]:
    out = {}
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name] = ast.dump(node)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = ast.dump(node)
    return out


def sink(task: dict) -> set[str]:
    v, f = defs(task["vulnerable"]), defs(reference_fix(task))
    return {n for n in v if f.get(n) != v[n]}


def label(task: dict, rel: str, patch: str) -> str:
    if rel != task["target"]:
        return "path-specific guard"
    try:
        p = defs(patch)
    except SyntaxError:
        return "unknown"
    v = defs(task["vulnerable"])
    return "root-cause" if any(p.get(n) != v[n] for n in sink(task)) else "path-specific guard"


def accepted(rec: dict) -> dict | None:
    return next((c for c in rec["candidates"] if c.get("gate_ok")), None) if rec.get("verified") else None


def rows(path: Path, key) -> dict:
    out = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if "error" in r:
            continue
        g = out.setdefault(key(r), {"verified": 0, "root-cause": 0, "path-specific guard": 0, "unknown": 0, "n": 0})
        g["n"] += 1
        c = accepted(r)
        if c:
            g["verified"] += 1
            g[label(TASK[r["task"]], c.get("file", ""), c.get("patch", ""))] += 1
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(R / "rootcause.md"))
    out = Path(ap.parse_args().out)
    L = ["# Root-cause fixes versus path-specific guards", "",
         "Sink: the definitions the reference fix changes. Root-cause: the accepted patch changes a sink definition. "
         "Path-specific guard: the gate passed, the sink is unchanged.", "",
         "Sinks per task: " + "; ".join(f"{t['id']} {', '.join(sorted(sink(t)))}" for t in TASKS), "",
         "| Runs | Configuration | Episodes | Verified | Root-cause | Path-specific guard | Unparsed |", "|---|---|---|---|---|---|---|"]
    sets = [("Kaggle main", R / "kaggle_main" / "main.jsonl", lambda r: r["config"]),
            ("Kaggle sizes", R / "kaggle_sizes" / "sizes.jsonl", lambda r: r["repair_model"]),
            ("Local AegisBench-Deep", None, None)]
    for name, path, key in sets[:2]:
        for k, g in sorted(rows(path, key).items()):
            L.append(f"| {name} | {k} | {g['n']} | {g['verified']} | {g['root-cause']} | {g['path-specific guard']} | {g['unknown']} |")
    for f in sorted((R / "local_deep").glob("*.jsonl")):
        for k, g in sorted(rows(f, lambda r: f"depth {r.get('depth', 1)}, {r['config']}").items()):
            L.append(f"| Local AegisBench-Deep | {k} | {g['n']} | {g['verified']} | {g['root-cause']} | {g['path-specific guard']} | {g['unknown']} |")
    out.write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
