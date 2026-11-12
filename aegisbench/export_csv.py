"""Flatten the raw JSONL results into CSV files (no model calls, no recomputation).

  python -m aegisbench.export_csv --out aegisbench/results/csv

Writes:
  episodes.csv          one row per episode (main, injection and model-size runs)
  candidates.csv        one row per repair candidate, with the patch text, invariant, Z3 verdict and gate result
  replay_scope.csv      one row per replayed scope-rejected candidate (route-only ablation counterfactual)
  replay_docstring.csv  one row per replayed candidate whose only defect was the dropped docstring quote
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

R = Path(__file__).parent / "results"
SOURCES = [
    ("main", R / "kaggle_main" / "main.jsonl"),
    ("inject", R / "kaggle_main" / "inject.jsonl"),
    ("sizes", R / "kaggle_sizes" / "sizes.jsonl"),
]
EPISODE_COLS = [
    "run", "episode_id", "task", "class", "config", "trial", "injection", "edge_model", "repair_model",
    "observed", "triage", "triage_right", "triage_s",
    "edge_admitted", "edge_violation", "edge_z3", "edge_coverage", "edge_attempts", "edge_rule", "contain_s",
    "context_files", "context_has_bug", "gate_reproduces",
    "n_candidates", "localized_any", "shipped", "verified", "unsafe_ship", "model_test_right",
    "heldout_live", "heldout_safe", "tokens_in", "tokens_out", "heal_s", "episode_s", "error",
]
CAND_COLS = [
    "run", "episode_id", "task", "config", "trial", "injection", "repair_model", "k", "file", "localized", "partial",
    "latency_s", "phi_ok", "phi_violations", "gate_ok", "model_test_passed", "gate_reason", "invariant", "patch_chars",
    "patch", "reject", "phi",
]


def rows(path: Path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def cell(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        if isinstance(v, list) and all(isinstance(x, str) for x in v):
            return ";".join(v)
        return json.dumps(v, sort_keys=True)
    return v


def episode_id(run, r):
    return f"{run}:{r['task']}:{r['config']}:{r.get('trial')}:{r.get('injection') or '-'}:{r.get('repair_model')}"


def write(path: Path, cols, records):
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for rec in records:
            w.writerow({c: cell(rec.get(c)) for c in cols})
    print(f"{path}: {len(records)} rows")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(R / "csv"))
    out = Path(ap.parse_args().out)
    out.mkdir(parents=True, exist_ok=True)

    episodes, cands = [], []
    for run, path in SOURCES:
        for r in rows(path):
            eid = episode_id(run, r)
            episodes.append({**r, "run": run, "episode_id": eid})
            for c in r.get("candidates") or []:
                phi = c.get("phi") or {}
                viol = phi.get("violated") if isinstance(phi, dict) else None
                cands.append({**c, "run": run, "episode_id": eid, "task": r["task"], "config": r["config"],
                              "trial": r.get("trial"), "injection": r.get("injection"),
                              "repair_model": r.get("repair_model"),
                              "phi_ok": phi.get("admit") if isinstance(phi, dict) else None,
                              "phi_violations": viol, "patch_chars": len(c.get("patch") or "")})
    write(out / "episodes.csv", EPISODE_COLS, episodes)
    extra = sorted({k for c in cands for k in c} - set(CAND_COLS))
    write(out / "candidates.csv", CAND_COLS + extra, cands)

    scope = []
    for r in rows(R / "replay_scope.jsonl"):
        for c in r["candidates"]:
            scope.append({"task": r["task"], "class": r["class"], "trial": r["trial"], "episode_any_pass": r["any_pass"],
                          **c})
    write(out / "replay_scope.csv", ["task", "class", "trial", "episode_any_pass", "k", "file", "gate_ok",
                                     "truncated", "reason"], scope)

    doc = []
    for run, name in (("main", "replay_docstring_main.jsonl"), ("sizes", "replay_docstring_sizes.jsonl")):
        for r in rows(R / name):
            for c in r["candidates"]:
                doc.append({"run": run, "task": r["task"], "config": r["config"], "trial": r["trial"],
                            "repair_model": r["repair_model"], "episode_verified": r["verified"], **c})
    write(out / "replay_docstring.csv", ["run", "task", "config", "trial", "repair_model", "episode_verified", "k",
                                         "pattern", "gate_ok", "reason"], doc)


if __name__ == "__main__":
    main()
