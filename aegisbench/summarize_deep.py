"""Summarise the AegisBench-Deep model runs (results/local_deep/*.jsonl) into a markdown table.

  python -m aegisbench.summarize_deep > aegisbench/results/summary_deep.md
"""
from __future__ import annotations

import json
import statistics as st
from math import sqrt
from pathlib import Path

R = Path(__file__).parent / "results" / "local_deep"
NAMES = {"full": "graph k=2 (main runs)", "graph_slice": "graph slice",
         "no_graph_flat": "whole repository", "no_graph_route": "route file only"}


def wilson(k, n, z=1.96):
    if n == 0:
        return 0, 0
    p, d = k / n, 1 + z * z / n
    c, h = (p + z * z / (2 * n)) / d, z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(100 * (c - h)), round(100 * (c + h))


def load():
    return [json.loads(l) for f in sorted(R.glob("*.jsonl")) for l in f.read_text().splitlines() if l.strip()]


def main() -> None:
    rows = load()
    errs = sum(1 for r in rows if "error" in r)
    print("# AegisBench-Deep: model runs (Gemma 4 E4B in both roles, local, one trial)\n")
    print("| Bug depth | Retrieval | Bug file in context | Verified fix [95% CI] | Fix in the vulnerable file | Held-out blocked | Median prompt tokens | Median time to fix |")
    print("|---|---|---|---|---|---|---|---|")
    keys = sorted({(r.get("depth", 1), r["config"]) for r in rows if "error" not in r},
                  key=lambda x: (x[0], list(NAMES).index(x[1])))
    for d, c in keys:
        rs = [r for r in rows if r.get("depth", 1) == d and r["config"] == c and "error" not in r]
        k, n = sum(r["verified"] for r in rs), len(rs)
        lo, hi = wilson(k, n)
        ctx = sum(r["context_has_bug"] for r in rs)
        hl = sum(r.get("heldout_live", 0) for r in rs if r["verified"])
        hs = sum(r.get("heldout_safe", 0) for r in rs if r["verified"])
        root = sum(1 for r in rs if r["verified"] and any(c.get("gate_ok") and c.get("localized") for c in r["candidates"]))
        tok = st.median(r["tokens_in"] for r in rs)
        heal = [r["heal_s"] for r in rs if r["verified"] and r.get("heal_s") is not None]
        print(f"| {d} | {NAMES[c]} | {ctx}/{n} | {k}/{n} ({100 * k / n:.1f}%) [{lo}, {hi}] | {root}/{k} | {hs}/{hl} | {tok:,.0f} | "
              f"{st.median(heal):.0f} s |" if heal else
              f"| {d} | {NAMES[c]} | {ctx}/{n} | {k}/{n} ({100 * k / n:.1f}%) [{lo}, {hi}] | n/a | n/a | {tok:,.0f} | n/a |")
    print(f"\nEpisodes: {len(rows)}; harness errors: {errs}. Prompt tokens: median per episode, summed over its repair calls (as in the main tables).")


if __name__ == "__main__":
    main()
