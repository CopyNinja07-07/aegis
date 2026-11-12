"""Offline code-graph analysis of AegisBench (no model calls, deterministic).

For every task: build the repository with the vulnerable helper, build the call graph, and measure
  - the call-hop distance from the attacked route's handler to the vulnerable file,
  - for retrieval depth k = 0..3: whether the vulnerable file is in the context (recall@k),
    how many files and characters the context holds,
  - against the whole repository (flat context).
Also counts the gate-labelled candidates (a ready-made verifiable-reward dataset).

  python -m aegisbench.graph_stats --out aegisbench/results/graph_stats.md
"""
from __future__ import annotations

import argparse
import json
import shutil
import statistics as st
import tempfile
from pathlib import Path

import networkx as nx

from aegisbench import codegraph, sandbox
from aegisbench.tasks import TASKS

R = Path(__file__).parent / "results"


def context(repo: Path, graph, handler: str, k: int) -> list[str]:
    reached = nx.single_source_shortest_path_length(graph, handler, cutoff=k)
    files = []
    for fn in sorted(reached, key=lambda n: reached[n]):
        rel = graph.nodes[fn]["file"]
        if rel not in files:
            files.append(rel)
    return files


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(R / "graph_stats.md"))
    out = Path(ap.parse_args().out)
    rows = []
    for t in TASKS:
        work = Path(tempfile.mkdtemp(prefix="aegis-graph-"))
        try:
            repo = sandbox.build_repo(t, work / "repo")
            graph, routes = codegraph.build(repo)
            handler = routes[t["route"]]
            dist = nx.single_source_shortest_path_length(graph, handler)
            hops = min(d for n, d in dist.items() if graph.nodes[n]["file"] == t["target"])
            all_rel = codegraph.all_files(repo)
            flat = len(codegraph.render(repo, all_rel))
            per_k = {}
            for k in range(4):
                files = context(repo, graph, handler, k)
                per_k[k] = {"recall": t["target"] in files, "files": len(files),
                            "chars": len(codegraph.render(repo, files))}
            rows.append({"task": t["id"], "hops": hops, "n_nodes": graph.number_of_nodes(),
                         "n_edges": graph.number_of_edges(), "n_files": len(all_rel), "flat_chars": flat, "k": per_k})
        finally:
            shutil.rmtree(work, ignore_errors=True)

    cands = [json.loads(l) for f in ("kaggle_main/main.jsonl", "kaggle_main/inject.jsonl", "kaggle_sizes/sizes.jsonl")
             for l in (R / f).read_text().splitlines() if l.strip()]
    labelled = [c for r in cands for c in r["candidates"] if c.get("gate_ok") is not None]
    pos = sum(1 for c in labelled if c["gate_ok"])

    L = ["# Code-graph analysis of AegisBench (offline, deterministic)", "",
         f"Graph: {rows[0]['n_nodes']} function/class nodes, {rows[0]['n_edges']} call edges, {rows[0]['n_files']} files "
         "(task variants differ by at most a few edges).", "",
         "| Task | Hops route → vulnerable file |", "|---|---|"]
    L += [f"| {r['task']} | {r['hops']} |" for r in rows]
    L += ["", "Hop distribution: " + ", ".join(f"{h} hop(s): {sum(r['hops'] == h for r in rows)}" for h in sorted({r['hops'] for r in rows})), "",
          "| Retrieval depth k | Recall (vulnerable file in context) | Files (median) | Context chars (median) | Share of flat repo |",
          "|---|---|---|---|---|"]
    for k in range(4):
        rec = sum(r["k"][k]["recall"] for r in rows)
        files = st.median(r["k"][k]["files"] for r in rows)
        chars = st.median(r["k"][k]["chars"] for r in rows)
        share = st.median(r["k"][k]["chars"] / r["flat_chars"] for r in rows)
        L.append(f"| {k} | {rec}/{len(rows)} | {files:g} | {chars:,.0f} | {share:.0%} |")
    fl = st.median(r["flat_chars"] for r in rows)
    L.append(f"| flat (whole repo) | {len(rows)}/{len(rows)} | {rows[0]['n_files']} | {fl:,.0f} | 100% |")
    L += ["", f"Gate-labelled candidates across all 400 episodes: {len(labelled)} ({pos} accepted, {len(labelled) - pos} rejected)."]
    out.write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
