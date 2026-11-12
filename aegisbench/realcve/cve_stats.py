"""Retrieval on real CVEs (offline, deterministic, no model calls).

  python -m aegisbench.realcve.cves                          # fetch the pinned vulnerable sources once
  python -m aegisbench.realcve.cve_stats --out aegisbench/results/cve_stats.md

For each case: package size, how many call hops separate the public entry point from the nearest function the
upstream fix changed (cves.py lists them; cves.py --verify checks them against the fixed release), and how much code each strategy must hand the model before that function is in
its context ("code to reach the bug", as a share of the package's source). Function-level strategies
add whole functions in order:
  graph distance      functions reachable from the entry, nearest first (ties by name)
  graph + BM25        reachable functions, nearest first, ties broken by BM25 on the alert text
  BM25 (alert)        all package functions ranked by BM25 on the alert's description
  BM25 (class)        all package functions ranked by BM25 on the triaged class only
  slice + BM25        only functions reachable from the entry, ranked by BM25 (alert text / class only)
File-level rows repeat the AegisBench strategies: files within k hops, and the whole forward slice.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics as st
from collections import Counter
from pathlib import Path

import networkx as nx

from aegisbench.realcve import cves
from aegisbench.realcve.libgraph import LibGraph

R = Path(__file__).resolve().parents[1] / "results"


def tokens(text: str) -> list[str]:
    import re
    out = []
    for w in re.findall(r"[A-Za-z][A-Za-z0-9]*", text):
        out += [p.lower() for p in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", w) if len(p) > 1]
    return out


def bm25_scores(docs: dict[str, str], query: str, k1: float = 1.5, b: float = 0.75) -> dict[str, float]:
    tf = {d: Counter(tokens(t)) for d, t in docs.items()}
    avg = st.mean(sum(c.values()) or 1 for c in tf.values())
    df = Counter(t for c in tf.values() for t in c)
    q, n = tokens(query), len(docs)
    out = {}
    for d, c in tf.items():
        ln = sum(c.values()) or 1
        out[d] = sum(math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5)) * c[t] * (k1 + 1) / (c[t] + k1 * (1 - b + b * ln / avg))
                     for t in q if t in c)
    return out


def source(G: LibGraph, n: str) -> str:
    d = G.g.nodes[n]
    lines = (G.root / d["file"]).read_text(errors="replace").splitlines()
    return "\n".join(lines[d["lines"][0] - 1: d["lines"][1]])


def share_to_reach(G: LibGraph, order: list[str], targets: set[str], total: int) -> float | None:
    used = 0
    for n in order:
        used += len(source(G, n)) + 1
        if n in targets:
            return used / total
    return None


TRACES = R / "realcve" / "traces.json"


def measure(case: dict) -> dict:
    G = LibGraph(cves.case_root(case), case["packages"])
    tr = json.loads(TRACES.read_text()).get(case["id"], []) if TRACES.exists() else []
    total = G.size(G.files)
    loc = sum(len((G.root / f).read_text(errors="replace").splitlines()) for f in G.files)
    e, targets = case["entry"], set(case["vulnerable"])
    assert e in G.g and all(v in G.g for v in targets), (e in G.g, [v for v in targets if v not in G.g])
    dist = G.reached(e)
    hit = sorted((t for t in targets if t in dist), key=lambda t: dist[t])
    path = nx.shortest_path(G.g, e, hit[0]) if hit else None
    funcs = [n for n in G.g if not G.g.nodes[n].get("cls")]
    docs = {n: n + "\n" + source(G, n) for n in funcs}
    alert, klass = bm25_scores(docs, case["query_alert"]), bm25_scores(docs, case["query_class"])
    reach = [n for n in funcs if n in dist]
    orders = {
        "graph": sorted(reach, key=lambda n: (dist[n], n)),
        "graph_bm25": sorted(reach, key=lambda n: (dist[n], -alert[n], n)),
        "bm25_alert": sorted(funcs, key=lambda n: (-alert[n], n)),
        "bm25_class": sorted(funcs, key=lambda n: (-klass[n], n)),
        "slice_alert": sorted(reach, key=lambda n: (-alert[n], dist[n], n)),
        "slice_class": sorted(reach, key=lambda n: (-klass[n], dist[n], n)),
    }
    # Slice + trace: the static graph plus the calls recorded while the exploit ran (exploits.py --trace).
    H = G.g.copy()
    H.add_edges_from((u, v) for u, v in tr if u in H and v in H)
    dist_t = nx.single_source_shortest_path_length(H, e)
    hit_t = sorted((t for t in targets if t in dist_t), key=lambda t: dist_t[t])
    reach_t = [n for n in funcs if n in dist_t]
    order_t = sorted(reach_t, key=lambda n: (-klass[n], dist_t[n], n))
    order_ta = sorted(reach_t, key=lambda n: (-alert[n], dist_t[n], n))
    vfiles = {G.g.nodes[t]["file"] for t in targets}
    files = {k: G.files_within(e, k) for k in (2, 4, None)}
    return {
        "case": case, "files": len(G.files), "loc": loc, "hops": len(path) - 1 if path else None,
        "path": " → ".join(".".join(x.split(".")[-2:]) for x in path) if path else "unreachable",
        "slice_files": len(files[None]), "slice_share": G.size(files[None]) / total,
        "slice_func_share": G.function_size(dist) / total,
        **{f"k{k}": bool(vfiles & set(files[k])) for k in (2, 4)},
        **{f"reach_{s}": share_to_reach(G, o, targets, total) for s, o in orders.items()},
        "unresolved": G.unresolved, "trace_edges": len(tr),
        "hops_trace": dist_t[hit_t[0]] if hit_t else None,
        "reach_trace_class": share_to_reach(G, order_t, targets, total),
        "reach_trace_alert": share_to_reach(G, order_ta, targets, total),
    }


def pct(x):
    return "not reached" if x is None else f"{100 * x:.1f}%"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(R / "cve_stats.md"))
    out = Path(ap.parse_args().out)
    if not cves.available():
        raise SystemExit("sources missing: run python -m aegisbench.realcve.cves first")
    rows = [measure(c) for c in cves.CASES]
    L = ["# Retrieval on real CVEs (offline, deterministic)", "",
         "Shares are of the package's Python source (characters). \"Code to reach the bug\": how much code a strategy "
         "hands the model, adding whole functions in its order, before the function the upstream fix changed is included.", "",
         "| Case | CVE | Files / lines | Bug hops from entry | Forward slice: files (code share) | Slice functions only | "
         "Bug file within k=2 / k=4 | Code to reach the bug: graph distance | graph + BM25 | BM25 (alert text) | BM25 (class only) | "
         "slice + BM25 (alert) | slice + BM25 (class) | Bug hops with exploit trace | slice + trace + BM25 (alert) | slice + trace + BM25 (class) |",
         "|---" * 16 + "|"]
    for r in rows:
        c = r["case"]
        L.append(f"| {c['id']} | {c['cve']} | {r['files']} / {r['loc']:,} | {r['hops']} | {r['slice_files']} ({pct(r['slice_share'])}) | "
                 f"{pct(r['slice_func_share'])} | {'yes' if r['k2'] else 'no'} / {'yes' if r['k4'] else 'no'} | "
                 f"{pct(r['reach_graph'])} | {pct(r['reach_graph_bm25'])} | {pct(r['reach_bm25_alert'])} | {pct(r['reach_bm25_class'])} | "
                 f"{pct(r['reach_slice_alert'])} | {pct(r['reach_slice_class'])} | {r['hops_trace']} | {pct(r['reach_trace_alert'])} | {pct(r['reach_trace_class'])} |")
    big = [r for r in rows if r["loc"] > 20000]
    L += ["", f"Slice + trace reaches a fixed function in {sum(r['hops_trace'] is not None for r in rows)} of {len(rows)} cases "
          f"(static slice alone: {sum(r['hops'] is not None for r in rows)}). Packages above 20,000 lines: "
          + "; ".join(f"{r['case']['id']} {r['loc']:,} lines, slice + trace + BM25 alert {pct(r['reach_trace_alert'])}, "
                      f"class {pct(r['reach_trace_class'])}" for r in big) + ".",
          "", "Exploit traces: calls recorded while the exploit ran against the vulnerable release (exploits.py --trace; "
          "results/realcve/traces.json). The agent has the exploit (Observe replays it), so this trace is available to it."]
    L += ["", "Call paths found by the graph (entry → vulnerable function):", ""]
    L += [f"- {r['case']['id']}: {r['path']}" for r in rows]
    L += ["", "Queries:", ""]
    L += [f"- {c['id']}: class \"{c['query_class']}\"; alert \"{c['query_alert']}\"" for c in cves.CASES]
    L += ["", f"Calls with an unresolved receiver (linked to every package method of that name): "
          + ", ".join(f"{r['case']['id']} {r['unresolved']}" for r in rows) + "."]
    out.write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
