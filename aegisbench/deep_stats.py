"""Offline retrieval analysis on AegisBench-Deep (no model calls, deterministic).

For bug depth d = 1..5 call hops and every task, measure whether each retrieval strategy puts the
vulnerable file in the repair context, and how large that context is:
  graph k=1, k=2 (the paper's setting), k=4, the forward call slice (all reachable functions),
  BM25 over files (a similarity baseline in the spirit of RepoCoder) with the same file budget as the slice,
  and the whole repository.
A stress case replaces the route's direct call with dynamic dispatch (getattr), which a static call
graph cannot resolve; an import-closure fallback is measured for it.

  python -m aegisbench.deep_stats --out aegisbench/results/deep_stats.md
"""
from __future__ import annotations

import argparse
import ast
import math
import re
import shutil
import statistics as st
import tempfile
from collections import Counter
from pathlib import Path

import networkx as nx

from aegisbench import codegraph, sandbox
from aegisbench.tasks import TASKS

R = Path(__file__).parent / "results"


def tokens(text: str) -> list[str]:
    out = []
    for w in re.findall(r"[A-Za-z][A-Za-z0-9]*", text):
        out += [p.lower() for p in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", w) if len(p) > 1]
    return out


def bm25(repo: Path, rels: list[str], query: str, n: int, k1: float = 1.5, b: float = 0.75) -> list[str]:
    docs = {r: Counter(tokens(r + " " + (repo / r).read_text())) for r in rels}
    avg = st.mean(sum(c.values()) for c in docs.values())
    df = Counter(t for c in docs.values() for t in c)
    q = tokens(query)

    def score(c):
        ln = sum(c.values())
        return sum(math.log(1 + (len(docs) - df[t] + 0.5) / (df[t] + 0.5)) * c[t] * (k1 + 1)
                   / (c[t] + k1 * (1 - b + b * ln / avg)) for t in q if t in c)
    return sorted(rels, key=lambda r: -score(docs[r]))[:n]


def files_within(graph, handler, k):
    reached = nx.single_source_shortest_path_length(graph, handler, cutoff=k)
    out = []
    for fn in sorted(reached, key=lambda x: reached[x]):
        if graph.nodes[fn]["file"] not in out:
            out.append(graph.nodes[fn]["file"])
    return out


def import_closure(repo: Path, start: str) -> list[str]:
    seen, todo = [], [start]
    while todo:
        rel = todo.pop(0)
        if rel in seen or not (repo / rel).is_file():
            continue
        seen.append(rel)
        for node in ast.parse((repo / rel).read_text()).body:
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("vault"):
                for a in node.names:
                    for cand in (f"{node.module}.{a.name}", node.module):
                        p = cand.replace(".", "/") + ".py"
                        if (repo / p).is_file():
                            todo.append(p)
                            break
    return seen


def dynamic(repo: Path, task: dict) -> None:
    """Route calls the helper through getattr(module, "name")(...): invisible to a static call graph."""
    mod = Path(task["target"]).stem
    for f in (repo / "vault" / "routes").glob("*.py"):
        s = f.read_text()
        s2 = re.sub(rf"\b{mod}\.([a-z_]+)\(", rf'getattr({mod}, "\1")(', s)
        if s2 != s:
            f.write_text(s2)


TRACE = r'''
import json, os, sys, threading
from fastapi.testclient import TestClient
root = os.path.join(os.getcwd(), "vault")
edges = set()
def name(code):
    rel = os.path.relpath(code.co_filename, os.getcwd())
    return rel[:-3].replace(os.sep, ".") + "." + code.co_name
def prof(frame, event, arg):
    if event != "call" or not frame.f_code.co_filename.startswith(root):
        return
    up = frame.f_back
    while up is not None and not up.f_code.co_filename.startswith(root):
        up = up.f_back
    if up is not None:
        edges.add((name(up.f_code), name(frame.f_code)))
from vault.main import app
c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
path, cases = sys.argv[1], json.loads(sys.argv[2])
threading.setprofile_all_threads(prof); sys.setprofile(prof)
for params in cases:
    c.get(path, params=params)
sys.setprofile(None); threading.setprofile_all_threads(None)
print(json.dumps(sorted(edges)))
'''


def trace_edges(repo: Path, task: dict) -> list[tuple[str, str]]:
    """Calls recorded while the legitimate requests are replayed (a one-turn dynamic trace)."""
    import json, subprocess, sys
    out = subprocess.run([sys.executable, "-c", TRACE, task["route"], json.dumps(task["benign"])], cwd=repo,
                         env=sandbox._env(repo), capture_output=True, text=True, timeout=60)
    return [tuple(e) for e in json.loads(out.stdout.strip().splitlines()[-1])]


REGISTRY = """
_HANDLERS = {}


def _register(name):
    def deco(fn):
        _HANDLERS[name] = fn
        return fn
    return deco
"""
MANAGER = """


class _Manager:
    def __init__(self, module):
        self._module = module

    def __getattr__(self, name):
        return getattr(self._module, name)
"""


def _after_imports(src: str, block: str) -> str:
    lines = src.splitlines()
    last = max(i for i, l in enumerate(lines) if l.startswith(("import ", "from ")))
    return "\n".join(lines[:last + 1] + block.splitlines() + lines[last + 1:]) + "\n"


def indirect(repo: Path, task: dict, kind: str) -> None:
    """The route reaches the helper through a decorator registry or an ORM-style manager (__getattr__)."""
    mod = Path(task["target"]).stem
    for f in (repo / "vault" / "routes").glob("*.py"):
        s = f.read_text()
        names = sorted(set(re.findall(rf"\b{mod}\.([a-z_]+)\(", s)))
        if not names:
            continue
        if kind == "registry":
            s = re.sub(rf"\b{mod}\.([a-z_]+)\(", r'_HANDLERS["\1"](', s)
            regs = "".join(f'\n\n@_register("{n}")\ndef _h_{n}(*a, **k):\n    return {mod}.{n}(*a, **k)\n' for n in names)
            s = _after_imports(s, REGISTRY + regs)
        else:
            s = re.sub(rf"\b{mod}\.([a-z_]+)\(", r"_Records.objects.\1(", s)
            s = _after_imports(s, MANAGER + f"\n\nclass _Records:\n    objects = _Manager({mod})\n")
        f.write_text(s)


def measure(task, depth, dyn=False):
    work = Path(tempfile.mkdtemp(prefix="aegis-deep-"))
    try:
        repo = sandbox.build_repo({**task, "depth": depth}, work / "repo")
        if dyn is True:
            dynamic(repo, task)
        elif dyn:
            indirect(repo, task, dyn)
        graph, routes = codegraph.build(repo)
        h = routes[task["route"]]
        dist = nx.single_source_shortest_path_length(graph, h)
        hops = min((d for n, d in dist.items() if graph.nodes[n]["file"] == task["target"]), default=None)
        allf = codegraph.all_files(repo)
        flat = len(codegraph.render(repo, allf))
        size = lambda fs: len(codegraph.render(repo, fs)) / flat
        strat = {f"k={k}": files_within(graph, h, k) for k in (1, 2, 4)}
        strat["slice"] = files_within(graph, h, None)
        query = f"{task['route']} {' '.join(map(str, task['exploit'].keys()))} {task['class']}"
        strat["bm25"] = bm25(repo, allf, query, len(strat["slice"]))
        strat["imports"] = import_closure(repo, graph.nodes[h]["file"])
        hy = graph.copy()
        hy.add_edges_from((u, v) for u, v in trace_edges(repo, task) if u in hy and v in hy)
        strat["hybrid"] = files_within(hy, h, None)
        route_f = graph.nodes[h]["file"]
        casc = strat["slice"]
        if casc == [route_f]:  # (a) static slice found nothing beyond the route: (b) add the trace
            casc = strat["hybrid"]
        if casc == [route_f]:  # (c) still nothing: the route's import closure
            casc = strat["imports"]
        strat["cascade"] = casc
        return {"hops": hops, "files": len(allf),
                **{s: (task["target"] in fs, size(fs)) for s, fs in strat.items()}}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(R / "deep_stats.md"))
    out = Path(ap.parse_args().out)
    S = ["k=1", "k=2", "k=4", "slice", "bm25", "imports", "hybrid", "cascade"]
    names = {"k=1": "graph k=1", "k=2": "graph k=2 (paper)", "k=4": "graph k=4", "slice": "graph slice",
             "bm25": "BM25, same file budget", "imports": "import closure",
             "hybrid": "slice + trace", "cascade": "cascade"}
    L = ["# Retrieval on AegisBench-Deep (offline, deterministic)", "",
         "Recall = tasks (of 16) whose vulnerable file is in the context. Size = median context as a share of the whole repository.", "",
         "| Bug depth (hops) | Repo files | " + " | ".join(names[s] for s in S) + " |", "|---" * (len(S) + 2) + "|"]
    for depth in range(1, 6):
        rs = [measure(t, depth) for t in TASKS]
        assert all(r["hops"] == depth for r in rs), [r["hops"] for r in rs]
        cells = [f"{sum(r[s][0] for r in rs)}/16 ({st.median(r[s][1] for r in rs):.0%})" for s in S]
        L.append(f"| {depth} | {rs[0]['files']} | " + " | ".join(cells) + " |")
    for kind, label in ((True, "dynamic dispatch"), ("registry", "decorator registry"), ("orm", "ORM-style manager")):
        for depth in (1, 3, 5):
            rs = [measure(t, depth, dyn=kind) for t in TASKS]
            cells = [f"{sum(r[s][0] for r in rs)}/16 ({st.median(r[s][1] for r in rs):.0%})" for s in S]
            L.append(f"| {depth}, {label} | {rs[0]['files']} | " + " | ".join(cells) + " |")
    L += ["", "Indirection rows: the route calls the helper through getattr (dynamic dispatch), through a dict filled by a "
          "registering decorator, or through an ORM-style manager that resolves attributes in __getattr__.",
          "", "Slice + trace: the static graph plus calls recorded while the legitimate requests are replayed. "
          "Cascade: static slice; if it reaches nothing beyond the route file, add the trace; if still nothing, the import closure.",
          "", "BM25 query: the attacked route, the exploit's parameter names and the triaged class (what the agent sees)."]
    out.write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
