"""A deployable root-cause clause from dynamic taint: does the patch change the code where the payload ends up?

  python -m aegisbench.taint --out aegisbench/results/taint.md

The label in rootcause.py needs a reference fix, so it can only evaluate the agent. This clause needs only the
exploit, so the agent could use it as a gate: replay the exploit under a profiler, record every service function
that receives the attacker's payload as an argument (dynamic taint: an argument equal to a payload value, or
containing one of at least 4 characters), and take the sink module, the module of the deepest such function on
the call stack. Then
  sink_changed(patch)  <=>  the patch edits the sink module and changes a tainted function there, or a
                            module-level assignment (a pattern, a constant) that such a function reads.
It is evaluated offline on every verified fix in the logs and compared with the reference-fix label (Eq. 7).
"""
from __future__ import annotations

import argparse
import ast
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from aegisbench import rootcause, sandbox
from aegisbench.tasks import TASKS

R = Path(__file__).parent / "results"
TASK = {t["id"]: t for t in TASKS}

TRACE = r'''
import json, os, sys, threading
from fastapi.testclient import TestClient
root = os.path.join(os.getcwd(), "vault")
path, params = sys.argv[1], json.loads(sys.argv[2])
pay = [str(v) for v in params.values()]
hits = {}
def tainted(v):
    try:
        s = v if isinstance(v, str) else (v.decode("latin-1") if isinstance(v, (bytes, bytearray)) else str(v))
    except Exception:
        return False
    return any(s == p or (len(p) >= 4 and p in s) for p in pay)
def prof(frame, event, arg):
    if event != "call" or not frame.f_code.co_filename.startswith(root):
        return
    code = frame.f_code
    args = [frame.f_locals.get(n) for n in code.co_varnames[:code.co_argcount + code.co_kwonlyargcount]]
    if any(tainted(a) for a in args):
        depth, f = 0, frame
        while f is not None:
            depth += f.f_code.co_filename.startswith(root)
            f = f.f_back
        rel = os.path.relpath(code.co_filename, os.getcwd())
        key = rel + "::" + code.co_name
        hits[key] = max(hits.get(key, 0), depth)
c = TestClient(__import__("vault.main", fromlist=["app"]).app, raise_server_exceptions=False, follow_redirects=False)
threading.setprofile_all_threads(prof); sys.setprofile(prof)
t = threading.Thread(target=lambda: c.get(path, params=params), daemon=True); t.start(); t.join(5)
sys.setprofile(None); threading.setprofile_all_threads(None)
print(json.dumps(hits)); sys.stdout.flush(); os._exit(0)
'''


def taint_trace(task: dict, depth: int) -> dict[str, int]:
    work = Path(tempfile.mkdtemp(prefix="aegis-taint-"))
    try:
        repo = sandbox.build_repo({**task, "depth": depth}, work / "repo")
        out = subprocess.run([sys.executable, "-c", TRACE, task["route"], json.dumps(task["exploit"])], cwd=repo,
                             env=sandbox._env(repo), capture_output=True, text=True, timeout=60)
        return json.loads(out.stdout.strip().splitlines()[-1])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def sink(hits: dict[str, int]) -> tuple[str, set[str]]:
    """Sink module (deepest tainted function's file) and the tainted functions in it."""
    deepest = max(hits.values())
    mod = sorted(k.split("::")[0] for k, d in hits.items() if d == deepest)[0]
    return mod, {k.split("::")[1] for k in hits if k.startswith(mod + "::")}


def reads(src: str, funcs: set[str]) -> set[str]:
    """Module-level assignment names read by the given functions."""
    tree = ast.parse(src)
    glob = {t.id for n in tree.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
    out = set()
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in funcs:
            out |= {x.id for x in ast.walk(n) if isinstance(x, ast.Name) and x.id in glob}
    return out


def sink_changed(original: str, rel: str, patch: str, mod: str, funcs: set[str]) -> bool:
    if rel != mod:
        return False
    try:
        a, b = rootcause.defs(original), rootcause.defs(patch)
    except SyntaxError:
        return False
    watch = funcs | reads(original, funcs)
    return any(a.get(n) != b.get(n) for n in watch if n in a)


def original_source(task: dict, depth: int, rel: str) -> str | None:
    work = Path(tempfile.mkdtemp(prefix="aegis-src-"))
    try:
        repo = sandbox.build_repo({**task, "depth": depth}, work / "repo")
        p = repo / rel
        return p.read_text() if p.is_file() else None
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(R / "taint.md"))
    out = Path(ap.parse_args().out)
    sinks = {}
    for t in TASKS:
        for d in (1, 3, 5):
            sinks[(t["id"], d)] = sink(taint_trace(t, d))
    agree, agree_df = Counter(), Counter()
    rows = []
    sets = [("Kaggle main", R / "kaggle_main" / "main.jsonl"), ("Kaggle sizes", R / "kaggle_sizes" / "sizes.jsonl")]
    sets += [("Local AegisBench-Deep", f) for f in sorted((R / "local_deep").glob("*.jsonl"))]
    per = {}
    srcs = {}
    for name, f in sets:
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            c = rootcause.accepted(r) if "error" not in r else None
            if not c:
                continue
            t, d = TASK[r["task"]], r.get("depth", 1)
            mod, funcs = sinks[(t["id"], d)]
            key = (t["id"], d, mod)
            if key not in srcs:
                srcs[key] = original_source(t, d, mod)
            dyn = sink_changed(srcs[key], c.get("file", ""), c.get("patch", ""), mod, funcs)
            ref = rootcause.label(t, c.get("file", ""), c.get("patch", "")) == "root-cause"
            agree[(ref, dyn)] += 1
            if t["class"] != "idor":  # data-flow bugs; IDOR is a missing authorisation check in the caller
                agree_df[(ref, dyn)] += 1
            cfg = f"{name}: {r['config'] if name != 'Kaggle sizes' else r['repair_model']}" + (f", depth {d}" if d > 1 else "")
            g = per.setdefault(cfg, Counter())
            g["verified"] += 1
            g["dyn"] += dyn
            g["ref"] += ref
    L = ["# Deployable root-cause clause (dynamic taint) versus the reference-fix label", "",
         "Sink module per task and depth (deepest service function that receives the exploit's payload):", ""]
    for t in TASKS:
        mods = {d: sinks[(t["id"], d)] for d in (1, 3, 5)}
        L.append(f"- {t['id']}: " + "; ".join(f"depth {d} {m} ({', '.join(sorted(f))})" for d, (m, f) in mods.items())
                 + ("" if all(m == t["target"] for m, _ in mods.values()) else "  [differs from the vulnerable file]"))
    L += ["", "| Runs | Verified fixes | sink_changed holds | Reference label: root-cause |", "|---|---|---|---|"]
    for cfg, g in per.items():
        L.append(f"| {cfg} | {g['verified']} | {g['dyn']} | {g['ref']} |")
    n = sum(agree.values())
    L += ["", f"Agreement over {n} verified fixes: both root-cause {agree[(True, True)]}; both not {agree[(False, False)]}; "
          f"reference root-cause but clause fails {agree[(True, False)]}; clause holds but reference says not "
          f"{agree[(False, True)]}.",
          "", f"Without the two IDOR tasks (missing authorisation: the payload flows to the data lookup, but the check "
          f"belongs in the caller), over {sum(agree_df.values())} verified fixes: both root-cause {agree_df[(True, True)]}; "
          f"both not {agree_df[(False, False)]}; reference root-cause but clause fails {agree_df[(True, False)]}; clause "
          f"holds but reference says not {agree_df[(False, True)]}."]
    out.write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
