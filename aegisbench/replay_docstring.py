"""Post-hoc analysis: how many candidates rejected for a SyntaxError were lost to one missing quote?

Gemma 4 in JSON mode sometimes closes the module docstring with two quotes instead of three
(e.g. '\"\"\"Input validation.\"\"').  This replays every such logged candidate, with only that
character restored, through the same agent-built gate.  No model calls.

  python -m aegisbench.replay_docstring aegisbench/results/kaggle_main/main.jsonl --out aegisbench/results/replay_docstring.jsonl
"""
from __future__ import annotations

import argparse, json, re, shutil, tempfile
from pathlib import Path

from aegisbench import sandbox
from aegisbench.agent import compiles
from aegisbench.tasks import BY_ID

BROKEN = re.compile(r'^(\s*"""[^"\n]*"")(?!")')


def restore(src: str) -> str | None:
    first, _, rest = src.partition("\n")
    if not BROKEN.match(first):
        return None
    fixed = BROKEN.sub(r'\1"', first, count=1) + "\n" + rest
    return fixed if compiles(fixed) is None else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--out", required=True)
    ap.add_argument("--stage", default="/tmp/aegis_stage_doc")
    a = ap.parse_args()
    rows = [json.loads(l) for l in Path(a.results).read_text().splitlines() if l.strip()]
    out = Path(a.out); out.write_text("")
    for r in rows:
        if r.get("error") or r.get("injection"):
            continue
        cands = [c for c in r["candidates"] if "SyntaxError" in (c.get("reject") or "") and c.get("patch")]
        if not cands:
            continue
        task = BY_ID[r["task"]]
        work = Path(tempfile.mkdtemp(prefix="aegis-doc-"))
        res = []
        try:
            gate = None
            for c in cands:
                fixed = restore(c["patch"])
                if fixed is None:
                    res.append({"k": c["k"], "pattern": False}); continue
                gate = gate or sandbox.Gate(task, work / "gate", Path(a.stage))
                g = gate.check(c["file"], fixed, f"cand-{c['k']}")
                res.append({"k": c["k"], "pattern": True, "gate_ok": g["ok"], "reason": g["reason"][:200]})
        finally:
            shutil.rmtree(work, ignore_errors=True)
        rec = {"task": r["task"], "config": r["config"], "trial": r["trial"], "repair_model": r["repair_model"],
               "verified": r["verified"], "candidates": res}
        with out.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        print(r["task"], r["config"], r["repair_model"], [(x["pattern"], x.get("gate_ok")) for x in res], flush=True)


if __name__ == "__main__":
    main()
