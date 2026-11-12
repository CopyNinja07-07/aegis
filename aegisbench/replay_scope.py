"""Counterfactual for the route-only ablation: would the patches that the in_scope clause rejected
have passed the agent-built gate?

The route-only configuration shows the repair model only the route file. The model often names the right
helper module (it is imported there) and rewrites it without having seen it; Phi_safety's in_scope clause
rejects such edits. This script replays every logged, scope-rejected patch through the same gate, offline
(no model calls), and writes one JSON line per episode.

  python -m aegisbench.replay_scope aegisbench/results/kaggle_main/main.jsonl --out aegisbench/results/replay_scope.jsonl
"""
from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from aegisbench import sandbox
from aegisbench.tasks import BY_ID


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--out", required=True)
    ap.add_argument("--stage", default="/tmp/aegis_stage_replay")
    a = ap.parse_args()
    rows = [json.loads(l) for l in Path(a.results).read_text().splitlines() if l.strip()]
    rows = [r for r in rows if r.get("config") == "no_graph_route" and not r.get("error")]
    out = Path(a.out)
    out.write_text("")
    for r in rows:
        task = BY_ID[r["task"]]
        work = Path(tempfile.mkdtemp(prefix="aegis-replay-"))
        try:
            gate = sandbox.Gate(task, work / "gate", Path(a.stage))
            results = []
            for c in r["candidates"]:
                if not (c.get("reject") or "").startswith("Phi_safety: violates in_scope") or not c.get("patch"):
                    continue
                truncated = len(c["patch"]) >= 8000
                res = gate.check(c["file"], c["patch"], f"cand-{c['k']}")
                results.append({"k": c["k"], "file": c["file"], "gate_ok": res["ok"], "truncated": truncated,
                                "reason": res["reason"][:300]})
            rec = {"task": r["task"], "class": r["class"], "trial": r["trial"], "replayed": len(results),
                   "any_pass": any(x["gate_ok"] for x in results), "candidates": results}
        finally:
            shutil.rmtree(work, ignore_errors=True)
        with out.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        print(r["task"], r["trial"], [x["gate_ok"] for x in results], flush=True)


if __name__ == "__main__":
    main()
