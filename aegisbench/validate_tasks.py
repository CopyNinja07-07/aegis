"""Check every task: the exploit works on the vulnerable code and a reference fix passes the gate."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aegisbench import oracle, sandbox
from aegisbench.tasks import TASKS, reference_fix

work = Path(tempfile.mkdtemp(prefix="aegisbench-"))
stage = Path("/tmp/aegis_stage")
depth = int(sys.argv[sys.argv.index("--depth") + 1]) if "--depth" in sys.argv else 1  # AegisBench-Deep
rows = []
for t in ({**t, "depth": depth} for t in TASKS):
    v1 = sandbox.build_repo(t, work / t["id"] / "probe")
    r = sandbox.probe(v1, stage, t["route"], t["exploit"])
    hits = oracle.findings(r["status"], r["sample"], {"location": r.get("location")}, r["duration_ms"], t["exploit"])
    heldout_v1 = []
    for h in t["heldout"]:
        hr = sandbox.probe(v1, stage, t["route"], h)
        heldout_v1.append(bool(oracle.findings(hr["status"], hr["sample"], {"location": hr.get("location")}, hr["duration_ms"], h)))
    gate = sandbox.Gate(t, work / t["id"] / "gate", stage, extra_attacks=sandbox.heldout_attacks(t))
    ref = gate.check(t["target"], reference_fix(t), "ref")
    rows.append({"id": t["id"], "exploit_hits": hits, "reproduces": gate.reproduces, "golden_ok": gate.golden_ok,
                 "heldout_exploitable_on_v1": f"{sum(heldout_v1)}/{len(heldout_v1)}",
                 "reference_passes": ref["ok"], "ref_counts": ref["counts"], "why": "" if ref["ok"] else ref["reason"][:200]})
    print(json.dumps(rows[-1]), flush=True)
print("ALL OK" if all(r["reproduces"] and r["reference_passes"] and r["exploit_hits"] for r in rows) else "SOME FAILED")
