"""Numbers for the two offline (post-hoc) replays; no model calls.

  python -m aegisbench.summarize_replays > aegisbench/results/summary_replays.md
"""
import json
from collections import defaultdict
from pathlib import Path

R = Path("aegisbench/results")
load = lambda p: [json.loads(l) for l in (R / p).read_text().splitlines() if l.strip()]

sc = load("replay_scope.jsonl")
cands = [c for r in sc for c in r["candidates"]]
print("# Offline replays\n\n## Route-only context, in_scope clause removed\n")
print(f"Episodes {len(sc)}; would be verified {sum(r['any_pass'] for r in sc)}/{len(sc)}; "
      f"candidates replayed {len(cands)}, passing the gate {sum(c['gate_ok'] for c in cands)}; "
      f"failing because legitimate traffic changed {sum('legitimate_traffic_unchanged' in c['reason'] for c in cands if not c['gate_ok'])}, "
      f"because the attack still works {sum('attack_is_neutralised' in c['reason'] for c in cands if not c['gate_ok'])}.\n")

print("## One missing docstring quote restored\n")
print("| Run | Config | Repair model | Candidates with the dropped quote | Pass the gate once restored | Unverified episodes with a syntax error: rescued |")
print("|---|---|---|---|---|---|")
for f in ("main", "sizes"):
    agg = defaultdict(lambda: [0, 0, 0, 0])
    for r in load(f"replay_docstring_{f}.jsonl"):
        a = agg[(r["config"], r["repair_model"])]
        pats = [x for x in r["candidates"] if x["pattern"]]
        a[0] += len(pats); a[1] += sum(bool(x.get("gate_ok")) for x in pats)
        if not r["verified"]:
            a[2] += 1; a[3] += any(x.get("gate_ok") for x in pats)
    for (cfg, m), a in sorted(agg.items()):
        print(f"| {f} | {cfg} | {m} | {a[0]} | {a[1]} | {a[3]} of {a[2]} |")

from aegisbench.replay_docstring import restore  # noqa: E402

syn = [c for f in ("kaggle_main/main.jsonl", "kaggle_main/inject.jsonl", "kaggle_sizes/sizes.jsonl") for r in load(f)
       for c in r["candidates"] if "SyntaxError" in (c.get("reject") or "")]
print(f"\nSyntax rejections across all 400 episodes: {len(syn)}; parse once the one dropped quote is restored: "
      f"{sum(1 for c in syn if c.get('patch') and restore(c['patch']) is not None)}.")
