#!/usr/bin/env bash
# Regenerate every table, chart and CSV in the paper from the raw logs (no model calls, about two minutes).
# The real-CVE tables need the pinned sources once: python -m aegisbench.realcve.cves (PyPI, SHA-256 checked).
# Run from the repository root after: pip install -r requirements.txt
# With --validate it also checks that every exploit works and every reference fix passes the gate (slower).
set -euo pipefail
R=aegisbench/results
python -m aegisbench.summarize $R/kaggle_main/main.jsonl $R/kaggle_main/inject.jsonl $R/kaggle_sizes/sizes.jsonl --out $R/summary
python -m aegisbench.summarize_replays > $R/summary_replays.md
python -m aegisbench.graph_stats --out $R/graph_stats.md > /dev/null
python -m aegisbench.deep_stats --out $R/deep_stats.md > /dev/null
python -m aegisbench.summarize_deep > $R/summary_deep.md
python -m aegisbench.rootcause --out $R/rootcause.md > /dev/null
python -m aegisbench.taint --out $R/taint.md > /dev/null
python -m aegisbench.sanitizer --out $R/sanitizer.md > /dev/null
python -m aegisbench.semantic --out $R/semantic.md > /dev/null
if python -c "from aegisbench.realcve import cves; raise SystemExit(0 if cves.available() else 1)"; then
  python -m aegisbench.realcve.cve_stats --out $R/cve_stats.md > /dev/null
  python -m aegisbench.realcve.summarize > $R/realcve/summary.md
else
  echo "Real-CVE sources not fetched (python -m aegisbench.realcve.cves); keeping the committed cve_stats.md and realcve/summary.md."
fi
python -m aegisbench.export_csv --out $R/csv > /dev/null
python -m aegisbench.paper.make_figures > /dev/null
if [[ "${1:-}" == "--validate" ]]; then
  for d in 1 3 5; do python -m aegisbench.validate_tasks --depth $d | tail -1; done
  if python -c "from aegisbench.realcve import cves; raise SystemExit(0 if cves.available() else 1)"; then
    python -m aegisbench.realcve.cves --verify | tail -1
    python -m aegisbench.realcve.repair_urllib3 --check
    # runs the CVE releases' own code in isolated processes (python3.12, no network): python -m aegisbench.realcve.runtime first
    python -m aegisbench.realcve.exploits --out $R/realcve/exploits.md && sed -n 3p $R/realcve/exploits.md
    python -m aegisbench.realcve.regress --out $R/realcve/regress.md > /dev/null && sed -n 3p $R/realcve/regress.md
  fi
fi
if git rev-parse --git-dir > /dev/null 2>&1; then
  if git diff --quiet -- $R aegisbench/paper; then echo "Reproduced: every summary, CSV and chart source matches the committed files."
  else echo "Differences from the committed files:"; git diff --stat -- $R aegisbench/paper; exit 1; fi
fi
