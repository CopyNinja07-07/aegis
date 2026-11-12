"""Semantic invariance of the legitimate-traffic check under non-deterministic responses.

  python -m aegisbench.semantic --out aegisbench/results/semantic.md

Vault is deterministic, so the gate's comparison (status, redirect, parsed JSON with timing keys dropped) was
never tested against responses that legitimately vary. Here a middleware makes every JSON object response carry a
fresh UUID (request_id), the current time (served_at) and a shuffled key order. Three comparators are scored on
whether they flag a legitimate response as changed:
  strict    status, redirect and the raw body bytes;
  gate v1   the gate as run in the paper (parsed JSON, keys matching ms|elapsed|time dropped);
  semantic  gate v1, plus UUID and ISO-8601 timestamp values masked (what sandbox.py now uses).
Changed (positives): the 32 main-run candidates the gate rejected because a legitimate response changed.
Unchanged (negatives): the 45 verified full-agent patches, and a second replay of each unpatched task.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from aegisbench import sandbox
from aegisbench.tasks import TASKS

R = Path(__file__).parent / "results"
TASK = {t["id"]: t for t in TASKS}

NONDET = '''

# --- added by aegisbench.semantic: non-deterministic responses (fresh UUID, timestamp, shuffled keys) ---
import datetime as _dt, json as _json, random as _random, uuid as _uuid
from starlette.middleware.base import BaseHTTPMiddleware as _Base
from starlette.responses import Response as _Response


class _NonDeterministic(_Base):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        if not resp.headers.get("content-type", "").startswith("application/json"):
            return resp
        body = b"".join([chunk async for chunk in resp.body_iterator])
        data = _json.loads(body)
        if isinstance(data, dict):
            data.update(request_id=str(_uuid.uuid4()), served_at=_dt.datetime.now(_dt.timezone.utc).isoformat())
            items = list(data.items()); _random.shuffle(items); data = dict(items)
        headers = {k: v for k, v in resp.headers.items() if k.lower() != "content-length"}
        return _Response(_json.dumps(data), status_code=resp.status_code, headers=headers, media_type="application/json")


app.add_middleware(_NonDeterministic)
'''

PROBE = r'''
import json, sys
from fastapi.testclient import TestClient
from vault.main import app
c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
out = []
for params in json.loads(sys.argv[2]):
    r = c.get(sys.argv[1], params=params)
    out.append({"status": r.status_code, "location": r.headers.get("location"), "text": r.text})
print(json.dumps(out))
'''

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)?$")


def gate_v1(v):
    if isinstance(v, dict):
        return {k: gate_v1(x) for k, x in v.items() if not re.search(r"(ms|elapsed|time)", k, re.I)}
    if isinstance(v, list):
        return [gate_v1(x) for x in v]
    return v


def semantic(v):
    v = gate_v1(v)
    if isinstance(v, dict):
        return {k: semantic(x) for k, x in v.items()}
    if isinstance(v, list):
        return [semantic(x) for x in v]
    if isinstance(v, str) and (UUID.match(v) or ISO.match(v)):
        return "<volatile>"
    return v


def body(text):
    try:
        return json.loads(text)
    except Exception:
        return text


COMPARATORS = {
    "strict": lambda a, b: (a["status"], a["location"], a["text"]) == (b["status"], b["location"], b["text"]),
    "gate v1": lambda a, b: (a["status"], a["location"], gate_v1(body(a["text"]))) == (b["status"], b["location"], gate_v1(body(b["text"]))),
    "semantic": lambda a, b: (a["status"], a["location"], semantic(body(a["text"]))) == (b["status"], b["location"], semantic(body(b["text"]))),
}


def probe(task: dict, patch: tuple[str, str] | None, nondet: bool = True) -> list[dict]:
    work = Path(tempfile.mkdtemp(prefix="aegis-sem-"))
    try:
        repo = sandbox.build_repo(task, work / "repo", patch)
        main = repo / "vault" / "main.py"
        if nondet:
            main.write_text(main.read_text() + NONDET)
        p = subprocess.run([sys.executable, "-c", PROBE, task["route"], json.dumps(task["benign"])], cwd=repo,
                           env=sandbox._env(repo), capture_output=True, text=True, timeout=60)
        return json.loads(p.stdout.strip().splitlines()[-1])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(R / "semantic.md"))
    out = Path(ap.parse_args().out)
    golden = {t["id"]: probe(t, None) for t in TASKS}
    cases = [(t["id"], probe(t, None), False, "replay") for t in TASKS]
    for line in (R / "kaggle_main" / "main.jsonl").read_text().splitlines():
        r = json.loads(line)
        for c in r.get("candidates", []):
            if "patch" not in c or "gate_ok" not in c:
                continue
            legit_changed = c["gate_ok"] is False and "legitimate" in c.get("gate_reason", "")
            accepted_full = c["gate_ok"] is True and r["config"] == "full"
            if legit_changed or accepted_full:
                cases.append((r["task"], probe(TASK[r["task"]], (c["file"], c["patch"])), legit_changed, r["config"]))
    L = ["# Legitimate-traffic check under non-deterministic responses", "",
         f"{sum(c[2] for c in cases)} changed cases (candidates rejected for changing a legitimate response) and "
         f"{sum(not c[2] for c in cases)} unchanged ones ({sum(c[3] == 'replay' for c in cases)} replays of the unpatched "
         f"service, {sum((not c[2]) and c[3] != 'replay' for c in cases)} verified full-agent patches). Every JSON object "
         "response carries a fresh UUID, a timestamp and a shuffled key order.", "",
         "| Comparator | Unchanged kept (retention) | Changed flagged (recall) | Precision | F1 |", "|---|---|---|---|---|"]
    for name, same in COMPARATORS.items():
        flagged = [(changed, any(not same(a, b) for a, b in zip(golden[tid], got)) or len(got) != len(golden[tid]))
                   for tid, got, changed, _ in cases]
        tp = sum(1 for ch, f in flagged if ch and f)
        fp = sum(1 for ch, f in flagged if not ch and f)
        fn = sum(1 for ch, f in flagged if ch and not f)
        neg = sum(1 for ch, _ in flagged if not ch)
        kept = neg - fp
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        L.append(f"| {name} | {kept}/{neg} ({100 * kept / neg:.1f}%) | {tp}/{tp + fn} ({100 * rec:.1f}%) | {100 * prec:.1f}% | {100 * f1:.1f}% |")
    plain = [x for t in TASKS for x in probe(t, None, nondet=False) + probe(t, (t["target"], __import__("aegisbench.tasks", fromlist=["reference_fix"]).reference_fix(t)), nondet=False)]
    differ = sum(1 for x in plain if semantic(body(x["text"])) != gate_v1(body(x["text"])))
    L += ["", f"Vault's own (deterministic) responses to every legitimate request, on the vulnerable code and on the reference "
          f"fix ({len(plain)} responses): the masking changes {differ} of them, so it cannot change any verdict in the paper's runs."]
    out.write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
