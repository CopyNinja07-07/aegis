"""Build a task's repository and run the agent-built verification gate on it.

The gate is written by the agent, not the model:
  phase v1 (original code): record golden answers for legitimate requests, and
      require the production exploit to still succeed (the harness reproduces it);
  phase v2 (candidate patch): the exploit and every visible red-team variant must
      come back safe within HANG_S, every legitimate request must return exactly
      the same JSON (timing fields ignored), and the service's own tests must pass.
The model's own reproduction test is run separately and is advisory only.
Code runs from a short path (stage) in a subprocess with a timeout.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICE = HERE / "service"

HARNESS = r'''"""Written by OODA-Aegis: replays attacks and legitimate traffic against this folder."""
import json, os, re, sys, threading, time
import pytest
from fastapi.testclient import TestClient
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aegis_oracle import is_safe
from vault.main import app

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = json.load(open(os.path.join(HERE, "aegis_cases.json")))
GOLDEN = os.path.join(HERE, "aegis_golden.json")
client = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
HANG_S = 2.5


def call(params):
    box = {}
    def run():
        t = time.perf_counter()
        try:
            box["r"] = client.get(CASES["path"], params=params)
        except Exception as exc:
            box["error"] = repr(exc)
        box["ms"] = (time.perf_counter() - t) * 1000
    w = threading.Thread(target=run, daemon=True); w.start(); w.join(HANG_S)
    if w.is_alive():
        return None, HANG_S * 1000
    assert "error" not in box, f"the service crashed: {box.get('error')}"
    return box["r"], box["ms"]


VOLATILE = re.compile(r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                      r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)?)$", re.I)


def stable(v):
    """Semantic view: key order and timing keys ignored, UUID and ISO-8601 timestamp values masked."""
    if isinstance(v, dict):
        return {k: stable(x) for k, x in v.items() if not re.search(r"(ms|elapsed|time)", k, re.I)}
    if isinstance(v, list):
        return [stable(x) for x in v]
    if isinstance(v, str) and VOLATILE.match(v):
        return "<volatile>"
    return v


def view(r):
    try:
        body = r.json()
    except Exception:
        body = r.text
    return {"status": r.status_code, "location": r.headers.get("location"), "body": stable(body)}


def test_record_golden_responses():
    if os.path.exists(GOLDEN):
        pytest.skip("golden already recorded")
    golden = {}
    for case in CASES["benign"]:
        r, _ = call(case["params"])
        assert r is not None and r.status_code < 500, f"legitimate request failed on the original code: {case}"
        golden[case["id"]] = view(r)
    json.dump(golden, open(GOLDEN, "w"), indent=1)


@pytest.mark.parametrize("case", CASES["attacks"], ids=[c["id"] for c in CASES["attacks"]])
def test_attack_is_neutralised(case):
    r, ms = call(case["params"])
    assert r is not None, f"request hung for more than {HANG_S}s (denial of service)"
    ok, hits = is_safe(r.status_code, r.text, dict(r.headers), ms, case["params"])
    assert ok, f"unsafe response (HTTP {r.status_code}): {', '.join(hits)}"


@pytest.mark.parametrize("case", CASES["benign"], ids=[c["id"] for c in CASES["benign"]])
def test_legitimate_traffic_unchanged(case):
    golden = json.load(open(GOLDEN))
    r, _ = call(case["params"])
    assert r is not None, "legitimate request hung"
    assert view(r) == golden[case["id"]], "legitimate response changed after the patch"
'''

PROBE = r'''
import json, sys, time
from fastapi.testclient import TestClient
from vault.main import app
path, params = sys.argv[1], json.loads(sys.argv[2])
c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
t = time.perf_counter(); r = c.get(path, params=params); ms = (time.perf_counter() - t) * 1000
print(json.dumps({"status": r.status_code, "duration_ms": round(ms, 1), "sample": r.text[:600],
                  "location": r.headers.get("location")}))
'''


def build_repo(task: dict, dest: Path, patch: tuple[str, str] | None = None) -> Path:
    """Copy the service, plant the task's bug, optionally apply a patch (file, new source)."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(SERVICE, dest, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc", "data"))
    (dest / "data").mkdir()
    subprocess.run([sys.executable, str(dest / "seed_db.py"), str(dest / "data" / "vault.db")], check=True,
                   capture_output=True)
    (dest / task["target"]).write_text(task["vulnerable"])
    if task.get("depth", 1) > 1:  # AegisBench-Deep: move the bug further from the route
        from aegisbench.deep import deepen
        deepen(dest, task, task["depth"])
    if patch:
        rel, src = patch
        (dest / rel).write_text(src)
    return dest


def repo_files(repo: Path) -> dict[str, str]:
    return {str(p.relative_to(repo)): p.read_text() for p in sorted((repo / "vault").rglob("*.py"))}


def _env(stage: Path) -> dict:
    return {**os.environ, "PYTHONPATH": str(stage), "APP_ROOT": str(stage), "PYTHONDONTWRITEBYTECODE": "1"}


def _stage(src: Path, stage: Path) -> None:
    if stage.exists():
        shutil.rmtree(stage)
    shutil.copytree(src, stage)


def probe(repo: Path, stage: Path, path: str, params: dict, timeout: int = 20) -> dict:
    """Send one request to the code in `repo` and return what came back (status, sample, location, ms)."""
    _stage(repo, stage)
    try:
        out = subprocess.run([sys.executable, "-c", PROBE, path, json.dumps(params)], cwd=stage, env=_env(stage),
                             capture_output=True, text=True, timeout=timeout)
        return json.loads(out.stdout.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        return {"status": 0, "duration_ms": timeout * 1000.0, "sample": "", "location": None, "timeout": True}
    except Exception as exc:  # crashed probe: report as a server error
        return {"status": 500, "duration_ms": 0, "sample": repr(exc)[:300], "location": None}


def _parse_junit(path: Path) -> tuple[dict, list]:
    counts, tests = {"passed": 0, "failed": 0, "skipped": 0}, []
    if not path.exists():
        return counts, tests
    for case in ET.parse(path).getroot().iter("testcase"):
        outcome, msg = "passed", ""
        for child in case:
            if child.tag in ("failure", "error"):
                outcome, msg = "failed", (child.get("message") or "")[:300]
            elif child.tag == "skipped":
                outcome = "skipped"
        counts[outcome] += 1
        tests.append({"name": f"{case.get('classname', '').split('.')[-1]}::{case.get('name')}", "outcome": outcome,
                      "message": msg})
    return counts, tests


def run_pytest(folder: Path, stage: Path, targets: list[str], timeout: int) -> dict:
    _stage(folder, stage)
    junit = stage / "report.xml"
    args = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--timeout=20", "--timeout-method=thread",
            "--junitxml=report.xml", *targets]
    try:
        proc = subprocess.run(args, cwd=stage, env=_env(stage), capture_output=True, text=True, timeout=timeout)
        code, output = proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        code, output = 124, f"timed out after {timeout}s"
    counts, tests = _parse_junit(junit)
    for name in ("aegis_golden.json",):
        if (stage / name).exists():
            shutil.copy(stage / name, folder / name)
    if not tests and code != 0:
        counts, tests = {"passed": 0, "failed": 1, "skipped": 0}, [{"name": "pytest session", "outcome": "failed",
                                                                      "message": output[-300:]}]
    return {"passed": code == 0 and counts["failed"] == 0, "counts": counts, "tests": tests, "output": output[-3000:]}


def _prepare(folder: Path, cases: dict, model_test: str | None = None) -> None:
    (folder / "aegis_cases.json").write_text(json.dumps(cases, indent=1))
    (folder / "test_aegis_harness.py").write_text(HARNESS)
    shutil.copy(HERE / "oracle.py", folder / "aegis_oracle.py")
    if model_test:
        (folder / "test_model_repro.py").write_text(model_test)


def cases_for(task: dict, attacks: list[dict]) -> dict:
    return {"path": task["route"],
            "attacks": [{"id": a["id"], "params": a["params"]} for a in attacks],
            "benign": [{"id": f"benign-{i + 1}", "params": p} for i, p in enumerate(task["benign"])]}


def visible_attacks(task: dict) -> list[dict]:
    return [{"id": "original", "params": task["exploit"]}] + [{"id": f"visible-{i + 1}", "params": p}
                                                             for i, p in enumerate(task["visible"])]


def heldout_attacks(task: dict) -> list[dict]:
    return [{"id": f"heldout-{i + 1}", "params": p} for i, p in enumerate(task["heldout"])]


class Gate:
    """Phase v1 is computed once per task; phase v2 once per candidate."""

    def __init__(self, task: dict, work: Path, stage: Path, extra_attacks: list[dict] | None = None):
        self.task, self.work, self.stage = task, work, stage
        self.attacks = visible_attacks(task) + (extra_attacks or [])
        self.cases = cases_for(task, self.attacks)
        v1 = build_repo(task, work / "v1")
        _prepare(v1, self.cases)
        rec = run_pytest(v1, stage, ["test_aegis_harness.py::test_record_golden_responses"], 90)
        self.golden_ok = rec["passed"]
        repro = run_pytest(v1, stage, ["test_aegis_harness.py::test_attack_is_neutralised[original]"], 60)
        self.reproduces = not repro["passed"]
        self.golden = (v1 / "aegis_golden.json").read_text() if (v1 / "aegis_golden.json").exists() else None

    def check(self, rel: str, source: str, tag: str, model_test: str | None = None,
              attacks: list[dict] | None = None) -> dict:
        cases = self.cases if attacks is None else cases_for(self.task, attacks)
        v2 = build_repo(self.task, self.work / tag, (rel, source))
        _prepare(v2, cases, model_test)
        if self.golden:
            (v2 / "aegis_golden.json").write_text(self.golden)
        gate = run_pytest(v2, self.stage, ["test_aegis_harness.py", "tests"], 180)
        advisory = run_pytest(v2, self.stage, ["test_model_repro.py"], 60) if model_test and model_test.strip() else None
        failed = [t for t in gate["tests"] if t["outcome"] == "failed"]
        reason = "ok" if gate["passed"] else "; ".join(f"{t['name']}: {t['message']}" for t in failed[:4]) or "failed"
        return {"ok": bool(self.reproduces and gate["passed"]), "reason": reason, "counts": gate["counts"],
                "tests": gate["tests"], "output": gate["output"],
                "model_test_passed": advisory["passed"] if advisory else None}
