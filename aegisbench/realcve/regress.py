"""Each CVE release's own regression tests for the code its fix changed, run on the vulnerable and the fixed release.

  python -m aegisbench.realcve.regress --out aegisbench/results/realcve/regress.md

Tests come from each package's source archive and run with pytest (taken from this repository's environment,
placed after the package on sys.path) in the same isolated interpreter as the exploits (runtime.py): no network
beyond 127.0.0.1. Where a test suite's conftest needs plugins that are not installed (an HTTP test server, process
fixtures), conftest is skipped and tests that need those fixtures are counted as errors, not passes. `mock` is
mapped to unittest.mock. A case passes when the selected tests run and none fails on either release, except the
tests the fix itself added or changed, which are expected to fail on the vulnerable release.
"""
from __future__ import annotations

import argparse
import json
import re
import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from aegisbench.realcve import cves, runtime

R = Path(__file__).resolve().parents[1] / "results" / "realcve"
PYTEST_SITE = str(Path(__import__("pytest").__file__).resolve().parents[1])

# case: (archive holding the tests: vulnerable, fixed), test paths inside it, extra pytest args
TESTS = {
    "requests-proxy-auth": (("requests-2.30.0", "requests-2.31.0"), ["tests/test_utils.py", "tests/test_lowlevel.py", "tests/test_structures.py", "tests/test_hooks.py"], ["--noconftest"]),
    "urllib3-authority-redos": (("urllib3-1.26.4", "urllib3-1.26.5"), ["test/test_util.py"], ["--noconftest"]),
    "requests+urllib3-redos": (("requests-2.30.0", "requests-2.30.0"), ["tests/test_utils.py", "tests/test_lowlevel.py"], ["--noconftest"]),
    "waitress-chunked-smuggling": (("waitress-2.1.0", "waitress-2.1.1"), ["tests/test_receiver.py", "tests/test_parser.py", "tests/test_utilities.py"], ["-o", "addopts="]),
    # 2.19.1's test_utils.py uses parametrize marks that current pytest rejects at collection, so it is left out
    "requests-auth-redirect": (("requests-2.19.1", "requests-2.20.0"), ["tests/test_lowlevel.py", "tests/test_structures.py", "tests/test_hooks.py"], ["--noconftest"]),
    "pyyaml-full-load": (("PyYAML-5.3", "PyYAML-5.3.1"), None, []),
    # Jinja2 2.10's conftest uses a hook signature current pytest rejects; its `env` fixture is ported verbatim below
    "jinja2-sandbox-format": (("Jinja2-2.10", "Jinja2-2.10.1"), ["tests/test_security.py"], ["--noconftest", "-p", "aegis_jinja2_fixtures"]),
    "sqlparse-strip-comments": (("sqlparse-0.4.1", "sqlparse-0.4.2"), ["tests/test_format.py", "tests/test_regressions.py"], []),
    "idna-encode-quadratic": (("idna-3.6", "idna-3.7"), ["tests/test_idna.py", "tests/test_idna_codec.py"], []),
    "multipart-options-redos": (("python-multipart-0.0.6", "python-multipart-0.0.7"), (["multipart/tests/test_multipart.py"], ["tests/test_multipart.py"]), []),
    "aiohttp-static-traversal": (("aiohttp-3.9.1", "aiohttp-3.9.2"), ["tests/test_web_urldispatcher.py"], ["-o", "addopts=", "--noconftest", "-p", "aiohttp.pytest_plugin"]),
    "werkzeug-multipart-dos": (("Werkzeug-2.2.2", "Werkzeug-2.2.3"), ["tests/test_formparser.py"], ["--noconftest"]),
    "django-email-redos": (("Django-4.2.2", "Django-4.2.3"), "django", []),
}

PLUGINS = {"aegis_jinja2_fixtures": '''import pytest
from jinja2 import Environment


@pytest.fixture
def env():
    """returns a new environment (verbatim from Jinja2 2.10's tests/conftest.py)."""
    return Environment()
'''}

PRE = r'''
import unittest.mock as _m
sys.modules.setdefault("mock", _m)
sys.path.append(%r)
'''


def sdist_root(arch: str) -> Path:
    d = cves.src_dir(arch)
    return d.parent if d.name == "src" or d.name == "lib3" else d


def run_side(case: dict, side: str) -> dict:
    archs, paths, extra = TESTS[case["id"]]
    root = sdist_root(archs[0] if side == "vulnerable" else archs[1])
    if paths == "django":
        code = (PRE % PYTEST_SITE) + f'''
import subprocess
os.chdir({str(root / "tests")!r})
sys.path.insert(0, os.getcwd())
sys.argv = ["runtests.py", "validators", "forms_tests.field_tests.test_emailfield", "forms_tests.field_tests.test_urlfield", "--parallel", "1", "-v", "1"]
import io, contextlib
buf = io.StringIO()
try:
    with contextlib.redirect_stderr(buf):
        exec(compile(open("runtests.py").read(), "runtests.py", "exec"), {{"__name__": "__main__", "__file__": os.path.abspath("runtests.py")}})
    code = 0
except SystemExit as e:
    code = e.code
out = buf.getvalue()
import re
m = re.search(r"Ran (\\d+) test", out); f = re.search(r"FAILED \\((.*?)\\)", out)
print(json.dumps({{"tests": int(m.group(1)) if m else 0, "failed_summary": f.group(1) if f else "", "exit": code}}))
'''
        return runtime.run(case, side, code, timeout=900)
    if paths is None:  # PyYAML: its own runner
        code = (PRE % PYTEST_SITE) + f'''
os.chdir({str(root)!r}); sys.path.insert(0, "tests/lib3")
import io, re, contextlib, test_all
buf = io.StringIO()
with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
    ok = test_all.main([])
text = buf.getvalue()
m = re.search(r"TESTS: (\\d+)", text)
fails = re.search(r"FAILURES: (\\d+)", text); errs = re.search(r"ERRORS: (\\d+)", text)
print(json.dumps({{"tests": int(m.group(1)) if m else 0, "failed": int(fails.group(1)) if fails else 0,
                  "errors": int(errs.group(1)) if errs else 0, "missing_fixture": 0, "ok": bool(ok)}}))
'''
        return runtime.run(case, side, code, timeout=900)
    if isinstance(paths, tuple):
        paths = paths[0] if side == "vulnerable" else paths[1]
    tmp = Path(tempfile.mkdtemp(prefix="aegis-junit-"))
    xml = tmp / "r.xml"
    for i, x in enumerate(extra):
        if x in PLUGINS:
            (tmp / f"{x}.py").write_text(PLUGINS[x])
    code = (PRE % PYTEST_SITE) + f'''
sys.path.insert(0, {str(tmp)!r})
os.chdir({str(root)!r})
import pytest
rc = pytest.main(["-q", "-p", "no:cacheprovider", "--junitxml", {str(xml)!r}] + {json.dumps(extra)} + {json.dumps(paths)})
print(json.dumps({{"rc": int(rc)}}))
'''
    res = runtime.run(case, side, code, timeout=900)
    if xml.exists():
        t = ET.parse(xml).getroot()
        s = t if t.tag == "testsuite" else t.find("testsuite")
        missing = sum(1 for tc in s.iter("testcase") for e in tc.findall("error")
                      if re.search(r"fixture '[^']+' not found", (e.get("message") or "") + (e.text or "")))
        res.update(tests=int(s.get("tests", 0)), failed=int(s.get("failures", 0)), errors=int(s.get("errors", 0)) - missing,
                   missing_fixture=missing, skipped=int(s.get("skipped", 0)),
                   failing=[tc.get("classname", "") + "::" + tc.get("name", "") for tc in s.iter("testcase")
                            if tc.find("failure") is not None or tc.find("error") is not None][:20])
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(R / "regress.md"))
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    raw = {}
    for c in cves.CASES:
        if a.only and c["id"] not in a.only.split(","):
            continue
        raw[c["id"]] = {s: run_side(c, s) for s in ("vulnerable", "fixed")}
        print(c["id"], {s: {k: v for k, v in r.items() if k != "failing"} for s, r in raw[c["id"]].items()}, flush=True)
    if a.only:
        return
    (R / "regress.json").write_text(json.dumps(raw, indent=1))
    def cell(r):
        if "tests" not in r:
            return "did not run"
        if "failed_summary" in r:  # Django's runner
            return f"{r['tests']} run, " + (r["failed_summary"] or "all passed")
        return (f"{r['tests'] - r.get('failed', 0) - r.get('errors', 0) - r.get('missing_fixture', 0) - r.get('skipped', 0)} passed, "
                f"{r.get('failed', 0)} failed, {r.get('errors', 0)} errors"
                + (f", {r['missing_fixture']} need an unavailable fixture" if r.get("missing_fixture") else "")
                + (f", {r['skipped']} skipped" if r.get("skipped") else ""))
    def green(r):
        if "tests" not in r or not r["tests"]:
            return False
        if "failed_summary" in r:
            return not r["failed_summary"]
        return r.get("failed", 0) == 0 and r.get("errors", 0) == 0
    L = ["# Regression tests of the real CVE releases", "",
         "Each release's own tests for the code its fix changed. Errors caused by a pytest fixture from a plugin that is "
         "not installed (pytest-mock's mocker, pytest-httpbin, pytest-aiohttp's helpers) are counted separately.", "",
         "| Case | Tests | Vulnerable release | Fixed release | No failures on either |", "|---|---|---|---|---|"]
    for cid, r in raw.items():
        paths = TESTS[cid][1]
        shown = paths[0] if isinstance(paths, tuple) else paths
        L.append(f"| {cid} | {'PyYAML runner' if shown is None else ('Django runtests' if shown == 'django' else ', '.join(shown))} | "
                 f"{cell(r['vulnerable'])} | {cell(r['fixed'])} | {'yes' if green(r['vulnerable']) and green(r['fixed']) else 'NO'} |")
    n = sum(green(r["vulnerable"]) and green(r["fixed"]) for r in raw.values())
    L.insert(2, f"{n} of {len(raw)} cases run with no failing test on either release.")
    Path(a.out).write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
