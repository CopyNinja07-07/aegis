"""OODA-Aegis on a real CVE: CVE-2021-33503, ReDoS in urllib3 1.26.4's URL parser (CWE-1333).

  python -m aegisbench.realcve.cves                   # fetch the pinned sources once
  python -m aegisbench.realcve.repair_urllib3 --repair gemma4:e4b --trials 3 \
      --out aegisbench/results/realcve/urllib3_redos.jsonl

The loop is the AegisBench loop on library code:
  OBSERVE  time the real exploit (a URL whose authority holds many '@' and no valid host) against the
           vulnerable parse_url; the oracle is the ReDoS oracle (slower than 1 s);
  ORIENT   rank the functions reachable from the public entry PoolManager.urlopen by BM25 on the alert
           text (slice + BM25, cve_stats.py) and give the model whole functions until 5% of the package's
           code, with each file's module-level statements (imports, compiled patterns);
  DECIDE   the repair model returns the changed top-level definitions, merged by name into the original
           module (splice); Z3 checks the patch clauses of AegisBench (in_scope, api_kept, no_new_sinks, changed);
  ACT      the gate accepts only if the exploit and visible variants each finish within 1 s and every URL
           from urllib3's own test suite (test/test_util.py) parses to exactly the same result as before.
Held-out variants are scored only on accepted patches. JSON: Ollama's MLX runner has no constrained decoding and the
model often leaves regex backslashes unescaped inside JSON strings; this harness (only) repairs such strings before
parsing (lenient_json below) and records how often it did. urllib3's own pytest suite is not run: its package
import fails on Python 3.15 (vendored six), so url.py is loaded on its own (load_url below).
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from aegisbench import agent, guard
from aegisbench.realcve import cves
from aegisbench.realcve.cve_stats import bm25_scores, source
from aegisbench.realcve.libgraph import LibGraph
from aegisbench.splice import splice

REPAIRED = {"n": 0}


def lenient_json(text: str) -> dict:
    """agent.parse_json, then: allow raw control characters, and escape backslashes that start no JSON escape."""
    try:
        return _strict(text)
    except ValueError:
        t = (text or "").strip()
        a, b = t.find("{"), t.rfind("}")
        if a < 0 or b < a:
            raise
        fixed = re.sub(r'\\(?![\\"/bfnrtu])', r"\\\\", t[a:b + 1])
        REPAIRED["n"] += 1
        return json.loads(fixed, strict=False)


_strict = agent.parse_json
agent.parse_json = lenient_json  # Model.chat looks the parser up in its module at call time

CASE = next(c for c in cves.CASES if c["id"] == "urllib3-authority-redos")
TARGET = "urllib3/util/url.py"
SLOW_S = 1.0
BUDGET = 0.05
EXPLOIT = {"url": "https://" + "@" * 12000 + ":a"}
VISIBLE = [{"url": "https://" + "@" * 16000 + "%"}, {"url": "http://" + "a@" * 8000 + "["}]
# Gate v2 (added after inspecting v1's accepted patches, which were all length caps): long legitimate URLs
# (long paths, queries, signatures, userinfo, fragments) must also parse exactly as before, within 1 s.
LONG_LEGIT = ["https://example.com/" + "a" * 6000, "https://example.com/search?q=" + "x" * 9000,
              "https://cdn.example.com/f.png?sig=" + "Ab9" * 3000 + "&exp=1", "https://" + "u" * 3000 + "@example.com/",
              "https://user:" + "p" * 5000 + "@example.com:8443/x", "http://example.com/" + "seg/" * 2000 + "#" + "f" * 3000,
              "https://example.com/a%20b/" + "%41" * 3000]
HELDOUT = [{"url": "https://" + "@" * 20000 + ":x"}, {"url": "ftp://" + "user@" * 4000 + "["},
           {"url": "//" + "@" * 15000 + "%zz"}, {"url": "https://x" + "@:" * 8000 + "["}]

RUN = r'''
import importlib.util, json, sys, time, types
import six
def load(path):
    pkg = types.ModuleType("urllib3"); pkg.__path__ = []
    exc = types.ModuleType("urllib3.exceptions")
    class LocationParseError(ValueError): pass
    exc.LocationParseError = LocationParseError
    pk = types.ModuleType("urllib3.packages"); pk.six = six
    ut = types.ModuleType("urllib3.util"); ut.__path__ = []
    sys.modules.update({"urllib3": pkg, "urllib3.exceptions": exc, "urllib3.packages": pk, "urllib3.util": ut})
    spec = importlib.util.spec_from_file_location("urllib3.util.url", path)
    m = importlib.util.module_from_spec(spec); sys.modules["urllib3.util.url"] = m; spec.loader.exec_module(m)
    return m
m = load(sys.argv[1])
out = []
for url in json.loads(sys.argv[2]):
    t = time.perf_counter()
    try:
        r = m.parse_url(url); res = repr(tuple(r)) + "|" + repr(r.url)
    except Exception as e:
        res = "raises " + type(e).__name__
    out.append({"s": round(time.perf_counter() - t, 3), "result": res})
print(json.dumps(out))
'''


def run(url_py: Path, urls: list[str], timeout: float = 120) -> list[dict] | None:
    try:
        p = subprocess.run([sys.executable, "-I", "-c", RUN, str(url_py), json.dumps(urls)], capture_output=True,
                           text=True, timeout=timeout, cwd=tempfile.gettempdir())
        return json.loads(p.stdout.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return [{"s": 0, "result": "crash"}] * len(urls)


def legit_urls(root: Path) -> list[str]:
    """URL inputs of urllib3's own parse_url tests (test/test_util.py, the three host-map lists)."""
    tree = ast.parse((cves.VENDOR / "urllib3-1.26.4" / "test" / "test_util.py").read_text())
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in
                                                ("parse_url_host_map", "non_round_tripping_parse_url_host_map", "url_vulnerabilities")
                                                for t in node.targets):
            for el in node.value.elts:
                if isinstance(el, ast.Tuple) and isinstance(el.elts[0], ast.Constant) and isinstance(el.elts[0].value, str):
                    out.append(el.elts[0].value)
    return sorted(set(out))


def render(G: LibGraph, chosen: list[str]) -> tuple[str, list[str], int]:
    files = []
    for n in chosen:
        if G.g.nodes[n]["file"] not in files:
            files.append(G.g.nodes[n]["file"])
    parts, shown = [], 0
    for rel in files:
        lines = (G.root / rel).read_text().splitlines()
        keep = set()
        for node in ast.parse("\n".join(lines)).body:
            top = node.name if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else None
            q = f"{rel[:-3].replace('/', '.')}.{top}" if top else None
            if top is None or any(c == q or c.startswith(q + ".") for c in chosen if G.g.nodes[c]["file"] == rel):
                keep.update(range(node.lineno - 1, node.end_lineno))
        parts.append(f"### File: {rel} (module-level code and the retrieved definitions; others omitted)\n"
                     + "\n".join(f"{i + 1:4d}| {lines[i]}" for i in sorted(keep)))
        shown += sum(len(lines[i]) + 1 for i in keep)
    return "\n\n".join(parts), files, shown


def context(G: LibGraph) -> tuple[str, list[str], float]:
    """Slice + BM25 (alert): reachable functions by BM25 score, added while everything shown stays within BUDGET."""
    dist = G.reached(CASE["entry"])
    funcs = [n for n in dist if not G.g.nodes[n].get("cls")]
    docs = {n: n + "\n" + source(G, n) for n in funcs}
    score = bm25_scores(docs, CASE["query_alert"])
    total, chosen = G.size(G.files), []
    for n in sorted(funcs, key=lambda n: (-score[n], dist[n], n)):
        if render(G, chosen + [n])[2] <= BUDGET * total:
            chosen.append(n)
    text, files, shown = render(G, chosen)
    return text, files, shown / total


SYS = ("You are the program-repair model of an autonomous defense agent. A widely used Python library was exploited. "
       "You get parts of its source (line numbers for reference only) and the evidence. Find the root cause and fix it.\n"
       "First state the invariant the fixed code must enforce for EVERY input. Then enforce exactly that, keeping the "
       "result for every legitimate input exactly the same. Blocklists of bad strings or length caps are not acceptable.\n"
       "Return only the top-level definitions you change or add (whole functions, or whole module-level assignments such "
       "as compiled patterns), as Python source without line numbers or markdown; they are merged into the module by name. "
       "Keep every function name and argument. Use only the standard library.")
KEYS = '"file" (repository path of the module you fix), "root_cause", "invariant", "patched_source"'


def evidence(obs_s: float) -> str:
    u = EXPLOIT["url"]
    return (f"Evidence: PoolManager.urlopen() on a client-supplied URL of {len(u)} characters "
            f"({u[:20]!r} ... {u[-4:]!r}: the authority holds {u.count('@')} '@' characters and no valid host) spent "
            f"{obs_s:.1f} s inside urllib3 before raising LocationParseError, blocking the worker (denial of service). "
            "Legitimate URLs are parsed normally.")


def episode(repair: agent.Model, trial: int, work: Path, gate: str = "v2") -> dict:
    G = LibGraph(cves.case_root(CASE), CASE["packages"])
    orig = G.root / TARGET
    legit = legit_urls(G.root) + (LONG_LEGIT if gate == "v2" else [])
    t0 = time.time()
    base = run(orig, [EXPLOIT["url"]])
    obs_s = base[0]["s"] if base else 120.0
    golden = run(orig, legit)
    rec = {"case": CASE["id"], "cve": CASE["cve"], "trial": trial, "repair_model": repair.name, "gate": gate,
           "exploit_s": obs_s, "reproduces": obs_s > SLOW_S, "legit_cases": len(legit)}
    ctx, files, share = context(G)
    rec.update(context_files=files, context_share=round(share, 4), context_has_bug=TARGET in files)
    feedback, cands, tok = "", [], 0
    accepted = None
    for k in range(1, 5):
        user = ctx + "\n\n" + evidence(obs_s) + (f"\n\nYour previous fix failed verification:\n{feedback[-1500:]}" if feedback else "")
        c = {"k": k}
        REPAIRED["n"] = 0
        try:
            out, meta = repair.chat(SYS, user, 4096, agent.TEMPS[(k - 1) % 2], KEYS)
            c["json_repaired"] = REPAIRED["n"] > 0
            tok += meta["prompt_tokens"] or 0
            c["latency_s"] = meta["latency_s"]
        except Exception as exc:
            c["error"] = str(exc)[:200]; cands.append(c); feedback = c["error"]; continue
        rel = str(out.get("file") or "").strip().lstrip("./")
        rel = rel[rel.index("urllib3/"):] if "urllib3/" in rel else rel
        c["file"], c["localized"] = rel, rel == TARGET
        c["invariant"] = str(out.get("invariant") or "")[:400]
        raw = agent.clean_source(str(out.get("patched_source") or ""))
        if not (G.root / rel).is_file():
            c["reject"] = f"file {rel!r} is not in the repository"
        else:
            before = (G.root / rel).read_text()
            src, c["partial"] = splice(before, raw)
            if agent.compiles(src):
                c["reject"] = agent.compiles(src)
            else:
                c["patch"] = src[:20000]
                pg = guard.verify_patch(guard.patch_facts(rel, before, src, files))
                c["phi"] = pg
                if not pg["admit"]:
                    c["reject"] = "Phi_safety: " + pg["reason"]
        if "reject" in c:
            cands.append(c); feedback = c["reject"]; continue
        patched = work / f"t{trial}-c{k}.py"
        patched.write_text(src)
        att = run(patched, [EXPLOIT["url"]] + [v["url"] for v in VISIBLE], timeout=60)
        leg = run(patched, legit, timeout=60)
        slow = None if att is None else [i for i, a in enumerate(att) if a["s"] > SLOW_S]
        diff = None if leg is None else [legit[i] for i, (a, b) in enumerate(zip(leg, golden))
                                         if a["result"] != b["result"] or a["s"] > SLOW_S]
        c["attack_s"] = None if att is None else [a["s"] for a in att]
        c["legit_changed"] = None if diff is None else len(diff)
        ok = att is not None and leg is not None and not slow and not diff
        c["gate_ok"] = ok
        cands.append(c)
        if ok:
            accepted = (src, c); break
        if att is None or slow:
            feedback = f"the attack is still slow: exploit/variants took {c['attack_s'] or 'over 60 s'} (limit {SLOW_S} s)"
        else:
            i = legit.index(diff[0])
            shown = diff[0] if len(diff[0]) < 120 else f"{diff[0][:60]}... ({len(diff[0])} characters)"
            feedback = (f"{len(diff)} legitimate URLs now parse differently, e.g. {shown!r}: before {golden[i]['result'][:200]}, "
                        f"after {leg[i]['result'][:200]}")
    rec.update(candidates=cands, n_candidates=len(cands), tokens_in=tok, verified=bool(accepted))
    if accepted:
        src, c = accepted
        rec["heal_s"] = round(time.time() - t0, 1)
        live = [h for h, r in zip(HELDOUT, run(orig, [h["url"] for h in HELDOUT], timeout=300) or []) if r["s"] > SLOW_S]
        after = run(work / f"t{trial}-c{c['k']}.py", [h["url"] for h in live], timeout=60) or []
        rec["heldout_live"], rec["heldout_safe"] = len(live), sum(1 for a in after if a["s"] <= SLOW_S)
        rec["localized"] = c["localized"]
    return rec


def reference_fix() -> dict:
    """Sanity check of the gate: a fix in the style of urllib3 1.26.5 (split the userinfo at the last '@')."""
    G = LibGraph(cves.case_root(CASE), CASE["packages"])
    s = (G.root / TARGET).read_text()
    s = s.replace('SUBAUTHORITY_RE = re.compile(SUBAUTHORITY_PAT, re.UNICODE | re.DOTALL)\n',
                  'SUBAUTHORITY_RE = re.compile(SUBAUTHORITY_PAT, re.UNICODE | re.DOTALL)\n'
                  '_HOST_PORT_RE = re.compile("^(%s|%s|%s)(?::([0-9]{0,5}))?$" % (REG_NAME_PAT, IPV4_PAT, IPV6_ADDRZ_PAT),\n'
                  '                           re.UNICODE | re.DOTALL)\n')
    s = s.replace('            auth, host, port = SUBAUTHORITY_RE.match(authority).groups()\n',
                  '            if "@" in authority:\n'
                  '                auth, _, host_port = authority.rpartition("@")\n'
                  '            else:\n'
                  '                auth, host_port = None, authority\n'
                  '            host, port = _HOST_PORT_RE.match(host_port).groups()\n')
    f = Path(tempfile.mkdtemp()) / "url.py"
    f.write_text(s)
    legit = legit_urls(G.root) + LONG_LEGIT
    golden, now = run(G.root / TARGET, legit), run(f, legit)
    att = run(f, [EXPLOIT["url"]] + [v["url"] for v in VISIBLE + HELDOUT])
    return {"legit_cases": len(legit), "legit_changed": sum(a["result"] != b["result"] for a, b in zip(now, golden)),
            "attack_s": [a["s"] for a in att]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repair", default="gemma4:e4b")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--out", default="aegisbench/results/realcve/urllib3_redos.jsonl")
    ap.add_argument("--check", action="store_true", help="only verify the gate with the reference fix")
    ap.add_argument("--gate", default="v2", choices=["v1", "v2"], help="v1: urllib3's test URLs; v2: plus long legitimate URLs")
    a = ap.parse_args()
    if a.check:
        r = reference_fix()
        ok = r["legit_changed"] == 0 and max(r["attack_s"]) <= SLOW_S
        print(("CVE-2021-33503 gate OK: " if ok else "CVE-2021-33503 gate FAILED: ") + json.dumps(r))
        raise SystemExit(0 if ok else 1)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    done = {json.loads(l)["trial"] for l in out.read_text().splitlines() if l.strip()} if out.exists() else set()
    work = Path(tempfile.mkdtemp(prefix="aegis-cve-"))
    for trial in range(1, a.trials + 1):
        if trial in done:
            continue
        rec = episode(agent.Model(a.repair), trial, work, a.gate)
        with out.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        print(f"trial {trial}: verified={rec['verified']} cands={rec['n_candidates']} context={rec['context_files']} "
              f"({rec['context_share']:.1%}) exploit {rec['exploit_s']} s", flush=True)


if __name__ == "__main__":
    main()
