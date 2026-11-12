"""Decide: the constrained action policy, checked with the Z3 SMT solver.

Two kinds of action reach production, and each must satisfy Phi_safety before it runs.

1. Edge action (virtual patch). The edge model fills in a rule in a small language
   (contains / max_length / repeated_run). We translate that rule into a Z3 regular
   expression over request URIs and ask Z3 whether ANY string is both matched by the
   rule and inside the protected language (health checks and the recorded legitimate
   request shapes). UNSAT is a proof that the rule can never block protected traffic.
   Concrete checks then confirm it matches the exploit. A raw regex written freely by
   the model cannot be translated, so the unconstrained variant can only be tested on
   samples; that difference is the point of the constrained language.

2. Repair action (code patch). Static facts are extracted from the patch with the AST
   (which file it edits, whether protected checks survive, whether it introduces
   dangerous sinks, whether the module's public API is intact). Phi_safety is a
   propositional formula over those facts; Z3 decides it and returns the violated
   clauses as an audit trail.
"""
from __future__ import annotations

import ast
import re
from urllib.parse import quote

import z3

ENC = {".": "%2e", "/": "%2f", "\\": "%5c", "'": "%27", '"': "%22", " ": "%20", "=": "%3d", "<": "%3c", ">": "%3e",
       ";": "%3b", "-": "%2d", "(": "%28", ")": "%29", "|": "%7c", "&": "%26", "#": "%23", "*": "%2a", ":": "%3a",
       "@": "%40", "$": "%24", "`": "%60", "{": "%7b", "}": "%7d", "%": "%25"}

# ---------------------------------------------------------------- the rule language


def compile_rule(rule: dict) -> tuple[str | None, str]:
    """The rule language compiled to an encoding-aware, non-backtracking PCRE regex for the proxy."""
    kind = rule.get("rule_type")
    param = re.sub(r"[^A-Za-z0-9_]", "", str(rule.get("param") or ""))
    if not param:
        return None, "rule names no query parameter"
    prefix = f"[?&]{param}=[^&]*"
    if kind == "contains":
        subs = [s for s in (rule.get("substrings") or []) if isinstance(s, str) and len(s.strip()) >= 2][:6]
        if not subs:
            return None, "contains rule has no substring of 2+ characters"
        def ch(c):
            if c.lower() in ENC:
                return f"(?:{re.escape(c)}|{ENC[c.lower()]})"
            return re.escape(c)
        body = "|".join("".join(ch(c) for c in s.strip()) for s in subs)
        return f"{prefix}(?:{body})", "ok"
    if kind == "max_length":
        n = int(rule.get("max_length") or 0)
        if not 4 <= n <= 4000:
            return None, "max_length must be between 4 and 4000"
        return f"[?&]{param}=[^&]{{{n + 1},}}", "ok"
    if kind == "repeated_run":
        n = int(rule.get("min_run") or 0)
        if not 4 <= n <= 200:
            return None, "min_run must be between 4 and 200"
        return f"{prefix}([A-Za-z0-9])\\1{{{n - 1},}}", "ok"
    return None, f"unknown rule_type {kind!r}"


def _z3_char_or_enc(c: str):
    opts = [z3.Re(c)]
    if c.lower() in ENC:
        e = ENC[c.lower()]
        opts.append(z3.Re(e))
        opts.append(z3.Re(e.upper()))
    if c.isalpha():
        opts.append(z3.Re(c.swapcase()))
    return opts[0] if len(opts) == 1 else z3.Union(*opts)


def rule_to_z3(rule: dict):
    """The same rule as a Z3 regex over the whole request URI (path?query)."""
    param = re.sub(r"[^A-Za-z0-9_]", "", str(rule.get("param") or ""))
    anything = z3.Star(z3.AllChar(z3.ReSort(z3.StringSort())))
    not_amp = z3.Star(z3.Diff(z3.AllChar(z3.ReSort(z3.StringSort())), z3.Re("&")))
    head = z3.Concat(anything, z3.Union(z3.Re("?"), z3.Re("&")), z3.Re(param + "="))
    kind = rule.get("rule_type")
    if kind == "contains":
        subs = [s.strip() for s in (rule.get("substrings") or []) if isinstance(s, str) and len(s.strip()) >= 2][:6]
        alts = [z3.Concat(*[_z3_char_or_enc(c) for c in s]) if len(s) > 1 else _z3_char_or_enc(s) for s in subs]
        return z3.Concat(head, not_amp, z3.Union(*alts) if len(alts) > 1 else alts[0], anything)
    if kind == "max_length":
        n = int(rule.get("max_length") or 0)
        one = z3.Diff(z3.AllChar(z3.ReSort(z3.StringSort())), z3.Re("&"))
        return z3.Concat(head, z3.Loop(one, n + 1, n + 1), anything)
    if kind == "repeated_run":
        n = int(rule.get("min_run") or 0)
        runs = [z3.Loop(z3.Re(c), n, n) for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]
        return z3.Concat(head, not_amp, z3.Union(*runs), anything)
    raise ValueError("unknown rule")


def protected_language(route: str, benign: list[dict]):
    """URIs that must never be blocked: the health check, and each legitimate request with its values."""
    langs = [z3.Re("/health")]
    for params in benign:
        q = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        langs.append(z3.Re(f"{route}?{q}"))
    return z3.Union(*langs)


def verify_edge_rule(rule: dict, route: str, benign: list[dict], attack_uris: list[str], timeout_ms: int = 4000) -> dict:
    """Phi_safety for an edge action. Returns the verdict and the reason (the audit stamp)."""
    regex, why = compile_rule(rule)
    if regex is None:
        return {"admit": False, "reason": why, "z3": "not_run"}
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    uri = z3.String("uri")
    s.add(z3.InRe(uri, rule_to_z3(rule)), z3.InRe(uri, protected_language(route, benign)))
    verdict = s.check()
    if verdict == z3.sat:
        return {"admit": False, "reason": f"Z3 found a protected request the rule would block: {s.model()[uri]}",
                "z3": "sat", "regex": regex}
    if verdict == z3.unknown:
        return {"admit": False, "reason": "Z3 could not decide within the time limit", "z3": "unknown", "regex": regex}
    compiled = re.compile(regex, re.I)
    missed = [u for u in attack_uris if not compiled.search(u)]
    if missed:
        return {"admit": False, "reason": f"rule does not match the exploit {missed[0][:80]}", "z3": "unsat",
                "regex": regex}
    return {"admit": True, "reason": "proved: no protected request can match; exploit matches", "z3": "unsat",
            "regex": regex}


# ---------------------------------------------------------------- repair action

DANGEROUS = {("eval",), ("exec",), ("pickle", "loads"), ("os", "system"), ("os", "popen"), ("yaml", "load"),
             ("marshal", "loads")}
PROTECTED_CALLS = {"require_same_tenant"}


def _calls(tree) -> set[tuple]:
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                out.add((f.id,))
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                out.add((f.value.id, f.attr))
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                out.add(("shell=True",))
    return out


def _api(tree) -> dict[str, list[str]]:
    return {n.name: [a.arg for a in n.args.args] for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not n.name.startswith("_")}


def patch_facts(rel: str, before: str, after: str, allowed_files: list[str]) -> dict:
    try:
        tb, ta = ast.parse(before), ast.parse(after)
    except SyntaxError as exc:
        return {"parses": False, "error": str(exc)}
    cb, ca = _calls(tb), _calls(ta)
    ab, aa = _api(tb), _api(ta)
    missing = [n for n in ab if n not in aa]
    changed = [n for n in ab if n in aa and aa[n] != ab[n]]
    return {
        "parses": True,
        "api_detail": (f"missing functions: {', '.join(missing)}. " if missing else "")
                      + (f"changed arguments: {', '.join(changed)}. " if changed else ""),
        "new_sinks": sorted(".".join(c) for c in (DANGEROUS | {("shell=True",)}) if c in ca and c not in cb),
        "in_scope": rel in allowed_files,
        "protected_kept": all(any(c[-1] == p for c in ca) for p in PROTECTED_CALLS if any(c[-1] == p for c in cb)),
        "no_new_sinks": not any(c in ca and c not in cb for c in DANGEROUS | {("shell=True",)}),
        "api_kept": all(name in aa and aa[name] == args for name, args in ab.items()),
        "changed": before.strip() != after.strip(),
    }


def verify_patch(facts: dict) -> dict:
    """Phi_safety for a repair action, decided by Z3 with named clauses (unsat core = what was violated)."""
    if not facts.get("parses"):
        return {"admit": False, "violated": ["parses"], "reason": facts.get("error", "does not parse")}
    s = z3.Solver()
    names = ["in_scope", "protected_kept", "no_new_sinks", "api_kept", "changed"]
    vars_ = {n: z3.Bool(n) for n in names}
    for n in names:
        s.add(vars_[n] == z3.BoolVal(bool(facts[n])))
    for n in names:
        s.assert_and_track(vars_[n], f"phi_{n}")
    if s.check() == z3.sat:
        return {"admit": True, "violated": [], "reason": "Phi_safety satisfied"}
    core = [str(c).replace("phi_", "") for c in s.unsat_core()]
    why = {"api_kept": "the module's public functions must all stay, with the same arguments; " + facts.get("api_detail", "")
                       + "Return the COMPLETE file.",
           "protected_kept": "the tenant check require_same_tenant must still be called",
           "no_new_sinks": "the patch adds a dangerous call: " + ", ".join(facts.get("new_sinks", [])),
           "in_scope": "the patch edits a file outside the code reachable from the attacked route",
           "changed": "the file is unchanged"}
    return {"admit": False, "violated": core, "reason": "violates " + ", ".join(core) + ": " + " ".join(why[c] for c in core)}
