"""AegisBench-Deep: the same 16 bugs, moved further from the route.

In AegisBench every vulnerable helper is one call hop from its route handler. This module
inserts `depth - 1` pass-through layers (service, policy, adapter, gateway) between the route
and the vulnerable module, so the bug sits `depth` call hops away. The vulnerable code, the
exploit, the variants and the legitimate requests are unchanged; only the distance grows.

  sandbox.build_repo calls deepen() when a task carries a "depth" key (see deep_tasks()).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

LAYERS = [("services", "service", "Service layer: request-level orchestration."),
          ("policies", "policy", "Policy layer: business rules applied before storage access."),
          ("adapters", "adapter", "Adapter layer: translates domain calls to infrastructure calls."),
          ("gateways", "gateway", "Gateway layer: last stop before the core helpers.")]
MAX_DEPTH = len(LAYERS) + 1


def _wrapper(fn: ast.FunctionDef, nxt: str) -> str:
    a = fn.args
    call = [x.arg for x in a.posonlyargs + a.args]
    if a.vararg:
        call.append("*" + a.vararg.arg)
    call += [f"{x.arg}={x.arg}" for x in a.kwonlyargs]
    if a.kwarg:
        call.append("**" + a.kwarg.arg)
    ret = f" -> {ast.unparse(fn.returns)}" if fn.returns else ""
    return f"def {fn.name}({ast.unparse(a)}){ret}:\n    return {nxt}.{fn.name}({', '.join(call)})\n"


def deepen(repo: Path, task: dict, depth: int) -> None:
    if depth <= 1:
        return
    if depth > MAX_DEPTH:
        raise ValueError(f"depth {depth} > {MAX_DEPTH}")
    mod = Path(task["target"]).stem
    funcs = [n for n in ast.parse(task["vulnerable"]).body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")]
    used = LAYERS[:depth - 1]
    for i, (pkg, suffix, doc) in enumerate(used):
        if i + 1 < len(used):
            npkg, nsuffix, _ = used[i + 1]
            imp, nxt = f"from vault.{npkg} import {mod}_{nsuffix} as nxt", "nxt"
        else:
            imp, nxt = f"from vault.core import {mod}", mod
        d = repo / "vault" / pkg
        d.mkdir(exist_ok=True)
        (d / "__init__.py").touch()
        body = "\n\n".join(_wrapper(f, nxt) for f in funcs)
        (d / f"{mod}_{suffix}.py").write_text(f'"""{doc}"""\n{imp}\n\n\n{body}')
    pkg, suffix, _ = used[0]
    for route_file in sorted((repo / "vault" / "routes").glob("*.py")):
        src = route_file.read_text()
        m = re.search(r"^from vault\.core import (.+)$", src, re.M)
        if not m:
            continue
        names = [x.strip() for x in m.group(1).split(",")]
        if mod not in names:
            continue
        rest = [x for x in names if x != mod]
        repl = (f"from vault.core import {', '.join(rest)}\n" if rest else "") + f"from vault.{pkg} import {mod}_{suffix} as {mod}"
        route_file.write_text(src[:m.start()] + repl + src[m.end():])


def deep_tasks(depth: int, tasks: list[dict] | None = None) -> list[dict]:
    from aegisbench.tasks import TASKS
    return [{**t, "depth": depth} for t in (tasks or TASKS)]
