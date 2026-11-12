"""AST splice editing: merge a model's partial file into the original by top-level name.

Small models often return only the function they changed, dropping imports and the
rest of the module. We always start from the original file and replace, by name, each top-level function, class or assignment
the patch defines; new definitions and new imports are added. The result is then
checked like any other candidate (compile, Phi_safety, gate).
"""
from __future__ import annotations

import ast


def _names(node) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def _segment(lines: list[str], node) -> list[str]:
    start = min([d.lineno for d in getattr(node, "decorator_list", [])] + [node.lineno]) - 1
    return lines[start:node.end_lineno]


def splice(original: str, patched: str) -> tuple[str, bool]:
    try:
        to, tp = ast.parse(original), ast.parse(patched)
    except SyntaxError:
        return patched, False
    orig_top = {nm for n in to.body for nm in _names(n)} | {ast.unparse(n) for n in to.body if isinstance(n, (ast.Import, ast.ImportFrom))}
    patch_top = {nm for n in tp.body for nm in _names(n)} | {ast.unparse(n) for n in tp.body if isinstance(n, (ast.Import, ast.ImportFrom))}
    partial = not orig_top <= patch_top  # the model left out imports or definitions
    ol, pl = original.splitlines(), patched.splitlines()
    replacements, additions, new_imports = {}, [], []
    orig_imports = {ast.unparse(n) for n in to.body if isinstance(n, (ast.Import, ast.ImportFrom))}
    by_name = {nm: n for n in to.body for nm in _names(n)}
    for node in tp.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if ast.unparse(node) not in orig_imports:
                new_imports.append(ast.unparse(node))
            continue
        names = _names(node)
        if not names:
            continue
        target = next((by_name[n] for n in names if n in by_name), None)
        if target is not None:
            replacements[id(target)] = (target, _segment(pl, node))
        else:
            additions.append(_segment(pl, node))
    out, i = [], 0
    spans = sorted(((min([d.lineno for d in getattr(t, "decorator_list", [])] + [t.lineno]) - 1, t.end_lineno, seg)
                    for t, seg in replacements.values()), key=lambda x: x[0])
    for start, end, seg in spans:
        out.extend(ol[i:start])
        out.extend(seg)
        i = end
    out.extend(ol[i:])
    last_import = max([n.end_lineno for n in to.body if isinstance(n, (ast.Import, ast.ImportFrom))], default=0)
    shift = sum((len(seg) - (end - start)) for start, end, seg in spans if start < last_import)
    pos = last_import + shift
    if new_imports:
        out[pos:pos] = new_imports
    for seg in additions:
        out.extend(["", ""] + seg)
    return "\n".join(out).rstrip() + "\n", partial
