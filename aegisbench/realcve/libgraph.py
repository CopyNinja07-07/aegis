"""A static call graph for real Python packages (methods, classes, relative imports, re-exports).

The AegisBench builder (aegisbench/codegraph.py) only needs module-level functions. Real libraries call
through methods, so this builder adds, with the same AST-only approach:
  nodes   module functions (pkg.mod.f), classes (pkg.mod.C) and methods (pkg.mod.C.m);
  calls   f() / Cls() resolved through local definitions, imports, relative imports and re-exports
          (Cls() also calls Cls.__init__); mod.f() through module aliases;
          self.m() / cls.m() by class-hierarchy analysis (the method found along the bases, plus overrides
          in package subclasses); x.m() where x = Cls(...) or `with Cls() as x` by the inferred class;
          super().m() along the bases; any other receiver links to every package method named m
          (a deliberate over-approximation, reported as such).
Dynamic calls (getattr, callbacks stored in containers) stay invisible, as in any static graph.
"""
from __future__ import annotations

import ast
from pathlib import Path

import networkx as nx


def _mod(rel: str) -> str:
    m = rel[:-3].replace("/", ".")
    return m[: -len(".__init__")] if m.endswith(".__init__") else m


class LibGraph:
    def __init__(self, root: Path, packages: list[str]):
        self.root = root
        self.files = sorted(str(p.relative_to(root)) for pkg in packages for p in (root / pkg).rglob("*.py")
                            if "__pycache__" not in p.parts)
        self.trees = {rel: ast.parse((root / rel).read_text(errors="replace")) for rel in self.files}
        self.g = nx.DiGraph()
        self.aliases: dict[str, dict[str, str]] = {}  # module -> local name -> qualified name
        self.bases: dict[str, list[str]] = {}         # class -> base classes (qualified, in package)
        self.methods: dict[str, list[str]] = {}       # method name -> qualified method nodes
        self.modules = {_mod(rel) for rel in self.files}
        self.unresolved = 0
        self._defs()
        self._calls()

    # ---------- definitions and imports
    def _defs(self) -> None:
        for rel, tree in self.trees.items():
            mod = _mod(rel)
            is_pkg = rel.endswith("__init__.py")
            al = self.aliases.setdefault(mod, {})
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.g.add_node(f"{mod}.{node.name}", file=rel, lines=(node.lineno, node.end_lineno))
                elif isinstance(node, ast.ClassDef):
                    c = f"{mod}.{node.name}"
                    self.g.add_node(c, file=rel, lines=(node.lineno, node.end_lineno), cls=True)
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            m = f"{c}.{item.name}"
                            self.g.add_node(m, file=rel, lines=(item.lineno, item.end_lineno))
                            self.methods.setdefault(item.name, []).append(m)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    base = self._from_base(mod, is_pkg, node)
                    for a in node.names:
                        if a.name != "*":
                            al[a.asname or a.name] = f"{base}.{a.name}" if base else a.name
                elif isinstance(node, ast.Import):
                    for a in node.names:
                        al[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        for rel, tree in self.trees.items():
            mod = _mod(rel)
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    out = []
                    for b in node.bases:
                        q = self._resolve_expr(mod, b)
                        if q and self.g.nodes.get(q, {}).get("cls"):
                            out.append(q)
                    self.bases[f"{mod}.{node.name}"] = out

    @staticmethod
    def _from_base(mod: str, is_pkg: bool, node: ast.ImportFrom) -> str:
        if not node.level:
            return node.module or ""
        parts = mod.split(".")
        pkg = parts if is_pkg else parts[:-1]
        pkg = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
        return ".".join(pkg + ([node.module] if node.module else []))

    def resolve(self, q: str, depth: int = 0) -> str | None:
        """Follow re-exports: pkg.util.parse_url -> pkg.util.url.parse_url."""
        if q in self.g or q in self.modules:
            return q
        if depth > 8 or "." not in q:
            return None
        head, name = q.rsplit(".", 1)
        head = self.resolve(head, depth + 1)
        if head is None:
            return None
        if f"{head}.{name}" in self.g or f"{head}.{name}" in self.modules:
            return f"{head}.{name}"
        target = self.aliases.get(head, {}).get(name)
        return self.resolve(target, depth + 1) if target and target != q else None

    def _resolve_expr(self, mod: str, e: ast.expr) -> str | None:
        if isinstance(e, ast.Name):
            local = f"{mod}.{e.id}"
            if local in self.g:
                return local
            t = self.aliases.get(mod, {}).get(e.id)
            return self.resolve(t) if t else None
        if isinstance(e, ast.Attribute):
            head = self._resolve_expr(mod, e.value)
            return self.resolve(f"{head}.{e.attr}") if head else None
        return None

    # ---------- class hierarchy
    def mro(self, c: str) -> list[str]:
        out, todo = [], [c]
        while todo:
            x = todo.pop(0)
            if x not in out:
                out.append(x)
                todo += self.bases.get(x, [])
        return out

    def subclasses(self, c: str) -> list[str]:
        return [k for k in self.bases if k != c and c in self.mro(k)]

    def lookup(self, c: str, name: str) -> list[str]:
        """Class-hierarchy analysis: the definition along the bases, plus overrides in subclasses."""
        out = []
        for x in self.mro(c):
            if f"{x}.{name}" in self.g:
                out.append(f"{x}.{name}")
                break
        out += [f"{s}.{name}" for s in self.subclasses(c) if f"{s}.{name}" in self.g]
        return out

    def _ctor(self, c: str) -> list[str]:
        return [c] + self.lookup(c, "__init__")

    # ---------- calls
    def _calls(self) -> None:
        for rel, tree in self.trees.items():
            mod = _mod(rel)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._body(mod, f"{mod}.{node.name}", None, node)
                elif isinstance(node, ast.ClassDef):
                    c = f"{mod}.{node.name}"
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self._body(mod, f"{c}.{item.name}", c, item)

    def _body(self, mod: str, src: str, cls: str | None, fn: ast.AST) -> None:
        types: dict[str, str] = {}
        for n in ast.walk(fn):  # local type inference: x = Cls(...), with Cls(...) as x
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                c = self._resolve_expr(mod, n.value.func)
                if c and self.g.nodes.get(c, {}).get("cls"):
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            types[t.id] = c
            elif isinstance(n, ast.withitem) and isinstance(n.context_expr, ast.Call) and isinstance(n.optional_vars, ast.Name):
                c = self._resolve_expr(mod, n.context_expr.func)
                if c and self.g.nodes.get(c, {}).get("cls"):
                    types[n.optional_vars.id] = c
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call):
                continue
            for t in self._targets(mod, cls, call.func, types):
                if t in self.g and t != src:
                    self.g.add_edge(src, t)

    def _targets(self, mod: str, cls: str | None, f: ast.expr, types: dict[str, str]) -> list[str]:
        if isinstance(f, ast.Name):
            q = self._resolve_expr(mod, f)
            if q is None:
                return []
            return self._ctor(q) if self.g.nodes.get(q, {}).get("cls") else [q]
        if not isinstance(f, ast.Attribute):
            return []
        v, name = f.value, f.attr
        if isinstance(v, ast.Name) and v.id in ("self", "cls") and cls:
            hit = self.lookup(cls, name)
            if hit:
                return hit
        if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "super" and cls:
            for b in self.mro(cls)[1:]:
                if f"{b}.{name}" in self.g:
                    return [f"{b}.{name}"]
            return []
        if isinstance(v, ast.Name) and v.id in types:
            return self.lookup(types[v.id], name)
        q = self._resolve_expr(mod, f)
        if q and q in self.g:
            return self._ctor(q) if self.g.nodes[q].get("cls") else [q]
        if name.startswith("__"):
            return []
        self.unresolved += 1
        return list(self.methods.get(name, []))  # unknown receiver: every package method of that name

    # ---------- retrieval
    def files_within(self, entry: str, k: int | None) -> list[str]:
        reached = nx.single_source_shortest_path_length(self.g, entry, cutoff=k)
        out = []
        for n in sorted(reached, key=lambda x: (reached[x], x)):
            if self.g.nodes[n]["file"] not in out:
                out.append(self.g.nodes[n]["file"])
        return out

    def reached(self, entry: str, k: int | None = None) -> dict[str, int]:
        return nx.single_source_shortest_path_length(self.g, entry, cutoff=k)

    def size(self, rels: list[str]) -> int:
        return sum(len((self.root / r).read_text(errors="replace")) for r in rels)

    def function_size(self, nodes) -> int:
        """Characters of just the reached function and method bodies (no enclosing class bodies)."""
        total = 0
        for n in nodes:
            d = self.g.nodes[n]
            if d.get("cls"):
                continue
            lines = (self.root / d["file"]).read_text(errors="replace").splitlines()
            total += sum(len(x) + 1 for x in lines[d["lines"][0] - 1: d["lines"][1]])
        return total
