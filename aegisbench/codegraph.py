"""Orient: a code graph of the repository and the ego-subgraph around an attacked route.

Nodes are functions (module.function). Edges are calls, resolved through imports
("from vault.core import db" then "db.find_customer(...)" -> vault.core.db.find_customer).
Route decorators map an HTTP path to its handler. The context given to the repair
model is the source of the files that hold the handler and everything it reaches
within k call hops: this is the Graph-RAG retrieval that the ablations remove.
"""
from __future__ import annotations

import ast
from pathlib import Path

import networkx as nx


def _module_name(rel: str) -> str:
    return rel[:-3].replace("/", ".")


def build(repo: Path) -> tuple[nx.DiGraph, dict[str, str]]:
    graph = nx.DiGraph()
    routes: dict[str, str] = {}
    files = {str(p.relative_to(repo)): p for p in sorted((repo / "vault").rglob("*.py"))}
    trees = {rel: ast.parse(p.read_text()) for rel, p in files.items()}
    defined: dict[str, set[str]] = {}
    for rel, tree in trees.items():
        mod = _module_name(rel)
        defined[mod] = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defined[mod].add(node.name)
                graph.add_node(f"{mod}.{node.name}", file=rel, kind=type(node).__name__)
    for rel, tree in trees.items():
        mod = _module_name(rel)
        aliases: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    full = f"{node.module}.{a.name}"
                    aliases[a.asname or a.name] = full
            elif isinstance(node, ast.Import):
                for a in node.names:
                    aliases[a.asname or a.name] = a.name
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            src = f"{mod}.{node.name}"
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant):
                    if isinstance(dec.args[0].value, str) and dec.args[0].value.startswith("/"):
                        routes[dec.args[0].value] = src
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                f = call.func
                target = None
                if isinstance(f, ast.Name):
                    if f.id in defined.get(mod, ()):
                        target = f"{mod}.{f.id}"
                    elif f.id in aliases:
                        target = aliases[f.id]
                elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in aliases:
                    target = f"{aliases[f.value.id]}.{f.attr}"
                if target and target in graph:
                    graph.add_edge(src, target)
    return graph, routes


def ego_files(repo: Path, route: str, hops: int = 2) -> list[str]:
    """Files holding the route's handler and every function within `hops` calls of it."""
    graph, routes = build(repo)
    handler = routes.get(route)
    if handler is None:
        return []
    reached = nx.single_source_shortest_path_length(graph, handler, cutoff=hops)
    files = []
    for fn in sorted(reached, key=lambda n: reached[n]):
        rel = graph.nodes[fn]["file"]
        if rel not in files:
            files.append(rel)
    return files


def route_file(repo: Path, route: str) -> list[str]:
    graph, routes = build(repo)
    handler = routes.get(route)
    return [graph.nodes[handler]["file"]] if handler else []


def all_files(repo: Path) -> list[str]:
    return [str(p.relative_to(repo)) for p in sorted((repo / "vault").rglob("*.py")) if p.stat().st_size > 0]


def render(repo: Path, rels: list[str]) -> str:
    """Numbered source for the prompt."""
    out = []
    for rel in rels:
        lines = (repo / rel).read_text().splitlines()
        out.append(f"### File: {rel}\n" + "\n".join(f"{i + 1:3d}| {line}" for i, line in enumerate(lines)))
    return "\n\n".join(out)
