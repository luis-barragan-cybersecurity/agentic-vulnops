"""The call-and-import syntax layer of the blast-radius pass (ticket 28).

Binds every in-tree call in the already-parsed allowlisted tree to the one top-level
definition it names, through per-file import resolution — ``import a.b as c``, ``from m
import x [as y]``, relative levels, ``from .m import *`` re-exports, and namespace packages
without ``__init__.py`` — rather than name matching, because the fixture really does hold
two unrelated ``update_menu_item`` definitions and a name-only index conflates them.

A call this pass cannot bind is an `UnresolvedEdge` carrying its reason: every instance is
a completeness gap the reach must surface, never a silent zero. A call into fastapi,
sqlalchemy, the stdlib, or a builtin is not represented at all — an out-of-tree callee has
no in-tree body whose change could ripple back. Only call edges are recorded; ``Depends(f)``
passes ``f`` as an argument, not as ``ast.Call.func``, so a reference is structurally
excluded. This module knows nothing about routes, findings, or policy.
"""

from __future__ import annotations

import ast
import builtins
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from ave.adapters.python_authz.inventory import ParsedTree

UnresolvedReason = Literal[
    "receiver_type_unknown",
    "attribute_not_in_module",
    "unbound_name",
    "callee_is_expression",
]

_BUILTINS = frozenset(dir(builtins))

#: A module-scope name binding: what a bare name means in one file. `kind` is ``def`` (an
#: in-tree top-level definition, target ``file:symbol``), ``module`` (an in-tree module,
#: target its rel path), ``external`` (out of tree), or ``unbound`` (a re-export that never
#: resolved).
_Binding = tuple[str, str | None]


@dataclass(frozen=True)
class ResolvedEdge:
    """One call bound to exactly one in-tree top-level definition."""

    caller_file: str
    caller_symbol: str  # enclosing def name, or "<module>"
    line: int
    callee: str  # ``file:symbol``


@dataclass(frozen=True)
class UnresolvedEdge:
    """One in-tree call this pass could not bind — every instance is a completeness gap."""

    caller_file: str
    caller_symbol: str
    line: int
    callee_name: str
    reason: UnresolvedReason


@dataclass(frozen=True)
class CallGraph:
    """Three maps, one per access pattern the reach needs — no fourth index later."""

    by_callee: Mapping[str, tuple[ResolvedEdge, ...]]
    unresolved_by_name: Mapping[str, tuple[UnresolvedEdge, ...]]
    top_level_defs: frozenset[str]


def build_call_graph(trees: Sequence[ParsedTree], *, app_root: str) -> CallGraph:
    """Bind every in-tree call across `trees`. `app_root` is the repo-relative allowlist
    root (``allow.rel(allow.root)``); module names are derived against it. Ported from the
    verified ticket-28 prototype (`reach_proto.py`)."""
    index = _Index(trees, app_root)
    resolved, unresolved = index.edges()

    by_callee: dict[str, list[ResolvedEdge]] = defaultdict(list)
    for edge in resolved:
        by_callee[edge.callee].append(edge)
    by_name: dict[str, list[UnresolvedEdge]] = defaultdict(list)
    for gap in unresolved:
        by_name[gap.callee_name].append(gap)

    return CallGraph(
        by_callee={
            callee: tuple(sorted(edges, key=lambda e: (e.caller_file, e.line)))
            for callee, edges in by_callee.items()
        },
        unresolved_by_name={
            name: tuple(sorted(gaps, key=lambda e: (e.caller_file, e.line)))
            for name, gaps in by_name.items()
        },
        top_level_defs=frozenset(
            symbol for defs in index.defs.values() for symbol in defs.values()
        ),
    )


def _module_of(rel: str, app_root: str) -> str:
    prefix = app_root + "/"
    assert rel.startswith(prefix), rel
    dotted = rel[len(prefix) : -3].replace("/", ".")
    # The allowlist-root package is the empty module, not "__init__"; removesuffix
    # only strips the dotted form used by nested packages.
    if dotted == "__init__":
        return ""
    return dotted.removesuffix(".__init__")


def _enclosing_defs(tree: ast.Module) -> dict[int, str]:
    """Map each source line to the def that encloses it; later (inner) defs win."""
    lines: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for line in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                lines[line] = node.name
    return lines


class _Index:
    """Per-file module-scope bindings over the whole tree, then one edge pass per file."""

    def __init__(self, trees: Sequence[ParsedTree], app_root: str) -> None:
        self._app_root = app_root
        self._trees: dict[str, ast.Module] = {parsed.rel: parsed.tree for parsed in trees}
        self._by_module: dict[str, str] = {
            _module_of(rel, app_root): rel for rel in self._trees
        }
        self.defs: dict[str, dict[str, str]] = {}
        for rel, tree in self._trees.items():
            self.defs[rel] = {
                node.name: f"{rel}:{node.name}"
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            }
        self._bindings: dict[str, dict[str, _Binding]] = {
            rel: self._bind(rel, set()) for rel in self._trees
        }

    def _resolve_module(self, rel: str, node: ast.ImportFrom) -> str:
        if not node.level:
            return node.module or ""
        name = _module_of(rel, self._app_root)
        # "".split(".") is [""], which would join to ".foo" for a root-relative import.
        pkg = name.split(".") if name else []
        if not rel.endswith("__init__.py"):
            pkg = pkg[:-1]
        if node.level > 1:
            pkg = pkg[: len(pkg) - (node.level - 1)]
        return ".".join(pkg + ([node.module] if node.module else []))

    def _exports(self, rel: str, seen: set[str]) -> dict[str, _Binding]:
        """What ``from <rel-module> import *`` brings in: its defs plus its re-exports."""
        if rel in seen:
            return {}
        return {
            name: binding
            for name, binding in self._bind(rel, seen | {rel}).items()
            if not name.startswith("_")
        }

    def _bind(self, rel: str, seen: set[str]) -> dict[str, _Binding]:
        # Walk body order so a later local def/class wins over an earlier import of
        # the same name, matching Python. Preloading defs first inverted that.
        bindings: dict[str, _Binding] = {}
        for node in self._trees[rel].body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bindings[node.name] = ("def", self.defs[rel][node.name])
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    # `import a.b` binds `a` to package `a`; `import a.b as c` binds `c`
                    # to module `a.b`.
                    module_name = alias.name if alias.asname else local
                    target = self._by_module.get(module_name)
                    bindings[local] = ("module", target) if target else ("external", None)
            elif isinstance(node, ast.ImportFrom):
                mod = self._resolve_module(rel, node)
                mod_rel = self._by_module.get(mod)
                for alias in node.names:
                    if alias.name == "*":
                        if mod_rel:
                            bindings.update(self._exports(mod_rel, seen))
                        continue
                    local = alias.asname or alias.name
                    sub = self._by_module.get(f"{mod}.{alias.name}" if mod else alias.name)
                    if mod_rel is None:
                        # A namespace package (no __init__.py) has no defs of its own;
                        # only a submodule can bind.
                        bindings[local] = ("module", sub) if sub else ("external", None)
                        continue
                    if alias.name in self.defs[mod_rel]:
                        bindings[local] = ("def", self.defs[mod_rel][alias.name])
                    elif sub:
                        bindings[local] = ("module", sub)
                    else:
                        # A re-export through the module's own bindings — one hop,
                        # cycle-guarded by `seen`.
                        inner = (
                            self._bind(mod_rel, seen | {rel})
                            if mod_rel not in seen
                            else {}
                        )
                        bindings[local] = inner.get(alias.name, ("unbound", None))
        return bindings

    def edges(self) -> tuple[list[ResolvedEdge], list[UnresolvedEdge]]:
        resolved: list[ResolvedEdge] = []
        unresolved: list[UnresolvedEdge] = []
        for rel, tree in self._trees.items():
            file_resolved, file_unresolved = self._file_edges(rel, tree)
            resolved.extend(file_resolved)
            unresolved.extend(file_unresolved)
        return resolved, unresolved

    def _file_edges(
        self, rel: str, tree: ast.Module
    ) -> tuple[list[ResolvedEdge], list[UnresolvedEdge]]:
        enclosing = _enclosing_defs(tree)
        binds = self._bindings[rel]
        resolved: list[ResolvedEdge] = []
        unresolved: list[UnresolvedEdge] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            caller = enclosing.get(node.lineno, "<module>")
            func = node.func
            if isinstance(func, ast.Name):
                kind, target = binds.get(func.id, (None, None))
                if kind == "def" and target is not None:
                    resolved.append(ResolvedEdge(rel, caller, node.lineno, target))
                elif kind not in ("external", "module") and func.id not in _BUILTINS:
                    unresolved.append(
                        UnresolvedEdge(rel, caller, node.lineno, func.id, "unbound_name")
                    )
            elif isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name):
                    kind, target = binds.get(func.value.id, (None, None))
                    if kind == "module" and target is not None:
                        bound = self.defs[target].get(func.attr)
                        if bound is None:
                            inner = self._bindings[target].get(func.attr)
                            if inner is not None and inner[0] == "def":
                                bound = inner[1]
                        if bound is not None:
                            resolved.append(ResolvedEdge(rel, caller, node.lineno, bound))
                        else:
                            unresolved.append(
                                UnresolvedEdge(
                                    rel,
                                    caller,
                                    node.lineno,
                                    func.attr,
                                    "attribute_not_in_module",
                                )
                            )
                        continue
                    if kind == "external":
                        continue
                unresolved.append(
                    UnresolvedEdge(
                        rel, caller, node.lineno, func.attr, "receiver_type_unknown"
                    )
                )
            else:
                unresolved.append(
                    UnresolvedEdge(
                        rel, caller, node.lineno, "<expr>", "callee_is_expression"
                    )
                )
        return resolved, unresolved
