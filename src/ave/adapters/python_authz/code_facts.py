"""The code-facts store and the typed tools the find stage reaches it through.

This is the deterministic layer's public face. The inventory pass (`inventory`) and the
pre-filter (`prefilter`) produce facts; this module holds them as a **per-run store** and
serves them through a **small, typed surface** — a lookup, a filter, a source reader, a
model reader, a caller index — scoped to the ownership invariant, not a general toolbox
(find-stage design, decision 3; ticket 23). The LLM finder (ticket 25) will plan its
retrieval through exactly these calls, one candidate at a time; the blast-radius pass
(ticket 28) is a second query against the same store, not a second analyzer.

Two properties the store guarantees, both structural rather than prompted:

* **The store is JSON behind the interface.** Every query is a lookup or filter over ~two
  dozen records; the backing format is swappable (a database is earned by cross-run history,
  parallel workers, or a target too large for memory — none yet). Callers depend on the
  tools, never the format.
* **Source is served through the allowlist, comments stripped.** `get_source` and
  `model_definition` read only files the stage's `ScanAllowlist` permits — the answer key is
  unreachable — and strip ``#`` comments on the way out, closing the last leak channel a
  GPL-§5 change-mark's *presence* left open (ticket 22's residual). The AST facts never
  needed comments, so nothing is lost.
"""

from __future__ import annotations

import ast
import io
import json
import tokenize
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ave.adapters.python_authz.allowlist import ScanAllowlist, finder_allowlist
from ave.adapters.python_authz.inventory import (
    Inventory,
    InventoryRecord,
    ModelFacts,
    build_inventory,
)
from ave.adapters.python_authz.prefilter import Screen, ScreenResult, screen_inventory

STORE_FILENAME = "code-facts.json"
#: The store format version — bumped if the on-disk shape changes, so a persisted store is
#: never silently misread by a newer reader.
STORE_VERSION = 1


class HandlerNotFound(KeyError):
    """No handler with the requested id — the model cited a record that does not exist, and
    a citation that does not resolve is rejected, not guessed at."""


@dataclass(frozen=True)
class CallSite:
    """One place a symbol is called: the file, the enclosing def, and the line. Lets the
    find stage follow a handler into the helper that performs its query (the I-08 shape,
    where the mutation is one call away from the route)."""

    file: str
    caller_symbol: str
    line: int


@dataclass(frozen=True)
class ModelDefinition:
    """A model's owner-column facts and its source, comments stripped — what the model reads
    to see which columns bind a row to a user."""

    facts: ModelFacts
    source: str


@dataclass(frozen=True)
class Coverage:
    """The coverage denominator: handlers found versus handlers judged. Carried into the run
    record so a finding report can say "examined N of M handlers" rather than implying full
    coverage. Judged = the candidates a model call is (or would be) spent on — everything the
    pre-filter did not drop by arithmetic."""

    found: int
    judged: int
    dropped: int
    by_screen: dict[str, int]

    def summary(self) -> str:
        return f"examined {self.judged} of {self.found} handlers"

    def to_dict(self) -> dict[str, Any]:
        return {
            "found": self.found,
            "judged": self.judged,
            "dropped": self.dropped,
            "by_screen": dict(self.by_screen),
            "summary": self.summary(),
        }


def strip_comments(source: str) -> str:
    """Return `source` with ``#`` comments removed, line numbers preserved. Uses the
    tokenizer, so a ``#`` inside a string literal is untouched; docstrings (string
    expressions, not comments) are left in place. The channel this closes is the change-mark
    comment, not the code."""
    tokens = [
        tok
        for tok in tokenize.generate_tokens(io.StringIO(source).readline)
        if tok.type != tokenize.COMMENT
    ]
    return tokenize.untokenize(tokens)


@dataclass(frozen=True)
class CodeFactsStore:
    """The per-run code-facts store. Built once by the deterministic pass, then queried
    through the typed tools below. Holds the inventory, the pre-filter screens, and the
    allowlist every source read is funnelled through."""

    inventory: Inventory
    screens: dict[str, ScreenResult]
    allowlist: ScanAllowlist

    # -- construction ----------------------------------------------------------------
    @classmethod
    def build(cls, allowlist: ScanAllowlist | None = None) -> CodeFactsStore:
        """Run the deterministic pass end to end: inventory the allowlisted tree, screen
        every handler, and hold the result. No model, no network."""
        allow = allowlist or finder_allowlist()
        inventory = build_inventory(allow)
        return cls(
            inventory=inventory,
            screens=screen_inventory(inventory),
            allowlist=allow,
        )

    # -- typed tools -----------------------------------------------------------------
    def get_handler(self, handler_id: str) -> InventoryRecord:
        """The inventory record for one handler, by ``file:symbol`` id. Raises rather than
        returning a default — an unresolvable id is a rejected citation."""
        for record in self.inventory.handlers:
            if record.handler_id == handler_id:
                return record
        raise HandlerNotFound(handler_id)

    def list_candidates(
        self, predicate: Callable[[InventoryRecord], bool]
    ) -> list[InventoryRecord]:
        """Every handler record matching `predicate`, in id order. The general filter; for
        the common case of "the candidates worth a model call", see `candidates`."""
        return [r for r in self.inventory.handlers if predicate(r)]

    def candidates(self, screen: Screen | None = None) -> list[InventoryRecord]:
        """Handler records by pre-filter screen — ``examine`` for the ones the model judges,
        or all screens when `screen` is None. The find stage iterates
        ``candidates("examine")``."""
        if screen is None:
            return list(self.inventory.handlers)
        return [
            r
            for r in self.inventory.handlers
            if self.screens[r.handler_id].screen == screen
        ]

    def screen_of(self, handler_id: str) -> ScreenResult:
        """The pre-filter's screen and reason for one handler."""
        if handler_id not in self.screens:
            raise HandlerNotFound(handler_id)
        return self.screens[handler_id]

    def get_source(
        self, path: str, lines: tuple[int, int] | None = None
    ) -> str:
        """Serve source from an allowlisted file, comments stripped. `lines` is an inclusive
        1-based ``(start, end)`` range, or None for the whole file. A path outside the
        stage's allowlist raises `AllowlistViolation` before any byte is read."""
        text = strip_comments(self.allowlist.read_text(path))
        if lines is None:
            return text
        start, end = lines
        selected = text.splitlines()[max(start - 1, 0) : end]
        return "\n".join(selected)

    def model_definition(self, name: str) -> ModelDefinition:
        """A data model's owner-column facts and its source (comments stripped). Raises if
        the model is unknown."""
        facts = self.inventory.models.get(name)
        if facts is None:
            raise HandlerNotFound(f"model:{name}")
        source = self.get_source(facts.file, (facts.line_start, facts.line_end))
        return ModelDefinition(facts=facts, source=source)

    def callers_of(self, symbol: str) -> list[CallSite]:
        """Every call site of `symbol` across the allowlisted tree, in file/line order —
        the deterministic caller index the find stage follows to reach a delegated query.
        Matches a call by name (``symbol(...)``) or attribute (``x.symbol(...)``)."""
        sites: list[CallSite] = []
        for file in self.allowlist.files():
            rel = self.allowlist.rel(file)
            tree = ast.parse(self.allowlist.read_text(file))
            enclosing = _enclosing_defs(tree)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _call_names(node.func) == symbol:
                    sites.append(
                        CallSite(
                            file=rel,
                            caller_symbol=enclosing.get(node.lineno, "<module>"),
                            line=node.lineno,
                        )
                    )
        sites.sort(key=lambda s: (s.file, s.line))
        return sites

    # -- coverage --------------------------------------------------------------------
    def coverage(self) -> Coverage:
        """The coverage denominator over this run's inventory."""
        by_screen: dict[str, int] = {"drop": 0, "cheap": 0, "examine": 0}
        for result in self.screens.values():
            by_screen[result.screen] += 1
        dropped = by_screen["drop"]
        found = len(self.screens)
        return Coverage(
            found=found,
            judged=found - dropped,
            dropped=dropped,
            by_screen=by_screen,
        )

    def run_record_attributes(self) -> dict[str, Any]:
        """The find-stage facts ready to attach to the run record's span (ticket 25 wires
        this onto the live Match/find span): the coverage denominator and the screen for
        each handler, so the record carries *why* a handler was or was not judged."""
        return {
            "coverage": self.coverage().to_dict(),
            "screens": {
                hid: {"screen": r.screen, "reason": r.reason}
                for hid, r in sorted(self.screens.items())
            },
        }

    # -- persistence (JSON behind the interface) -------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": STORE_VERSION,
            "allowlist": self.allowlist.name,
            "handlers": [r.to_dict() for r in self.inventory.handlers],
            "models": {n: m.to_dict() for n, m in self.inventory.models.items()},
            "screens": {
                hid: {"screen": r.screen, "reason": r.reason}
                for hid, r in self.screens.items()
            },
        }

    def write(self, run_dir: Path) -> Path:
        """Persist the store as JSON under `run_dir`; returns the file path."""
        run_dir.mkdir(parents=True, exist_ok=True)
        path = run_dir / STORE_FILENAME
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path, allowlist: ScanAllowlist | None = None) -> CodeFactsStore:
        """Rehydrate a store from its JSON. The allowlist is re-attached (source reads need
        it); pass one for a non-finder stage, else the finder allowlist is used."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("version") != STORE_VERSION:
            raise ValueError(
                f"code-facts store version {data.get('version')} != {STORE_VERSION}"
            )
        inventory = Inventory(
            handlers=tuple(
                InventoryRecord.from_dict(r) for r in data["handlers"]
            ),
            models={n: ModelFacts.from_dict(m) for n, m in data["models"].items()},
        )
        screens = {
            hid: ScreenResult(hid, s["screen"], s["reason"])
            for hid, s in data["screens"].items()
        }
        return cls(
            inventory=inventory,
            screens=screens,
            allowlist=allowlist or finder_allowlist(),
        )


def _enclosing_defs(tree: ast.Module) -> dict[int, str]:
    """Map each source line to the name of the function/method that encloses it, so a call
    site can name its caller. Later (inner) defs win on overlapping lines."""
    lines: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno or node.lineno
            for ln in range(node.lineno, end + 1):
                lines[ln] = node.name
    return lines


def _call_names(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None
