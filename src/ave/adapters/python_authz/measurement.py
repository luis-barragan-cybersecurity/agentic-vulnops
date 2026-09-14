"""The blast-radius measurement record (ticket 28) — what `find()` proves, persisted.

One frozen value pairs the reach the store measured with the citation that proves the
source claim and the fix plan's proposed paths. The item lists are the source of truth;
every count is a property, so an unresolved edge can never read as zero anywhere but the
two `ReachResult` properties. `measured_finding` is the only writer of the evidence keys;
`from_finding` is the boundary parse every reader goes through — a forged or corrupt
record is "unmeasured", never a crash and never a number.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from ave.adapters.python_authz.callgraph import (
    ResolvedEdge,
    UnresolvedEdge,
    UnresolvedReason,
)
from ave.adapters.python_authz.citations import (
    Citation,
    CitationRejected,
    require_identity,
    validate_citations,
)
from ave.adapters.python_authz.code_facts import CodeFactsStore, ReachResult, RouteRef
from ave.adapters.python_authz.llm_finder import (
    _TARGET_PREFIX,
    AcceptedCandidate,
    _location,
)
from ave.state import REVIEW_LOCATION, Finding

Provenance = Literal["ast_resolved", "model_cited"]

#: How sure a fact earned by each provenance is (1-5). A `5` came from resolved AST
#: records; a `2` from a citation-validated model inference. No provenance, no number.
_HOW_SURE: Mapping[Provenance, int] = {"ast_resolved": 5, "model_cited": 2}

MEASUREMENT_KEY = "blast_radius_measurement"


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


@dataclass(frozen=True)
class BlastRadiusMeasurement:
    """JSON-ready. Every `Citation` here passed `validate_citations()` against the live
    store at measure time. `changed_paths` is None when no fix plan exists, which is not
    an empty plan."""

    #: None when the source citation failed validation — the reach stays measured, only
    #: the fact is withheld.
    provenance: Provenance | None
    reach: ReachResult
    changed_paths: tuple[str, ...] | None
    citations: tuple[Citation, ...]

    @property
    def files(self) -> int | None:
        return len(set(self.changed_paths)) if self.changed_paths is not None else None

    @property
    def dependents(self) -> int | None:
        return self.reach.dependents

    @property
    def routes(self) -> int | None:
        return self.reach.routes

    def fact(self) -> dict[str, Any] | None:
        """Deterministic sentences built from the record — emitted only when provenance
        grades, the reach is complete, and a citation validated. Otherwise None and the
        renderer prints `Unproven`."""
        if self.provenance is None or not self.reach.complete or not self.citations:
            return None
        file, symbol = self.reach.handler_id.rsplit(":", 1)
        start = next(
            (r for r in self.reach.affected_routes if r.handler_id == self.reach.handler_id),
            None,
        )
        if start is not None:
            identified = (
                f"The AST inventory identifies {symbol} as the {start.method} "
                f"{start.path} route handler."
            )
        else:
            identified = f"The AST inventory identifies {symbol} as a helper in {file}."
        sites = len(self.reach.dependent_sites)
        if sites == 0:
            found = (
                "A complete caller-index query found no dependent call sites in the "
                "allowlisted tree."
            )
            listed = "dependent_sites is empty"
        else:
            found = (
                f"A complete caller-index query found {_plural(sites, 'dependent call site')} "
                f"across {_plural(len(self.reach.affected_routes), 'route')} in the "
                "allowlisted tree."
            )
            listed = f"dependent_sites lists {_plural(sites, 'call site')}"
        cite = self.citations[0]
        return {
            "statement": f"{identified} {found}",
            "provenance": self.provenance,
            "how_sure": _HOW_SURE[self.provenance],
            "proof": (
                f"The inventory cites {cite.file}:{cite.start_line}-{cite.end_line}. "
                f"The recorded reach is complete, and {listed}."
            ),
            "citations": [c.to_dict() for c in self.citations],
        }

    def projection(self) -> dict[str, Any]:
        """The public policy dimensions plus the fact when earned. Pure."""
        return {
            "files": self.files,
            "dependents": self.dependents,
            "routes": self.routes,
            "fact": self.fact(),
        }

    def to_dict(self) -> dict[str, Any]:
        # reach_complete is a derived convenience for JSON readers; from_finding ignores
        # it and re-derives, so a stored flag can never contradict the edge lists.
        return {
            "provenance": self.provenance,
            "handler_id": self.reach.handler_id,
            "symbol_resolved": self.reach.symbol_resolved,
            "reach_complete": self.reach.complete,
            "changed_paths": (
                list(self.changed_paths) if self.changed_paths is not None else None
            ),
            "dependent_sites": [
                {
                    "caller_file": e.caller_file,
                    "caller_symbol": e.caller_symbol,
                    "line": e.line,
                    "callee": e.callee,
                }
                for e in self.reach.dependent_sites
            ],
            "affected_routes": [
                {"handler_id": r.handler_id, "method": r.method, "path": r.path}
                for r in self.reach.affected_routes
            ],
            "unresolved_edges": [
                {
                    "caller_file": e.caller_file,
                    "caller_symbol": e.caller_symbol,
                    "line": e.line,
                    "callee_name": e.callee_name,
                    "reason": e.reason,
                }
                for e in self.reach.unresolved_edges
            ],
            "citations": [c.to_dict() for c in self.citations],
        }

    @staticmethod
    def from_finding(finding: Finding) -> BlastRadiusMeasurement | None:
        """Boundary parse of `evidence[MEASUREMENT_KEY]`. The recorded handler must be
        the finding's own location (`require_identity`), an unknown provenance string
        becomes None, and any malformed field makes the whole record unmeasured."""
        evidence = finding.get("evidence")
        raw = evidence.get(MEASUREMENT_KEY) if isinstance(evidence, dict) else None
        if not isinstance(raw, dict):
            return None
        try:
            handler_id = str(raw["handler_id"])
            location = handler_id.removeprefix(_TARGET_PREFIX)
            require_identity(
                location, str(finding.get("location", "")), label="measured handler"
            )
            provenance: Provenance | None = (
                cast("Provenance", raw["provenance"])
                if raw["provenance"] in _HOW_SURE
                else None
            )
            reach = ReachResult(
                handler_id=handler_id,
                symbol_resolved=bool(raw["symbol_resolved"]),
                dependent_sites=tuple(
                    ResolvedEdge(
                        caller_file=str(e["caller_file"]),
                        caller_symbol=str(e["caller_symbol"]),
                        line=int(e["line"]),
                        callee=str(e["callee"]),
                    )
                    for e in raw["dependent_sites"]
                ),
                affected_routes=tuple(
                    RouteRef(
                        handler_id=str(r["handler_id"]),
                        method=str(r["method"]),
                        path=str(r["path"]),
                    )
                    for r in raw["affected_routes"]
                ),
                unresolved_edges=tuple(
                    UnresolvedEdge(
                        caller_file=str(e["caller_file"]),
                        caller_symbol=str(e["caller_symbol"]),
                        line=int(e["line"]),
                        callee_name=str(e["callee_name"]),
                        reason=cast("UnresolvedReason", str(e["reason"])),
                    )
                    for e in raw["unresolved_edges"]
                ),
            )
            changed = raw["changed_paths"]
            changed_paths = (
                tuple(str(p) for p in changed) if changed is not None else None
            )
            citations = tuple(Citation.from_dict(c) for c in raw["citations"])
        except (CitationRejected, KeyError, TypeError, ValueError):
            return None
        return BlastRadiusMeasurement(
            provenance=provenance,
            reach=reach,
            changed_paths=changed_paths,
            citations=citations,
        )


def measured_finding(
    store: CodeFactsStore,
    candidate: AcceptedCandidate,
    *,
    changed_paths: Sequence[str] | None,
) -> Finding:
    """Measure one accepted candidate against the store `find()` already holds. The only
    writer of `evidence[MEASUREMENT_KEY]` and `evidence[REVIEW_LOCATION]`; returns a new
    finding, the candidate is not mutated."""
    record = candidate.record
    reach = store.reach_of(record.handler_id)
    citation = Citation(
        file=record.file,
        start_line=record.line_start,
        end_line=record.line_end,
        contains=f"def {record.symbol}(",
    )
    provenance: Provenance | None
    citations: tuple[Citation, ...]
    try:
        validate_citations(store, [citation])
        provenance, citations = "ast_resolved", (citation,)
    except CitationRejected:
        provenance, citations = None, ()
    measurement = BlastRadiusMeasurement(
        provenance=provenance,
        reach=reach,
        changed_paths=(
            tuple(sorted(set(changed_paths))) if changed_paths is not None else None
        ),
        citations=citations,
    )
    finding = dict(candidate.finding)
    raw = finding.get("evidence")
    evidence: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}
    evidence[MEASUREMENT_KEY] = measurement.to_dict()
    # line_start includes the route decorator (11 for get_order) — the reviewer's anchor.
    evidence[REVIEW_LOCATION] = (
        f"{_location(record).rsplit(':', 1)[0]}:{record.line_start}"
    )
    finding["evidence"] = evidence
    return cast("Finding", finding)
