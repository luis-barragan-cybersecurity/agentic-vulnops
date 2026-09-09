"""The LLM finder — the model-side finding source (ticket 25).

This is the half of the find stage the deterministic layer (ticket 23) was built to carry:
a model that rediscovers the ownership and role gaps a pattern scanner is blind to, reading
only the code-facts store and never the answer key. It is **retrieve-then-reason, one
candidate at a time** (find-stage design, decisions 3-6):

* The pre-filter already dropped the handlers that cannot be a finding by arithmetic. The
  finder iterates only ``store.candidates("examine")`` — the candidates a call can change
  the answer for.
* For each, a **fresh, stateless session** (`model.ModelClient.begin`) plans its own
  retrieval through the typed tools under a **call budget**, then submits one structured
  verdict. Context never accumulates across candidates; no session sees a previous verdict.
  The store is the workspace, not the context window.
* **Verdicts are validated at the submission boundary** (decision 5, from Mulder): a verdict
  must cite the inventory record and the source line spans it claims about, and this module
  checks that those spans resolve *and contain what is claimed* before a `Finding` is
  produced. A verdict that fails is **rejected, not down-weighted** — an architectural
  invariant, not a prompt instruction.

Every finding this produces carries ``source = "ave:llm-finder"`` and a `location` in the
target's own path scheme (``app/...:symbol``), so it merges and de-dups with any other
source on the same flaw (ticket 24). The finder never drives the fix or the exploit — it is
a finding *source*; binding a finding to a generated exploit is ticket 27, and measuring its
blast radius is ticket 28.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ave.adapters.python_authz.citations import (
    Citation,
    CitationRejected,
    require_identity,
    validate_citations,
)
from ave.adapters.python_authz.code_facts import Coverage, HandlerNotFound
from ave.adapters.python_authz.inventory import InventoryRecord
from ave.adapters.python_authz.model import (
    SUBMIT_VERDICT,
    ModelClient,
    ToolCall,
    ToolResult,
)
from ave.prompts import load_prompt, prompt_version
from ave.state import Finding

#: Public name the finder tests and callers already import. The shared validator raises
#: `CitationRejected`; this alias keeps the finder's rejection type stable.
VerdictRejected = CitationRejected

#: The finder's `source` stamp — what per-source recall counts it under (ticket 24). Never
#: the pack anchor's name and never the answer key's: a run finding carrying this was found
#: by the model, reasoning over the store.
LLM_FINDER_SOURCE = "ave:llm-finder"

#: The two neutral finding kinds this pack's finder may return — the same labels the catalog
#: projects instances into (`catalog._to_finding`), so a model finding and a catalogued one
#: share identity for de-dup and scoring. A verdict naming any other kind is rejected.
OWNERSHIP_GAP = "object-ownership-gap"
ROLE_GAP = "function-role-gap"
_ALLOWED_KINDS = frozenset({OWNERSHIP_GAP, ROLE_GAP})

#: The most tool-call turns one candidate's session may take before it must have submitted a
#: verdict. Scale is a budget problem (decision 4): the cap is per candidate, not per run,
#: and holds at any target size.
DEFAULT_CALL_BUDGET = 8

#: Handler ids carry the finder's read root as a prefix; a finding's location is reported in
#: the target's own scheme, the one the catalog and every other source speak, so de-dup lands.
_TARGET_PREFIX = "target/dvrestaurant/"

#: The system + per-candidate prompts, versioned through `prompts/manifest.json`.
_SYSTEM_PROMPT_ID = "python_authz.llm_finder.system"
_CANDIDATE_PROMPT_ID = "python_authz.llm_finder.candidate"


@dataclass(frozen=True)
class Verdict:
    """A parsed `submit_verdict` payload, before validation. `is_finding` False is a cleared
    candidate (the model ruled it benign) — a real outcome, kept for the coverage/precision
    story, not a finding."""

    handler_id: str
    is_finding: bool
    kind: str
    confidence: float
    rationale: str
    citations: tuple[Citation, ...]

    @staticmethod
    def from_arguments(handler_id: str, args: dict[str, Any]) -> Verdict:
        return Verdict(
            handler_id=str(args.get("handler_id") or handler_id),
            is_finding=bool(args.get("is_finding")),
            kind=str(args.get("kind", "")),
            confidence=float(args.get("confidence", 0.0)),
            rationale=str(args.get("rationale", "")),
            citations=tuple(
                Citation.from_dict(c) for c in args.get("cited_spans", [])
            ),
        )


@dataclass(frozen=True)
class Rejection:
    """A verdict that did not pass the submission boundary. Recorded so a run can report how
    many verdicts were rejected and why — the invariant is visible, not silent."""

    handler_id: str
    reason: str


@dataclass(frozen=True)
class AcceptedCandidate:
    """A minted finding paired with the inventory record it was judged against.

    Cull sessions consume these pairs so accepted identity stays the trusted record,
    not a later lookup through a compatibility findings view.
    """

    record: InventoryRecord
    finding: Finding


@dataclass(frozen=True)
class FindReport:
    """Everything one finder pass produced: the accepted pairs, the candidates cleared as
    benign, the rejected verdicts, and the coverage denominator. `findings` is a
    compatibility view; cull receives `accepted`."""

    accepted: list[AcceptedCandidate] = field(default_factory=list)
    cleared: list[str] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)
    budget_exhausted: list[str] = field(default_factory=list)
    coverage: Coverage | None = None
    prompt_versions: dict[str, int] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        return [candidate.finding for candidate in self.accepted]

    def by_source(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            src = str(finding.get("source", LLM_FINDER_SOURCE))
            counts[src] = counts.get(src, 0) + 1
        return counts

    def to_attributes(self) -> dict[str, Any]:
        """The find-stage facts for the run record's Match span."""
        attrs: dict[str, Any] = {
            "finder": "llm",
            "found": len(self.findings),
            "cleared": len(self.cleared),
            "rejected": len(self.rejected),
            "budget_exhausted": len(self.budget_exhausted),
            "by_source": self.by_source(),
            "prompt_versions": dict(self.prompt_versions),
        }
        if self.coverage is not None:
            attrs["coverage"] = self.coverage.to_dict()
        return attrs


# -- the tool surface exposed to the model ------------------------------------------

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "get_handler",
        "description": "The full inventory record for a handler id (file:symbol).",
        "input_schema": {
            "type": "object",
            "properties": {"handler_id": {"type": "string"}},
            "required": ["handler_id"],
        },
    },
    {
        "name": "get_source",
        "description": (
            "Source of an allowlisted file, comments stripped. Optional inclusive 1-based "
            "line range."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["file"],
        },
    },
    {
        "name": "model_definition",
        "description": "A data model's owner-column facts and source.",
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "callers_of",
        "description": "Every call site of a symbol across the allowlisted tree.",
        "input_schema": {
            "type": "object",
            "properties": {"symbol": {"type": "string"}},
            "required": ["symbol"],
        },
    },
    {
        "name": "list_candidates",
        "description": "The handler ids the pre-filter kept for judgement (screen=examine).",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": SUBMIT_VERDICT,
        "description": (
            "Submit the one verdict for this candidate. cited_spans must resolve to source "
            "that contains the claimed text, or the verdict is rejected."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "handler_id": {"type": "string"},
                "is_finding": {"type": "boolean"},
                "kind": {"type": "string", "enum": sorted(_ALLOWED_KINDS)},
                "confidence": {"type": "number"},
                "rationale": {"type": "string"},
                "cited_spans": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string"},
                            "start_line": {"type": "integer"},
                            "end_line": {"type": "integer"},
                            "contains": {"type": "string"},
                        },
                        "required": ["file", "start_line", "end_line", "contains"],
                    },
                },
            },
            "required": ["handler_id", "is_finding", "rationale"],
        },
    },
]


@dataclass(frozen=True)
class LLMFinder:
    """Runs the model over the store's `examine` candidates and returns validated findings.

    `store` is any object exposing the typed tools (`get_handler`, `get_source`,
    `model_definition`, `callers_of`, `candidates`, `coverage`) — the `CodeFactsStore`. The
    finder never reaches past that surface, so it inherits the store's allowlist and its
    comment-stripping for free."""

    store: Any
    client: ModelClient
    budget: int = DEFAULT_CALL_BUDGET

    def find(self) -> FindReport:
        accepted: list[AcceptedCandidate] = []
        cleared: list[str] = []
        rejected: list[Rejection] = []
        exhausted: list[str] = []
        for record in self.store.candidates("examine"):
            try:
                verdict = self._judge(record)
            except _BudgetExhausted:
                exhausted.append(record.handler_id)
                continue
            if verdict is None:
                exhausted.append(record.handler_id)
                continue
            try:
                finding = self._accept(record, verdict)
            except VerdictRejected as exc:
                rejected.append(Rejection(record.handler_id, str(exc)))
                continue
            if finding is None:
                cleared.append(record.handler_id)
            else:
                accepted.append(AcceptedCandidate(record=record, finding=finding))
        accepted.sort(key=lambda candidate: str(candidate.finding.get("location", "")))
        return FindReport(
            accepted=accepted,
            cleared=cleared,
            rejected=rejected,
            budget_exhausted=exhausted,
            coverage=self.store.coverage(),
            prompt_versions={
                _SYSTEM_PROMPT_ID: prompt_version(_SYSTEM_PROMPT_ID),
                _CANDIDATE_PROMPT_ID: prompt_version(_CANDIDATE_PROMPT_ID),
            },
        )

    # -- one candidate, one stateless session ---------------------------------------
    def _judge(self, record: InventoryRecord) -> Verdict | None:
        system = load_prompt(_SYSTEM_PROMPT_ID)
        user = load_prompt(_CANDIDATE_PROMPT_ID).format(
            record=json.dumps(record.to_dict(), indent=2)
        )
        session = self.client.begin(
            candidate_id=record.handler_id,
            system=system,
            user=user,
            tools=TOOL_SCHEMAS,
        )
        results: Sequence[ToolResult] = []
        for _ in range(self.budget):
            calls = session.respond(results)
            if not calls:
                return None
            next_results: list[ToolResult] = []
            for call in calls:
                if call.name == SUBMIT_VERDICT:
                    return Verdict.from_arguments(record.handler_id, call.arguments)
                next_results.append(self._execute(call))
            results = next_results
        raise _BudgetExhausted(record.handler_id)

    def _execute(self, call: ToolCall) -> ToolResult:
        """Run one retrieval tool against the store and package the result as JSON the model
        reads next. An unknown tool or a bad argument returns an error payload rather than
        raising — the model can recover, and a stuck session ends by budget."""
        try:
            content = self._dispatch(call)
        except (HandlerNotFound, KeyError, PermissionError, ValueError) as exc:
            content = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
        return ToolResult(call=call, content=content)

    def _dispatch(self, call: ToolCall) -> str:
        args = call.arguments
        if call.name == "get_handler":
            return json.dumps(self.store.get_handler(str(args["handler_id"])).to_dict())
        if call.name == "get_source":
            lines = _line_range(args)
            return json.dumps(
                {"source": self.store.get_source(str(args["file"]), lines)}
            )
        if call.name == "model_definition":
            defn = self.store.model_definition(str(args["name"]))
            return json.dumps(
                {"facts": defn.facts.to_dict(), "source": defn.source}
            )
        if call.name == "callers_of":
            sites = self.store.callers_of(str(args["symbol"]))
            return json.dumps(
                [
                    {"file": s.file, "caller": s.caller_symbol, "line": s.line}
                    for s in sites
                ]
            )
        if call.name == "list_candidates":
            return json.dumps(
                [
                    {"handler_id": r.handler_id, "method": r.method, "path": r.path}
                    for r in self.store.candidates("examine")
                ]
            )
        return json.dumps({"error": f"unknown tool {call.name!r}"})

    # -- the submission boundary ----------------------------------------------------
    def _accept(self, record: InventoryRecord, verdict: Verdict) -> Finding | None:
        """Validate the verdict's citations against the store and, if it is a finding, mint a
        neutral `Finding`. Rejection is total: a citation that does not resolve to what it
        claims yields no finding, whatever the verdict's confidence."""
        if not verdict.is_finding:
            return None
        self._validate(record, verdict)
        return {
            "id": _finding_id(record),
            "kind": verdict.kind,
            "location": _location(record),
            "confidence": _clamp(verdict.confidence),
            "source": LLM_FINDER_SOURCE,
            "evidence": {
                "rationale": verdict.rationale,
                "citations": [c.to_dict() for c in verdict.citations],
                "candidate_screen": "examine",
                "finder": "llm",
                "handler": {
                    "method": record.method,
                    "path": record.path,
                    "auth_dependencies": list(record.auth_dependencies),
                },
            },
        }

    def _validate(self, record: InventoryRecord, verdict: Verdict) -> None:
        if verdict.kind not in _ALLOWED_KINDS:
            raise VerdictRejected(
                f"kind {verdict.kind!r} is not one of {sorted(_ALLOWED_KINDS)}"
            )
        require_identity(verdict.handler_id, record.handler_id, label="cited handler")
        validate_citations(self.store, verdict.citations)


class _BudgetExhausted(Exception):
    """A session spent its whole call budget without submitting a verdict."""


def _line_range(args: dict[str, Any]) -> tuple[int, int] | None:
    if "start_line" in args and "end_line" in args:
        return (int(args["start_line"]), int(args["end_line"]))
    return None


def _location(record: InventoryRecord) -> str:
    """The finding's location in the target's own path scheme (``app/...:symbol``), the one
    the catalog and every source speak, so the pack's `dedup_key` folds a model finding and
    another source's onto the same flaw."""
    file = record.file
    if file.startswith(_TARGET_PREFIX):
        file = file[len(_TARGET_PREFIX) :]
    return f"{file}:{record.symbol}"


def _finding_id(record: InventoryRecord) -> str:
    """A stable, readable id for a model finding — the handler symbol under its file stem, so
    two runs over the same target agree on identity even as lines drift."""
    stem = Path(record.file).stem
    return f"ave-llm-{stem}-{record.symbol}"


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))
