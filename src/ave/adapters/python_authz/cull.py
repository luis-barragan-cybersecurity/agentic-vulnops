from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypedDict, cast

from ave.adapters.python_authz.citations import (
    Citation,
    CitationRejected,
    require_identity,
    validate_citations,
)
from ave.adapters.python_authz.code_facts import HandlerNotFound
from ave.adapters.python_authz.llm_finder import AcceptedCandidate
from ave.adapters.python_authz.model import ModelClient, ToolCall, ToolResult
from ave.prompts import load_prompt, prompt_version
from ave.state import Finding

Stance = Literal["keep", "suppress"]
HypothesisKind = Literal["ruled_out", "supports_suppress"]
Disposition = Literal["keep", "suppress"]
ReviewBasis = Literal[
    "validated",
    "bound_oracle",
    "fail_open_invalid",
    "fail_open_missing",
    "fail_open_exhausted",
    "fail_open_unavailable",
    "fail_open_session_error",
]

FAIL_OPEN_BASES: frozenset[ReviewBasis] = frozenset(
    {
        "fail_open_invalid",
        "fail_open_missing",
        "fail_open_exhausted",
        "fail_open_unavailable",
        "fail_open_session_error",
    }
)

SUBMIT_REVIEW = "submit_review"
DEFAULT_CALL_BUDGET = 8
_SYSTEM_PROMPT_ID = "python_authz.llm_cull.system"
_CANDIDATE_PROMPT_ID = "python_authz.llm_cull.candidate"
_ALLOWED_STANCES: frozenset[Stance] = frozenset({"keep", "suppress"})
_ALLOWED_HYPOTHESES: frozenset[HypothesisKind] = frozenset(
    {"ruled_out", "supports_suppress"}
)
_RETRIEVAL_TOOLS = frozenset(
    {"get_handler", "get_source", "model_definition", "callers_of"}
)


class _ReviewMeta(TypedDict):
    location_key: str
    prompt_versions: dict[str, int]
    client_mode: str


_FORBIDDEN_CASE_KEYS = frozenset(
    {
        "oracle",
        "is_loop_anchor",
        "confidence",
        "catalog",
        "ground_truth",
        "family",
        "instance_id",
    }
)


@dataclass(frozen=True)
class Hypothesis:
    kind: HypothesisKind
    claim: str
    citations: tuple[Citation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "claim": self.claim,
            "citations": [c.to_dict() for c in self.citations],
        }


@dataclass(frozen=True)
class SubmittedStance:
    stance: Stance
    reason: str
    citations: tuple[Citation, ...]
    hypotheses: tuple[Hypothesis, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "stance": self.stance,
            "reason": self.reason,
            "citations": [c.to_dict() for c in self.citations],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
        }


@dataclass(frozen=True)
class CounterReview:
    location_key: str
    kind: str
    source: str
    submitted: SubmittedStance | None
    effective: Disposition
    reason: str
    citations: tuple[Citation, ...]
    hypotheses: tuple[Hypothesis, ...]
    basis: ReviewBasis
    prompt_versions: dict[str, int]
    client_mode: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "location_key": self.location_key,
            "kind": self.kind,
            "source": self.source,
            "submitted": None if self.submitted is None else self.submitted.to_dict(),
            "effective": self.effective,
            "reason": self.reason,
            "citations": [c.to_dict() for c in self.citations],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "basis": self.basis,
            "prompt_versions": dict(self.prompt_versions),
            "client_mode": self.client_mode,
        }


def has_bound_oracle(finding: Finding) -> bool:
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return False
    oracle = evidence.get("oracle")
    return isinstance(oracle, dict) and bool(oracle.get("path"))


def fail_open(
    finding: Finding,
    *,
    basis: ReviewBasis,
    reason: str,
    location_key: str,
    prompt_versions: dict[str, int],
    client_mode: str,
) -> CounterReview:
    if basis not in FAIL_OPEN_BASES:
        raise ValueError(f"{basis} is not a fail-open basis")
    return CounterReview(
        location_key=location_key,
        kind=str(finding.get("kind", "")),
        source=str(finding.get("source", "")),
        submitted=None,
        effective="keep",
        reason=reason,
        citations=(),
        hypotheses=(),
        basis=basis,
        prompt_versions=dict(prompt_versions),
        client_mode=client_mode,
    )


def resolve_submitted(
    finding: Finding,
    submitted: SubmittedStance,
    *,
    location_key: str,
    prompt_versions: dict[str, int],
    client_mode: str,
) -> CounterReview:
    if submitted.stance == "suppress" and has_bound_oracle(finding):
        effective: Disposition = "keep"
        basis: ReviewBasis = "bound_oracle"
    else:
        effective = submitted.stance
        basis = "validated"
    return CounterReview(
        location_key=location_key,
        kind=str(finding.get("kind", "")),
        source=str(finding.get("source", "")),
        submitted=submitted,
        effective=effective,
        reason=submitted.reason,
        citations=submitted.citations,
        hypotheses=submitted.hypotheses,
        basis=basis,
        prompt_versions=dict(prompt_versions),
        client_mode=client_mode,
    )


def partition_batch(
    findings: Sequence[Finding], reviews: Sequence[CounterReview]
) -> tuple[tuple[Finding, ...], tuple[Finding, ...]]:
    by_key = {(review.location_key, review.kind): review for review in reviews}
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        key = (str(finding.get("location", "")), str(finding.get("kind", "")))
        review = by_key.get(key)
        if review is not None and review.effective == "suppress":
            suppressed.append(finding)
        else:
            kept.append(finding)
    return tuple(kept), tuple(suppressed)


CULL_TOOL_SCHEMAS: list[dict[str, Any]] = [
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
        "name": SUBMIT_REVIEW,
        "description": (
            "Submit the keep or suppress argument for this one finding. cited_spans and "
            "every hypothesis must resolve to source that contains the claimed text."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "location": {"type": "string"},
                "kind": {"type": "string"},
                "stance": {"type": "string", "enum": ["keep", "suppress"]},
                "reason": {"type": "string"},
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
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": ["ruled_out", "supports_suppress"],
                            },
                            "claim": {"type": "string"},
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
                                    "required": [
                                        "file",
                                        "start_line",
                                        "end_line",
                                        "contains",
                                    ],
                                },
                            },
                        },
                        "required": ["kind", "claim", "cited_spans"],
                    },
                },
            },
            "required": [
                "location",
                "kind",
                "stance",
                "reason",
                "cited_spans",
                "hypotheses",
            ],
        },
    },
]


def prompt_versions() -> dict[str, int]:
    return {
        _SYSTEM_PROMPT_ID: prompt_version(_SYSTEM_PROMPT_ID),
        _CANDIDATE_PROMPT_ID: prompt_version(_CANDIDATE_PROMPT_ID),
    }


def location_key(finding: Finding) -> str:
    return str(finding.get("location", ""))


def redacted_case(candidate: AcceptedCandidate) -> dict[str, Any]:
    finding = candidate.finding
    record = candidate.record
    evidence = finding.get("evidence")
    evidence_dict = evidence if isinstance(evidence, dict) else {}
    case = {
        "location": finding.get("location"),
        "kind": finding.get("kind"),
        "rationale": evidence_dict.get("rationale", ""),
        "citations": list(evidence_dict.get("citations") or []),
        "handler": {
            "handler_id": record.handler_id,
            "method": record.method,
            "path": record.path,
            "file": record.file,
            "symbol": record.symbol,
            "auth_dependencies": list(record.auth_dependencies),
        },
    }
    _reject_forbidden(case)
    return case


def review_accepted(
    store: Any,
    accepted: Sequence[AcceptedCandidate],
    client: ModelClient,
    *,
    budget: int = DEFAULT_CALL_BUDGET,
) -> list[CounterReview]:
    try:
        versions = prompt_versions()
        load_prompt(_SYSTEM_PROMPT_ID)
        load_prompt(_CANDIDATE_PROMPT_ID)
    except Exception as exc:
        return [
            fail_open(
                candidate.finding,
                basis="fail_open_unavailable",
                reason=str(exc),
                location_key=location_key(candidate.finding),
                prompt_versions={},
                client_mode=client.name,
            )
            for candidate in accepted
        ]
    return [
        review_one(
            store,
            candidate,
            client,
            budget=budget,
            prompt_versions=versions,
        )
        for candidate in accepted
    ]


def review_one(
    store: Any,
    candidate: AcceptedCandidate,
    client: ModelClient,
    *,
    budget: int,
    prompt_versions: dict[str, int],
) -> CounterReview:
    finding = candidate.finding
    key = location_key(finding)
    meta: _ReviewMeta = {
        "location_key": key,
        "prompt_versions": prompt_versions,
        "client_mode": client.name,
    }
    try:
        session = client.begin(
            candidate_id=candidate.record.handler_id,
            system=load_prompt(_SYSTEM_PROMPT_ID),
            user=load_prompt(_CANDIDATE_PROMPT_ID).format(
                case=json.dumps(redacted_case(candidate), indent=2)
            ),
            tools=CULL_TOOL_SCHEMAS,
            terminal_tool=SUBMIT_REVIEW,
        )
    except FileNotFoundError as exc:
        return fail_open(
            finding, basis="fail_open_unavailable", reason=str(exc), **meta
        )
    except Exception as exc:
        return fail_open(
            finding, basis="fail_open_session_error", reason=str(exc), **meta
        )

    results: Sequence[ToolResult] = []
    try:
        for _ in range(budget):
            calls = session.respond(results)
            if not calls:
                return fail_open(
                    finding,
                    basis="fail_open_missing",
                    reason="session submitted no review",
                    **meta,
                )
            next_results: list[ToolResult] = []
            for call in calls:
                if call.name == SUBMIT_REVIEW:
                    return _accept_review(store, candidate, call.arguments, **meta)
                next_results.append(_execute(store, call))
            results = next_results
    except Exception as exc:
        return fail_open(
            finding, basis="fail_open_session_error", reason=str(exc), **meta
        )
    return fail_open(
        finding,
        basis="fail_open_exhausted",
        reason=f"call budget {budget} exhausted without submit_review",
        **meta,
    )


def attach_review(finding: Finding, review: CounterReview | None) -> Finding:
    if review is None:
        return finding
    attached = dict(finding)
    raw = attached.get("evidence", {})
    evidence = dict(raw) if isinstance(raw, dict) else {}
    evidence["counter_review"] = review.to_dict()
    attached["evidence"] = evidence
    return cast("Finding", attached)


def cull_attributes(
    reviews: Sequence[CounterReview], *, client_mode: str
) -> dict[str, Any]:
    versions = dict(reviews[0].prompt_versions) if reviews else prompt_versions()
    return {
        "reviewed": len(reviews),
        "kept": sum(1 for review in reviews if review.effective == "keep"),
        "suppressed": sum(1 for review in reviews if review.effective == "suppress"),
        "fail_open": sum(1 for review in reviews if review.basis in FAIL_OPEN_BASES),
        "bound_oracle_overrides": sum(
            1 for review in reviews if review.basis == "bound_oracle"
        ),
        "client": client_mode,
        "prompt_versions": versions,
        "reviews": [review.to_dict() for review in reviews],
    }


def _accept_review(
    store: Any,
    candidate: AcceptedCandidate,
    args: dict[str, Any],
    *,
    location_key: str,
    prompt_versions: dict[str, int],
    client_mode: str,
) -> CounterReview:
    try:
        submitted = _parse_submitted(store, candidate, args)
    except (CitationRejected, KeyError, TypeError, ValueError) as exc:
        return fail_open(
            candidate.finding,
            basis="fail_open_invalid",
            reason=str(exc),
            location_key=location_key,
            prompt_versions=prompt_versions,
            client_mode=client_mode,
        )
    return resolve_submitted(
        candidate.finding,
        submitted,
        location_key=location_key,
        prompt_versions=prompt_versions,
        client_mode=client_mode,
    )


def _parse_submitted(
    store: Any, candidate: AcceptedCandidate, args: dict[str, Any]
) -> SubmittedStance:
    finding = candidate.finding
    require_identity(
        str(args.get("location", "")),
        str(finding.get("location", "")),
        label="location",
    )
    require_identity(
        str(args.get("kind", "")),
        str(finding.get("kind", "")),
        label="kind",
    )
    stance = str(args.get("stance", ""))
    if stance not in _ALLOWED_STANCES:
        raise CitationRejected(f"stance {stance!r} is not keep or suppress")
    reason = str(args.get("reason", "")).strip()
    if not reason:
        raise CitationRejected("reason must be non-empty")
    citations = tuple(Citation.from_dict(item) for item in args.get("cited_spans", []))
    validate_citations(store, citations)
    if "hypotheses" not in args:
        raise CitationRejected("at least one hypothesis is required")
    hypotheses = tuple(
        _parse_hypothesis(store, item) for item in args.get("hypotheses") or []
    )
    if not hypotheses:
        raise CitationRejected("at least one hypothesis is required")
    kinds = {hypothesis.kind for hypothesis in hypotheses}
    typed_stance: Stance = "keep" if stance == "keep" else "suppress"
    expected = "ruled_out" if typed_stance == "keep" else "supports_suppress"
    if kinds != {expected}:
        raise CitationRejected(
            f"{typed_stance} requires only {expected} hypotheses, got {sorted(kinds)}"
        )
    return SubmittedStance(
        stance=typed_stance,
        reason=reason,
        citations=citations,
        hypotheses=hypotheses,
    )


def _parse_hypothesis(store: Any, data: dict[str, Any]) -> Hypothesis:
    kind = str(data.get("kind", ""))
    if kind not in _ALLOWED_HYPOTHESES:
        raise CitationRejected(f"hypothesis kind {kind!r} is not allowed")
    claim = str(data.get("claim", "")).strip()
    if not claim:
        raise CitationRejected("hypothesis claim must be non-empty")
    citations = tuple(Citation.from_dict(item) for item in data.get("cited_spans", []))
    validate_citations(store, citations)
    typed_kind: HypothesisKind = (
        "ruled_out" if kind == "ruled_out" else "supports_suppress"
    )
    return Hypothesis(
        kind=typed_kind,
        claim=claim,
        citations=citations,
    )


def _execute(store: Any, call: ToolCall) -> ToolResult:
    try:
        content = _dispatch(store, call)
    except (HandlerNotFound, KeyError, PermissionError, ValueError) as exc:
        content = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    return ToolResult(call=call, content=content)


def _dispatch(store: Any, call: ToolCall) -> str:
    if call.name not in _RETRIEVAL_TOOLS:
        return json.dumps({"error": f"unknown tool {call.name!r}"})
    args = call.arguments
    if call.name == "get_handler":
        return json.dumps(store.get_handler(str(args["handler_id"])).to_dict())
    if call.name == "get_source":
        lines = _line_range(args)
        return json.dumps({"source": store.get_source(str(args["file"]), lines)})
    if call.name == "model_definition":
        definition = store.model_definition(str(args["name"]))
        return json.dumps({"facts": definition.facts.to_dict(), "source": definition.source})
    sites = store.callers_of(str(args["symbol"]))
    return json.dumps(
        [{"file": site.file, "caller": site.caller_symbol, "line": site.line} for site in sites]
    )


def _line_range(args: dict[str, Any]) -> tuple[int, int] | None:
    if "start_line" in args and "end_line" in args:
        return (int(args["start_line"]), int(args["end_line"]))
    return None


def _reject_forbidden(value: Any) -> None:
    if isinstance(value, dict):
        leaked = _FORBIDDEN_CASE_KEYS.intersection(value)
        if leaked:
            raise ValueError(f"redacted case leaked {sorted(leaked)}")
        for child in value.values():
            _reject_forbidden(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden(child)
