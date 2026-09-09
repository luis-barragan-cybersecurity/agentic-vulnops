"""Adversarial cull types and fail-open resolution (ticket 26).

The argument is advisory. The oracle is dispositive. A missing, invalid, exhausted,
unavailable, or failed session has no fabricated submitted stance and resolves to keep.
A valid suppress against bound independent oracle evidence records the suppress argument
and still resolves to keep. It cannot lower confidence, remove oracle metadata, or make
the finding non-drivable.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from ave.adapters.python_authz.citations import Citation
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


@dataclass(frozen=True)
class Hypothesis:
    """One cited explanation: a benign pattern ruled out, or support for suppress."""

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
    """A citation-valid keep or suppress argument. Fail-open reviews have none."""

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
    """One adversarial decision for an accepted finding.

    Identity is the stable `(location_key, kind)` plus `source`. `submitted` is the
    model argument when validation passed; `effective` is keep unless a validated
    suppress landed on a finding with no bound independent oracle.
    """

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
    """Keep with no fabricated submitted stance. `basis` must be a named fail-open."""
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
    """Apply a citation-valid stance. Bound-oracle suppress records the argument and keeps."""
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
    """Split accepted findings into kept and suppressed. No review means keep."""
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
