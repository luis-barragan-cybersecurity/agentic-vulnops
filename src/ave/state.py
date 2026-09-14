"""The graph state that flows through AVE's seven phases.

Language- and vuln-family-neutral by construction (D3): fields describe *findings*,
*changes*, and *verification*, never `authz` or `fastapi` specifics. Target-specific
detail is carried opaquely (e.g. `Finding.evidence`) and interpreted only behind the
adapter seam.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, TypedDict

from langgraph.graph.message import add_messages

#: Neutral, display-only ``file:line`` a source may record under `Finding.evidence`;
#: never an identity (`location` stays the de-dup key).
REVIEW_LOCATION = "review_location"


class Finding(TypedDict, total=False):
    """A single candidate vulnerability surfaced during Match/Assess."""

    id: str
    kind: str  # neutral label supplied by the adapter (e.g. an ownership-check gap)
    location: str  # file:symbol or route, as the adapter reports it
    confidence: float
    # Which finding source produced this: `ave:<finder>` for AVE's own, `sarif:<tool>` for
    # an external feed. Always set by Match, because the scoreboard reports recall *per
    # source* — an external scanner's findings must never silently inflate AVE's own
    # number. `corroborated_by` holds the other sources a de-dup merge folded in, so a
    # flaw two sources agree on keeps both without losing which one led.
    source: str
    corroborated_by: list[str]
    # Opaque, adapter-interpreted. `REVIEW_LOCATION` is the one neutral key the renderer
    # may read from it.
    evidence: dict[str, Any]


class VerificationLadder(TypedDict, total=False):
    """The steps that prove a fix. Polarity of the exploit oracle is inverted:
    it passes while the target is vulnerable and fails once the fix works."""

    t0_build: bool
    t1_exploit_oracle_flipped: bool
    t2_full_suite: bool
    reattack_clean: bool


PinnedStatus = Literal[
    "success",
    "not_flipped",
    "unavailable",
    "launch_failed",
    "patch_failed",
    "test_failed",
    "malformed",
    "unsafe_capture",
]


class PinnedExploitResult(TypedDict):
    """One explicit outcome from a requested pinned-environment run."""

    status: PinnedStatus
    before_vulnerable: bool | None
    after_blocked: bool | None
    flipped: bool | None
    attack_exchange: dict[str, Any] | None
    detail: str
    patch_applied: bool


class AVEState(TypedDict, total=False):
    """State threaded through Intake -> Match -> Assess -> Decide -> Prepare ->
    Execute -> Verify."""

    # Intake
    target_ref: str  # pinned ref of the target under review
    policy_version: str  # the policy.yaml version this run obeys
    use_pinned_env: bool

    # Match / Assess
    findings: list[Finding]
    suppressed_findings: list[Finding]
    selected_finding: Finding | None
    selection_rationale: dict[str, Any]  # why *this* finding is the one remediated
    assessment: dict[str, Any]

    # Decide (+ HITL gate)
    decision_record: dict[str, Any] | None
    human_approved: bool

    # Prepare / Execute
    prepared_change: dict[str, Any] | None
    pr_ref: str | None
    pinned_exploit: PinnedExploitResult

    # Verify
    verification: VerificationLadder
    ready_to_merge: bool

    # Cross-cutting: the OTel-shaped run record every phase appends a span to.
    run_record_id: str
    target_ref_pack: str  # which language pack drove this run (adapter seam)
    spans: Annotated[list[dict[str, Any]], operator.add]
    messages: Annotated[list[Any], add_messages]
