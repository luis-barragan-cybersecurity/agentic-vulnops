"""The graph state that flows through AVE's seven phases.

Language- and vuln-family-neutral by construction (D3): fields describe *findings*,
*changes*, and *verification*, never `authz` or `fastapi` specifics. Target-specific
detail is carried opaquely (e.g. `Finding.evidence`) and interpreted only behind the
adapter seam.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from langgraph.graph.message import add_messages


class Finding(TypedDict, total=False):
    """A single candidate vulnerability surfaced during Match/Assess."""

    id: str
    kind: str  # neutral label supplied by the adapter (e.g. an ownership-check gap)
    location: str  # file:symbol or route, as the adapter reports it
    confidence: float
    evidence: dict[str, Any]  # opaque, adapter-interpreted


class VerificationLadder(TypedDict, total=False):
    """The steps that prove a fix. Polarity of the exploit oracle is inverted:
    it passes while the target is vulnerable and fails once the fix works."""

    t0_build: bool
    t1_exploit_oracle_flipped: bool
    t2_full_suite: bool
    reattack_clean: bool


class AVEState(TypedDict, total=False):
    """State threaded through Intake -> Match -> Assess -> Decide -> Prepare ->
    Execute -> Verify."""

    # Intake
    target_ref: str  # pinned ref of the target under review
    policy_version: str  # the policy.yaml version this run obeys
    use_pinned_env: bool  # opt in to running the by-path oracle in the target's pinned env

    # Match / Assess
    findings: list[Finding]
    selected_finding: Finding | None
    assessment: dict[str, Any]

    # Decide (+ HITL gate)
    decision_record: dict[str, Any] | None
    human_approved: bool

    # Prepare / Execute
    prepared_change: dict[str, Any] | None
    pr_ref: str | None
    # The pinned-env exploit result, when opted in and the env was available (else absent).
    # Prepare captures it (threading the attack exchange into prepared_change); Verify reads
    # its `flipped` signal for T1 instead of the hermetic oracle. Shape: PinnedExploitResult.
    pinned_exploit: dict[str, Any] | None

    # Verify
    verification: VerificationLadder
    ready_to_merge: bool

    # Cross-cutting: the OTel-shaped run record every phase appends a span to.
    run_record_id: str
    target_ref_pack: str  # which language pack drove this run (adapter seam)
    spans: Annotated[list[dict[str, Any]], operator.add]
    messages: Annotated[list[Any], add_messages]
