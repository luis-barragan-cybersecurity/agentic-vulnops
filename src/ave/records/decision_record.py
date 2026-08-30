"""The two-part decision record: *what* AVE decided about a vulnerability, and *how* the
fix ships — every PR embeds one, and none becomes ready-to-merge without it (the invariant).

The SANS Field Guide's two-part shape (locked in ticket 05, landed in ticket 08):

  * `ResponseDecision` — the security judgement: classification, disposition, severity,
    the class-level remediation, and the class it removes.
  * `ExecutionRoute` — the operational route: standing-preauthorized vs. HITL, the ring
    plan, the measured blast radius, the required verification ladder, and which HITL
    route (if any) fired.

Every record cites the `policy.yaml` version plus the exploit oracle and the catalog
ground-truth id, so CI can re-derive the same verdict. Field names stay language- and
vuln-family-neutral (D3). `ave.policy.decide()` constructs these; this module owns the shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Disposition = Literal["fix", "accept_risk", "defer"]
ExecutionRouteKind = Literal["standing_preauthorized", "hitl_approved"]
DecidedBy = Literal["agent", "human"]


@dataclass
class ResponseDecision:
    """Part 1 — WHAT to do about the vulnerability (the security judgement)."""

    classification: str          # the finding's neutral kind (e.g. object-ownership-gap)
    disposition: Disposition
    severity: str
    remediation: str             # the class-level fix, described
    scope: str                   # the class it removes, not the instance


@dataclass
class ExecutionRoute:
    """Part 2 — HOW the fix ships (the operational route)."""

    route: ExecutionRouteKind
    ring_plan: list[str]
    blast_radius: dict[str, int | None]
    verification_ladder_required: list[str]
    hitl_route: str | None       # which of the four routes fired, if any


@dataclass
class DecisionRecord:
    """The two-part record every PR embeds; cites the policy version (the invariant's
    decision-record half). Serialize with `dataclasses.asdict` to thread through graph
    state and render into the PR body."""

    finding_id: str
    policy_version: str
    rule_matched: str
    response: ResponseDecision
    execution: ExecutionRoute
    citations: dict[str, str]    # finding, oracle, catalog ground-truth ref
    rationale: str
    decided_by: DecidedBy
    decided_at: str
