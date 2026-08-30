"""Governance-as-data: loading `policy.yaml` and the pure decision it drives.

`policy.yaml` (repo root) holds the rules AVE obeys as data, never as prompt: valid-fix
predicates, blast-radius limits, verification-ladder requirements, per-ring stop criteria,
and HITL routes. Its *shape* is a first-class compounding export.

`decide()` is the predicate machine that reads it: a pure function mapping a proposed
`(finding, FixPlan, BlastRadius)` to `Autonomous` or `Escalation`. The Decide node calls it.
"""

from __future__ import annotations

from ave.policy.decide import (
    Autonomous,
    BlastRadius,
    Decision,
    Escalation,
    FixPlan,
    decide,
    ring_stop_criterion,
)
from ave.policy.loader import load_policy, policy_version

__all__ = [
    "Autonomous",
    "BlastRadius",
    "Decision",
    "Escalation",
    "FixPlan",
    "decide",
    "load_policy",
    "policy_version",
    "ring_stop_criterion",
]
