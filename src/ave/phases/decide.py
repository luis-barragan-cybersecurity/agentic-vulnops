"""Phase 4 — Decide.

Call the pure policy `decide()` over the selected finding and its proposed fix, producing
the two-part decision record that the human reviews at the HITL `interrupt()` gate (the
graph is compiled to pause *before* Prepare). A standing-preauthorized finding yields an
`Autonomous` decision the human need only review; anything out of policy yields an
`Escalation` naming one of the four HITL routes — the record is a draft either way and is
threaded into state as a plain dict so it renders into the PR body and persists with the run.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ave.policy import Autonomous, BlastRadius, FixPlan, load_policy
from ave.policy import decide as policy_decide
from ave.records.store import make_span, now_iso
from ave.state import AVEState


def _fix_plan_from(assessment: dict[str, Any]) -> FixPlan:
    raw = assessment.get("fix_plan", {})
    return FixPlan(
        changed_paths=list(raw.get("changed_paths", [])),
        is_class_level=bool(raw.get("is_class_level", False)),
        preserves_legitimate_access=bool(raw.get("preserves_legitimate_access", False)),
    )


def _blast_from(assessment: dict[str, Any]) -> BlastRadius:
    raw = assessment.get("blast_radius", {})
    return BlastRadius(
        files=raw.get("files"),
        dependents=raw.get("dependents"),
        routes=raw.get("routes"),
    )


def decide(state: AVEState) -> AVEState:
    started = now_iso()
    selected = state.get("selected_finding")
    assessment = state.get("assessment", {})

    if selected is None:
        return {
            "decision_record": None,
            "human_approved": False,
            "spans": [make_span("decide", started, {"has_record": False})],
        }

    policy = load_policy()
    decision = policy_decide(
        selected,
        _fix_plan_from(assessment),
        _blast_from(assessment),
        policy,
        now=started,
    )
    record = decision.record if isinstance(decision, Autonomous) else decision.record_draft
    hitl_route = None if isinstance(decision, Autonomous) else decision.route

    return {
        "decision_record": asdict(record),
        "human_approved": False,
        "spans": [
            make_span(
                "decide",
                started,
                {
                    "route": record.execution.route,
                    "hitl_route": hitl_route,
                    "autonomous": isinstance(decision, Autonomous),
                },
            )
        ],
    }
