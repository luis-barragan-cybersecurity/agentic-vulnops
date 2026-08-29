"""Phase 4 — Decide.

Produce the two-part decision record citing the policy version. This is the phase that
precedes the HITL `interrupt()` gate: the graph is compiled to pause *before* Prepare so
a human approves this record. Skeleton: fills the record's rationale and policy predicate
for the selected finding (ticket 05 firms the full two-part shape).
"""

from __future__ import annotations

from ave.records.decision_record import new_decision_record
from ave.records.store import make_span, now_iso
from ave.state import AVEState


def decide(state: AVEState) -> AVEState:
    started = now_iso()
    selected = state.get("selected_finding")
    record = new_decision_record(
        finding=selected,
        policy_version=state.get("policy_version", "unset"),
    )
    if selected is not None:
        record["rationale"] = (
            f"Class-level ownership guard removes the {selected.get('kind')} at "
            f"{selected.get('location')} (fixes the whole class, not one call site)."
        )
        record["authorization"]["predicate"] = (
            "helper-only diff within blast-radius limits; verification ladder required"
        )
    return {
        "decision_record": record,
        "human_approved": False,
        "spans": [make_span("decide", started, {"has_record": True})],
    }
