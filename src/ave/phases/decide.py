"""Phase 4 — Decide.

Produce the two-part decision record citing the policy version. This is the phase that
precedes the HITL `interrupt()` gate: the graph is compiled to pause *before* Prepare so
a human approves this record. Stub: emits a decision-record shell.
"""

from __future__ import annotations

from ave.records.decision_record import new_decision_record
from ave.state import AVEState


def decide(state: AVEState) -> AVEState:
    record = new_decision_record(
        finding=state.get("selected_finding"),
        policy_version=state.get("policy_version", "unset"),
    )
    return {"decision_record": record, "human_approved": False}
