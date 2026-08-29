"""Phase 3 — Assess.

Reason about each finding (retrieve-then-reason, to avoid caller-graph context
overflow) and select the one to drive. Stub: selects the first finding, if any.
"""

from __future__ import annotations

from ave.state import AVEState


def assess(state: AVEState) -> AVEState:
    findings = state.get("findings", [])
    selected = findings[0] if findings else None
    return {"selected_finding": selected, "assessment": {"reasoned": bool(selected)}}
