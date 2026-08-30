"""Phase 3 — Assess.

Reason about each finding (retrieve-then-reason, to avoid caller-graph context overflow)
and select the one to drive, attaching its blast radius. Skeleton: selects the first
finding and asks the pack for its caller/PR-level reach.
"""

from __future__ import annotations

from typing import Any

from ave.adapters import get_default_pack
from ave.records.store import make_span, now_iso
from ave.state import AVEState


def assess(state: AVEState) -> AVEState:
    started = now_iso()
    findings = state.get("findings", [])
    selected = findings[0] if findings else None
    assessment: dict[str, Any] = {"reasoned": selected is not None}
    if selected is not None:
        pack = get_default_pack()
        assessment["blast_radius"] = pack.blast_radius(selected)
        assessment["fix_plan"] = pack.fix_plan(selected)
    return {
        "selected_finding": selected,
        "assessment": assessment,
        "spans": [make_span("assess", started, {"selected": bool(selected)})],
    }
