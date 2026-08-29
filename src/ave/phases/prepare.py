"""Phase 5 — Prepare.

After the human approves at the gate, prepare the class-level change (a fix that removes
the whole class of the flaw, not one instance) and a draft PR. Stub: emits a change shell.
"""

from __future__ import annotations

from ave.state import AVEState


def prepare(state: AVEState) -> AVEState:
    change = {
        "class_level": True,
        "summary": "stub change",
        "finding_id": (state.get("selected_finding") or {}).get("id"),
    }
    return {"prepared_change": change, "pr_ref": None}
