"""Phase 5 — Prepare.

After the human approves at the gate, prepare the class-level change — a fix that removes
the whole class of the flaw, not one instance — via the language pack's fix template. The
change carries a real unified-diff patch and its blast radius. No finding selected => no
change (the loop stays honest).
"""

from __future__ import annotations

from ave.adapters import get_default_pack
from ave.records.store import make_span, now_iso
from ave.state import AVEState


def prepare(state: AVEState) -> AVEState:
    started = now_iso()
    selected = state.get("selected_finding")
    change = get_default_pack().prepare_fix(selected) if selected is not None else None
    return {
        "prepared_change": change,
        "pr_ref": None,
        "spans": [make_span("prepare", started, {"prepared": change is not None})],
    }
