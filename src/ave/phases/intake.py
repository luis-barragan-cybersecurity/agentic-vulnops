"""Phase 1 — Intake.

Pin the target under review and the policy version this run obeys, select the language
pack that will drive it, and open the run record (its first span). Every later phase
appends its own span to `state["spans"]`.
"""

from __future__ import annotations

import uuid

from ave.adapters import get_default_pack
from ave.records.store import make_span, now_iso
from ave.state import AVEState


def intake(state: AVEState) -> AVEState:
    started = now_iso()
    pack = get_default_pack()
    target_ref = state.get("target_ref", "unset")
    run_id = state.get("run_record_id") or uuid.uuid4().hex
    return {
        "run_record_id": run_id,
        "target_ref": target_ref,
        "target_ref_pack": pack.name,
        "policy_version": state.get("policy_version", "unset"),
        "findings": [],
        "spans": [
            make_span("intake", started, {"target_ref": target_ref, "pack": pack.name})
        ],
    }
