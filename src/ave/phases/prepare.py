"""Phase 5 — Prepare.

After the human approves at the gate, prepare the class-level change — a fix that removes
the whole class of the flaw, not one instance — via the language pack's fix template. The
change carries a real unified-diff patch and its blast radius. No finding selected => no
change (the loop stays honest).
"""

from __future__ import annotations

from typing import Any

from ave.adapters import get_default_pack
from ave.adapters.base import PinnedEnvCapable
from ave.records.store import make_span, now_iso
from ave.state import AVEState, PinnedExploitResult


def prepare(state: AVEState) -> AVEState:
    started = now_iso()
    selected = state.get("selected_finding")
    pack = get_default_pack()
    change = pack.prepare_fix(selected) if selected is not None else None

    attributes: dict[str, Any] = {"prepared": change is not None}
    result: AVEState = {
        "prepared_change": change,
        "pr_ref": None,
    }

    if state.get("use_pinned_env"):
        pinned: PinnedExploitResult
        if (
            change is not None
            and selected is not None
            and isinstance(pack, PinnedEnvCapable)
        ):
            pinned = pack.run_pinned_exploit(selected, change)
        else:
            pinned = {
                "status": "unavailable",
                "before_vulnerable": None,
                "after_blocked": None,
                "flipped": None,
                "attack_exchange": None,
                "detail": "pinned environment is not available",
                "patch_applied": False,
            }
        exchange = pinned.get("attack_exchange")
        if change is not None and exchange is not None:
            change["attack_exchange"] = exchange
        result["pinned_exploit"] = pinned
        attributes["pinned_status"] = pinned.get("status")
        attributes["pinned_patch_applied"] = bool(pinned.get("patch_applied"))
        attributes["attack_exchange_captured"] = bool(exchange)
        attributes["pinned_detail"] = pinned.get("detail")

    result["spans"] = [make_span("prepare", started, attributes)]
    return result
