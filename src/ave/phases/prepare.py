"""Phase 5 — Prepare.

After the human approves at the gate, prepare the class-level change — a fix that removes
the whole class of the flaw, not one instance — via the language pack's fix template. The
change carries a real unified-diff patch and its blast radius. No finding selected => no
change (the loop stays honest). The generated patch must touch exactly the fix plan's
`changed_paths`: the policy decision was made over those paths, so a patch outside them
was never decided and fails closed here, before Execute.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ave.adapters import get_default_pack
from ave.adapters.base import PinnedEnvCapable
from ave.records.store import make_span, now_iso
from ave.state import AVEState, PinnedExploitResult


class PatchScopeMismatch(RuntimeError):
    """The generated patch touches different files than the fix plan Decide evaluated."""


def prepare(state: AVEState) -> AVEState:
    started = now_iso()
    selected = state.get("selected_finding")
    pack = get_default_pack()
    run_root = Path("results/runs") / str(state.get("run_record_id") or "unset")
    bind = getattr(pack, "bind_run", None)
    if callable(bind):
        bind(run_root)
    change = pack.prepare_fix(selected) if selected is not None else None
    if change is not None:
        proposed = tuple(
            sorted(
                set(state.get("assessment", {}).get("fix_plan", {}).get("changed_paths", []))
            )
        )
        actual = tuple(change.get("patch_paths", ()))
        if actual != proposed:
            raise PatchScopeMismatch(
                f"patch touches {list(actual)} but the fix plan proposed {list(proposed)}"
            )

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
