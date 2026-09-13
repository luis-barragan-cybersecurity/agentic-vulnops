"""Phase 7 — Verify.

Run the verification ladder — T0 build, T1 the flipped exploit oracle, T2 the full suite,
plus a re-attack — and only then mark the PR ready-to-merge. The invariant lives here
structurally: `ready_to_merge` can be True only with a fully green ladder AND a decision
record. The exploit oracle has **inverted polarity**: it passes (True) while the target is
vulnerable and must fail (False) once the fix holds — so T1 is "flipped", not "passed".

Unpinned T1 stays false. Pinned T1 is green only from a stored pinned success.
T0, T2, and re-attack stay false until those rungs exist, so `ready_to_merge` stays false.
No selected finding or prepared change => an all-false ladder.
"""

from __future__ import annotations

from typing import Any

from ave.records.store import make_span, now_iso
from ave.state import AVEState, PinnedExploitResult, VerificationLadder


def _pinned_t1(pinned: PinnedExploitResult | None) -> bool:
    if not pinned:
        return False
    return pinned.get("status") == "success" and bool(pinned.get("flipped"))


def verify(state: AVEState) -> AVEState:
    started = now_iso()
    selected = state.get("selected_finding")
    change = state.get("prepared_change")

    ladder: VerificationLadder = {
        "t0_build": False,
        "t1_exploit_oracle_flipped": False,
        "t2_full_suite": False,
        "reattack_clean": False,
    }
    attributes: dict[str, Any] = {}

    if selected is not None and change is not None:
        if state.get("use_pinned_env"):
            pinned = state.get("pinned_exploit")
            ladder["t1_exploit_oracle_flipped"] = _pinned_t1(pinned)
            attributes["t1_runner"] = "pinned"
            if pinned is not None:
                attributes["pinned_status"] = pinned["status"]
                attributes["pinned_detail"] = pinned.get("detail")
        else:
            ladder["t1_exploit_oracle_flipped"] = False

    green = all(ladder.values())
    has_record = state.get("decision_record") is not None
    ready = green and has_record
    attributes["ladder_green"] = green
    attributes["ready"] = ready
    return {
        "verification": ladder,
        "ready_to_merge": ready,
        "spans": [make_span("verify", started, attributes)],
    }
