"""Phase 7 — Verify.

Run the verification ladder — T0 build, T1 the flipped exploit oracle, T2 the full suite,
plus a re-attack — and only then mark the PR ready-to-merge. The invariant lives here
structurally: `ready_to_merge` can be True only with a fully green ladder AND a decision
record. The exploit oracle has **inverted polarity**: it passes (True) while the target is
vulnerable and must fail (False) once the fix holds — so T1 is "flipped", not "passed".

Skeleton: only T1 is a real check (the oracle flips on the pack's one instance). T0,
T2, and re-attack stay false until those rungs exist, so `ready_to_merge` stays false.
No selected finding or prepared change => an all-false ladder.

T1 has two runner shapes behind one rung. By default the hermetic in-process oracle
(`run_exploit`) supplies the flip. When the run opted into the pinned env and Prepare
actually ran it (`pinned_exploit["ran"]`), that pinned result's `flipped` — the by-path
oracle measured against the *real* target — supplies T1 instead. If the pinned run was
requested but did not run (env absent), the hermetic oracle still answers, so T1 is never
silently dropped.
"""

from __future__ import annotations

from typing import Any

from ave.adapters import get_default_pack
from ave.records.store import make_span, now_iso
from ave.state import AVEState, VerificationLadder


def _t1_from_pinned(pinned: dict[str, Any] | None) -> bool | None:
    """The pinned env's T1 verdict, or None when it did not run (fall back to hermetic)."""
    if not pinned or not pinned.get("ran"):
        return None
    return bool(pinned.get("flipped"))


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
    t1_runner = "none"

    if selected is not None and change is not None:
        pinned_t1 = _t1_from_pinned(state.get("pinned_exploit"))
        if pinned_t1 is not None:
            ladder["t1_exploit_oracle_flipped"] = pinned_t1
            t1_runner = "pinned"
        else:
            pack = get_default_pack()
            exploit_before = pack.run_exploit(selected, fixed=False)
            exploit_after = pack.run_exploit(selected, fixed=True)
            # T1 only. A nonempty patch is not a build; a legitimate-owner call is not
            # a full suite; a second exploit call is not a re-attack.
            ladder["t1_exploit_oracle_flipped"] = exploit_before and not exploit_after
            t1_runner = "hermetic"

    green = all(ladder.values())
    has_record = state.get("decision_record") is not None
    ready = green and has_record
    return {
        "verification": ladder,
        "ready_to_merge": ready,
        "spans": [
            make_span(
                "verify",
                started,
                {"ladder_green": green, "ready": ready, "t1_runner": t1_runner},
            )
        ],
    }
