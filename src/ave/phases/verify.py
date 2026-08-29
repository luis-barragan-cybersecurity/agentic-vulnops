"""Phase 7 — Verify.

Run the verification ladder — T0 build, T1 the flipped exploit oracle, T2 the full suite,
plus a re-attack — and only then mark the PR ready-to-merge. The invariant lives here
structurally: `ready_to_merge` can be True only with a fully green ladder AND a decision
record. The exploit oracle has **inverted polarity**: it passes (True) while the target is
vulnerable and must fail (False) once the fix holds — so T1 is "flipped", not "passed".

Skeleton: the ladder is run for real against the `python_authz` pack's one instance. No
selected finding or prepared change => an all-false ladder, so nothing is ever falsely
claimed.
"""

from __future__ import annotations

from ave.adapters import get_default_pack
from ave.records.store import make_span, now_iso
from ave.state import AVEState, VerificationLadder


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

    if selected is not None and change is not None:
        pack = get_default_pack()
        exploit_before = pack.run_exploit(selected, fixed=False)  # True == vulnerable
        exploit_after = pack.run_exploit(selected, fixed=True)  # False == fix holds
        ladder = {
            "t0_build": bool(change.get("patch")),
            # Flipped: the oracle succeeded before the fix and is blocked after it.
            "t1_exploit_oracle_flipped": exploit_before and not exploit_after,
            "t2_full_suite": pack.legitimate_use_holds(fixed=True),
            "reattack_clean": not pack.run_exploit(selected, fixed=True),
        }

    green = all(ladder.values())
    has_record = state.get("decision_record") is not None
    ready = green and has_record
    return {
        "verification": ladder,
        "ready_to_merge": ready,
        "spans": [make_span("verify", started, {"ladder_green": green, "ready": ready})],
    }
