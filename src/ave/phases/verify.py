"""Phase 7 — Verify.

Run the verification ladder — T0 build, T1 the flipped exploit oracle, T2 the full
suite, plus a re-attack — and only then mark the PR ready-to-merge. The invariant lives
here structurally: `ready_to_merge` can be True only with a fully green ladder and a
decision record. Stub: computes readiness from an all-false ladder (so nothing is ever
falsely claimed).
"""

from __future__ import annotations

from ave.state import AVEState, VerificationLadder


def verify(state: AVEState) -> AVEState:
    ladder: VerificationLadder = {
        "t0_build": False,
        "t1_exploit_oracle_flipped": False,
        "t2_full_suite": False,
        "reattack_clean": False,
    }
    green = all(ladder.values())
    has_record = state.get("decision_record") is not None
    return {"verification": ladder, "ready_to_merge": green and has_record}
