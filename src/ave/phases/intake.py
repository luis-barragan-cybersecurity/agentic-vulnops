"""Phase 1 — Intake.

Pin the target under review and the policy version this run obeys, and open the run
record. Stub: records the inputs it was given.
"""

from __future__ import annotations

from ave.state import AVEState


def intake(state: AVEState) -> AVEState:
    return {
        "target_ref": state.get("target_ref", "unset"),
        "policy_version": state.get("policy_version", "unset"),
        "findings": [],
    }
