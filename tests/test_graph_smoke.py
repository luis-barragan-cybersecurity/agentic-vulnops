"""Smoke test: the seven-phase graph builds, halts at the HITL gate, and — once approved —
walks to completion. The end-to-end skeleton behavior is covered in test_walking_skeleton."""

from __future__ import annotations

from ave.graph import HITL_GATE_BEFORE
from ave.phases import PHASE_ORDER
from ave.policy import policy_version
from ave.runner import paused_at_gate, run_once
from ave.state import AVEState

_INITIAL: AVEState = {
    "target_ref": "skeleton://python_authz/bola-order-owner",
    "policy_version": policy_version(),
}


def test_phase_order_is_the_seven_phases() -> None:
    assert PHASE_ORDER == (
        "intake",
        "match",
        "assess",
        "decide",
        "prepare",
        "execute",
        "verify",
    )


def test_hitl_gate_is_declared_before_prepare() -> None:
    assert HITL_GATE_BEFORE == "prepare"


def test_run_halts_at_the_hitl_gate_before_approval() -> None:
    # The boundary is real: a fresh run stops before Prepare and waits for a human.
    assert paused_at_gate(_INITIAL) is True

    paused = run_once(_INITIAL, auto_approve=False)
    assert paused.get("decision_record") is not None  # Decide ran
    assert paused.get("pr_ref") is None  # Prepare/Execute did not
    assert paused.get("ready_to_merge") is None
