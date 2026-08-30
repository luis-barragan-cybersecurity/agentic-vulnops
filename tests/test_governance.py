"""The landed governance surface (ticket 08): the pure `decide()` predicate machine, the
four HITL routes, the ring stop criterion, and the six SANS metrics computed from run records.

These exercise the schemas directly with constructed inputs — the same worked shape the
ticket-05 prototype validated — so the governance contract is guarded independent of the graph.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ave.metrics import compute_metrics
from ave.policy import (
    Autonomous,
    BlastRadius,
    Escalation,
    FixPlan,
    decide,
    load_policy,
    ring_stop_criterion,
)
from ave.records.run_record import ExceptionRecord, FindingLifecycle, RunRecord
from ave.records.store import build_run_record
from ave.runner import run_once
from ave.state import AVEState, Finding

_NOW = "2026-08-29T12:24:00+00:00"

_FINDING: Finding = {
    "id": "I-04",
    "kind": "object-ownership-gap",
    "location": "app/apis/orders/services/get_order_service.py:get_order",
    "confidence": 0.9,
    "evidence": {"oracle": {"path": "app/tests/vulns/ave_seed_bola_order_read.py"}},
}

# A helper-only, class-level fix within blast-radius limits — the standing-preauth shape.
_HELPER_FIX = FixPlan(
    changed_paths=["app/apis/orders/authorization.py", "app/apis/orders/dependencies.py"],
    is_class_level=True,
    preserves_legitimate_access=True,
)
_SMALL_BLAST = BlastRadius(files=2, dependents=6, routes=3)


def _policy() -> dict[str, object]:
    return load_policy()


# --- decide(): standing preauthorization ------------------------------------


def test_helper_only_class_level_fix_is_standing_preauthorized() -> None:
    decision = decide(_FINDING, _HELPER_FIX, _SMALL_BLAST, _policy(), now=_NOW)
    assert isinstance(decision, Autonomous)
    record = decision.record
    assert record.execution.route == "standing_preauthorized"
    assert record.execution.hitl_route is None
    assert record.decided_by == "agent"
    # The record is genuinely two-part and cites the policy + oracle + ground truth.
    assert record.response.classification == "object-ownership-gap"
    assert record.policy_version == "1.0.0"
    assert record.citations["oracle"].endswith("ave_seed_bola_order_read.py")
    assert record.citations["ground_truth"] == "catalog.ground_truth()#I-04"


# --- decide(): the three before_prepare HITL routes -------------------------


def test_out_of_policy_change_fires_when_a_predicate_fails() -> None:
    # A fix that edits a *_service.py business-logic file is not helper-only.
    fix = FixPlan(
        changed_paths=["app/apis/orders/authorization.py",
                       "app/apis/orders/orders_service.py"],
        is_class_level=True,
        preserves_legitimate_access=True,
    )
    decision = decide(_FINDING, fix, _SMALL_BLAST, _policy(), now=_NOW)
    assert isinstance(decision, Escalation)
    assert decision.route == "out_of_policy_change"
    assert decision.record_draft.execution.route == "hitl_approved"
    assert decision.record_draft.decided_by == "human"


def test_blast_radius_exceeded_fires_when_a_hard_limit_is_breached() -> None:
    big = BlastRadius(files=9, dependents=6, routes=3)  # max_files is 3
    decision = decide(_FINDING, _HELPER_FIX, big, _policy(), now=_NOW)
    assert isinstance(decision, Escalation)
    assert decision.route == "blast_radius_exceeded"


def test_unknown_blast_radius_fires_when_a_dimension_is_unmeasured() -> None:
    unknown = BlastRadius(files=2, dependents=None, routes=3)
    decision = decide(_FINDING, _HELPER_FIX, unknown, _policy(), now=_NOW)
    assert isinstance(decision, Escalation)
    assert decision.route == "unknown_blast_radius"


# --- the fourth route: failed_stop_criterion (before_execute ring gate) ------


def test_failed_stop_criterion_fires_when_a_ring_rung_is_unmet() -> None:
    policy = _policy()
    # caller ring requires t1_exploit_oracle_flipped + reattack_clean.
    unmet = {"t1_exploit_oracle_flipped": True, "reattack_clean": False}
    assert ring_stop_criterion(policy, "caller", unmet) == "failed_stop_criterion"

    met = {"t1_exploit_oracle_flipped": True, "reattack_clean": True}
    assert ring_stop_criterion(policy, "caller", met) is None


def test_all_four_hitl_routes_are_reachable() -> None:
    policy = _policy()
    routes = {
        decide(_FINDING, FixPlan(changed_paths=["app/apis/orders/models.py"],
                                 is_class_level=True, preserves_legitimate_access=True),
               _SMALL_BLAST, policy, now=_NOW).route,  # type: ignore[union-attr]
        decide(_FINDING, _HELPER_FIX, BlastRadius(files=99, dependents=6, routes=3),
               policy, now=_NOW).route,  # type: ignore[union-attr]
        decide(_FINDING, _HELPER_FIX, BlastRadius(files=None, dependents=6, routes=3),
               policy, now=_NOW).route,  # type: ignore[union-attr]
        ring_stop_criterion(policy, "pr", {"t0_build": False}),
    }
    assert routes == {
        "out_of_policy_change",
        "blast_radius_exceeded",
        "unknown_blast_radius",
        "failed_stop_criterion",
    }


# --- the six SANS metrics compute from run records --------------------------


def _t(hours: float) -> str:
    base = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
    return (base + timedelta(hours=hours)).isoformat()


def test_six_metrics_compute_from_run_records() -> None:
    # Two verified fixes, one failed verification, one accepted exception past review-due.
    records = [
        RunRecord(
            run_id="run_a", target_ref="dvrestaurant@d32d0997", policy_version="1.0.0",
            findings=[
                FindingLifecycle("I-04", _t(0), triaged_at=_t(0.4), verified_at=_t(1.6),
                                 outcome="verified_fixed"),
                FindingLifecycle("I-02", _t(0), triaged_at=_t(0.5), verified_at=_t(2.0),
                                 outcome="verified_fixed"),
            ],
            ready_to_merge=True, decision_record_present=True,
        ),
        RunRecord(
            run_id="run_b", target_ref="dvrestaurant@d32d0997", policy_version="1.0.0",
            findings=[
                FindingLifecycle("I-05", _t(0), triaged_at=_t(0.3),
                                 outcome="failed_verification"),
            ],
            exceptions=[ExceptionRecord("I-09", accepted_at=_t(0), review_due_at=_t(1.0))],
        ),
    ]
    as_of = _t(3.0)
    metrics = compute_metrics(records, as_of=as_of)

    # 1. exposure hours: two verified (1.6h, 2.0h)
    assert metrics["observed_exposure_hours"]["median"] == 1.8
    assert metrics["observed_exposure_hours"]["p90"] is not None
    # 2. absorption: 2 verified of 3 found (failed_verification still counts as found)
    assert metrics["absorption_ratio"] == round(2 / 3, 3)
    # 3. triage latency median across the three triaged findings (0.4, 0.5, 0.3)
    assert metrics["triage_latency_hours_median"] == 0.4
    # 4. change failure: 1 failed of 3 fix-attempts
    assert metrics["change_failure_rate"] == round(1 / 3, 3)
    # 5. verification rate: 2 verified of 3 fix-attempts (the thesis metric)
    assert metrics["verification_rate"] == round(2 / 3, 3)
    # 6. exception staleness: one exception, review-due at 1h, as_of 3h => 2h overdue
    assert metrics["exception_staleness_hours_median"] == 2.0
    assert metrics["counts"] == {"found": 3, "fixed": 2, "verified": 2, "false_positive": 0}


def test_metrics_are_null_not_crashing_on_an_empty_run() -> None:
    # v1's honest early state: nothing verified yet. All six compute, several are null.
    record = RunRecord(
        run_id="run_0", target_ref="t", policy_version="1.0.0",
        findings=[FindingLifecycle("I-04", _t(0), triaged_at=_t(0.4), outcome="open")],
    )
    metrics = compute_metrics([record], as_of=_t(1.0))
    assert metrics["observed_exposure_hours"]["median"] is None
    assert metrics["absorption_ratio"] == 0.0  # 0 verified of 1 found
    assert metrics["verification_rate"] is None  # no fix attempts yet
    assert metrics["exception_staleness_hours_median"] is None


# --- the schema is live: a real graph run produces it -----------------------

_INITIAL: AVEState = {
    "target_ref": "target/dvrestaurant@d32d0997",
    "policy_version": "1.0.0",
}


def test_graph_run_produces_a_two_part_decision_record() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    record = final.get("decision_record")
    assert record is not None
    # The Decide node called the pure decide(); the anchor is standing-preauthorized.
    assert record["execution"]["route"] == "standing_preauthorized"
    assert record["response"]["classification"] == "object-ownership-gap"
    assert record["citations"]["ground_truth"] == "catalog.ground_truth()#I-04"
    assert record["policy_version"] == "1.0.0"


def test_run_record_carries_the_finding_lifecycle() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    run_record = build_run_record(final)
    assert len(run_record.findings) == 1
    lifecycle = run_record.findings[0]
    assert lifecycle.finding_id == "I-04"
    assert lifecycle.first_observed_at is not None
    assert lifecycle.triaged_at is not None
    # The skeleton greens only T1, so the loop is honest: not verified, no exceptions.
    assert lifecycle.verified_at is None
    assert lifecycle.outcome == "open"
    assert run_record.exceptions == []
