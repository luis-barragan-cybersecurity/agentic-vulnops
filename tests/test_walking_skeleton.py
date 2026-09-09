"""The walking skeleton: one seeded instance walks all seven phases to a real PR, T1
flips, stub rungs stay false, and the run's artifacts persist to disk.

This is the Phase-1 end-to-end proof — the loop runs on one case and produces the first
run records. Later tickets deepen each phase; this test guards that the spine stays whole.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ave.adapters import get_default_pack
from ave.adapters.python_authz import catalog
from ave.invariant import invariant_holds
from ave.phases.verify import verify
from ave.policy import policy_version
from ave.records.store import build_run_record
from ave.runner import persist_run, run_once
from ave.state import AVEState

# Seed the run with the policy version decide() will actually cite, so a single run's
# decision record and run record agree on one version (not the scaffold's "0").
_INITIAL: AVEState = {
    "target_ref": "target/dvrestaurant@d32d0997",
    "policy_version": policy_version(),
}


def test_loop_runs_end_to_end_and_produces_a_pr() -> None:
    final = run_once(_INITIAL, auto_approve=True)

    assert final.get("human_approved") is True
    assert final.get("decision_record") is not None
    assert str(final.get("pr_ref")).startswith("local:pr/")
    assert final.get("verification") == {
        "t0_build": False,
        "t1_exploit_oracle_flipped": True,
        "t2_full_suite": False,
        "reattack_clean": False,
    }
    assert final.get("ready_to_merge") is False


def test_every_phase_recorded_a_span() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    phases = [s["phase"] for s in final.get("spans", [])]
    assert phases == ["intake", "match", "assess", "decide", "prepare", "execute", "verify"]


def test_run_record_persists_and_satisfies_the_invariant(tmp_path: Path) -> None:
    final = run_once(_INITIAL, auto_approve=True)
    artifacts = persist_run(final, base_dir=tmp_path)

    record_path = artifacts["run_record"]
    assert record_path.exists()
    doc = json.loads(record_path.read_text())
    assert doc["ready_to_merge"] is False
    assert doc["decision_record_present"] is True
    assert [s["phase"] for s in doc["spans"]] == [
        "intake", "match", "assess", "decide", "prepare", "execute", "verify"
    ]
    # The persisted record is what CI re-validates the invariant from.
    assert invariant_holds(build_run_record(final)) is True


def test_pr_bundle_written_with_patch_and_verdict(tmp_path: Path) -> None:
    final = run_once(_INITIAL, auto_approve=True)
    artifacts = persist_run(final, base_dir=tmp_path)

    body = artifacts["pr_body"].read_text()
    assert "Ready to merge: no" in body
    assert "object-ownership-gap (BOLA)" not in body
    assert "| Ruled out | How |" in body
    assert "already has an ownership guard" not in body.lower()
    assert "```diff" in body
    assert "Not an applicable diff" not in body
    patch = artifacts["patch"].read_text()
    assert "current_user" in patch
    assert "_skeleton_target.py" not in patch
    assert "get_order_service.py" in patch


def test_catalog_ground_truth_holds_every_seeded_instance() -> None:
    instances = catalog.ground_truth()
    assert len(instances) == 8
    assert [i["id"] for i in instances if i["evidence"]["is_loop_anchor"]] == ["I-04"]
    for i in instances:
        oracle = i["evidence"]["oracle"]
        assert oracle["path"].endswith(".py")
        assert oracle["polarity"] == "inverted"


def test_find_rediscovers_gaps_and_binds_one_drivable_anchor() -> None:
    batch = get_default_pack().find("target/dvrestaurant@d32d0997")
    findings = list(batch.kept)
    assert len(findings) > 1
    assert {f["source"] for f in findings} == {"ave:llm-finder"}
    drivable = [f for f in findings if f["evidence"].get("is_loop_anchor")]
    assert len(drivable) == 1
    assert drivable[0]["location"] == catalog.anchor_location()
    assert drivable[0]["evidence"]["oracle"]["polarity"] == "inverted"
    assert batch.suppressed == ()


def test_non_anchor_instances_are_not_claimed() -> None:
    pack = get_default_pack()
    other = next(i for i in catalog.ground_truth() if i["id"] == "I-03")

    with pytest.raises(NotImplementedError, match="I-03"):
        pack.blast_radius(other)
    with pytest.raises(NotImplementedError, match="I-03"):
        pack.fix_plan(other)
    with pytest.raises(NotImplementedError, match="I-03"):
        pack.prepare_fix(other)
    with pytest.raises(NotImplementedError, match="I-03"):
        pack.run_exploit(other, fixed=False)


def test_exploit_oracle_has_inverted_polarity() -> None:
    pack = get_default_pack()
    findings = pack.find("target/dvrestaurant@d32d0997").kept
    anchor = next(f for f in findings if pack.can_drive(f))
    # Inverted polarity: exploit SUCCEEDS while vulnerable, is BLOCKED once fixed.
    assert pack.run_exploit(anchor, fixed=False) is True
    assert pack.run_exploit(anchor, fixed=True) is False
    # The fix must not break legitimate owner access.
    assert pack.legitimate_use_holds(fixed=True) is True


def test_nothing_is_claimed_without_a_green_ladder() -> None:
    # The invariant's structural point: no finding => an all-false ladder => not ready,
    # even though a (finding-less) decision record is present.
    out = verify({"decision_record": {"x": 1}, "selected_finding": None})
    assert out["ready_to_merge"] is False
    assert not any(out["verification"].values())
