"""The measured blast-radius pass (ticket 28): `find()` measures every accepted
candidate against the store it already holds, `blast_radius()` projects that record,
and every reader goes through the `from_finding` boundary — a forged or corrupt record
is "unmeasured", never a crash and never a number.
"""

from __future__ import annotations

import copy
import dataclasses
from pathlib import Path

import pytest

from ave.adapters.python_authz.code_facts import CodeFactsStore
from ave.adapters.python_authz.llm_finder import AcceptedCandidate
from ave.adapters.python_authz.measurement import (
    MEASUREMENT_KEY,
    BlastRadiusMeasurement,
    measured_finding,
)
from ave.adapters.python_authz.pack import PythonAuthzPack
from ave.phases.prepare import PatchScopeMismatch, prepare
from ave.policy import policy_version
from ave.pr import _one_fact
from ave.runner import run_once
from ave.state import AVEState, Finding

_INITIAL: AVEState = {
    "target_ref": "target/dvrestaurant@d32d0997",
    "policy_version": policy_version(),
}

_ANCHOR_ID = "ave-llm-get_order_service-get_order"
_ANCHOR_HANDLER = "target/dvrestaurant/app/apis/orders/services/get_order_service.py:get_order"
_MENU_HANDLER = (
    "target/dvrestaurant/app/apis/menu/services/update_menu_item_service.py:update_menu_item"
)


@pytest.fixture(scope="module")
def pack() -> PythonAuthzPack:
    return PythonAuthzPack()


@pytest.fixture(scope="module")
def kept(pack: PythonAuthzPack) -> tuple[Finding, ...]:
    return pack.find("target/dvrestaurant@d32d0997").kept


def _by_id(kept: tuple[Finding, ...], finding_id: str) -> Finding:
    return next(f for f in kept if f["id"] == finding_id)


def test_anchor_is_measured_through_the_pack(
    pack: PythonAuthzPack, kept: tuple[Finding, ...]
) -> None:
    anchor = _by_id(kept, _ANCHOR_ID)
    assert (
        anchor["evidence"]["review_location"]
        == "app/apis/orders/services/get_order_service.py:11"
    )
    blast = pack.blast_radius(anchor)
    assert blast["files"] == 1
    assert blast["dependents"] == 0
    assert blast["routes"] == 1
    assert blast["fact"]["how_sure"] == 5
    assert blast["fact"]["statement"] == (
        "The AST inventory identifies get_order as the GET /orders/{order_id} route "
        "handler. A complete caller-index query found no dependent call sites in the "
        "allowlisted tree."
    )
    assert blast["fact"]["citations"] == [
        {
            "file": "target/dvrestaurant/app/apis/orders/services/get_order_service.py",
            "start_line": 11,
            "end_line": 20,
            "contains": "def get_order(",
        }
    ]
    assert "changed_symbol" not in blast


def test_measured_dependents_covers_all_eight_fixture_findings(
    pack: PythonAuthzPack, kept: tuple[Finding, ...]
) -> None:
    assert pack.measured_dependents(kept) == {
        "ave-llm-update_profile_service-update_profile": 0,
        "ave-llm-delete_menu_item_service-delete_menu_item": 0,
        "ave-llm-update_menu_item_service-update_menu_item": 0,
        "ave-llm-get_order_service-get_order": 0,
        "ave-llm-get_orders_for_delivery_service-get_orders": 0,
        "ave-llm-service-get_discount_coupons": 0,
        "ave-llm-service-get_referral_code_endpoint": 0,
        "ave-llm-update_user_role_service-update_user_role": 0,
    }


def test_measured_but_undrivable_finding_is_readable(
    pack: PythonAuthzPack, kept: tuple[Finding, ...]
) -> None:
    menu = _by_id(kept, "ave-llm-update_menu_item_service-update_menu_item")
    assert pack.can_drive(menu) is False
    assert pack.blast_radius(menu)["dependents"] == 0

    unmeasured: Finding = {
        "id": "foreign-1",
        "kind": "object-ownership-gap",
        "location": "app/other.py:handler",
        "evidence": {},
    }
    with pytest.raises(NotImplementedError, match="foreign-1"):
        pack.blast_radius(unmeasured)


def test_incomplete_reach_withholds_the_counts_and_the_fact(
    pack: PythonAuthzPack, kept: tuple[Finding, ...]
) -> None:
    mutated = copy.deepcopy(_by_id(kept, _ANCHOR_ID))
    mutated["evidence"][MEASUREMENT_KEY]["unresolved_edges"] = [
        {
            "caller_file": "target/dvrestaurant/app/x.py",
            "caller_symbol": "f",
            "line": 1,
            "callee_name": "get_order",
            "reason": "unbound_name",
        }
    ]
    blast = pack.blast_radius(mutated)
    assert blast["dependents"] is None
    assert blast["routes"] is None
    assert blast["files"] == 1
    assert blast["fact"] is None
    assert any("**Unproven.**" in line for line in _one_fact(blast))


def test_rejected_citation_withholds_only_the_fact(pack: PythonAuthzPack) -> None:
    store = CodeFactsStore.build()
    record = store.get_handler(_ANCHOR_HANDLER)
    forged_span = dataclasses.replace(record, line_start=9000, line_end=9001)
    candidate = AcceptedCandidate(
        record=forged_span,
        finding={
            "id": _ANCHOR_ID,
            "kind": "object-ownership-gap",
            "location": "app/apis/orders/services/get_order_service.py:get_order",
            "evidence": {},
        },
    )
    measured = measured_finding(
        store, candidate, changed_paths=["app/apis/orders/services/get_order_service.py"]
    )
    assert measured["evidence"][MEASUREMENT_KEY]["provenance"] is None
    assert measured["evidence"][MEASUREMENT_KEY]["citations"] == []
    blast = pack.blast_radius(measured)
    assert blast["fact"] is None
    assert blast["dependents"] == 0  # the reach is still measured; only the fact is withheld


def test_forged_handler_identity_reads_as_unmeasured(
    pack: PythonAuthzPack, kept: tuple[Finding, ...]
) -> None:
    forged = copy.deepcopy(_by_id(kept, _ANCHOR_ID))
    forged["evidence"][MEASUREMENT_KEY]["handler_id"] = _MENU_HANDLER
    assert BlastRadiusMeasurement.from_finding(forged) is None
    assert pack.measured_dependents([forged]) == {}


def test_prepared_patch_paths_equal_the_fix_plan(
    pack: PythonAuthzPack, kept: tuple[Finding, ...], tmp_path: Path
) -> None:
    anchor = copy.deepcopy(_by_id(kept, _ANCHOR_ID))
    pack.bind_run(tmp_path)
    fix = pack.prepare_fix(anchor)
    assert fix["patch_paths"] == ("app/apis/orders/services/get_order_service.py",)
    assert fix["patch_paths"] == tuple(pack.fix_plan(anchor)["changed_paths"])


def test_prepare_fails_closed_when_the_patch_leaves_the_decided_scope(
    kept: tuple[Finding, ...],
) -> None:
    state: AVEState = {
        "selected_finding": copy.deepcopy(_by_id(kept, _ANCHOR_ID)),
        "assessment": {"fix_plan": {"changed_paths": ["app/other.py"]}},
        "run_record_id": "blast-radius-scope-mismatch",
    }
    with pytest.raises(PatchScopeMismatch, match=r"app/other\.py"):
        prepare(state)


def test_measurement_roundtrips_and_unknown_provenance_degrades(
    kept: tuple[Finding, ...],
) -> None:
    anchor = _by_id(kept, _ANCHOR_ID)
    measurement = BlastRadiusMeasurement.from_finding(anchor)
    assert measurement is not None
    assert measurement.to_dict() == anchor["evidence"][MEASUREMENT_KEY]

    made_up = copy.deepcopy(anchor)
    made_up["evidence"][MEASUREMENT_KEY]["provenance"] = "made_up"
    parsed = BlastRadiusMeasurement.from_finding(made_up)
    assert parsed is not None
    assert parsed.provenance is None


def test_assess_decision_and_prepared_change_agree_on_the_counts() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    assess = next(span for span in final["spans"] if span["phase"] == "assess")
    assess_blast = assess["attributes"]["blast_radius"]
    assert {k: assess_blast[k] for k in ("files", "dependents", "routes")} == {
        "files": 1,
        "dependents": 0,
        "routes": 1,
    }
    prepared = final["prepared_change"]["blast_radius"]
    for key in ("files", "dependents", "routes", "fact"):
        assert prepared[key] == assess_blast[key]
    assert assess_blast["fact"] == {
        "statement": (
            "The AST inventory identifies get_order as the GET /orders/{order_id} route "
            "handler. A complete caller-index query found no dependent call sites in the "
            "allowlisted tree."
        ),
        "provenance": "ast_resolved",
        "how_sure": 5,
        "proof": (
            "The inventory cites "
            "target/dvrestaurant/app/apis/orders/services/get_order_service.py:11-20. "
            "The recorded reach is complete, and dependent_sites is empty."
        ),
        "citations": [
            {
                "file": "target/dvrestaurant/app/apis/orders/services/get_order_service.py",
                "start_line": 11,
                "end_line": 20,
                "contains": "def get_order(",
            }
        ],
    }
    assert final["decision_record"]["execution"]["blast_radius"] == {
        "files": 1,
        "dependents": 0,
        "routes": 1,
    }
    assert final["prepared_change"]["patch_paths"] == (
        "app/apis/orders/services/get_order_service.py",
    )


def test_measurement_record_shape_on_the_anchor(kept: tuple[Finding, ...]) -> None:
    measurement = BlastRadiusMeasurement.from_finding(_by_id(kept, _ANCHOR_ID))
    assert measurement is not None
    assert measurement.to_dict() == {
        "provenance": "ast_resolved",
        "handler_id": (
            "target/dvrestaurant/app/apis/orders/services/get_order_service.py:get_order"
        ),
        "symbol_resolved": True,
        "reach_complete": True,
        "changed_paths": ["app/apis/orders/services/get_order_service.py"],
        "dependent_sites": [],
        "affected_routes": [
            {
                "handler_id": (
                    "target/dvrestaurant/app/apis/orders/services/"
                    "get_order_service.py:get_order"
                ),
                "method": "GET",
                "path": "/orders/{order_id}",
            }
        ],
        "unresolved_edges": [],
        "citations": [
            {
                "file": "target/dvrestaurant/app/apis/orders/services/get_order_service.py",
                "start_line": 11,
                "end_line": 20,
                "contains": "def get_order(",
            }
        ],
    }
