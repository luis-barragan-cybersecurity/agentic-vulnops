"""Fail-open resolution and batch partition for the adversarial cull."""

from __future__ import annotations

from typing import Any, cast

from ave.adapters.python_authz.citations import Citation
from ave.adapters.python_authz.cull import (
    FAIL_OPEN_BASES,
    Stance,
    SubmittedStance,
    fail_open,
    partition_batch,
    resolve_submitted,
)
from ave.state import Finding

_CITATION = Citation(
    file="target/dvrestaurant/app/apis/orders/services/get_order_service.py",
    start_line=17,
    end_line=17,
    contains="Order.id == order_id",
)


def _finding(**over: Any) -> Finding:
    base: dict[str, Any] = {
        "id": "ave-llm-get_order_service-get_order",
        "kind": "object-ownership-gap",
        "location": "app/apis/orders/services/get_order_service.py:get_order",
        "confidence": 0.9,
        "source": "ave:llm-finder",
        "evidence": {"rationale": "no ownership binding"},
    }
    base.update(over)
    return cast("Finding", base)


def _stance(stance: Stance, *, reason: str = "argument") -> SubmittedStance:
    return SubmittedStance(
        stance=stance,
        reason=reason,
        citations=(_CITATION,),
        hypotheses=(),
    )


def _meta() -> dict[str, Any]:
    return {
        "location_key": "app/apis/orders/services/get_order_service.py:get_order",
        "prompt_versions": {"python_authz.llm_cull.system": 1},
        "client_mode": "fixture",
    }


def test_each_fail_open_basis_keeps_with_no_submitted_stance() -> None:
    finding = _finding()
    for basis in sorted(FAIL_OPEN_BASES):
        review = fail_open(finding, basis=basis, reason=basis, **_meta())
        assert review.submitted is None
        assert review.effective == "keep"
        assert review.basis == basis
        assert review.citations == ()
        assert review.hypotheses == ()


def test_validated_suppress_without_oracle_is_effective_suppress() -> None:
    finding = _finding()
    review = resolve_submitted(finding, _stance("suppress"), **_meta())
    assert review.submitted is not None
    assert review.submitted.stance == "suppress"
    assert review.effective == "suppress"
    assert review.basis == "validated"
    kept, suppressed = partition_batch([finding], [review])
    assert kept == ()
    assert suppressed == (finding,)


def test_bound_oracle_records_suppress_but_keeps_and_preserves_drivability() -> None:
    finding = _finding(
        evidence={
            "rationale": "no ownership binding",
            "oracle": {"path": "app/tests/vulns/x.py", "test": "t", "polarity": "inverted"},
            "is_loop_anchor": True,
        }
    )
    before = dict(finding["evidence"])
    confidence = finding["confidence"]
    review = resolve_submitted(finding, _stance("suppress", reason="looks guarded"), **_meta())
    assert review.submitted is not None
    assert review.submitted.stance == "suppress"
    assert review.effective == "keep"
    assert review.basis == "bound_oracle"
    assert finding["confidence"] == confidence
    assert finding["evidence"] == before
    kept, suppressed = partition_batch([finding], [review])
    assert kept == (finding,)
    assert suppressed == ()


def test_partition_without_a_review_keeps_the_finding() -> None:
    finding = _finding()
    kept, suppressed = partition_batch([finding], [])
    assert kept == (finding,)
    assert suppressed == ()
