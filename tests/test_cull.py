"""Adversarial cull: fail-open resolution, fixture replay, and session boundaries."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, cast

from ave.adapters import get_default_pack
from ave.adapters.python_authz.citations import Citation
from ave.adapters.python_authz.code_facts import CodeFactsStore
from ave.adapters.python_authz.cull import (
    FAIL_OPEN_BASES,
    Stance,
    SubmittedStance,
    _execute,
    fail_open,
    partition_batch,
    redacted_case,
    resolve_submitted,
    review_one,
)
from ave.adapters.python_authz.llm_finder import AcceptedCandidate, LLMFinder
from ave.adapters.python_authz.model import FixtureModelClient, ToolCall, ToolResult
from ave.adapters.python_authz.pack import FIXTURES_DIR, _bind_anchor
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


def test_default_fixture_replay_keeps_eight_with_no_suppress_or_fail_open() -> None:
    batch = get_default_pack().find("target/dvrestaurant@d32d0997")
    assert len(batch.kept) == 8
    assert batch.suppressed == ()
    cull = batch.report["cull"]
    assert cull["reviewed"] == 8
    assert cull["kept"] == 8
    assert cull["suppressed"] == 0
    assert cull["fail_open"] == 0
    assert cull["bound_oracle_overrides"] == 0
    assert cull["client"] == "fixture"
    for review in cull["reviews"]:
        assert review["effective"] == "keep"
        assert review["basis"] == "validated"
        assert review["submitted"]["stance"] == "keep"
        assert any(hyp["kind"] == "ruled_out" for hyp in review["hypotheses"])
        assert review["submitted"] is not None


def test_redacted_case_omits_oracle_confidence_and_catalog() -> None:
    store = CodeFactsStore.build()
    report = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR)).find()
    anchor = next(c for c in report.accepted if c.record.symbol == "get_order")
    bound = AcceptedCandidate(
        record=anchor.record, finding=_bind_anchor(anchor.finding)
    )
    assert bound.finding["evidence"]["oracle"]
    assert bound.finding["confidence"] == 0.9
    case = redacted_case(bound)
    blob = json.dumps(case)
    assert "oracle" not in blob
    assert "confidence" not in blob
    assert "is_loop_anchor" not in blob
    assert "I-04" not in blob
    assert "catalog" not in blob
    assert "ground_truth" not in blob


def test_cull_tools_reject_list_candidates() -> None:
    result = _execute(CodeFactsStore.build(), ToolCall("list_candidates", {}))
    payload = json.loads(result.content)
    assert "error" in payload
    assert "list_candidates" in payload["error"]


class _ScriptedSession:
    def __init__(self, turns: list[list[ToolCall]]):
        self._turns = turns
        self._index = 0

    def respond(self, results: Sequence[ToolResult]) -> list[ToolCall]:
        del results
        if self._index >= len(self._turns):
            return []
        batch = self._turns[self._index]
        self._index += 1
        return batch


class _ScriptedClient:
    name = "fixture"

    def __init__(self, session: Any):
        self._session = session

    def begin(self, **kwargs: Any) -> Any:
        del kwargs
        return self._session


def _anchor_candidate() -> AcceptedCandidate:
    store = CodeFactsStore.build()
    report = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR)).find()
    anchor = next(c for c in report.accepted if c.record.symbol == "get_order")
    return AcceptedCandidate(record=anchor.record, finding=_bind_anchor(anchor.finding))


def test_missing_submit_fail_opens_keep() -> None:
    candidate = _anchor_candidate()
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _ScriptedClient(_ScriptedSession([])),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_missing"


def test_exhausted_budget_fail_opens_keep() -> None:
    candidate = _anchor_candidate()
    retrieval = ToolCall(
        "get_source",
        {"file": candidate.record.file},
    )
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _ScriptedClient(_ScriptedSession([[retrieval], [retrieval]])),
        budget=2,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_exhausted"


def test_invalid_identity_fail_opens_keep() -> None:
    candidate = _anchor_candidate()
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _ScriptedClient(
            _ScriptedSession(
                [
                    [
                        ToolCall(
                            "submit_review",
                            {
                                "location": "app/other.py:ghost",
                                "kind": candidate.finding["kind"],
                                "stance": "keep",
                                "reason": "x",
                                "cited_spans": [_CITATION.to_dict()],
                            },
                        )
                    ]
                ]
            )
        ),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_invalid"


def test_unavailable_fixture_fail_opens_keep() -> None:
    candidate = _anchor_candidate()

    class _Missing:
        name = "fixture"

        def begin(self, **kwargs: Any) -> Any:
            del kwargs
            raise FileNotFoundError("no recorded cull transcript")

    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _Missing(),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_unavailable"


def test_session_error_fail_opens_keep() -> None:
    candidate = _anchor_candidate()

    class _Boom:
        name = "fixture"

        def begin(self, **kwargs: Any) -> Any:
            del kwargs
            raise RuntimeError("model dropped")

    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _Boom(),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_session_error"
