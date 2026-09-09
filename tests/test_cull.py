from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, cast

import pytest

from ave.adapters import get_default_pack
from ave.adapters.python_authz import catalog
from ave.adapters.python_authz.citations import Citation
from ave.adapters.python_authz.code_facts import CodeFactsStore
from ave.adapters.python_authz.cull import (
    CULL_TOOL_SCHEMAS,
    FAIL_OPEN_BASES,
    SUBMIT_REVIEW,
    Stance,
    SubmittedStance,
    attach_review,
    cull_attributes,
    fail_open,
    pair_reviews,
    redacted_case,
    resolve_submitted,
    review_accepted,
    review_one,
)
from ave.adapters.python_authz.inventory import InventoryRecord
from ave.adapters.python_authz.llm_finder import (
    ROLE_GAP,
    AcceptedCandidate,
    LLMFinder,
)
from ave.adapters.python_authz.model import FixtureModelClient, ToolCall, ToolResult
from ave.adapters.python_authz.pack import FIXTURES_DIR, _bind_anchor
from ave.adapters.python_authz.tools import CULL_RETRIEVAL, execute_retrieval
from ave.prompts import load_prompt
from ave.state import Finding

_CITATION = Citation(
    file="target/dvrestaurant/app/apis/orders/services/get_order_service.py",
    start_line=17,
    end_line=17,
    contains="Order.id == order_id",
)


def _record() -> InventoryRecord:
    return InventoryRecord(
        handler_id="app/x.py:handler",
        method="GET",
        path="/x",
        file="target/dvrestaurant/app/x.py",
        symbol="handler",
        line_start=1,
        line_end=2,
        inputs=(),
        dependencies=(),
        auth_dependencies=(),
        mutates_state=False,
        models_queried=(),
        query_filters=(),
        identity_guards=(),
        caller_identity_reaches_query=False,
    )


def _accepted(finding: Finding) -> AcceptedCandidate:
    return AcceptedCandidate(record=_record(), finding=finding)


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
    kept, suppressed = pair_reviews([_accepted(finding)], [review])
    assert kept == ()
    assert [item["id"] for item in suppressed] == [finding["id"]]
    assert suppressed[0]["evidence"]["counter_review"]["effective"] == "suppress"


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
    kept, suppressed = pair_reviews([_accepted(finding)], [review])
    assert suppressed == ()
    assert [item["id"] for item in kept] == [finding["id"]]
    assert kept[0]["evidence"]["counter_review"]["basis"] == "bound_oracle"


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
    for finding in batch.kept:
        review = finding["evidence"]["counter_review"]
        assert review["submitted"]["stance"] == "keep"
        assert review["effective"] == "keep"
        assert review["reason"]
        assert review["citations"]
        assert review["hypotheses"]
        assert review["basis"] == "validated"
        assert review["prompt_versions"]
        assert review["client_mode"] == "fixture"
        assert any(hyp["kind"] == "ruled_out" for hyp in review["hypotheses"])
        cite = review["hypotheses"][0]["citations"][0]
        assert cite["end_line"] >= cite["start_line"]
        assert cite["end_line"] > cite["start_line"]
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
    result = execute_retrieval(
        CodeFactsStore.build(),
        ToolCall("list_candidates", {}),
        allowed=CULL_RETRIEVAL,
    )
    payload = json.loads(result.content)
    assert payload == {"error": "unknown tool 'list_candidates'"}


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


def _non_anchor_candidate() -> AcceptedCandidate:
    store = CodeFactsStore.build()
    report = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR)).find()
    other = next(c for c in report.accepted if c.record.symbol != "get_order")
    return other


def _cited_review(
    candidate: AcceptedCandidate,
    *,
    stance: Stance,
    hyp_kind: str,
    reason: str = "cited argument",
    hypotheses: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    evidence = candidate.finding.get("evidence", {})
    cites = list(evidence.get("citations") or [])
    payload: dict[str, Any] = {
        "location": candidate.finding["location"],
        "kind": candidate.finding["kind"],
        "stance": stance,
        "reason": reason,
        "cited_spans": cites,
    }
    if hypotheses is not None:
        payload["hypotheses"] = hypotheses
    else:
        payload["hypotheses"] = [
            {"kind": hyp_kind, "claim": "a cited claim", "cited_spans": cites}
        ]
    return payload


def _submit_client(payload: dict[str, Any]) -> _ScriptedClient:
    return _ScriptedClient(
        _ScriptedSession([[ToolCall("submit_review", payload)]])
    )


def test_review_one_suppress_without_oracle_is_suppressed() -> None:
    candidate = _non_anchor_candidate()
    assert not (candidate.finding.get("evidence") or {}).get("oracle")
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _submit_client(
            _cited_review(candidate, stance="suppress", hyp_kind="supports_suppress")
        ),
        budget=8,
        prompt_versions={"python_authz.llm_cull.system": 1},
    )
    assert review.submitted is not None
    assert review.submitted.stance == "suppress"
    assert review.effective == "suppress"
    assert review.basis == "validated"
    attached = attach_review(candidate.finding, review)
    payload = attached["evidence"]["counter_review"]
    assert payload["submitted"]["stance"] == "suppress"
    assert payload["effective"] == "suppress"
    assert payload["reason"]
    assert payload["citations"]
    assert payload["hypotheses"]
    assert payload["basis"] == "validated"
    assert payload["prompt_versions"] == {"python_authz.llm_cull.system": 1}
    assert payload["client_mode"] == "fixture"
    kept, suppressed = pair_reviews(
        [AcceptedCandidate(record=candidate.record, finding=candidate.finding)],
        [review],
    )
    assert kept == ()
    assert suppressed[0]["evidence"]["counter_review"]["effective"] == "suppress"


def test_review_one_suppress_against_bound_anchor_keeps_with_bound_oracle() -> None:
    candidate = _anchor_candidate()
    assert candidate.finding["evidence"]["oracle"]
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _submit_client(
            _cited_review(candidate, stance="suppress", hyp_kind="supports_suppress")
        ),
        budget=8,
        prompt_versions={"python_authz.llm_cull.system": 1},
    )
    assert review.submitted is not None
    assert review.submitted.stance == "suppress"
    assert review.effective == "keep"
    assert review.basis == "bound_oracle"


def test_blank_reason_fail_opens_invalid() -> None:
    candidate = _non_anchor_candidate()
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _submit_client(
            _cited_review(
                candidate,
                stance="keep",
                hyp_kind="ruled_out",
                reason="   ",
            )
        ),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_invalid"
    assert "reason" in review.reason


def test_missing_hypotheses_fail_opens_invalid() -> None:
    candidate = _non_anchor_candidate()
    payload = _cited_review(candidate, stance="keep", hyp_kind="ruled_out")
    del payload["hypotheses"]
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _submit_client(payload),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_invalid"
    assert "hypothesis" in review.reason


def test_keep_with_supports_suppress_hypothesis_fail_opens_invalid() -> None:
    candidate = _non_anchor_candidate()
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _submit_client(
            _cited_review(candidate, stance="keep", hyp_kind="supports_suppress")
        ),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_invalid"


def test_suppress_with_ruled_out_hypothesis_fail_opens_invalid() -> None:
    candidate = _non_anchor_candidate()
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _submit_client(_cited_review(candidate, stance="suppress", hyp_kind="ruled_out")),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_invalid"


def test_review_accepted_opens_a_fresh_empty_session_per_candidate() -> None:
    store = CodeFactsStore.build()
    report = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR)).find()
    accepted = report.accepted[:3]
    begins: list[str] = []
    first_results: list[list[ToolResult]] = []

    class _SpySession:
        def __init__(self) -> None:
            self._first = True

        def respond(self, results: Sequence[ToolResult]) -> list[ToolCall]:
            if self._first:
                first_results.append(list(results))
                self._first = False
            return []

    class _SpyClient:
        name = "spy"

        def begin(self, **kwargs: Any) -> _SpySession:
            begins.append(str(kwargs["candidate_id"]))
            return _SpySession()

    reviews = review_accepted(store, accepted, _SpyClient())
    assert begins == [candidate.record.handler_id for candidate in accepted]
    assert len(first_results) == len(accepted)
    assert all(results == [] for results in first_results)
    assert len(reviews) == len(accepted)


def test_cull_setup_failure_fail_opens_each_accepted(monkeypatch: Any) -> None:
    store = CodeFactsStore.build()
    report = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR)).find()
    accepted = report.accepted[:2]

    def _boom() -> dict[str, int]:
        raise KeyError("cull prompts unavailable")

    monkeypatch.setattr(
        "ave.adapters.python_authz.cull.prompt_versions", _boom
    )
    reviews = review_accepted(store, accepted, FixtureModelClient(fixtures_dir=FIXTURES_DIR))
    assert len(reviews) == 2
    assert {review.basis for review in reviews} == {"fail_open_unavailable"}
    assert all(review.effective == "keep" for review in reviews)
    assert all(review.submitted is None for review in reviews)


def test_two_submit_reviews_in_one_batch_is_fail_open_invalid() -> None:
    candidate = _non_anchor_candidate()
    keep = _cited_review(candidate, stance="keep", hyp_kind="ruled_out")
    suppress = _cited_review(candidate, stance="suppress", hyp_kind="supports_suppress")
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _ScriptedClient(
            _ScriptedSession(
                [
                    [
                        ToolCall("submit_review", keep),
                        ToolCall("submit_review", suppress),
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
    assert "exactly one submit_review" in review.reason


def test_pair_reviews_keeps_duplicate_location_kind_as_separate_rows() -> None:
    first = _finding(id="first")
    second = _finding(id="second")
    keep = resolve_submitted(first, _stance("keep"), **_meta())
    suppress = resolve_submitted(second, _stance("suppress"), **_meta())
    kept, suppressed = pair_reviews([_accepted(first), _accepted(second)], [keep, suppress])
    assert [item["id"] for item in kept] == ["first"]
    assert [item["id"] for item in suppressed] == ["second"]
    assert kept[0]["evidence"]["counter_review"]["effective"] == "keep"
    assert suppressed[0]["evidence"]["counter_review"]["effective"] == "suppress"


def test_role_gap_at_anchor_is_not_bound_protected_or_drivable() -> None:
    loc = catalog.anchor_location()
    finding = _finding(kind=ROLE_GAP, location=loc)
    bound = _bind_anchor(finding)
    assert bound["evidence"] == finding["evidence"]
    assert "oracle" not in bound["evidence"]
    assert not bound["evidence"].get("is_loop_anchor")
    review = resolve_submitted(
        bound,
        _stance("suppress"),
        location_key=loc,
        prompt_versions={},
        client_mode="fixture",
    )
    assert review.basis == "validated"
    assert review.effective == "suppress"
    smuggled = _finding(
        kind=ROLE_GAP,
        location=loc,
        evidence={
            "oracle": {"path": "app/tests/x.py", "test": "t", "polarity": "inverted"},
            "is_loop_anchor": True,
        },
    )
    assert get_default_pack().can_drive(_bind_anchor(smuggled)) is False
    assert get_default_pack().can_drive(smuggled) is False


def test_review_one_sends_exact_redacted_user_and_cull_tools() -> None:
    store = CodeFactsStore.build()
    report = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR)).find()
    candidate = _anchor_candidate()
    captured: dict[str, Any] = {}

    class _Capture:
        name = "fixture"

        def begin(self, **kwargs: Any) -> Any:
            captured.update(kwargs)
            raise FileNotFoundError("stop after capture")

    review = review_one(
        store,
        candidate,
        _Capture(),
        budget=8,
        prompt_versions={},
    )
    assert review.basis == "fail_open_unavailable"
    case = redacted_case(candidate)
    expected_user = load_prompt("python_authz.llm_cull.candidate").format(
        case=json.dumps(case, indent=2)
    )
    assert captured["user"] == expected_user
    assert captured["tools"] == CULL_TOOL_SCHEMAS
    assert captured["terminal_tool"] == SUBMIT_REVIEW
    assert "list_candidates" not in [tool["name"] for tool in captured["tools"]]
    blob = captured["user"]
    assert "oracle" not in blob
    assert "confidence" not in blob
    assert "catalog" not in blob
    assert "list_candidates" not in blob
    for other in report.accepted:
        if other.record.handler_id != candidate.record.handler_id:
            assert other.record.handler_id not in blob


def test_redaction_leak_aborts_before_begin(monkeypatch: Any) -> None:
    began: list[object] = []

    class _Capture:
        name = "fixture"

        def begin(self, **kwargs: Any) -> Any:
            began.append(kwargs)
            raise AssertionError("begin must not run")

    monkeypatch.setattr(
        "ave.adapters.python_authz.cull.redacted_case",
        lambda candidate: {"location": "x", "oracle": {"path": "leaked"}},
    )
    with pytest.raises(ValueError, match="leaked"):
        review_one(
            CodeFactsStore.build(),
            _anchor_candidate(),
            _Capture(),
            budget=8,
            prompt_versions={},
        )
    assert began == []


def test_null_hypothesis_is_fail_open_invalid_not_session_error() -> None:
    candidate = _non_anchor_candidate()
    payload = _cited_review(candidate, stance="keep", hyp_kind="ruled_out")
    payload["hypotheses"] = [None]
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _submit_client(payload),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_invalid"


def test_null_citation_item_is_fail_open_invalid_not_session_error() -> None:
    candidate = _non_anchor_candidate()
    payload = _cited_review(candidate, stance="keep", hyp_kind="ruled_out")
    payload["cited_spans"] = [None]
    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _submit_client(payload),
        budget=8,
        prompt_versions={},
    )
    assert review.submitted is None
    assert review.effective == "keep"
    assert review.basis == "fail_open_invalid"


def test_null_start_line_is_a_recoverable_tool_error() -> None:
    candidate = _non_anchor_candidate()
    seen: list[list[ToolResult]] = []

    class _RecoverSession:
        def __init__(self) -> None:
            self._turn = 0

        def respond(self, results: Sequence[ToolResult]) -> list[ToolCall]:
            if self._turn == 0:
                self._turn = 1
                return [
                    ToolCall(
                        "get_source",
                        {
                            "file": candidate.record.file,
                            "start_line": None,
                            "end_line": 3,
                        },
                    )
                ]
            seen.append(list(results))
            return [
                ToolCall(
                    "submit_review",
                    _cited_review(candidate, stance="keep", hyp_kind="ruled_out"),
                )
            ]

    review = review_one(
        CodeFactsStore.build(),
        candidate,
        _ScriptedClient(_RecoverSession()),
        budget=8,
        prompt_versions={},
    )
    assert seen
    payload = json.loads(seen[0][0].content)
    assert "error" in payload
    assert review.basis == "validated"
    assert review.submitted is not None
    assert review.effective == "keep"


def _bad_cite(**over: Any) -> dict[str, Any]:
    cite: dict[str, Any] = {
        "file": "target/dvrestaurant/app/apis/orders/services/get_order_service.py",
        "start_line": 17,
        "end_line": 17,
        "contains": "Order.id == order_id",
    }
    cite.update(over)
    return cite


def test_negative_beyond_eof_and_wrong_typed_citations_cannot_suppress() -> None:
    candidate = _non_anchor_candidate()
    store = CodeFactsStore.build()
    file = candidate.record.file
    line_count = len(store.get_source(file).splitlines())
    cases = [
        _bad_cite(file=file, start_line=-1, end_line=1, contains="x"),
        _bad_cite(file=file, start_line=1, end_line=line_count + 1, contains="x"),
        _bad_cite(file=file, start_line=True, end_line=1, contains="x"),
        _bad_cite(file=file, start_line=1.0, end_line=1, contains="x"),
        _bad_cite(file=file, start_line="1", end_line=1, contains="x"),
    ]
    for cite in cases:
        payload = _cited_review(candidate, stance="suppress", hyp_kind="supports_suppress")
        payload["cited_spans"] = [cite]
        payload["hypotheses"][0]["cited_spans"] = [cite]
        review = review_one(
            store,
            candidate,
            _submit_client(payload),
            budget=8,
            prompt_versions={},
        )
        assert review.submitted is None, cite
        assert review.basis == "fail_open_invalid", cite


def test_cull_attributes_empty_reviews_does_not_reread_prompt_metadata(
    monkeypatch: Any,
) -> None:
    def _boom() -> dict[str, int]:
        raise AssertionError("prompt_versions must not be read for an empty set")

    monkeypatch.setattr("ave.adapters.python_authz.cull.prompt_versions", _boom)
    attrs = cull_attributes((), client_mode="fixture")
    assert attrs["reviewed"] == 0
    assert attrs["kept"] == 0
    assert attrs["suppressed"] == 0
    assert attrs["fail_open"] == 0
    assert attrs["prompt_versions"] == {}
    assert attrs["reviews"] == []
    assert attrs["client"] == "fixture"
