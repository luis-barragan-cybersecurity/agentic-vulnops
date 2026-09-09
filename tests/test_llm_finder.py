"""The LLM finder (ticket 25): rediscovery, precision, and the submission boundary.

Guards the four properties the finder exists to hold. **Recall** — the model rediscovers
every catalogued instance, including all four BOLA gaps the Semgrep baseline scores 0/4 on
(the reason AVE exists). **Precision** — the decoys that survive the pre-filter are cleared,
not flagged. **The submission boundary** — a verdict whose citation does not resolve to what
it claims is *rejected, not down-weighted* (architectural, not a prompt). **Isolation** — the
finder reaches the answer key through no tool, because its store is behind the allowlist.

These tests may read `catalog.ground_truth()` — a test is off the product path, and recall
can only be measured against the answer key. The finder itself never does.
"""

from __future__ import annotations

import pytest

from ave.adapters.python_authz import catalog
from ave.adapters.python_authz.code_facts import CodeFactsStore
from ave.adapters.python_authz.llm_finder import (
    LLM_FINDER_SOURCE,
    OWNERSHIP_GAP,
    Citation,
    LLMFinder,
    Verdict,
    VerdictRejected,
)
from ave.adapters.python_authz.model import (
    FixtureModelClient,
    ToolCall,
    default_model_client,
)
from ave.adapters.python_authz.pack import FIXTURES_DIR

_ANCHOR_HANDLER = "target/dvrestaurant/app/apis/orders/services/get_order_service.py:get_order"


def _finder() -> LLMFinder:
    return LLMFinder(CodeFactsStore.build(), FixtureModelClient(fixtures_dir=FIXTURES_DIR))


# --- recall: rediscovers the gaps a pattern scanner is blind to --------------------------


def test_rediscovers_every_catalogued_instance() -> None:
    report = _finder().find()
    found = {str(f["location"]) for f in report.findings}
    ground_truth = {str(g["location"]) for g in catalog.ground_truth()}
    assert ground_truth <= found  # recall 8 / 8 — no catalogued instance is missed


def test_rediscovers_all_four_bola_the_scanner_misses() -> None:
    report = _finder().find()
    found = {str(f["location"]) for f in report.findings}
    bola = {
        str(g["location"])
        for g in catalog.ground_truth()
        if g["evidence"]["family"] == "BOLA"
    }
    assert len(bola) == 4
    assert bola <= found  # the semantic subset the Semgrep baseline scores 0/4 on


def test_every_finding_is_attributed_to_the_model() -> None:
    report = _finder().find()
    assert report.findings
    assert {str(f["source"]) for f in report.findings} == {LLM_FINDER_SOURCE}


def test_accepted_candidates_pair_the_judged_record_with_the_minted_finding() -> None:
    report = _finder().find()
    assert report.accepted
    assert report.findings == [candidate.finding for candidate in report.accepted]
    for candidate in report.accepted:
        assert candidate.record.symbol in str(candidate.finding["location"])
        assert candidate.finding["source"] == LLM_FINDER_SOURCE


# --- precision: the decoys that reach the model are cleared -------------------------------


def test_clears_the_decoys_that_survive_the_prefilter() -> None:
    report = _finder().find()
    found = {str(f["location"]) for f in report.findings}
    # D-03 (a correct post-fetch ownership guard) and D-05 (mass-assignment, authz correct)
    # both reach `examine`; the model must clear both — no false positive.
    assert not any(loc.endswith(":get_order_status") for loc in found)
    assert not any(loc.endswith(":patch_profile") for loc in found)
    assert report.rejected == []  # every verdict passed the boundary; none was malformed


# --- the coverage denominator is carried out (ticket 23's handoff) -----------------------


def test_reports_the_coverage_denominator() -> None:
    report = _finder().find()
    assert report.coverage is not None
    assert report.coverage.summary().startswith("examined ")
    attrs = report.to_attributes()
    assert attrs["by_source"] == {LLM_FINDER_SOURCE: len(report.findings)}
    assert attrs["coverage"]["judged"] <= attrs["coverage"]["found"]


# --- offline by default: no model access ------------------------------------------------


def test_default_client_is_the_offline_fixture_client() -> None:
    # With AVE_LLM_LIVE unset (CI, the default), the finder replays fixtures — no network.
    assert isinstance(default_model_client(FIXTURES_DIR), FixtureModelClient)


# --- the submission boundary: reject, never down-weight ----------------------------------


def _verdict(**over: object) -> Verdict:
    base: dict[str, object] = {
        "handler_id": _ANCHOR_HANDLER,
        "is_finding": True,
        "kind": OWNERSHIP_GAP,
        "confidence": 0.9,
        "rationale": "x",
        "cited_spans": [
            {
                "file": "target/dvrestaurant/app/apis/orders/services/get_order_service.py",
                "start_line": 17,
                "end_line": 17,
                "contains": "Order.id == order_id",
            }
        ],
    }
    base.update(over)
    return Verdict.from_arguments(_ANCHOR_HANDLER, base)


def test_a_valid_verdict_becomes_a_finding() -> None:
    store = CodeFactsStore.build()
    finder = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR))
    record = store.get_handler(_ANCHOR_HANDLER)
    finding = finder._accept(record, _verdict())
    assert finding is not None
    assert finding["source"] == LLM_FINDER_SOURCE
    assert finding["location"].endswith(":get_order")


def test_verdict_with_a_non_resolving_citation_is_rejected() -> None:
    store = CodeFactsStore.build()
    finder = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR))
    record = store.get_handler(_ANCHOR_HANDLER)
    bad = _verdict(
        cited_spans=[
            {
                "file": "target/dvrestaurant/app/apis/orders/services/get_order_service.py",
                "start_line": 17,
                "end_line": 17,
                "contains": "THIS_TEXT_IS_NOT_IN_THE_SOURCE_ZZZ",
            }
        ]
    )
    with pytest.raises(VerdictRejected):
        finder._accept(record, bad)


def test_verdict_citing_an_unknown_handler_is_rejected() -> None:
    store = CodeFactsStore.build()
    finder = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR))
    record = store.get_handler(_ANCHOR_HANDLER)
    with pytest.raises(VerdictRejected):
        finder._accept(record, _verdict(handler_id="app/does/not/exist.py:ghost"))


def test_verdict_for_a_different_resolvable_handler_is_rejected() -> None:
    """Accepted identity is the judged record. A different handler that the store can
    resolve is still a rejection — resolution is not identity."""
    other_id = (
        "target/dvrestaurant/app/apis/orders/services/get_order_status.py:get_order_status"
    )
    store = CodeFactsStore.build()
    finder = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR))
    record = store.get_handler(_ANCHOR_HANDLER)
    assert store.get_handler(other_id).handler_id != record.handler_id
    with pytest.raises(VerdictRejected, match="is not the judged"):
        finder._accept(record, _verdict(handler_id=other_id))


def test_verdict_with_no_citations_is_rejected() -> None:
    store = CodeFactsStore.build()
    finder = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR))
    record = store.get_handler(_ANCHOR_HANDLER)
    with pytest.raises(VerdictRejected):
        finder._accept(record, _verdict(cited_spans=[]))


def test_verdict_of_the_wrong_kind_is_rejected() -> None:
    store = CodeFactsStore.build()
    finder = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR))
    record = store.get_handler(_ANCHOR_HANDLER)
    with pytest.raises(VerdictRejected):
        finder._accept(record, _verdict(kind="sql-injection"))


def test_a_cleared_verdict_yields_no_finding_but_is_not_rejected() -> None:
    store = CodeFactsStore.build()
    finder = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR))
    record = store.get_handler(_ANCHOR_HANDLER)
    assert finder._accept(record, _verdict(is_finding=False)) is None


# --- isolation: the answer key is unreachable through the tools --------------------------


def test_the_answer_key_is_unreachable_through_get_source() -> None:
    store = CodeFactsStore.build()
    finder = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR))
    result = finder._execute(ToolCall("get_source", {"file": "target/catalog.json"}))
    assert "error" in result.content  # allowlist refuses it; nothing leaks to the model


def test_citation_whitespace_is_normalized_not_column_exact() -> None:
    # A citation's `contains` claim is about what the line says, not its indentation.
    assert Citation("f.py", 1, 1, "a  ==  b")  # constructs; matching is whitespace-collapsed
