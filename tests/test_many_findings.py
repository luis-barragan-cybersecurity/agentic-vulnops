from __future__ import annotations

import json
from typing import Any, cast

from ave.adapters import FindingBatch, LanguagePack, get_default_pack
from ave.adapters.python_authz import catalog
from ave.findings import (
    RANK_FUNCTION,
    UNATTRIBUTED_SOURCE,
    all_sources,
    attribute,
    merge_findings,
    rank_findings,
    select_head,
)
from ave.policy import policy_version
from ave.pr import render_pr_body
from ave.records.store import build_run_record
from ave.runner import run_once
from ave.state import AVEState, Finding

_INITIAL: AVEState = {
    "target_ref": "target/dvrestaurant@d32d0997",
    "policy_version": policy_version(),
}


def _finding(
    id_: str,
    *,
    location: str = "app/x.py:handler",
    kind: str = "object-ownership-gap",
    confidence: float = 0.5,
    source: str | None = "ave:test",
    **extra: Any,
) -> Finding:
    finding: dict[str, Any] = {
        "id": id_,
        "kind": kind,
        "location": location,
        "confidence": confidence,
        "evidence": {},
        **extra,
    }
    if source is not None:
        finding["source"] = source
    return cast("Finding", finding)


def _by_location(finding: Finding) -> str:
    return str(finding.get("location", ""))


# --- attribution -------------------------------------------------------------------------


def test_attribute_backfills_a_missing_source_and_leaves_set_ones_alone() -> None:
    out = attribute(
        [_finding("a", source=None), _finding("b", source="sarif:tool")],
        default_source="ave:backfill",
    )
    assert [f["source"] for f in out] == ["ave:backfill", "sarif:tool"]


def test_unattributed_is_a_named_value_not_a_blank() -> None:
    assert UNATTRIBUTED_SOURCE
    assert all_sources(_finding("a", source=None)) == [UNATTRIBUTED_SOURCE]


def test_all_sources_lists_the_primary_first_then_corroborators_sorted() -> None:
    f = _finding("a", source="ave:llm", corroborated_by=["sarif:z", "sarif:b", "ave:llm"])
    assert all_sources(f) == ["ave:llm", "sarif:b", "sarif:z"]


# --- de-dup merge ------------------------------------------------------------------------


def test_same_location_and_kind_from_two_sources_merge_keeping_both_sources() -> None:
    llm = _finding("llm-1", confidence=0.9, source="ave:llm")
    sarif = _finding("sarif-1", confidence=0.6, source="sarif:tool")
    merged = merge_findings([sarif, llm], location_key=_by_location)
    assert len(merged) == 1
    head = merged[0]
    assert head["id"] == "llm-1"  # the higher confidence wins
    assert head["confidence"] == 0.9
    assert all_sources(head) == ["ave:llm", "sarif:tool"]


def test_confidence_tie_goes_to_the_first_seen() -> None:
    first = _finding("first", confidence=0.7, source="sarif:a")
    second = _finding("second", confidence=0.7, source="sarif:b")
    merged = merge_findings([first, second], location_key=_by_location)
    assert [f["id"] for f in merged] == ["first"]
    assert merged[0]["corroborated_by"] == ["sarif:b"]


def test_same_location_different_kind_does_not_merge() -> None:
    bola = _finding("a", kind="object-ownership-gap")
    bfla = _finding("b", kind="function-role-gap")
    assert len(merge_findings([bola, bfla], location_key=_by_location)) == 2


def test_merge_keeps_loser_only_oracle_metadata_when_winner_omits_it() -> None:
    winner = _finding(
        "high",
        confidence=0.9,
        source="ave:llm",
        evidence={"rationale": "from winner"},
    )
    loser = _finding(
        "low",
        confidence=0.4,
        source="sarif:tool",
        evidence={
            "rationale": "from loser",
            "oracle": {"path": "app/tests/x.py", "test": "t", "polarity": "inverted"},
            "is_loop_anchor": True,
        },
    )
    merged = merge_findings([loser, winner], location_key=_by_location)
    assert merged[0]["id"] == "high"
    evidence = merged[0]["evidence"]
    assert evidence["rationale"] == "from winner"
    assert evidence["oracle"] == {
        "path": "app/tests/x.py",
        "test": "t",
        "polarity": "inverted",
    }
    assert evidence["is_loop_anchor"] is True


def test_can_drive_requires_anchor_location_not_just_oracle_keys() -> None:
    pack = get_default_pack()
    route = {"method": "GET", "path": "/orders/{order_id}"}
    smuggled = _finding(
        "other",
        location="app/other.py:handler",
        evidence={
            "handler": route,
            "is_loop_anchor": True,
            "oracle": {"path": "app/tests/x.py", "test": "t", "polarity": "inverted"},
        },
    )
    assert pack.can_drive(smuggled) is False
    winner = _finding(
        "high",
        location="app/other.py:handler",
        confidence=0.9,
        evidence={"rationale": "from winner"},
    )
    loser = _finding(
        "low",
        location="app/other.py:handler",
        confidence=0.4,
        evidence={
            "oracle": {"path": "app/tests/x.py", "test": "t", "polarity": "inverted"},
            "is_loop_anchor": True,
        },
    )
    merged = merge_findings([loser, winner], location_key=_by_location)
    assert merged[0]["evidence"]["is_loop_anchor"] is True
    assert pack.can_drive(merged[0]) is False
    role_at_anchor = _finding(
        "role-anchor",
        location=catalog.anchor_location(),
        kind="function-role-gap",
        evidence={"handler": route},
    )
    assert pack.can_drive(role_at_anchor) is False
    missing_route = _finding(
        "no-route",
        location=catalog.anchor_location(),
        evidence={},
    )
    assert pack.can_drive(missing_route) is False
    finishable = _finding(
        "anchor",
        location=catalog.anchor_location(),
        evidence={"handler": route},
    )
    assert pack.can_drive(finishable) is True


def test_merge_preserves_ingest_order_and_folds_transitively() -> None:
    a = _finding("a", location="f.py:one", confidence=0.5, source="s1")
    b = _finding("b", location="f.py:two", confidence=0.5, source="s2")
    a2 = _finding("a2", location="f.py:one", confidence=0.8, source="s3")
    a3 = _finding("a3", location="f.py:one", confidence=0.1, source="s4")
    merged = merge_findings([a, b, a2, a3], location_key=_by_location)
    assert [f["id"] for f in merged] == ["a2", "b"]
    assert all_sources(merged[0]) == ["s3", "s1", "s4"]


# --- the pack-owned key ------------------------------------------------------------------


def test_dedup_key_is_on_the_seam_and_the_default_pack_still_satisfies_it() -> None:
    pack = get_default_pack()
    assert isinstance(pack, LanguagePack)
    assert hasattr(pack, "dedup_key")


def test_pack_find_returns_a_batch_and_has_no_report_side_channel() -> None:
    pack = get_default_pack()
    assert not hasattr(pack, "last_find_report")
    batch = pack.find("target/dvrestaurant@d32d0997")
    assert isinstance(batch, FindingBatch)
    assert len(batch.kept) > 1
    assert batch.suppressed == ()
    assert batch.report["finder"] == "llm"
    assert batch.report["found"] == len(batch.kept)


def test_pack_dedup_key_reads_file_and_symbol() -> None:
    pack = get_default_pack()
    key = pack.dedup_key(_finding("a", location="app/apis/orders/get.py:get_order"))
    assert key == "app/apis/orders/get.py:get_order"


def test_pack_dedup_key_fails_toward_not_merging_on_a_line_location() -> None:
    """A `file:line` location (what a SARIF feed reports) is not a symbol; resolving a
    line to its enclosing symbol is intake work. Until then the raw location is the key,
    so a duplicate survives visibly rather than a source being silently dropped."""
    pack = get_default_pack()
    by_symbol = _finding("a", location="app/x.py:handler")
    by_line = _finding("b", location="app/x.py:42")
    assert pack.dedup_key(by_line) == "app/x.py:42"
    assert pack.dedup_key(by_line) != pack.dedup_key(by_symbol)
    assert pack.dedup_key(_finding("c", location="no-colon-here")) == "no-colon-here"
    assert len(merge_findings([by_symbol, by_line], location_key=pack.dedup_key)) == 2


# --- ranked head selection ---------------------------------------------------------------


def test_rank_function_is_stated_as_text() -> None:
    assert "confidence" in RANK_FUNCTION and "dependents" in RANK_FUNCTION


def test_rank_orders_confidence_desc_first() -> None:
    low = _finding("low", confidence=0.2, location="a.py:x")
    high = _finding("high", confidence=0.9, location="z.py:x")
    assert [f["id"] for f in rank_findings([low, high])] == ["high", "low"]


def test_rank_prefers_fewer_measured_dependents_and_puts_unmeasured_last() -> None:
    wide = _finding("wide", location="a.py:x")
    narrow = _finding("narrow", location="b.py:x")
    unknown = _finding("unknown", location="c.py:x")
    ranked = rank_findings(
        [unknown, wide, narrow], dependents={"wide": 12, "narrow": 2, "unknown": None}
    )
    assert [f["id"] for f in ranked] == ["narrow", "wide", "unknown"]


def test_rank_breaks_remaining_ties_on_location_then_ingest_order() -> None:
    z = _finding("z", location="z.py:x")
    a2 = _finding("a2", location="a.py:x")
    a1 = _finding("a1", location="a.py:x")
    assert [f["id"] for f in rank_findings([z, a2, a1])] == ["a2", "a1", "z"]


def test_select_head_states_its_rationale() -> None:
    head, rationale = select_head(
        [_finding("b", confidence=0.4), _finding("a", confidence=0.8, location="q.py:h")]
    )
    assert head is not None and head["id"] == "a"
    assert rationale["rank_function"] == RANK_FUNCTION
    assert rationale["candidates"] == 2
    assert rationale["dependents_measured"] == 0
    assert rationale["selected"] == "a"
    assert "confidence" in rationale["why"]
    assert [r["id"] for r in rationale["ranking"]] == ["a", "b"]


def test_select_head_on_nothing_is_honest() -> None:
    head, rationale = select_head([])
    assert head is None
    assert rationale["candidates"] == 0 and rationale["selected"] is None


# --- honesty: the answer key never reaches the product path -------------------------------


def test_anchor_and_ground_truth_carry_different_sources() -> None:
    assert catalog.anchor()["source"] == catalog.ANCHOR_SOURCE
    assert all(f["source"] == catalog.GROUND_TRUTH_SOURCE for f in catalog.ground_truth())
    assert catalog.ANCHOR_SOURCE != catalog.GROUND_TRUTH_SOURCE


def test_no_run_finding_ever_carries_the_ground_truth_source() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    for finding in final["findings"]:
        assert catalog.GROUND_TRUTH_SOURCE not in all_sources(finding)


# --- the run shape end to end ------------------------------------------------------------


def test_run_ingests_many_findings_and_drives_the_anchor() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    assert len(final["findings"]) > 1
    assert {f["source"] for f in final["findings"]} == {"ave:llm-finder"}
    driven = final["selected_finding"]
    pack = get_default_pack()
    assert driven is not None and pack.can_drive(driven) is True
    assert driven["evidence"]["oracle"]["test"] == "test_authorization_boundary"
    assert driven["evidence"]["oracle"]["path"].endswith("bound/_ave_bound.py")
    rationale = final["selection_rationale"]
    assert rationale["candidates"] == len(final["findings"])
    assert rationale["selected"] == driven["id"]
    assert rationale["driven_is_top_ranked"] is True
    assert len(rationale["deferred_pending_exploit"]) == len(final["findings"]) - 1
    match = next(s for s in final["spans"] if s["phase"] == "match")
    assert match["attributes"]["found"] == len(final["findings"])
    assert match["attributes"]["sources"] == ["ave:llm-finder"]
    assert match["attributes"]["suppressed"] == 0
    assert final.get("suppressed_findings") == []
    # Ticket 23's handoff: the find span now carries the coverage denominator.
    assert "coverage" in match["attributes"]["find_stage"]
    assert match["attributes"]["find_stage"]["coverage"]["summary"].startswith("examined ")
    cull = match["attributes"]["find_stage"]["cull"]
    assert cull["reviewed"] == len(final["findings"])
    assert cull["suppressed"] == 0
    assert cull["fail_open"] == 0
    assert cull["client"] == "fixture"
    assess = next(s for s in final["spans"] if s["phase"] == "assess")
    assert assess["attributes"]["selection"]["rank_function"] == RANK_FUNCTION


def test_run_record_has_one_lifecycle_per_ingested_finding() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    driven_id = final["selected_finding"]["id"]
    ingested_ids = {f["id"] for f in final["findings"]}
    state: AVEState = cast(
        "AVEState",
        {
            **final,
            "findings": [
                *final["findings"],
                _finding("X-1", location="app/a.py:one", source="sarif:tool"),
                _finding("X-2", location="app/b.py:two", source="ave:llm"),
            ],
            "spans": final["spans"],
        },
    )
    record = build_run_record(state)
    by_id = {lc.finding_id: lc for lc in record.findings}
    assert set(by_id) == ingested_ids | {"X-1", "X-2"}
    assert by_id[driven_id].triaged_at is not None
    for other in ("X-1", "X-2"):
        assert by_id[other].outcome == "open"
        assert by_id[other].triaged_at is None
        assert by_id[other].verified_at is None
        assert by_id[other].first_observed_at == by_id[driven_id].first_observed_at
    json.dumps(record.findings[0].__dict__)  # serialisable, like the persisted record


def test_suppressed_findings_are_false_positives_triaged_at_match() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    extra = _finding("FP-1", location="app/a.py:one", source="ave:llm-finder")
    match = next(s for s in final["spans"] if s["phase"] == "match")
    state = cast(
        "AVEState",
        {**final, "suppressed_findings": [extra], "spans": final["spans"]},
    )
    record = build_run_record(state)
    by_id = {lc.finding_id: lc for lc in record.findings}
    assert by_id["FP-1"].outcome == "false_positive"
    assert by_id["FP-1"].triaged_at == match["ended_at"]
    assert by_id["FP-1"].verified_at is None
    body = render_pr_body(state)
    still_open = body[body.find("### Still open") : body.find("### Cleared")]
    assert "`FP-1`" not in still_open


def test_pr_body_says_which_of_many_was_selected_and_lists_the_rest_still_open() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    others = [
        _finding("X-1", location="app/a.py:one", source="sarif:tool"),
        _finding("X-2", location="app/b.py:two", source="ave:llm", corroborated_by=["sarif:tool"]),
    ]
    findings = [*final["findings"], *others]
    head, rationale = select_head(findings)
    driven_id = final["selected_finding"]["id"]
    assert head is not None and head["id"] == driven_id  # top confidence is the anchor gap
    state = cast(
        "AVEState", {**final, "findings": findings, "selection_rationale": rationale}
    )
    body = render_pr_body(state)
    assert f"**Selected** 1 of {len(findings)} ingested findings" in body
    assert RANK_FUNCTION in body
    still_open = body[body.find("### Still open") : body.find("### Cleared")]
    assert "`X-1`" in still_open and "`sarif:tool`" in still_open
    assert "`X-2`" in still_open and "`ave:llm`" in still_open


def test_golden_pr_body_states_the_many_ingested_findings_honestly() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    body = render_pr_body(final)
    assert f"**Selected** 1 of {len(final['findings'])} ingested findings" in body
    assert "found by `ave:llm-finder`" in body
