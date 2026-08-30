"""The PR-body template (ticket 09): the locked ticket-06 shape, rendered honestly.

Guards three things. The **order** — attack exchange, ladder table, the four
blast-radius blocks, decision record collapsed — is the contract. The **honesty rules** —
an unrun rung is never painted green, unfilled blocks render as honest empties or
"unproven", the exchange is never fabricated. And the **golden file** — a fresh run of
the real graph renders byte-identical (modulo run id and timestamps) to the committed
example run, so the committed artifact is provably what the code emits.
"""

from __future__ import annotations

import re
from pathlib import Path

from ave.policy import policy_version
from ave.pr import render_pr_body
from ave.runner import run_once
from ave.state import AVEState

_REPO_ROOT = Path(__file__).resolve().parents[1]
_GOLDEN = _REPO_ROOT / "results" / "example-run" / "pr" / "PR_BODY.md"

_INITIAL: AVEState = {
    "target_ref": "target/dvrestaurant@d32d0997",
    "policy_version": policy_version(),
}


def _normalize(body: str) -> str:
    """Mask the two per-run volatiles: the run id and ISO timestamps."""
    body = re.sub(r"\b[0-9a-f]{32}\b", "RUN_ID", body)
    return re.sub(r"\d{4}-\d{2}-\d{2}T[0-9:.]+(?:\+\d{2}:\d{2}|Z)?", "TIMESTAMP", body)


def _render_fresh() -> str:
    return render_pr_body(run_once(_INITIAL, auto_approve=True))


def test_golden_render_matches_the_committed_example_run() -> None:
    assert _normalize(_render_fresh()) == _normalize(_GOLDEN.read_text(encoding="utf-8"))


def test_sections_appear_in_the_locked_order() -> None:
    body = _render_fresh()
    landmarks = [
        "## The attack, and the deny that replaced it",
        "## Verification ladder",
        "## Blast radius",
        "### The one fact",
        "### Still open",
        "### Cleared",
        "### Before you merge",
        "**Rings:**",
        "<summary><b>Decision record</b>",
        "No fix is claimed, ever",
    ]
    positions = [body.find(mark) for mark in landmarks]
    assert all(p >= 0 for p in positions), f"missing landmark: {landmarks[positions.index(-1)]}"
    assert positions == sorted(positions), "sections out of the locked order"


def test_unrun_rungs_are_honest_empties_never_green() -> None:
    body = _render_fresh()
    # v1 runs T1 only; exactly that one rung may be green.
    ladder = body[body.find("## Verification ladder") : body.find("## Blast radius")]
    assert ladder.count("✅") == 1
    assert "T1" in ladder.split("✅")[0].splitlines()[-1]
    assert ladder.count("| ⬜ not green |") == 3
    assert "**Ready to merge: no**" in body


def test_uncaptured_exchange_is_declared_not_fabricated() -> None:
    body = _render_fresh()
    exchange = body[: body.find("## Verification ladder")]
    assert "Exchange not captured by this run." in exchange
    # No fabricated transcript: no HTTP status lines or http fences in the empty branch.
    assert "```http" not in exchange
    assert not re.search(r"\b(200 OK|403 Forbidden|404 Not Found)\b", exchange)


def test_captured_exchange_renders_verbatim_and_404_stays_404() -> None:
    state = run_once(_INITIAL, auto_approve=True)
    change = dict(state.get("prepared_change") or {})
    change["attack_exchange"] = {
        "request": "GET /orders/17 HTTP/1.1\nAuthorization: Bearer <user-B>",
        "before_response": "HTTP/1.1 200 OK",
        "after_response": "HTTP/1.1 404 Not Found",
    }
    body = render_pr_body({**state, "prepared_change": change})
    exchange = body[: body.find("## Verification ladder")]
    assert exchange.count("```http") == 2
    assert "HTTP/1.1 404 Not Found" in exchange, "the actual deny renders unprettied"
    assert "403" not in exchange


def test_the_one_fact_carries_a_grade_tied_to_a_proof_step() -> None:
    body = _render_fresh()
    fact = body[body.find("### The one fact") : body.find("### Still open")]
    assert "How sure: **2/5**" in fact
    assert "in-process oracle model flips (T1)" in fact, "a grade needs its proof step"


def test_unfilled_fact_renders_unproven() -> None:
    state = run_once(_INITIAL, auto_approve=True)
    change = dict(state.get("prepared_change") or {})
    change["blast_radius"] = {
        k: v for k, v in dict(change.get("blast_radius") or {}).items() if k != "fact"
    }
    body = render_pr_body({**state, "prepared_change": change})
    fact = body[body.find("### The one fact") : body.find("### Still open")]
    assert "**Unproven.**" in fact


def test_still_open_draws_from_run_findings_not_the_answer_key() -> None:
    body = _render_fresh()
    still_open = body[body.find("### Still open") : body.find("### Cleared")]
    # v1 surfaces the anchor only, so the block is an honest empty — no catalog ids leak.
    assert "surfaced no other instances" in still_open
    assert not re.search(r"\bI-0[1-35-9]\b", still_open)


def test_before_you_merge_commands_are_runnable_and_include_the_oracle() -> None:
    body = _render_fresh()
    block = body[body.find("### Before you merge") : body.find("**Rings:**")]
    assert "ave_seed_bola_order_read.py::test_bola_cross_customer_order_read" in block
    assert "FAILS after this fix" in block, "inverted polarity must be stated"
    assert "poetry run pytest app/tests" in block, "the T2 suite is one of the commands"


def test_no_router_or_file_tree_diagrams() -> None:
    body = _render_fresh()
    assert "```mermaid" not in body, "vetoed: diagrams unless nodes are risks (v1: none)"


def test_counts_sit_in_a_small_table_against_policy_limits() -> None:
    body = _render_fresh()
    radius = body[body.find("## Blast radius") : body.find("### The one fact")]
    assert f"Limit (policy `{policy_version()}`)" in radius
    assert "| Files changed | 2 | 3 |" in radius
    assert "| Dependent call sites | 1 | 25 |" in radius
    assert "| Routes affected | 1 | 15 |" in radius
