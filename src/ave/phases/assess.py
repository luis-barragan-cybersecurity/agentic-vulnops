"""Phase 3 — Assess.

Rank the batch Match produced and select the one finding this run drives, attaching its
blast radius and proposed fix plan. Ranking is the thin, deterministic, *stated* rank
function in `ave.findings` (confidence, then measured dependents, then location); its
rationale is written to state and into this phase's span so the run record and the PR
body can say why this finding, not just which.

**The run drives the highest-ranked finding the pack can prove today.** With the LLM finder
(ticket 25) a run ingests many real findings, but only the one bound to the pack's hermetic
oracle (the anchor location) can be driven to a test-verified fix; the rest are honest
findings awaiting a generated exploit (ticket 27). So Assess selects the top-ranked finding
`pack.can_drive()` accepts, and records the top-ranked-overall finding and the ones deferred
alongside it — the run never crashes on a finding it cannot yet prove, and it never hides one.

The dependents term is real (ticket 28): the fixture run reports `dependents_measured: 8`.
One mapping from `pack.measured_dependents()` feeds both orderings, so the rationale and
the selected finding never use different orders. The public blast radius is recorded on
this phase's span, so an agent reads the same counts a human reads in the PR body.
"""

from __future__ import annotations

from typing import Any

from ave.adapters import get_default_pack
from ave.findings import Dependents, rank_findings, select_head
from ave.records.store import make_span, now_iso
from ave.state import AVEState, Finding


def assess(state: AVEState) -> AVEState:
    started = now_iso()
    findings = state.get("findings", [])
    pack = get_default_pack()
    dependents = pack.measured_dependents(findings)
    top_ranked, rationale = select_head(findings, dependents=dependents)
    driven = _first_drivable(findings, pack, dependents=dependents)

    rationale["top_ranked"] = top_ranked.get("id") if top_ranked is not None else None
    rationale["selected"] = driven.get("id") if driven is not None else None
    rationale["driven_is_top_ranked"] = bool(
        driven is not None
        and top_ranked is not None
        and driven.get("id") == top_ranked.get("id")
    )
    rationale["deferred_pending_exploit"] = [
        f.get("id") for f in findings if not pack.can_drive(f)
    ]
    if driven is not None and not rationale["driven_is_top_ranked"]:
        rationale["why"] = (
            f"top-ranked {top_ranked.get('id') if top_ranked else '?'} has no bound "
            f"exploit yet (ticket 27); drove the highest-ranked finding with a working oracle"
        )
    elif driven is None and findings:
        rationale["why"] = "no ingested finding has a bound exploit yet (ticket 27)"

    assessment: dict[str, Any] = {"reasoned": driven is not None}
    if driven is not None:
        assessment["blast_radius"] = pack.blast_radius(driven)
        assessment["fix_plan"] = pack.fix_plan(driven)
    return {
        "selected_finding": driven,
        "selection_rationale": rationale,
        "assessment": assessment,
        "spans": [
            make_span(
                "assess",
                started,
                {
                    "selected": driven is not None,
                    "selection": rationale,
                    "blast_radius": assessment.get("blast_radius"),
                },
            )
        ],
    }


def _first_drivable(
    findings: list[Finding], pack: Any, *, dependents: Dependents
) -> Finding | None:
    """The highest-ranked finding the pack can drive to a verified fix, or None if the run
    ingested none it can prove yet."""
    for finding in rank_findings(findings, dependents=dependents):
        if pack.can_drive(finding):
            return finding
    return None
