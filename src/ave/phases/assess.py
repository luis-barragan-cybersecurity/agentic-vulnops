"""Phase 3 — Assess.

Rank the batch Match produced and select the one finding this run drives, attaching its
blast radius and proposed fix plan. Selection is the thin, deterministic, *stated* rank
function in `ave.findings` (confidence, then measured dependents, then location); its
rationale is written to state and into this phase's span so the run record and the PR
body can say why this finding, not just which.

The dependents term is inert today and the rationale says so (`dependents_measured: 0`):
the pack's `blast_radius()` reports dependents as unmeasured for the anchor and raises for
any other finding, so no candidate is probed for it here. The measured blast-radius pass
makes the term real; the function does not change.
"""

from __future__ import annotations

from typing import Any

from ave.adapters import get_default_pack
from ave.findings import select_head
from ave.records.store import make_span, now_iso
from ave.state import AVEState


def assess(state: AVEState) -> AVEState:
    started = now_iso()
    selected, rationale = select_head(state.get("findings", []))
    assessment: dict[str, Any] = {"reasoned": selected is not None}
    if selected is not None:
        pack = get_default_pack()
        assessment["blast_radius"] = pack.blast_radius(selected)
        assessment["fix_plan"] = pack.fix_plan(selected)
    return {
        "selected_finding": selected,
        "selection_rationale": rationale,
        "assessment": assessment,
        "spans": [
            make_span(
                "assess",
                started,
                {"selected": selected is not None, "selection": rationale},
            )
        ],
    }
