"""Phase 2 — Match.

The fan-in point for every finding source a run consults. Each source's findings are
attributed (`source` is never blank), then findings from different sources that name the
same flaw are merged on the pack's `(file, symbol)` key plus `kind`, keeping both sources
and the higher confidence. The core only ever sees neutral `Finding` records.

Sources today: whatever Intake already placed in `state["findings"]` (nothing yet — an
external SARIF feed lands there when intake grows one) and the pack's own `find()`, which
still declares only the loop anchor (ticket 04's honesty fix), so a run still ingests
exactly one finding. Many findings in, one remediated out: Assess ranks this batch and
picks the head; M3's triage stage slots in between the two over this same list.
"""

from __future__ import annotations

from typing import Any

from ave.adapters import get_default_pack
from ave.findings import UNATTRIBUTED_SOURCE, all_sources, attribute, merge_findings
from ave.records.store import make_span, now_iso
from ave.state import AVEState, Finding


def match(state: AVEState) -> AVEState:
    started = now_iso()
    pack = get_default_pack()
    target_ref = state.get("target_ref", "unset")

    # Every source, in ingest order. A producer that forgot to stamp its source shows up
    # as `unattributed` rather than blank, so the omission is visible in the run record.
    ingested: list[Finding] = []
    for produced in (state.get("findings") or [], pack.find(target_ref)):
        ingested.extend(attribute(produced, default_source=UNATTRIBUTED_SOURCE))

    findings = merge_findings(ingested, location_key=pack.dedup_key)
    sources = sorted({source for f in ingested for source in all_sources(f)})
    attributes: dict[str, Any] = {
        "found": len(findings),
        "ingested": len(ingested),
        "sources": sources,
    }
    attributes.update(_find_stage_report(pack))
    return {
        "findings": findings,
        "spans": [make_span("match", started, attributes)],
    }


def _find_stage_report(pack: object) -> dict[str, Any]:
    """The find-stage coverage denominator and per-source counts, when the pack exposes a
    finder report. Duck-typed so the core (D3) never depends on a pack's finder — a pack
    without one simply contributes nothing here (ticket 23's `examined N of M` handoff to
    the LLM finder, ticket 25)."""
    reporter = getattr(pack, "last_find_report", None)
    if not callable(reporter):
        return {}
    report = reporter()
    if report is None:
        return {}
    return {"find_stage": report.to_attributes()}
