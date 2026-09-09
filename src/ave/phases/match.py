"""Phase 2 — Match.

The fan-in point for every finding source a run consults. Each source's findings are
attributed (`source` is never blank), then findings from different sources that name the
same flaw are merged on the pack's `(file, symbol)` key plus `kind`, keeping both sources
and the higher confidence. The core only ever sees neutral `Finding` records.

Sources today: whatever Intake already placed in `state["findings"]` (nothing yet — an
external SARIF feed lands there when intake grows one) and the pack's own `find()`, which
returns one `FindingBatch`. Match puts `kept` in `AVEState.findings`, `suppressed` in
`AVEState.suppressed_findings`, and the batch report on the Match span. Assess ranks the
kept batch and picks the head.
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
    batch = pack.find(target_ref)

    ingested: list[Finding] = []
    for produced in (state.get("findings") or [], batch.kept):
        ingested.extend(attribute(produced, default_source=UNATTRIBUTED_SOURCE))

    findings = merge_findings(ingested, location_key=pack.dedup_key)
    sources = sorted({source for f in ingested for source in all_sources(f)})
    suppressed = attribute(batch.suppressed, default_source=UNATTRIBUTED_SOURCE)
    attributes: dict[str, Any] = {
        "found": len(findings),
        "ingested": len(ingested),
        "sources": sources,
        "suppressed": len(suppressed),
        "find_stage": dict(batch.report),
    }
    return {
        "findings": findings,
        "suppressed_findings": suppressed,
        "spans": [make_span("match", started, attributes)],
    }
