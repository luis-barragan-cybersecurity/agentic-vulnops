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
