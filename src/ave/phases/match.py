"""Phase 2 — Match.

Surface candidate findings from the target via the language pack. The pack fans in rule
and model findings behind the adapter seam; the core only ever sees neutral `Finding`
records. Skeleton: the pack declares one finding, the loop anchor it can drive end to end.
The target catalogue's remaining instances are ground truth for scoring, not pack output.
"""

from __future__ import annotations

from ave.adapters import get_default_pack
from ave.records.store import make_span, now_iso
from ave.state import AVEState


def match(state: AVEState) -> AVEState:
    started = now_iso()
    findings = get_default_pack().find(state.get("target_ref", "unset"))
    return {
        "findings": findings,
        "spans": [make_span("match", started, {"found": len(findings)})],
    }
