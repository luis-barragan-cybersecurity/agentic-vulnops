"""Phase 2 — Match.

Surface candidate findings from the target via the language pack. The pack fans in rule
and model findings behind the adapter seam; the core only ever sees neutral `Finding`
records. Skeleton: the `python_authz` pack returns one BOLA object-ownership gap.
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
