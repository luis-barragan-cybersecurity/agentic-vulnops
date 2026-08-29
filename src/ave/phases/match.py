"""Phase 2 — Match.

Surface candidate findings from the target. In v1 this fans in rule findings and LLM
findings behind the adapter seam; the core only sees neutral `Finding` records. Stub:
emits a single placeholder finding so the loop has something to carry.
"""

from __future__ import annotations

from ave.state import AVEState, Finding


def match(state: AVEState) -> AVEState:
    placeholder: Finding = {
        "id": "finding-0",
        "kind": "stub",
        "location": "unset",
        "confidence": 0.0,
        "evidence": {},
    }
    return {"findings": [placeholder]}
