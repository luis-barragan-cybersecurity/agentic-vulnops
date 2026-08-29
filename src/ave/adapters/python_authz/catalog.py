"""Load the vendored target's seeded-instance catalog and project it into neutral
`Finding` records for the core.

Ticket 04 repointed the pack's finding source from the single synthetic instance at the
real vendored target: `target/catalog.json` is the source of truth (8 authorization
instances + decoys, each bound to a by-path exploit oracle with inverted polarity). The
core only ever sees neutral `Finding`s — the `authz`/`fastapi`/BOLA specifics stay in
`evidence`, behind the seam (D3).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from ave.state import Finding

# src/ave/adapters/python_authz/catalog.py -> repo root is five parents up.
_REPO_ROOT = Path(__file__).resolve().parents[4]
_CATALOG_PATH = _REPO_ROOT / "target" / "catalog.json"


@lru_cache(maxsize=1)
def _raw() -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(_CATALOG_PATH.read_text()))


def anchor_id() -> str:
    """The instance the end-to-end loop drives (has a hermetic in-process oracle)."""
    return str(_raw()["anchor"])


def _to_finding(inst: dict[str, Any]) -> Finding:
    finding: Finding = {
        "id": inst["id"],
        "kind": (
            "object-ownership-gap" if inst["family"] == "BOLA" else "function-role-gap"
        ),
        "location": f"{inst['file']}:{inst['symbol']}",
        "confidence": 0.9 if inst.get("scanner_blind") else 0.6,
        "evidence": {
            "family": inst["family"],
            "endpoint": inst["endpoint"],
            "origin": inst["origin"],
            "why_scanner_blind": inst.get("why_scanner_blind", ""),
            "oracle": inst["oracle"],  # {path, test, polarity, origin} — the binding
            "fix_hint": inst.get("fix_hint", ""),
            "is_loop_anchor": bool(inst.get("loop_anchor")),
        },
    }
    return finding


def findings() -> list[Finding]:
    """Every catalogued vuln instance as a neutral Finding, anchor first (so Assess,
    which selects findings[0], drives the instance with the hermetic oracle)."""
    anchor = anchor_id()
    instances = _raw()["instances"]
    ordered = sorted(instances, key=lambda i: (i["id"] != anchor, i["id"]))
    return [_to_finding(i) for i in ordered]
