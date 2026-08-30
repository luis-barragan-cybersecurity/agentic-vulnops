"""Load the vendored target's seeded-instance catalog and project it into neutral
`Finding` records for the core.

`target/catalog.json` holds 8 authorization instances plus decoys, each bound to a by-path
exploit oracle with inverted polarity. It plays two roles, and this module keeps them
apart. `ground_truth()` is the scored answer key that ticket 07 measures precision and
recall against, so no detector may return it. `anchor()` is the single instance the loop
drives, which is all the pack claims to have found today.

The core only ever sees neutral `Finding`s. The `authz`/`fastapi`/BOLA specifics stay in
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


def ground_truth() -> list[Finding]:
    """Every catalogued vuln instance as a neutral Finding, ordered by id. This is the
    answer key ticket 07 scores against, not something a finding source may return."""
    return [_to_finding(i) for i in sorted(_raw()["instances"], key=lambda i: i["id"])]


def anchor() -> Finding:
    """The one instance the loop drives, the only one with a hermetic in-process oracle."""
    by_id = {i["id"]: i for i in _raw()["instances"]}
    return _to_finding(by_id[anchor_id()])
