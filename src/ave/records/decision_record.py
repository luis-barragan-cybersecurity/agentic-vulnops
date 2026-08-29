"""The two-part decision record: *why* AVE made a fix, and the policy that authorized it.

Cites the `policy.yaml` version. A PR cannot become ready-to-merge without one (the
invariant). Scaffold shape only (ticket 02); ticket 05 fixes the two-part structure.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def new_decision_record(
    finding: Mapping[str, Any] | None,
    policy_version: str,
) -> dict[str, Any]:
    """Build a decision-record shell.

    Two parts (named, not yet filled): `rationale` (why this is the class-level fix) and
    `authorization` (the policy predicate + version that permits it).
    """
    return {
        "finding_id": (finding or {}).get("id"),
        "rationale": None,  # part 1 — why this class-level fix
        "authorization": {  # part 2 — the policy grant
            "policy_version": policy_version,
            "predicate": None,
        },
    }
