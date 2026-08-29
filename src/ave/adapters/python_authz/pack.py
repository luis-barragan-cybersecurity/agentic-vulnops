"""`python_authz` — v1's language pack: Python + FastAPI, BOLA/BFLA.

The first concrete `LanguagePack`. The walking skeleton drives it against one synthetic
BOLA instance (`_skeleton_target`); ticket 04 repoints `find()` at the real vendored
target catalog and `run_exploit()` at the catalog's by-path exploit oracles. The seam
itself — these four methods — is what stays stable across that swap and across a future
second-language pack (D3).
"""

from __future__ import annotations

import difflib
import inspect
from typing import Any

from ave.adapters import python_authz as _pkg
from ave.adapters.base import PreparedFix
from ave.adapters.python_authz import _skeleton_target as target
from ave.state import Finding

_FINDING_ID = "bola-order-owner"


class PythonAuthzPack:
    """Python/FastAPI authorization pack. Skeleton scope: a single BOLA instance."""

    name = "python_authz"

    def find(self, target_ref: str) -> list[Finding]:
        """One object-ownership gap: `get_order` returns an object without checking its
        owner. A role-pattern scanner cannot see this (there is no missing role check —
        the gap is semantic), which is exactly the case AVE must catch."""
        finding: Finding = {
            "id": _FINDING_ID,
            "kind": "object-ownership-gap",  # neutral; the L2 BOLA anchor
            "location": f"{_pkg.__name__}._skeleton_target:get_order_vulnerable",
            "confidence": 0.9,
            "evidence": {
                "family": "BOLA",
                "why_scanner_blind": "no role check is missing; ownership is a data "
                "predicate a pattern rule cannot express",
                "oracle": "exploit_cross_owner_read",
            },
        }
        return [finding]

    def blast_radius(self, finding: Finding) -> dict[str, Any]:
        """Caller/PR-level reach of the fix. Skeleton: the one endpoint and its route.
        Ticket 06 designs the reviewer-facing visual; this is the data behind it."""
        return {
            "changed_symbol": "get_order",
            "callers": ["route:GET /orders/{order_id}"],
            "max_callers": 1,
            "rings": ["caller", "pr"],
        }

    def prepare_fix(self, finding: Finding) -> PreparedFix:
        """The class-level fix: add the ownership guard. The patch is a real unified diff
        between the vulnerable and fixed implementations."""
        before = inspect.getsource(target.get_order_vulnerable)
        after = inspect.getsource(target.get_order_fixed).replace(
            "get_order_fixed", "get_order", 1
        )
        before = before.replace("get_order_vulnerable", "get_order", 1)
        patch = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile="a/_skeleton_target.py:get_order",
                tofile="b/_skeleton_target.py:get_order",
            )
        )
        return PreparedFix(
            class_level=True,
            summary="Enforce object ownership in get_order (BOLA class-level fix)",
            patch=patch,
            finding_id=finding.get("id"),
            blast_radius=self.blast_radius(finding),
        )

    def run_exploit(self, finding: Finding, *, fixed: bool) -> bool:
        """Run the finding's exploit oracle against the vulnerable or fixed implementation.
        Inverted polarity: True == exploit succeeded == still vulnerable."""
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.exploit_cross_owner_read(impl)

    def legitimate_use_holds(self, *, fixed: bool) -> bool:
        """T2's positive check: the fix must not break the legitimate owner's access."""
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.legitimate_owner_read(impl)
