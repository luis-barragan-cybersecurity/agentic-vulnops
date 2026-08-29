"""`python_authz` — v1's language pack: Python + FastAPI, BOLA/BFLA.

The first concrete `LanguagePack`. Ticket 03 (walking skeleton) drove it against one
synthetic instance; **ticket 04 repointed `find()` at the real vendored target catalog**
(`target/catalog.json` — 8 authorization instances + decoys, each bound to a by-path
exploit oracle, inverted polarity). The four seam methods are what stay stable across that
swap and across a future second-language pack (D3).

`find()` now surfaces the real catalog. The end-to-end loop still drives one instance — the
**anchor** (I-04, the `get_order` object-ownership gap) — whose exploit oracle and fix
template are modelled **in-process** by `_skeleton_target`, so `make check` runs without
standing up the target's environment. Executing the *other* instances' by-path oracles in
the target's pinned env is the next deepening (find-stage / execution), tracked on the map.
"""

from __future__ import annotations

import difflib
import inspect
from typing import Any

from ave.adapters.base import PreparedFix
from ave.adapters.python_authz import _skeleton_target as target
from ave.adapters.python_authz import catalog
from ave.state import Finding


class PythonAuthzPack:
    """Python/FastAPI authorization pack. v1 scope: the vendored DVRestaurant catalog,
    with instance I-04 (BOLA) driven end to end by a hermetic in-process oracle."""

    name = "python_authz"

    def find(self, target_ref: str) -> list[Finding]:
        """Surface the vendored target's catalogued authorization instances as neutral
        Findings (anchor first). Rule + model finding sources fan in behind this method;
        for v1 the source is the curated `target/catalog.json`. A role/pattern scanner is
        structurally blind to the BOLA instances — the missing predicate is object
        ownership, not a missing role check — which is the case AVE exists to catch."""
        return catalog.findings()

    def _is_anchor(self, finding: Finding) -> bool:
        return finding.get("id") == catalog.anchor_id()

    def blast_radius(self, finding: Finding) -> dict[str, Any]:
        """Caller/PR-level reach of the fix. For the anchor this is the one endpoint and
        its route; ticket 06 designs the reviewer-facing visual, this is its data."""
        return {
            "changed_symbol": "get_order",
            "callers": ["route:GET /orders/{order_id}"],
            "max_callers": 1,
            "rings": ["caller", "pr"],
        }

    def prepare_fix(self, finding: Finding) -> PreparedFix:
        """The class-level fix for the anchor: add the ownership guard. The patch is a
        real unified diff between the vulnerable and fixed implementations (modelled
        in-process; the vendored file it stands for is
        `target/dvrestaurant/app/apis/orders/services/get_order_service.py`)."""
        before = inspect.getsource(target.get_order_vulnerable)
        after = inspect.getsource(target.get_order_fixed).replace(
            "get_order_fixed", "get_order", 1
        )
        before = before.replace("get_order_vulnerable", "get_order", 1)
        patch = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile="a/get_order_service.py:get_order",
                tofile="b/get_order_service.py:get_order",
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
        """Run the anchor's exploit oracle against the vulnerable or fixed implementation.
        Inverted polarity: True == exploit succeeded == still vulnerable. The hermetic
        in-process oracle models the anchor's by-path exploit test
        (`ave_seed_bola_order_read.py`), verified to flip this session."""
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.exploit_cross_owner_read(impl)

    def legitimate_use_holds(self, *, fixed: bool) -> bool:
        """T2's positive check: the fix must not break the legitimate owner's access."""
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.legitimate_owner_read(impl)
