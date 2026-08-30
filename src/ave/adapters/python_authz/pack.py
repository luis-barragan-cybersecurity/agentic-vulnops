"""`python_authz` — v1's language pack: Python + FastAPI, BOLA/BFLA.

The first concrete `LanguagePack`. Ticket 03 (walking skeleton) drove it against one
synthetic instance; ticket 04 repointed it at the real vendored target
(`target/catalog.json`, 8 authorization instances + decoys, each bound to a by-path
exploit oracle, inverted polarity). The four seam methods are what stay stable across that
swap and across a future second-language pack (D3).

The pack claims exactly one instance, the catalog's loop anchor I-04 (the `get_order`
object-ownership gap). Its exploit oracle and fix template are modelled in-process by
`_skeleton_target`, so `make check` runs without standing up the target's environment.
Every other seam method rejects a non-anchor finding rather than answering as if it were
I-04. A real finding source, and the other instances' by-path oracles in the target's
pinned env, are the next deepening (find-stage / execution), tracked on the map.
"""

from __future__ import annotations

import difflib
import inspect
from typing import Any

from ave.adapters.base import PreparedFix
from ave.adapters.python_authz import _skeleton_target as target
from ave.adapters.python_authz import catalog
from ave.state import Finding


def _no_oracle(finding: Finding) -> NotImplementedError:
    return NotImplementedError(
        f"{finding.get('id')} is not the loop anchor {catalog.anchor_id()}. "
        f"Driving it needs its by-path oracle in the target's pinned env."
    )


class PythonAuthzPack:
    """Python/FastAPI authorization pack. v1 scope: the vendored DVRestaurant catalog,
    with instance I-04 (BOLA) driven end to end by a hermetic in-process oracle."""

    name = "python_authz"

    def find(self, target_ref: str) -> list[Finding]:
        """Declare the one finding this pack stands behind, the catalog's loop anchor
        I-04. Rule and model finding sources fan in behind this method; v1 has neither, so
        returning `catalog.ground_truth()` would make ticket 07 score the answer key
        against itself. A role/pattern scanner is structurally blind to the BOLA
        instances anyway, because the missing predicate is object ownership rather than a
        missing role check, and that blindness is the case AVE exists to catch."""
        return [catalog.anchor()]

    def _is_anchor(self, finding: Finding) -> bool:
        return finding.get("id") == catalog.anchor_id()

    def blast_radius(self, finding: Finding) -> dict[str, Any]:
        """Caller/PR-level reach of the fix. For the anchor this is the one endpoint and
        its route; ticket 06 designs the reviewer-facing visual, this is its data. The
        `files`/`dependents`/`routes` keys are the policy-facing dimensions the governance
        predicate is measured against (ticket 05/08): the class-level guard touches two
        helper files, one dependent call site, one route."""
        if not self._is_anchor(finding):
            raise _no_oracle(finding)
        return {
            "changed_symbol": "get_order",
            "callers": ["route:GET /orders/{order_id}"],
            "max_callers": 1,
            "rings": ["caller", "pr"],
            "files": 2,
            "dependents": 1,
            "routes": 1,
        }

    def fix_plan(self, finding: Finding) -> dict[str, Any]:
        """The proposed class-level remediation surface for the anchor: route object reads
        through a shared ownership guard rather than inlining an `if user.id == ...` check
        at the one endpoint. Helper-only by construction, so the policy's fix predicates
        pass and the change is standing-preauthorized. `prepare_fix` realizes it as a patch
        (an in-process model for v1, per its caveat)."""
        if not self._is_anchor(finding):
            raise _no_oracle(finding)
        return {
            "changed_paths": [
                "app/apis/orders/authorization.py",
                "app/apis/orders/dependencies.py",
            ],
            "is_class_level": True,
            "preserves_legitimate_access": True,
        }

    def prepare_fix(self, finding: Finding) -> PreparedFix:
        """The class-level fix for the anchor: add the ownership guard. The patch is a
        real unified diff between the vulnerable and fixed implementations (modelled
        in-process; the vendored file it stands for is
        `target/dvrestaurant/app/apis/orders/services/get_order_service.py`)."""
        if not self._is_anchor(finding):
            raise _no_oracle(finding)
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
            patch_caveat=(
                "Not an applicable diff. This patch is the in-process model of the fix "
                "(`_skeleton_target.py`), which is why its headers name a different file "
                "than the finding above."
            ),
            finding_id=finding.get("id"),
            blast_radius=self.blast_radius(finding),
        )

    def run_exploit(self, finding: Finding, *, fixed: bool) -> bool:
        """Run the anchor's exploit oracle against the vulnerable or fixed implementation.
        Inverted polarity: True == exploit succeeded == still vulnerable. The hermetic
        in-process oracle models the anchor's by-path exploit test
        (`ave_seed_bola_order_read.py`), verified to flip this session."""
        if not self._is_anchor(finding):
            raise _no_oracle(finding)
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.exploit_cross_owner_read(impl)

    def legitimate_use_holds(self, *, fixed: bool) -> bool:
        """T2's positive check: the fix must not break the legitimate owner's access."""
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.legitimate_owner_read(impl)
