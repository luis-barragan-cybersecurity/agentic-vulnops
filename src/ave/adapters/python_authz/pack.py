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
from pathlib import Path
from typing import Any

from ave.adapters.base import PinnedExploitResult, PreparedFix
from ave.adapters.python_authz import _pinned_env, catalog
from ave.adapters.python_authz import _skeleton_target as target
from ave.state import Finding

_REPO_ROOT = Path(__file__).resolve().parents[4]
_GET_ORDER = (
    _REPO_ROOT
    / "target"
    / "dvrestaurant"
    / "app"
    / "apis"
    / "orders"
    / "services"
    / "get_order_service.py"
)
_PATCH_REL = "target/dvrestaurant/app/apis/orders/services/get_order_service.py"

_FIXED_GET_ORDER = """\
from apis.auth.utils import RolesBasedAuthChecker, get_current_user
from apis.orders import schemas
from db.models import Order, User, UserRole
from db.session import get_db
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter()


@router.get("/orders/{order_id}", response_model=schemas.Order)
def get_order(
    order_id: int,
    db: Session = Depends(get_db),
    auth=Depends(RolesBasedAuthChecker([UserRole.CUSTOMER])),
    current_user: User = Depends(get_current_user),
):
    db_order = db.query(Order).filter(Order.id == order_id).first()
    if db_order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    if db_order.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Order not found")
    return db_order
"""


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

    def dedup_key(self, finding: Finding) -> str:
        """`file:symbol` as this pack reports locations. A trailing numeric component is
        a *line* (what a SARIF feed reports) and resolving it to the enclosing symbol is
        intake work; until then the raw location is returned unchanged so the finding
        stays a visible duplicate rather than being merged on a guess."""
        location = str(finding.get("location", "")).strip()
        file, sep, tail = location.rpartition(":")
        if not sep or not file or not tail or tail.isdigit():
            return location
        return f"{file}:{tail}"

    def _is_anchor(self, finding: Finding) -> bool:
        return finding.get("id") == catalog.anchor_id()

    def blast_radius(self, finding: Finding) -> dict[str, Any]:
        """Return reviewer commands and an explicitly unmeasured policy radius."""
        if not self._is_anchor(finding):
            raise _no_oracle(finding)
        evidence = finding.get("evidence", {})
        oracle = evidence.get("oracle", {}) if isinstance(evidence, dict) else {}
        oracle_ref = f"{oracle.get('path')}::{oracle.get('test')}"
        return {
            "changed_symbol": "get_order",
            "callers": ["route:GET /orders/{order_id}"],
            "max_callers": 1,
            "rings": ["caller", "pr"],
            "files": None,
            "dependents": None,
            "routes": None,
            "cleared": [],
            "before_you_merge": [
                {
                    "command": f"cd target/dvrestaurant && poetry run pytest {oracle_ref}",
                    "expect": (
                        "FAILS after this fix (inverted polarity — this test IS the "
                        "attack); needs the target's pinned Poetry/Docker env"
                    ),
                },
                {
                    "command": "cd target/dvrestaurant && poetry run pytest app/tests",
                    "expect": (
                        "green — the target's own suite (the T2 rung; the ladder above "
                        "is honest about not having run it)"
                    ),
                },
            ],
        }

    def fix_plan(self, finding: Finding) -> dict[str, Any]:
        if not self._is_anchor(finding):
            raise _no_oracle(finding)
        return {
            "changed_paths": ["app/apis/orders/services/get_order_service.py"],
            "is_class_level": True,
            "preserves_legitimate_access": True,
        }

    def prepare_fix(self, finding: Finding) -> PreparedFix:
        if not self._is_anchor(finding):
            raise _no_oracle(finding)
        before = _GET_ORDER.read_text(encoding="utf-8")
        patch = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                _FIXED_GET_ORDER.splitlines(keepends=True),
                fromfile=f"a/{_PATCH_REL}",
                tofile=f"b/{_PATCH_REL}",
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
        if not self._is_anchor(finding):
            raise _no_oracle(finding)
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.exploit_cross_owner_read(impl)

    def legitimate_use_holds(self, *, fixed: bool) -> bool:
        """T2's positive check: the fix must not break the legitimate owner's access."""
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.legitimate_owner_read(impl)

    def run_pinned_exploit(
        self, finding: Finding, prepared: dict[str, Any]
    ) -> PinnedExploitResult:
        return _pinned_env.run_pinned_capture(finding, prepared)
