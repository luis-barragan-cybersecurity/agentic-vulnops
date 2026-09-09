"""`python_authz` — v1's language pack: Python + FastAPI, BOLA/BFLA.

The first concrete `LanguagePack`. Ticket 03 (walking skeleton) drove it against one
synthetic instance; ticket 04 repointed it at the real vendored target
(`target/catalog.json`, 8 authorization instances + decoys, each bound to a by-path
exploit oracle, inverted polarity). The four seam methods are what stay stable across that
swap and across a future second-language pack (D3).

The finding source is now the LLM finder (ticket 25): `find()` runs it over the code-facts
store and returns one `FindingBatch` of the ownership and role gaps it rediscovers, each
`ave:llm-finder` and citation-validated, offline by default (recorded fixtures). The
finding at the loop anchor location I-04 (the `get_order` object-ownership gap) is bound
to the pack's hermetic exploit oracle — modelled in-process by `_skeleton_target`, so
`make check` runs without standing up the target's environment — so one finding per run
is driven to a test-verified fix. Every other kept finding is real and reported but not
yet drivable (`can_drive()` is False there); a generated exploit binds each in ticket 27,
and the other by-path oracles run in the target's pinned env. The four seam methods stay
stable across that deepening and a second pack (D3).
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any, cast

from ave.adapters.base import FindingBatch, PinnedExploitResult, PreparedFix
from ave.adapters.python_authz import _pinned_env, catalog
from ave.adapters.python_authz import _skeleton_target as target
from ave.adapters.python_authz.code_facts import CodeFactsStore
from ave.adapters.python_authz.cull import (
    attach_review,
    cull_attributes,
    location_key,
    partition_batch,
    review_accepted,
)
from ave.adapters.python_authz.llm_finder import AcceptedCandidate, LLMFinder
from ave.adapters.python_authz.model import default_model_client
from ave.state import Finding

_REPO_ROOT = Path(__file__).resolve().parents[4]
#: The LLM finder's recorded transcripts — replayed offline so `find()` (and `make check`)
#: need no model access; the live model is reached only on `AVE_LLM_LIVE` (see `model`).
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "llm_finder"
CULL_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "llm_cull"
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


def _bind_anchor(original: Finding) -> Finding:
    finding = cast("Finding", dict(original))
    if finding.get("location") != catalog.anchor_location():
        return finding
    raw = finding.get("evidence", {})
    evidence: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}
    evidence["oracle"] = catalog.anchor_oracle()
    evidence["is_loop_anchor"] = True
    finding["evidence"] = evidence
    return finding


def _no_oracle(finding: Finding) -> NotImplementedError:
    return NotImplementedError(
        f"{finding.get('id')} is not at the loop anchor location {catalog.anchor_location()}. "
        f"Driving it needs a generated exploit bound to its own oracle (ticket 27)."
    )


class PythonAuthzPack:
    """Python/FastAPI authorization pack. v1 scope: the vendored DVRestaurant catalog.

    The LLM finder (ticket 25) reasons over the code-facts store and rediscovers the
    ownership and role gaps a pattern scanner is blind to; `find()` returns them as one
    `FindingBatch`. The finding that lands at the anchor location (I-04, `get_order`) is
    bound to the pack's hermetic exploit oracle so the end-to-end loop still drives one
    finding to a test-verified fix. Every other kept finding is real and reported, but
    not yet drivable — a generated exploit binds it in ticket 27 — so `can_drive()` is
    True only at the anchor location for now, and the seam widens there."""

    name = "python_authz"

    def find(self, target_ref: str) -> FindingBatch:
        """Run the model finder, then one adversarial session per accepted finding.

        Offline by default. The finding at the anchor location is enriched with the
        loop's hermetic oracle before the cull, so a valid suppress cannot overturn a
        bound oracle. The finder and the cull never read that binding (or the answer
        key) to detect it.
        """
        del target_ref
        store = CodeFactsStore.build()
        finder_client = default_model_client(FIXTURES_DIR)
        cull_client = default_model_client(CULL_FIXTURES_DIR)
        report = LLMFinder(store, finder_client).find()
        accepted = [
            AcceptedCandidate(record=candidate.record, finding=_bind_anchor(candidate.finding))
            for candidate in report.accepted
        ]
        reviews = review_accepted(store, accepted, cull_client)
        by_key = {(review.location_key, review.kind): review for review in reviews}
        findings = [candidate.finding for candidate in accepted]
        kept, suppressed = partition_batch(findings, reviews)
        kept = tuple(
            attach_review(
                finding,
                by_key.get((location_key(finding), str(finding.get("kind", "")))),
            )
            for finding in kept
        )
        attrs = report.to_attributes()
        attrs["cull"] = cull_attributes(reviews, client_mode=cull_client.name)
        return FindingBatch(kept=kept, suppressed=suppressed, report=attrs)

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

    def can_drive(self, finding: Finding) -> bool:
        """Whether this pack can drive `finding` to a test-verified fix now: True only for
        the finding bound to the loop's hermetic oracle (the anchor location). Ticket 27's
        generated exploits widen this to any finding whose exploit flips."""
        evidence = finding.get("evidence", {})
        return bool(isinstance(evidence, dict) and evidence.get("is_loop_anchor"))

    def _is_anchor(self, finding: Finding) -> bool:
        return self.can_drive(finding)

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
