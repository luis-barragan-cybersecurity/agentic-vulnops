from __future__ import annotations

import difflib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ave.adapters.base import FindingBatch, PinnedExploitResult, PreparedFix
from ave.adapters.python_authz import _pinned_env, catalog
from ave.adapters.python_authz import _skeleton_target as target
from ave.adapters.python_authz._binding import TARGET_NODE, BindingError, _ExploitBinder
from ave.adapters.python_authz.code_facts import CodeFactsStore
from ave.adapters.python_authz.cull import (
    cull_attributes,
    pair_reviews,
    review_accepted,
)
from ave.adapters.python_authz.llm_finder import (
    OWNERSHIP_GAP,
    AcceptedCandidate,
    LLMFinder,
)
from ave.adapters.python_authz.measurement import (
    BlastRadiusMeasurement,
    measured_finding,
)
from ave.adapters.python_authz.model import default_model_client
from ave.findings import Dependents
from ave.state import Finding

_REPO_ROOT = Path(__file__).resolve().parents[4]
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


def _has_route(finding: Finding) -> bool:
    evidence = finding.get("evidence")
    handler = evidence.get("handler") if isinstance(evidence, dict) else None
    if not isinstance(handler, dict):
        return False
    method = handler.get("method")
    path = handler.get("path")
    return (
        isinstance(method, str)
        and bool(method.strip())
        and isinstance(path, str)
        and bool(path.strip())
    )


def _cleared_how(reason: str, hypothesis: dict[str, Any]) -> str:
    citations = hypothesis.get("citations") or []
    first = citations[0] if citations and isinstance(citations[0], dict) else {}
    file = first.get("file", "?")
    start = first.get("start_line", "?")
    end = first.get("end_line", start)
    span = f"{file}:{start}" if start == end else f"{file}:{start}-{end}"
    contains = first.get("contains", "")
    cite = f"{span} — {contains}" if contains else span
    if reason:
        return f"{reason} ({cite})"
    return cite


def _cleared_rows(finding: Finding) -> list[dict[str, str]]:
    evidence = finding.get("evidence")
    review = evidence.get("counter_review") if isinstance(evidence, dict) else None
    if not isinstance(review, dict) or review.get("basis") != "validated":
        return []
    reason = str(review.get("reason", "")).strip()
    rows: list[dict[str, str]] = []
    for hypothesis in review.get("hypotheses") or []:
        if not isinstance(hypothesis, dict) or hypothesis.get("kind") != "ruled_out":
            continue
        claim = str(hypothesis.get("claim", "")).strip()
        if not claim:
            continue
        rows.append({"ruled_out": claim, "how": _cleared_how(reason, hypothesis)})
    return rows


def _cannot_finish(finding: Finding) -> NotImplementedError:
    return NotImplementedError(
        f"{finding.get('id')} is a finding this pack cannot finish."
    )


def _stamp_if_present(finding: Finding) -> dict[str, str] | None:
    evidence = finding.get("evidence")
    raw = evidence.get("oracle") if isinstance(evidence, dict) else None
    if not isinstance(raw, dict):
        return None
    path = raw.get("path")
    test = raw.get("test")
    if not isinstance(path, str) or not path or test != "test_authorization_boundary":
        return None
    return {"path": path, "test": test}


def _reviewer_commands(finding: Finding) -> list[dict[str, str]]:
    """The Before-you-merge commands: the bound exploit (when Prepare stamped one) and
    the target's own T2 suite."""
    commands: list[dict[str, str]] = []
    stamp = _stamp_if_present(finding)
    if stamp is not None:
        commands.append(
            {
                "command": (
                    f"cp {stamp['path']} target/dvrestaurant/{TARGET_NODE} && "
                    f"cd target/dvrestaurant && poetry run pytest "
                    f"{TARGET_NODE}::{stamp['test']}"
                ),
                "expect": (
                    "FAILS after this fix (inverted polarity — this test IS the "
                    "attack)"
                ),
            }
        )
    commands.append(
        {
            "command": "cd target/dvrestaurant && poetry run pytest app/tests",
            "expect": (
                "green — the target's own suite (the T2 rung; the ladder above "
                "is honest about not having run it)"
            ),
        }
    )
    return commands


def _patch_paths(patch: str) -> tuple[str, ...]:
    """Unique target-relative paths from the ``---``/``+++`` headers, sorted —
    ``a/target/dvrestaurant/app/x.py`` becomes ``app/x.py``. `/dev/null` is ignored."""
    paths: set[str] = set()
    for line in patch.splitlines():
        if not line.startswith(("--- ", "+++ ")):
            continue
        raw = line[4:].split("\t")[0].strip()
        if raw == "/dev/null":
            continue
        if raw.startswith(("a/", "b/")):
            raw = raw[2:]
        paths.add(raw.removeprefix("target/dvrestaurant/"))
    return tuple(sorted(paths))


class PythonAuthzPack:
    name = "python_authz"

    def __init__(self) -> None:
        self._binder = _ExploitBinder(patch_rel=_PATCH_REL)

    def bind_run(self, run_root: Path) -> None:
        self._binder.bind_run(run_root)

    def find(self, target_ref: str) -> FindingBatch:
        del target_ref
        store = CodeFactsStore.build()
        finder_client = default_model_client(FIXTURES_DIR)
        cull_client = default_model_client(CULL_FIXTURES_DIR)
        report = LLMFinder(store, finder_client).find()
        accepted = [
            AcceptedCandidate(
                record=candidate.record,
                finding=measured_finding(
                    store,
                    candidate,
                    changed_paths=self._proposed_paths(candidate.finding),
                ),
            )
            for candidate in report.accepted
        ]
        reviews = review_accepted(
            store, accepted, cull_client, protect=self.can_drive
        )
        kept, suppressed = pair_reviews(accepted, reviews)
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
        return (
            finding.get("location") == catalog.anchor_location()
            and finding.get("kind") == OWNERSHIP_GAP
            and _has_route(finding)
        )

    def _proposed_paths(self, finding: Finding) -> list[str] | None:
        """The fix plan's changed paths for a drivable finding, None when no plan exists."""
        if not self.can_drive(finding):
            return None
        return [str(p) for p in self.fix_plan(finding)["changed_paths"]]

    def measured_dependents(self, findings: Iterable[Finding]) -> Dependents:
        return {
            str(f.get("id")): m.dependents
            for f in findings
            if (m := BlastRadiusMeasurement.from_finding(f)) is not None
        }

    def blast_radius(self, finding: Finding) -> dict[str, Any]:
        """Project the measurement `find()` recorded on the finding. A measured finding
        is readable even when `can_drive()` is false; a finding this pack neither
        measured nor can drive still raises."""
        measurement = BlastRadiusMeasurement.from_finding(finding)
        if measurement is None and not self.can_drive(finding):
            raise _cannot_finish(finding)
        projected = (
            measurement.projection()
            if measurement is not None
            else {"files": None, "dependents": None, "routes": None, "fact": None}
        )
        return {
            **projected,
            "cleared": _cleared_rows(finding),
            "before_you_merge": _reviewer_commands(finding),
        }

    def fix_plan(self, finding: Finding) -> dict[str, Any]:
        if not self.can_drive(finding):
            raise _cannot_finish(finding)
        return {
            "changed_paths": ["app/apis/orders/services/get_order_service.py"],
            "is_class_level": True,
            "preserves_legitimate_access": True,
        }

    def prepare_fix(self, finding: Finding) -> PreparedFix:
        if not self.can_drive(finding):
            raise _cannot_finish(finding)
        stamp = self._binder.ensure_bound(finding)
        raw = finding.get("evidence")
        evidence: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}
        evidence["oracle"] = stamp
        finding["evidence"] = evidence
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
            patch_paths=_patch_paths(patch),
            finding_id=finding.get("id"),
            blast_radius=self.blast_radius(finding),
        )

    def run_exploit(self, finding: Finding, *, fixed: bool) -> bool:
        """Hermetic. Pack unit tests only. Not product T1."""
        if not self.can_drive(finding):
            raise _cannot_finish(finding)
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.exploit_cross_owner_read(impl)

    def legitimate_use_holds(self, *, fixed: bool) -> bool:
        """T2's positive check: the fix must not break the legitimate owner's access."""
        impl = target.get_order_fixed if fixed else target.get_order_vulnerable
        return target.legitimate_owner_read(impl)

    def run_pinned_exploit(
        self, finding: Finding, prepared: dict[str, Any]
    ) -> PinnedExploitResult:
        try:
            stamp = self._binder.read_stamp(finding)
        except BindingError:
            return _pinned_env.unavailable("bound exploit stamp is missing or invalid")
        return _pinned_env.run_bound(stamp, prepared)
