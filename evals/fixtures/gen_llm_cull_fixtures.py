from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ave.adapters.python_authz.code_facts import CodeFactsStore
from ave.adapters.python_authz.inventory import InventoryRecord
from ave.adapters.python_authz.llm_finder import LLMFinder
from ave.adapters.python_authz.model import FixtureModelClient, fixture_slug
from ave.adapters.python_authz.pack import FIXTURES_DIR

_CULL_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "ave"
    / "adapters"
    / "python_authz"
    / "fixtures"
    / "llm_cull"
)


@dataclass(frozen=True)
class Plan:
    ruled_out: str
    needle: str


_PLANS: dict[str, Plan] = {
    "get_order": Plan(
        ruled_out=(
            "A post-fetch ownership guard binds db_order to current_user on every path"
        ),
        needle="return db_order",
    ),
    "update_profile": Plan(
        ruled_out="The profile update operates only on current_user",
        needle="get_user_by_username(db, user.username)",
    ),
    "get_discount_coupons": Plan(
        ruled_out="Coupon listing always binds to current_user.id",
        needle="user_id if user_id is not None else current_user.id",
    ),
    "get_referral_code_endpoint": Plan(
        ruled_out="Referral code lookup always uses current_user.id",
        needle="UserModel.username == username",
    ),
    "delete_menu_item": Plan(
        ruled_out="A RolesBasedAuthChecker role gate protects this mutation",
        needle="Depends(get_current_user)",
    ),
    "update_menu_item": Plan(
        ruled_out="A RolesBasedAuthChecker role gate protects this mutation",
        needle="Depends(get_current_user)",
    ),
    "update_user_role": Plan(
        ruled_out="Only an administrator can change another user's role",
        needle="update_user(db, user.username, user)",
    ),
    "get_orders": Plan(
        ruled_out="Listing orders for delivery requires a staff role",
        needle="db.query(Order)",
    ),
}


def _find_line(store: CodeFactsStore, record: InventoryRecord, needle: str) -> int:
    source = store.get_source(record.file, (record.line_start, record.line_end))
    for offset, line in enumerate(source.splitlines()):
        if " ".join(needle.split()) in " ".join(line.split()):
            return record.line_start + offset
    raise ValueError(f"needle {needle!r} not found in {record.handler_id}")


def _turns(
    store: CodeFactsStore,
    record: InventoryRecord,
    finding: dict[str, Any],
    plan: Plan,
) -> list[list[dict[str, Any]]]:
    _find_line(store, record, plan.needle)
    evidence = finding.get("evidence", {})
    stance_cites = list(evidence.get("citations") or [])
    if not stance_cites:
        raise ValueError(f"finder finding {finding.get('id')} has no citations")
    hyp_cite = {
        "file": record.file,
        "start_line": record.line_start,
        "end_line": record.line_end,
        "contains": plan.needle,
    }
    review = {
        "location": finding.get("location"),
        "kind": finding.get("kind"),
        "stance": "keep",
        "reason": (
            "The benign authorization pattern does not hold on every path; "
            "the finder's gap stands."
        ),
        "cited_spans": stance_cites,
        "hypotheses": [
            {
                "kind": "ruled_out",
                "claim": plan.ruled_out,
                "cited_spans": [hyp_cite],
            }
        ],
    }
    return [
        [{"name": "get_source", "arguments": {"file": record.file}}],
        [{"name": "submit_review", "arguments": review}],
    ]


def main() -> int:
    store = CodeFactsStore.build()
    report = LLMFinder(store, FixtureModelClient(fixtures_dir=FIXTURES_DIR)).find()
    if not report.accepted:
        raise SystemExit("finder produced no accepted findings to review")
    _CULL_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for candidate in report.accepted:
        plan = _PLANS.get(candidate.record.symbol)
        if plan is None:
            raise SystemExit(
                f"no cull plan for accepted finding {candidate.record.handler_id!r}; "
                "add one to _PLANS."
            )
        turns = _turns(store, candidate.record, dict(candidate.finding), plan)
        path = _CULL_DIR / fixture_slug(candidate.record.handler_id)
        path.write_text(json.dumps({"turns": turns}, indent=2) + "\n", encoding="utf-8")
        written += 1
    print(f"wrote {written} LLM-cull fixtures to {_CULL_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
