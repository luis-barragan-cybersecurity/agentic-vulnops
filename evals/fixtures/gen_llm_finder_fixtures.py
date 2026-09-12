"""Regenerate the LLM finder's recorded transcripts (ticket 25).

The finder replays a recorded transcript per candidate so ``make check`` runs offline
(`ave.adapters.python_authz.model.FixtureModelClient`). This script writes those recordings
from the *real* code-facts store, so every citation a fixture submits resolves against the
same source the finder validates it against — the fixtures cannot drift from the target.

Each recording is a stand-in for a live model session, encoding the verdict a correct
authorization review reaches from the code facts (never from the catalog answer key, which
the finder cannot read). When live model access is available, ``AVE_LLM_LIVE=1`` with
``AVE_LLM_RECORD`` set to the parent record root writes
``<record-root>/llm_finder/<slug>.json``. Run:
``python -m evals.fixtures.gen_llm_finder_fixtures``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ave.adapters.python_authz.code_facts import CodeFactsStore
from ave.adapters.python_authz.inventory import InventoryRecord
from ave.adapters.python_authz.llm_finder import OWNERSHIP_GAP, ROLE_GAP
from ave.adapters.python_authz.model import fixture_slug

_FIXTURES_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "ave"
    / "adapters"
    / "python_authz"
    / "fixtures"
    / "llm_finder"
)


@dataclass(frozen=True)
class Plan:
    """The recording plan for one candidate: which models/symbols the session retrieves, and
    the verdict it submits. `needle` is the source text the finding cites — looked up in the
    real source so the citation is valid by construction."""

    is_finding: bool
    kind: str = ""
    confidence: float = 0.0
    rationale: str = ""
    needle: str = ""
    models: tuple[str, ...] = ()
    callers: tuple[str, ...] = ()


#: One plan per examine candidate, keyed by handler symbol. Verdicts are derived from the
#: code facts, not the catalog: a missing ownership binding under some branch is a finding; a
#: guard that holds on every path, or an object that is always the caller's own, is not.
_PLANS: dict[str, Plan] = {
    # --- findings: the ownership and role gaps a pattern scanner is blind to -----------
    "get_order": Plan(
        is_finding=True,
        kind=OWNERSHIP_GAP,
        confidence=0.9,
        rationale=(
            "Fetches an Order by caller-supplied order_id and returns it with no ownership "
            "binding: Order.user_id is never constrained and there is no post-fetch guard, "
            "so any authenticated customer reads any customer's order (BOLA)."
        ),
        needle="Order.id == order_id",
        models=("Order",),
    ),
    "update_profile": Plan(
        is_finding=True,
        kind=OWNERSHIP_GAP,
        confidence=0.86,
        rationale=(
            "Selects the profile to update by the caller-supplied body field user.username "
            "rather than current_user, so a caller updates another user's profile — the "
            "object is the identity itself (BOLA)."
        ),
        needle="get_user_by_username(db, user.username)",
        callers=("get_user_by_username",),
    ),
    "get_discount_coupons": Plan(
        is_finding=True,
        kind=OWNERSHIP_GAP,
        confidence=0.86,
        rationale=(
            "Honours an attacker-supplied user_id query parameter on one branch "
            "(user_id if user_id is not None else current_user.id), so a caller reads "
            "another user's discount coupons (BOLA); the caller-identity branch masks it."
        ),
        needle="user_id if user_id is not None else current_user.id",
        models=("DiscountCoupon",),
    ),
    "get_referral_code_endpoint": Plan(
        is_finding=True,
        kind=OWNERSHIP_GAP,
        confidence=0.85,
        rationale=(
            "On the username-is-not-None branch it queries User by the caller-supplied "
            "username instead of current_user.id, so a caller reads another user's referral "
            "code (BOLA); the else branch binds to the caller and hides the gap."
        ),
        needle="UserModel.username == username",
        models=("User",),
    ),
    "delete_menu_item": Plan(
        is_finding=True,
        kind=ROLE_GAP,
        confidence=0.83,
        rationale=(
            "Deletes a menu item behind get_current_user only, with no RolesBasedAuthChecker "
            "role gate, so any authenticated user performs a privileged mutation (BFLA)."
        ),
        needle="Depends(get_current_user)",
        callers=("delete_menu_item",),
    ),
    "update_menu_item": Plan(
        is_finding=True,
        kind=ROLE_GAP,
        confidence=0.82,
        rationale=(
            "Updates a menu item behind get_current_user only, with no role gate, so any "
            "authenticated user performs a privileged mutation delegated to "
            "utils.update_menu_item (BFLA)."
        ),
        needle="Depends(get_current_user)",
        callers=("update_menu_item",),
    ),
    "update_user_role": Plan(
        is_finding=True,
        kind=ROLE_GAP,
        confidence=0.84,
        rationale=(
            "Changes a user's role behind get_current_user only; the sole guard forbids the "
            "CHEF role, so any authenticated user escalates to other privileged roles "
            "(BFLA) — the role gate is a role check, not authentication."
        ),
        needle="update_user(db, user.username, user)",
    ),
    "get_orders": Plan(
        is_finding=True,
        kind=ROLE_GAP,
        confidence=0.8,
        rationale=(
            "Lists every order for delivery with no auth dependency at all, so an "
            "unauthenticated caller reads all orders — a function that must require a "
            "delivery/staff role exposed to the public (BFLA)."
        ),
        needle="db.query(Order)",
    ),
    # --- cleared: benign or correct-but-unusual authorization -------------------------
    "get_token": Plan(
        is_finding=False,
        rationale="Unauthenticated token issuance (login); no owned object is read or written.",
    ),
    "register_user": Plan(
        is_finding=False,
        rationale=(
            "Public registration bootstrap; creates the caller's own account, "
            "no object to own."
        ),
    ),
    "reset_password": Plan(
        is_finding=False,
        rationale=(
            "Password-reset request bootstrap; a public flow, not an "
            "object-ownership action."
        ),
    ),
    "set_new_password": Plan(
        is_finding=False,
        rationale=(
            "Password-reset completion; the User is selected via the reset flow, not a "
            "caller-owned object read, so this is a bootstrap path, not a BOLA."
        ),
    ),
    "patch_profile": Plan(
        is_finding=False,
        rationale=(
            "Operates only on current_user.username; there is no caller-controlled object "
            "selection. Mass-assignment of fields is an input-validation concern, not an "
            "authorization-ownership gap."
        ),
    ),
    "get_order_status": Plan(
        is_finding=False,
        rationale=(
            "Fetches Order by caller-supplied id but guards it on every path with "
            "db_order.user_id != current_user.id, binding access to the caller — a correct "
            "post-fetch ownership check, not a gap."
        ),
    ),
    "apply_referral_code": Plan(
        is_finding=False,
        rationale=(
            "Credits the caller's own account (DiscountCoupon.user_id = current_user.id); the "
            "referral_code lookup selects the referrer to attribute, not an object the caller "
            "reads or mutates, so there is no ownership gap."
        ),
    ),
}


def _find_line(store: CodeFactsStore, record: InventoryRecord, needle: str) -> int:
    """The 1-based line within the handler span whose (comment-stripped) source contains
    `needle`. Raises if absent, so a stale needle fails loudly at generation, never at
    replay."""
    source = store.get_source(record.file, (record.line_start, record.line_end))
    for offset, line in enumerate(source.splitlines()):
        if " ".join(needle.split()) in " ".join(line.split()):
            return record.line_start + offset
    raise ValueError(f"needle {needle!r} not found in {record.handler_id}")


def _turns(
    store: CodeFactsStore, record: InventoryRecord, plan: Plan
) -> list[list[dict[str, Any]]]:
    """The recorded turns: retrieval batches, then a submit_verdict batch."""
    turns: list[list[dict[str, Any]]] = [
        [{"name": "get_source", "arguments": {"file": record.file}}]
    ]
    for model in plan.models:
        turns.append([{"name": "model_definition", "arguments": {"name": model}}])
    for symbol in plan.callers:
        turns.append([{"name": "callers_of", "arguments": {"symbol": symbol}}])

    verdict: dict[str, object] = {
        "handler_id": record.handler_id,
        "is_finding": plan.is_finding,
        "rationale": plan.rationale,
    }
    if plan.is_finding:
        line = _find_line(store, record, plan.needle)
        verdict["kind"] = plan.kind
        verdict["confidence"] = plan.confidence
        verdict["cited_spans"] = [
            {
                "file": record.file,
                "start_line": line,
                "end_line": line,
                "contains": plan.needle,
            }
        ]
    turns.append([{"name": "submit_verdict", "arguments": verdict}])
    return turns


def main() -> int:
    store = CodeFactsStore.build()
    _FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for record in store.candidates("examine"):
        plan = _PLANS.get(record.symbol)
        if plan is None:
            raise SystemExit(
                f"no fixture plan for examine candidate {record.handler_id!r}; "
                f"add one to _PLANS."
            )
        turns = _turns(store, record, plan)
        path = _FIXTURES_DIR / fixture_slug(record.handler_id)
        path.write_text(json.dumps({"turns": turns}, indent=2) + "\n", encoding="utf-8")
        written += 1
    print(f"wrote {written} LLM-finder fixtures to {_FIXTURES_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
