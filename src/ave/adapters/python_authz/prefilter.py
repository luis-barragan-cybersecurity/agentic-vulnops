"""The deterministic pre-filter — drop candidates by arithmetic, before any model call.

Scale is a budget problem, not a context problem (find-stage design, decision 4): the
model reasons over one candidate at a time, so the way to keep the run cheap is to spend a
call only where a call can change the answer. This pass reads each inventory record and
assigns a **screen** — ``drop`` / ``cheap`` / ``examine`` — with a recorded reason, using
nothing but the facts already gathered. No model, no network.

The one property that matters is **soundness in the drop direction**: a real ownership or
function-level gap must never be dropped, or recall dies and "AVE beats the scanner" is a
lie. So ``drop`` is reserved for handlers that provably cannot be either class —

* a route that touches no owned object and performs no privileged mutation, and
* is either authenticated-and-reads-nothing, or is public and reads only public data or
  bootstraps auth (login / register / reset).

Everything that could still be a finding is kept. ``cheap`` marks the handlers whose
ownership binding is already, unconditionally, the caller's own identity — the D-03 / D-04
decoy shape — where at most a cheap look is warranted. ``examine`` is everything else: the
real candidates the model must judge. Crucially, a *conditional* identity binding (the
I-06 / I-07 shape, where an attacker-supplied id is honoured on one branch) is **never**
downgraded to cheap — that is exactly the case a structural predicate mis-clears, and the
reason the model exists.

The guarantee is testable and tested: every catalogued instance survives to ``examine``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ave.adapters.python_authz.inventory import Inventory, InventoryRecord

Screen = Literal["drop", "cheap", "examine"]


@dataclass(frozen=True)
class ScreenResult:
    """One handler's screen and the one-line reason it got it — carried into the run record
    so the coverage line can say not just how many were examined, but why the rest were
    not."""

    handler_id: str
    screen: Screen
    reason: str


def _owned_models_touched(record: InventoryRecord, inventory: Inventory) -> list[str]:
    return [m for m in record.models_queried if inventory.has_owner_column(m)]


def _reads_owned_object(record: InventoryRecord, inventory: Inventory) -> bool:
    """The handler queries a model that has an owner column — there is an object whose
    ownership could go unchecked."""
    return bool(_owned_models_touched(record, inventory))


def _unconditional_identity_binding(record: InventoryRecord) -> bool:
    """The caller's own identity constrains the object on *every* path — an owner-column
    filter bound to caller identity, or a post-fetch ownership guard, that does not sit
    inside a branch keyed on caller input. The D-03 / D-04 shape."""
    filter_bound = any(
        q.rhs == "caller-identity" and not q.under_caller_branch
        for q in record.query_filters
    )
    guard_bound = any(not g.under_caller_branch for g in record.identity_guards)
    return filter_bound or guard_bound


def _conditional_identity_binding(record: InventoryRecord) -> bool:
    """An identity binding that holds on some branch only — the I-06 / I-07 shape a
    structural predicate mis-clears. Its presence forces ``examine``, never ``cheap``."""
    return any(
        q.rhs == "caller-identity" and q.under_caller_branch
        for q in record.query_filters
    ) or any(g.under_caller_branch for g in record.identity_guards)


def screen_record(record: InventoryRecord, inventory: Inventory) -> ScreenResult:
    """Assign one handler its screen. Sound in the drop direction: only handlers that can be
    neither an object-ownership gap nor a function-level gap are dropped."""
    reads_owned = _reads_owned_object(record, inventory)

    # A mutation without a role gate is a function-level-authorization candidate, whatever
    # it touches (the object may be mutated through a helper the handler only calls). This
    # is the I-01 / I-03 / I-08 shape, and the reason method alone — not just in-handler
    # queries — decides `mutates_state`.
    if record.mutates_state and not record.role_gate:
        return ScreenResult(
            record.handler_id,
            "examine",
            "mutating route with no role gate — function-level authorization candidate",
        )

    # A role-gated mutation has the function-level check the class is about; the object it
    # writes is the caller's own by construction here. A cheap look at most.
    if record.mutates_state and record.role_gate:
        return ScreenResult(
            record.handler_id,
            "cheap",
            "mutation is role-gated — function-level check present",
        )

    # From here down the route is a non-mutating read.
    if not reads_owned:
        # Touches no owned object and does not mutate — nothing to own, no function to
        # abuse. Public infrastructure, a public read, or an authenticated no-op read.
        where = "public" if not record.authenticated else "authenticated"
        return ScreenResult(
            record.handler_id,
            "drop",
            f"{where} read of no owned object — neither an ownership nor a function gap",
        )

    # Reads an owned object. If the caller's identity constrains it on every path, the
    # ownership check is already there; a conditional binding is the trap and stays examine.
    if _unconditional_identity_binding(record) and not _conditional_identity_binding(
        record
    ):
        return ScreenResult(
            record.handler_id,
            "cheap",
            "object is bound to the caller's identity on every path",
        )

    return ScreenResult(
        record.handler_id,
        "examine",
        "reads an owned object without an unconditional ownership check",
    )


def screen_inventory(inventory: Inventory) -> dict[str, ScreenResult]:
    """Screen every handler; keyed by ``handler_id`` for the store and the coverage count."""
    return {
        record.handler_id: screen_record(record, inventory)
        for record in inventory.handlers
    }
