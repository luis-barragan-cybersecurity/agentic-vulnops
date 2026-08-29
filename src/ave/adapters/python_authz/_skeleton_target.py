"""Synthetic 'code under review' for the walking skeleton — one minimal BOLA
(object-ownership) instance.

This stands in for the real vendored Damn Vulnerable RESTaurant fork, which ticket 04
brings in as an 8-12 instance catalog with decoys. The skeleton needs exactly one real
case to walk the loop end to end; this is it. BOLA (missing object-ownership check) is
the L2 semantic anchor from the target survey — the family a pattern scanner structurally
cannot see, which is the whole point of AVE.

Two implementations of the same endpoint — vulnerable and fixed — plus the exploit oracle
(inverted polarity) and a legitimate-use check. The `python_authz` pack reads this module
as its finding source and its fix template; ticket 04 repoints the pack at the real target.
"""

from __future__ import annotations

from typing import Any

# A tiny data store: two orders owned by two different users.
_ORDERS: dict[int, dict[str, Any]] = {
    1: {"id": 1, "owner": "alice", "total": 42},
    2: {"id": 2, "owner": "bob", "total": 99},
}


def get_order_vulnerable(order_id: int, current_user: str) -> dict[str, Any]:
    """BOLA: returns the requested object with no ownership check — any authenticated
    user can read any order."""
    return _ORDERS[order_id]


def get_order_fixed(order_id: int, current_user: str) -> dict[str, Any]:
    """The class-level fix: enforce object ownership before returning the object."""
    order = _ORDERS[order_id]
    if order["owner"] != current_user:
        raise PermissionError("not the owner of this order")
    return order


def exploit_cross_owner_read(get_order: Any) -> bool:
    """The exploit oracle — **inverted polarity**.

    Alice (owner of order 1) attempts to read Bob's order (id 2). Returns True if the
    read SUCCEEDS with someone else's object (exploit worked -> still vulnerable), and
    False if it is blocked (fix holds).
    """
    try:
        order = get_order(2, "alice")
    except PermissionError:
        return False
    return bool(order["owner"] != "alice")


def legitimate_owner_read(get_order: Any) -> bool:
    """A positive test the fix must not break: the true owner can still read their order."""
    try:
        return bool(get_order(2, "bob")["id"] == 2)
    except PermissionError:
        return False
