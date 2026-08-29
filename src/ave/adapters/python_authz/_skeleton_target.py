"""Hermetic in-process oracle for the loop **anchor** (catalog instance I-04 — the
`get_order` object-ownership BOLA gap).

Ticket 04 pointed the pack at the real vendored target, whose catalog
(`target/catalog.json`, 8 instances + decoys) the pack declares exactly one finding from:
this anchor. The module is retained as that anchor's **in-process oracle model**: two
implementations of the same endpoint — vulnerable and fixed — plus the exploit oracle
(inverted polarity) and a legitimate-use check. The loop drives I-04 through this model so
`make check` runs without standing up the target's Python-3.10 / FastAPI-0.103
environment. The anchor's canonical by-path oracle is
`target/dvrestaurant/app/tests/vulns/ave_seed_bola_order_read.py` (verified to flip);
wiring the loop to run the by-path oracles of the other instances is the next deepening.

BOLA (missing object-ownership check) is the semantic family a pattern scanner structurally
cannot see, which is the whole point of AVE.
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
