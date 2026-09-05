# AVE capture harness (added 2026-09-04, planning ticket 12). NOT an upstream file.
# Instance I-04 — BOLA on GET /orders/{order_id}. This is the *pinned-env* companion to
# the by-path oracle `ave_seed_bola_order_read.py`: where that oracle only asserts the
# vulnerability, this harness captures the real attack EXCHANGE (request + the actual deny)
# so AVE's PR body can render a verbatim transcript instead of "not captured".
#
# It runs the same attack against the target as shipped (the vulnerable 200), then against
# the blessed ownership-check fix pattern (the get_order_status.py `user_id != current_user`
# -> 404) applied to the real models/session/router, and records both. It is INVERTED
# POLARITY like the oracle: before == 200 (vulnerable), after == 404 (fixed).
#
# Invoked BY PATH by AVE's pinned-env runner with $AVE_CAPTURE_PATH set (see
# src/ave/adapters/python_authz/_pinned_env.py); it is underscore-prefixed so pytest does
# not auto-collect it, and it needs the target's pinned Poetry env (Python 3.10 / FastAPI
# 0.103) — it does not run in AVE's own `make check`.
import json
import os
from typing import Any

from apis.auth.utils import RolesBasedAuthChecker, get_current_user
from apis.orders import schemas
from db.models import Order, OrderStatus, User, UserRole
from db.session import get_db
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

# Redaction, mirrored from ave._pinned_env / ave.pr — the capture never emits a
# secret-bearing header or a fence into the transcript AVE will publish. Two more gates
# (the runner and the renderer) re-check independently.
_FORBIDDEN = ("authorization:", "cookie:", "set-cookie:", "bearer ", "token=", "session=")
_MAX = 4000


def _fixed_app(attacker: User) -> FastAPI:
    """The real app with the BOLA fixed the blessed way: bind the object read to the caller
    and 404 on a mismatch, exactly as get_order_status.py already does. Built as a fresh app
    over the real Order model and session so the 'after' request is a faithful deny."""
    router = APIRouter()

    @router.get("/orders/{order_id}", response_model=schemas.Order)
    def get_order_fixed(
        order_id: int,
        db: Session = Depends(get_db),
        auth: Any = Depends(RolesBasedAuthChecker([UserRole.CUSTOMER])),
    ) -> Any:
        db_order = db.query(Order).filter(Order.id == order_id).first()
        if db_order is None or db_order.user_id != attacker.id:
            raise HTTPException(status_code=404, detail="Order not found")
        return db_order

    app = FastAPI()
    app.include_router(router)
    return app


def _redact(text: str) -> str:
    kept: list[str] = []
    for line in text.splitlines():
        if any(bad in line.lower() for bad in _FORBIDDEN):
            kept.append(line.split(":", 1)[0] + ": [redacted]")
        else:
            kept.append(line)
    return "\n".join(kept)[:_MAX]


def _render_request(response: Any) -> str:
    req = response.request
    path = req.url.raw_path.decode() if hasattr(req.url, "raw_path") else req.url.path
    lines = [f"{req.method} {path} HTTP/1.1", f"Host: {req.url.host}", "Accept: */*"]
    return _redact("\n".join(lines))


def _render_response(response: Any) -> str:
    reason = {200: "OK", 403: "Forbidden", 404: "Not Found"}.get(
        response.status_code, ""
    )
    head = f"HTTP/1.1 {response.status_code} {reason}".rstrip()
    ctype = response.headers.get("content-type", "application/json")
    body = response.text if len(response.text) <= 512 else response.text[:512] + "…"
    return _redact(f"{head}\ncontent-type: {ctype}\n\n{body}")


def test_capture_bola_cross_customer_order_read(test_db: Session) -> None:
    """Capture the attack twice: shipped (vulnerable 200) then fixed (deny 404)."""
    from init_app import init_app

    attacker = User(
        id=3,
        username="customer",
        password="x",
        first_name="Customer",
        last_name="",
        phone_number="1234",
        role=UserRole.CUSTOMER,
    )
    victim = User(
        id=99,
        username="victim",
        password="x",
        first_name="Victim",
        last_name="",
        phone_number="999",
        role=UserRole.CUSTOMER,
    )
    order = Order(
        id=500,
        user_id=99,
        status=OrderStatus.PENDING,
        delivery_address="1 Victim St",
        phone_number="999",
        final_price=42.0,
    )
    test_db.add_all([attacker, victim, order])
    test_db.commit()

    # 1) The target as shipped — the attacker (customer id=3) reads victim's order (id=99).
    shipped = init_app()
    shipped.dependency_overrides[get_db] = lambda: test_db
    shipped.dependency_overrides[get_current_user] = lambda: attacker
    before = TestClient(shipped).get("/orders/500")

    # 2) The blessed fix applied — the same request is denied.
    fixed = _fixed_app(attacker)
    fixed.dependency_overrides[get_db] = lambda: test_db
    fixed.dependency_overrides[get_current_user] = lambda: attacker
    after = TestClient(fixed).get("/orders/500")

    payload: dict[str, Any] = {
        "instance": "I-04",
        "before_status": before.status_code,
        "after_status": after.status_code,
        "attack_exchange": {
            "request": _render_request(before),
            "before_response": _render_response(before),
            "after_response": _render_response(after),
        },
    }
    capture_path = os.environ.get("AVE_CAPTURE_PATH")
    if capture_path:
        with open(capture_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    # Inverted polarity: vulnerable before the fix, denied after it.
    assert before.status_code == 200
    assert before.json()["user_id"] == 99  # read someone else's order
    assert after.status_code == 404
