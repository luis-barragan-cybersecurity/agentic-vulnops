# AVE owns this harness. Its leading underscore prevents normal target test collection.
import json
import os
import re
from typing import Any
from urllib.parse import unquote_plus

from apis.auth.utils import get_current_user
from db.models import Order, OrderStatus, User, UserRole
from db.session import get_db
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

_MAX = 4000
_FENCE = "```"
_SECRET_HEADERS = (
    "authorization:",
    "proxy-authorization:",
    "cookie:",
    "set-cookie:",
    "api-key:",
    "x-api-key:",
    "x-auth-token:",
    "x-access-token:",
)
_BEARER = "bearer "
_CREDENTIAL_KEYS = {
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "apikey",
    "clientsecret",
    "jwt",
    "authorization",
    "proxyauthorization",
    "xapikey",
    "xauthtoken",
    "xaccesstoken",
    "password",
    "secret",
    "session",
    "cookie",
}


def _has_disallowed_control(value: str) -> bool:
    return any(
        (ord(ch) < 32 or 127 <= ord(ch) <= 159) and ch not in "\r\n\t"
        for ch in value
    )


def _is_credential_key(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    return normalized in _CREDENTIAL_KEYS


def _query_or_form_credentials(value: str) -> bool:
    return any(
        _is_credential_key(match.group(1))
        for match in re.finditer(
            r"(?:^|[?&#;\s])([A-Za-z0-9_.-]+)=",
            unquote_plus(value),
        )
    )


def _walk_credential_keys(obj: Any) -> bool:
    if isinstance(obj, dict):
        for key, child in obj.items():
            if _is_credential_key(str(key)):
                return True
            if _walk_credential_keys(child):
                return True
        return False
    if isinstance(obj, list):
        return any(_walk_credential_keys(item) for item in obj)
    return False


def _json_credential_fields(value: str) -> bool:
    if any(
        _is_credential_key(match.group(1))
        for match in re.finditer(r'"([^"]+)"\s*:', value)
    ):
        return True
    try:
        parsed = json.loads(value)
    except ValueError:
        return False
    return _walk_credential_keys(parsed)


def _unsafe(value: str) -> bool:
    if _has_disallowed_control(value) or _FENCE in value:
        return True
    lowered = value.lower()
    if any(header in lowered for header in _SECRET_HEADERS) or _BEARER in lowered:
        return True
    if _query_or_form_credentials(value):
        return True
    return _json_credential_fields(value)


def _render_request(response: Any) -> str | None:
    req = response.request
    path = req.url.raw_path.decode() if hasattr(req.url, "raw_path") else req.url.path
    host = req.url.host
    if not isinstance(path, str) or not isinstance(host, str):
        return None
    if "?" in path.split(" HTTP/", 1)[0] and _query_or_form_credentials(path):
        return None
    rendered = f"{req.method} {path} HTTP/1.1\nHost: {host}\nAccept: */*"
    if _unsafe(rendered) or len(rendered) > _MAX:
        return None
    return rendered


def _render_response(response: Any) -> str | None:
    reason = {200: "OK", 403: "Forbidden", 404: "Not Found"}.get(response.status_code, "")
    head = f"HTTP/1.1 {response.status_code} {reason}".rstrip()
    ctype = response.headers.get("content-type", "application/json")
    body = response.text if len(response.text) <= 512 else response.text[:512] + "…"
    if _unsafe(body):
        return None
    rendered = f"{head}\ncontent-type: {ctype}\n\n{body}"
    if _unsafe(rendered) or len(rendered) > _MAX:
        return None
    return rendered


def _safe_exchange(response: Any) -> dict[str, str] | None:
    request = _render_request(response)
    rendered = _render_response(response)
    if request is None or rendered is None:
        return None
    return {"request": request, "response": rendered}


def test_capture_bola_cross_customer_order_read(test_db: Session) -> None:
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

    shipped = init_app()
    shipped.dependency_overrides[get_db] = lambda: test_db
    shipped.dependency_overrides[get_current_user] = lambda: attacker
    captured = TestClient(shipped).get("/orders/500")

    exchange = _safe_exchange(captured)
    assert exchange is not None
    assert captured.status_code in (200, 403, 404)

    capture_path = os.environ.get("AVE_CAPTURE_PATH")
    if capture_path:
        payload = {
            "instance": "I-04",
            "status": captured.status_code,
            "attack_exchange": exchange,
        }
        with open(capture_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
