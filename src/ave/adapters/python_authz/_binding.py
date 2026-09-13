from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Any, Literal, TypedDict

from ave.adapters.python_authz.allowlist import writer_allowlist
from ave.adapters.python_authz.model import FixtureModelClient
from ave.state import Finding

_REPO_ROOT = Path(__file__).resolve().parents[4]
WRITER_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "llm_writer"
SUBMIT_EXPLOIT = "submit_exploit"
TEST_NAME: Literal["test_authorization_boundary"] = "test_authorization_boundary"
TARGET_NODE: Literal["app/tests/_ave_bound.py"] = "app/tests/_ave_bound.py"
_BOUND_NAME = "_ave_bound.py"
_GET_ORDER_HANDLER = (
    "target/dvrestaurant/app/apis/orders/services/get_order_service.py:get_order"
)
_FINGERPRINT_RE = re.compile(
    r"^AVE_FINDING_FINGERPRINT\s*=\s*([\"'])([^\"']+)\1\s*$", re.MULTILINE
)
_PATH_PARAM_RE = re.compile(r"\{[^}/]+\}")


class _OracleStamp(TypedDict):
    path: str
    test: Literal["test_authorization_boundary"]


class BindingError(ValueError):
    pass


class BindingConflict(BindingError):
    pass


def _handler(finding: Finding) -> tuple[str, str]:
    evidence = finding.get("evidence")
    raw = evidence.get("handler") if isinstance(evidence, dict) else None
    if not isinstance(raw, dict):
        raise BindingError("finding has no handler route")
    method = raw.get("method")
    path = raw.get("path")
    if not isinstance(method, str) or not method.strip():
        raise BindingError("finding handler.method is missing")
    if not isinstance(path, str) or not path.strip():
        raise BindingError("finding handler.path is missing")
    return method.strip(), path.strip()


def _fingerprint(patch_rel: str, method: str, path: str) -> str:
    return f"{patch_rel}|{method}|{path}"


def _workspace_rel(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(_REPO_ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def _path_matches_handler(generated: str, handler_path: str) -> bool:
    if generated == handler_path:
        return True
    parts = _PATH_PARAM_RE.split(handler_path)
    pattern = "^" + "[^/]+".join(re.escape(part) for part in parts) + "$"
    return re.fullmatch(pattern, generated) is not None


def _render_source(
    fingerprint: str,
    *,
    method: str,
    path: str,
    control_path: str,
    victim_user_id: int,
    victim_order_id: int,
    leak_field: str,
    leak_equals: int,
) -> str:
    verb = method.lower()
    return f'''\
import json
import os

from db.models import Order, OrderStatus, User, UserRole

AVE_FINDING_FINGERPRINT = {fingerprint!r}


def test_authorization_boundary(test_db, customer_client) -> None:
    victim = User(
        id={victim_user_id},
        username="victim",
        password="x",
        first_name="Victim",
        last_name="",
        phone_number="999",
        role=UserRole.CUSTOMER,
    )
    own = Order(
        id=3,
        user_id=3,
        status=OrderStatus.PENDING,
        delivery_address="3 Owner St",
        phone_number="1234",
        final_price=10.0,
    )
    order = Order(
        id={victim_order_id},
        user_id={victim_user_id},
        status=OrderStatus.PENDING,
        delivery_address="1 Victim St",
        phone_number="999",
        final_price=42.0,
    )
    test_db.add(victim)
    test_db.add(own)
    test_db.add(order)
    test_db.commit()

    control = customer_client.{verb}({control_path!r})
    attack = customer_client.{verb}({path!r})
    capture_path = os.environ.get("AVE_CAPTURE_PATH")
    if capture_path:
        req = attack.request
        request = f"{{req.method}} {{req.url.path}} HTTP/1.1\\nHost: testserver\\nAccept: */*"
        reason = {{200: "OK", 403: "Forbidden", 404: "Not Found"}}.get(
            attack.status_code, ""
        )
        ctype = attack.headers.get("content-type", "application/json")
        rendered = (
            f"HTTP/1.1 {{attack.status_code}} {{reason}}".rstrip()
            + f"\\ncontent-type: {{ctype}}\\n\\n{{attack.text}}"
        )
        with open(capture_path, "w", encoding="utf-8") as handle:
            json.dump(
                {{
                    "status": attack.status_code,
                    "attack_exchange": {{"request": request, "response": rendered}},
                }},
                handle,
            )
    assert control.status_code == 200
    assert attack.status_code == 200
    assert attack.json()[{leak_field!r}] == {leak_equals!r}
'''


def _literal_fingerprint(source: str) -> str | None:
    match = _FINGERPRINT_RE.search(source)
    return None if match is None else match.group(2)


def _validate_source(
    source: str,
    *,
    fingerprint: str,
    method: str,
    handler_path: str,
) -> None:
    if _literal_fingerprint(source) != fingerprint:
        raise BindingError("generated source fingerprint is missing or unstable")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise BindingError("generated source is not valid Python") from exc
    names = {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    if TEST_NAME not in names:
        raise BindingError(f"generated source has no {TEST_NAME}")
    capture_at = source.find("AVE_CAPTURE_PATH")
    attack_assert = source.find("assert attack.status_code == 200")
    leak_assert = "assert attack.json()" in source
    if capture_at < 0:
        raise BindingError("generated source does not consult AVE_CAPTURE_PATH")
    if attack_assert < 0 or not leak_assert:
        raise BindingError("generated source is not inverted polarity")
    if capture_at > attack_assert:
        raise BindingError("AVE_CAPTURE_PATH must be consulted before inverted asserts")
    client_call = re.search(
        rf"attack\s*=\s*customer_client\.{method.lower()}\((['\"])([^'\"]+)\1\)",
        source,
    ) or re.search(
        rf"customer_client\.{method.lower()}\((['\"])([^'\"]+)\1\)", source
    )
    if client_call is None:
        raise BindingError("generated source request does not match handler method")
    if not _path_matches_handler(client_call.group(2), handler_path):
        raise BindingError("generated source request does not match handler path")


def _submit_fields(args: dict[str, Any]) -> dict[str, Any]:
    required = (
        "method",
        "path",
        "control_path",
        "victim_user_id",
        "victim_order_id",
        "leak_field",
        "leak_equals",
    )
    missing = [key for key in required if key not in args]
    if missing:
        raise BindingError(f"submit_exploit missing {missing}")
    return {
        "method": str(args["method"]).strip(),
        "path": str(args["path"]).strip(),
        "control_path": str(args["control_path"]).strip(),
        "victim_user_id": int(args["victim_user_id"]),
        "victim_order_id": int(args["victim_order_id"]),
        "leak_field": str(args["leak_field"]).strip(),
        "leak_equals": args["leak_equals"],
    }


class _ExploitBinder:
    def __init__(self, *, patch_rel: str) -> None:
        self._patch_rel = patch_rel
        self._run_root: Path | None = None

    def bind_run(self, run_root: Path) -> None:
        self._run_root = Path(run_root)

    def _expected(self) -> Path:
        if self._run_root is None:
            raise BindingError("bind_run was never called")
        return (self._run_root / "bound" / _BOUND_NAME).resolve()

    def _stamp_for(self, expected: Path) -> _OracleStamp:
        return {"path": _workspace_rel(expected), "test": TEST_NAME}

    def _require_file(self, expected: Path, fingerprint: str, method: str, path: str) -> None:
        if not expected.is_file():
            raise BindingError("bound exploit file is missing")
        _validate_source(
            expected.read_text(encoding="utf-8"),
            fingerprint=fingerprint,
            method=method,
            handler_path=path,
        )

    def ensure_bound(self, finding: Finding) -> _OracleStamp:
        expected = self._expected()
        method, path = _handler(finding)
        fingerprint = _fingerprint(self._patch_rel, method, path)
        stamp = self._stamp_for(expected)

        evidence = finding.get("evidence")
        existing = evidence.get("oracle") if isinstance(evidence, dict) else None
        if existing is not None:
            if existing != stamp:
                raise BindingError("finding stamp does not match the bound path")
            self._require_file(expected, fingerprint, method, path)
            return stamp

        if expected.is_file():
            try:
                self._require_file(expected, fingerprint, method, path)
            except BindingError as exc:
                raise BindingConflict(
                    "bound exploit already exists with different bytes"
                ) from exc
            return stamp

        fields = _submit_fields(self._emit(finding))
        if fields["method"].upper() != method.upper() or not _path_matches_handler(
            fields["path"], path
        ):
            raise BindingError("writer submit does not match handler route")
        generated = _render_source(fingerprint, **fields)
        _validate_source(
            generated, fingerprint=fingerprint, method=method, handler_path=path
        )
        self._persist(expected, generated)
        return stamp

    def read_stamp(self, finding: Finding) -> _OracleStamp:
        if self._run_root is None:
            raise BindingError("bind_run was never called")
        evidence = finding.get("evidence")
        raw = evidence.get("oracle") if isinstance(evidence, dict) else None
        if not isinstance(raw, dict):
            raise BindingError("finding has no oracle stamp")
        if set(raw) != {"path", "test"}:
            raise BindingError("oracle stamp keys are not exactly path and test")
        path = raw.get("path")
        test = raw.get("test")
        if not isinstance(path, str) or not path:
            raise BindingError("oracle stamp path is missing")
        if test != TEST_NAME:
            raise BindingError("oracle stamp test is not test_authorization_boundary")
        resolved = Path(path)
        if not resolved.is_absolute():
            resolved = (_REPO_ROOT / resolved).resolve()
        else:
            resolved = resolved.resolve()
        root = self._run_root.resolve()
        if not resolved.is_relative_to(root):
            raise BindingError("oracle stamp path is outside the bound run root")
        if not resolved.is_file():
            raise BindingError("bound exploit file is missing")
        return {"path": path, "test": TEST_NAME}

    def _emit(self, finding: Finding) -> dict[str, Any]:
        del finding
        allow = writer_allowlist()
        context = "\n".join(allow.rel(path) for path in allow.files())
        client = FixtureModelClient(WRITER_FIXTURES_DIR)
        session = client.begin(
            candidate_id=_GET_ORDER_HANDLER,
            system="Write a structured authorization-boundary exploit.",
            user=context,
            tools=[
                {
                    "name": SUBMIT_EXPLOIT,
                    "description": "Submit the structured exploit fields.",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string"},
                            "path": {"type": "string"},
                            "control_path": {"type": "string"},
                            "victim_user_id": {"type": "integer"},
                            "victim_order_id": {"type": "integer"},
                            "leak_field": {"type": "string"},
                            "leak_equals": {},
                        },
                        "required": [
                            "method",
                            "path",
                            "control_path",
                            "victim_user_id",
                            "victim_order_id",
                            "leak_field",
                            "leak_equals",
                        ],
                    },
                }
            ],
            terminal_tool=SUBMIT_EXPLOIT,
        )
        calls = session.respond([])
        terminals = [call for call in calls if call.name == SUBMIT_EXPLOIT]
        if len(terminals) != 1:
            raise BindingError("writer did not submit exactly one exploit")
        return dict(terminals[0].arguments)

    def _persist(self, expected: Path, source: str) -> None:
        expected.parent.mkdir(parents=True, exist_ok=True)
        if expected.is_file():
            existing = expected.read_text(encoding="utf-8")
            if existing == source:
                return
            raise BindingConflict("bound exploit already exists with different bytes")
        tmp = expected.with_name(expected.name + ".tmp")
        tmp.write_text(source, encoding="utf-8")
        os.replace(tmp, expected)
