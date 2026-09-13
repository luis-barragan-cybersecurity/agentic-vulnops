from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Literal, TypedDict
from urllib.parse import unquote_plus

from ave.adapters.base import PinnedExploitResult, PinnedStatus
from ave.adapters.python_authz._binding import TARGET_NODE, TEST_NAME, _OracleStamp

_REPO_ROOT = Path(__file__).resolve().parents[4]
_TARGET_DIR = _REPO_ROOT / "target" / "dvrestaurant"
_BOUND_COPY = TARGET_NODE
_TIMEOUT_S = 300
_POETRY_INFO_TIMEOUT_S = 60

_EXCHANGE_FIELDS: tuple[str, ...] = ("request", "before_response", "after_response")
_MAX_FIELD_LEN = 4000
_FENCE = "```"
_SECRET_HEADERS: tuple[str, ...] = (
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
_COPY_SKIP = {
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".git",
    "postgres_data",
    ".mypy_cache",
    ".ruff_cache",
}


_CaptureFailureStatus = Literal["launch_failed", "test_failed", "malformed"]


class _CaptureSuccess(TypedDict):
    kind: Literal["success"]
    payload: dict[str, Any]


class _CaptureFailure(TypedDict):
    kind: Literal["failure"]
    status: _CaptureFailureStatus


_CaptureResult = _CaptureSuccess | _CaptureFailure


def _outcome(
    status: PinnedStatus,
    detail: str,
    *,
    before_vulnerable: bool | None = None,
    after_blocked: bool | None = None,
    flipped: bool | None = None,
    attack_exchange: dict[str, str] | None = None,
    patch_applied: bool = False,
) -> PinnedExploitResult:
    return {
        "status": status,
        "before_vulnerable": before_vulnerable,
        "after_blocked": after_blocked,
        "flipped": flipped,
        "attack_exchange": attack_exchange,
        "detail": detail,
        "patch_applied": patch_applied,
    }


def unavailable(detail: str) -> PinnedExploitResult:
    return _outcome("unavailable", detail)


def _resolve_interpreter() -> Path | None:
    if not _TARGET_DIR.is_dir() or shutil.which("poetry") is None:
        return None
    try:
        proc = subprocess.run(
            ["poetry", "env", "info", "--executable"],
            cwd=_TARGET_DIR,
            capture_output=True,
            text=True,
            timeout=_POETRY_INFO_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    path = Path((proc.stdout or "").strip())
    return path if path.is_file() else None


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
    candidates = [value]
    parts = re.split(r"\r?\n\r?\n", value, maxsplit=1)
    if len(parts) == 2:
        candidates.append(parts[1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if _walk_credential_keys(parsed):
            return True
    return False


def _field_is_unsafe(value: str) -> bool:
    if _has_disallowed_control(value):
        return True
    lowered = value.lower()
    if _FENCE in value:
        return True
    if any(header in lowered for header in _SECRET_HEADERS):
        return True
    if _BEARER in lowered:
        return True
    if _query_or_form_credentials(value):
        return True
    return _json_credential_fields(value)


def sanitized_exchange(raw: Any) -> dict[str, str] | None:
    """Return the captured exchange only if safe to carry forward, else None.

    Fail-closed at this boundary: each of the three fields must be a non-empty string
    within a length cap, free of fences, disallowed control characters, secret-bearing
    headers, bearer values, query/form credential keys, and structured JSON credential
    fields. One failure withholds the whole exchange. The rejected value is not returned.
    """
    if not isinstance(raw, dict):
        return None
    cleaned: dict[str, str] = {}
    for key in _EXCHANGE_FIELDS:
        value = raw.get(key)
        if not isinstance(value, str):
            return None
        stripped = value.strip("\n")
        if not stripped.strip() or len(value) > _MAX_FIELD_LEN:
            return None
        if _field_is_unsafe(value):
            return None
        cleaned[key] = stripped
    return cleaned


def apply_unified_diff(root: Path, patch_text: str) -> Path:
    if not patch_text.strip():
        raise ValueError("empty patch")
    rel: str | None = None
    hunks: list[tuple[int, list[str]]] = []
    lines = patch_text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("--- "):
            rel = line[4:].split("\t", 1)[0].strip().removeprefix("a/")
            i += 1
            continue
        if line.startswith("+++ "):
            i += 1
            continue
        if line.startswith("@@ "):
            match = re.match(r"@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", line)
            if match is None:
                raise ValueError("malformed hunk header")
            old_start = int(match.group(1))
            body: list[str] = []
            i += 1
            while i < len(lines) and lines[i][:1] in {" ", "+", "-", "\\"}:
                if not lines[i].startswith("\\"):
                    body.append(lines[i])
                i += 1
            hunks.append((old_start, body))
            continue
        i += 1
    if not rel:
        raise ValueError("patch names no file")
    relative = Path(rel)
    resolved_root = root.resolve()
    path = (resolved_root / relative).resolve()
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not path.is_relative_to(resolved_root)
    ):
        raise ValueError("patch path escapes root")
    original = path.read_text(encoding="utf-8")
    source = original.splitlines(keepends=True)
    out: list[str] = []
    cursor = 0
    for old_start, body in hunks:
        target = max(old_start - 1, 0)
        if target < cursor:
            raise ValueError("hunk overlap")
        out.extend(source[cursor:target])
        cursor = target
        for raw in body:
            tag, rest = raw[:1], raw[1:]
            if tag == " ":
                if cursor >= len(source) or source[cursor] != rest:
                    raise ValueError("patch context does not match")
                out.append(source[cursor])
                cursor += 1
            elif tag == "-":
                if cursor >= len(source) or source[cursor] != rest:
                    raise ValueError("patch removal does not match")
                cursor += 1
            elif tag == "+":
                out.append(rest)
            else:
                raise ValueError("malformed hunk line")
    out.extend(source[cursor:])
    rewritten = "".join(out)
    if rewritten == original:
        raise ValueError("patch applied with no change")
    path.write_text(rewritten, encoding="utf-8")
    return path


def _patch_proved(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return "current_user" in text and "current_user.id" in text and "user_id" in text


def _stamp_source(stamp: _OracleStamp) -> Path | None:
    raw = stamp.get("path")
    test = stamp.get("test")
    if not isinstance(raw, str) or not raw or test != TEST_NAME:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = _REPO_ROOT / path
    resolved = path.resolve()
    return resolved if resolved.is_file() else None


def _flip(
    before_status: Any, after_status: Any
) -> tuple[bool, bool, bool]:
    before_vulnerable = before_status == 200
    after_blocked = isinstance(after_status, int) and after_status in (403, 404)
    return before_vulnerable, after_blocked, before_vulnerable and after_blocked


def _interpret(payload: dict[str, Any]) -> PinnedExploitResult:
    before_vulnerable, after_blocked, flipped = _flip(
        payload.get("before_status"), payload.get("after_status")
    )
    exchange = sanitized_exchange(payload.get("attack_exchange"))
    if exchange is None:
        return _outcome(
            "unsafe_capture",
            "captured exchange failed the redaction gate",
            before_vulnerable=before_vulnerable,
            after_blocked=after_blocked,
            flipped=False,
            patch_applied=True,
        )
    status: PinnedStatus = "success" if flipped else "not_flipped"
    return _outcome(
        status,
        (
            f"pinned env ran: before={payload.get('before_status')} "
            f"after={payload.get('after_status')}"
        ),
        before_vulnerable=before_vulnerable,
        after_blocked=after_blocked,
        flipped=flipped,
        attack_exchange=exchange,
        patch_applied=True,
    )


def _copy_ignore(_directory: str, names: list[str]) -> list[str]:
    return [name for name in names if name in _COPY_SKIP or name.endswith(".pyc")]


def _run_capture(
    interpreter: Path, cwd: Path, capture_rel: str
) -> _CaptureResult:
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "exchange.json"
        env = {**os.environ, "AVE_CAPTURE_PATH": str(out_path), "PYTHONDONTWRITEBYTECODE": "1"}
        for inherited_path in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"):
            env.pop(inherited_path, None)
        argv = [
            str(interpreter),
            "-m",
            "pytest",
            capture_rel,
            "-q",
            "-p",
            "no:cacheprovider",
        ]
        try:
            proc = subprocess.run(
                argv,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return {"kind": "failure", "status": "launch_failed"}
        payload: Any = None
        if out_path.exists():
            try:
                payload = json.loads(out_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                payload = None
        if isinstance(payload, dict) and isinstance(payload.get("status"), int):
            return {"kind": "success", "payload": payload}
        if proc.returncode != 0:
            return {"kind": "failure", "status": "test_failed"}
        return {"kind": "failure", "status": "malformed"}


def _combine(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_ex = before.get("attack_exchange")
    after_ex = after.get("attack_exchange")
    before_map = before_ex if isinstance(before_ex, dict) else {}
    after_map = after_ex if isinstance(after_ex, dict) else {}
    request = before_map.get("request") or after_map.get("request")
    return {
        "before_status": before.get("status"),
        "after_status": after.get("status"),
        "attack_exchange": {
            "request": request,
            "before_response": before_map.get("response") or before_map.get("before_response"),
            "after_response": after_map.get("response") or after_map.get("after_response"),
        },
    }


def run_bound(
    stamp: _OracleStamp, prepared: dict[str, Any] | None = None
) -> PinnedExploitResult:
    interpreter = _resolve_interpreter()
    if interpreter is None:
        return unavailable("pinned environment is not available")
    source = _stamp_source(stamp)
    if source is None:
        return unavailable("bound exploit stamp is missing or invalid")
    patch = (prepared or {}).get("patch")
    if not isinstance(patch, str) or not patch.strip():
        return _outcome("patch_failed", "generated patch is missing")
    capture_rel = f"{_BOUND_COPY}::{stamp['test']}"
    with tempfile.TemporaryDirectory() as tmp:
        repo_root = Path(tmp)
        copy_root = repo_root / "target" / "dvrestaurant"
        try:
            shutil.copytree(_TARGET_DIR, copy_root, ignore=_copy_ignore)
            dest = copy_root / Path(_BOUND_COPY)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            return unavailable("could not stage the bound exploit")
        before = _run_capture(interpreter, copy_root, capture_rel)
        if before["kind"] == "failure":
            status = before["status"]
            return _outcome(status, f"pinned {status.replace('_', ' ')}")
        try:
            patched = apply_unified_diff(repo_root, patch)
        except (OSError, ValueError):
            return _outcome("patch_failed", "generated patch did not apply")
        if not _patch_proved(patched):
            return _outcome("patch_failed", "generated patch did not apply")
        after = _run_capture(interpreter, copy_root, capture_rel)
        if after["kind"] == "failure":
            status = after["status"]
            return _outcome(
                status,
                f"pinned {status.replace('_', ' ')}",
                patch_applied=True,
            )
        return _interpret(_combine(before["payload"], after["payload"]))
