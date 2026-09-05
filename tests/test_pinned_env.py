from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ave import cli
from ave.adapters import get_default_pack
from ave.adapters.base import PinnedEnvCapable
from ave.adapters.python_authz import _pinned_env, catalog
from ave.adapters.python_authz.pack import _GET_ORDER, _PATCH_REL
from ave.policy import policy_version
from ave.pr import _safe_attack_exchange, render_pr_body
from ave.runner import run_once
from ave.state import AVEState, Finding

_INITIAL: AVEState = {
    "target_ref": "target/dvrestaurant@d32d0997",
    "policy_version": policy_version(),
}

_HARNESS = (
    Path(__file__).resolve().parents[1]
    / "target"
    / "dvrestaurant"
    / "app"
    / "tests"
    / "vulns"
    / "_ave_capture_bola_order_read.py"
)

_CLEAN_EXCHANGE = {
    "request": "GET /orders/500 HTTP/1.1\nHost: testserver\nAccept: */*",
    "before_response": (
        'HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"id":500,"user_id":99}'
    ),
    "after_response": (
        "HTTP/1.1 404 Not Found\ncontent-type: application/json\n\n"
        '{"detail":"Order not found"}'
    ),
}

_LEAK = "LEAK_VALUE_MUST_NOT_APPEAR"


def _canned_result(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "status": "success",
        "before_vulnerable": True,
        "after_blocked": True,
        "flipped": True,
        "attack_exchange": dict(_CLEAN_EXCHANGE),
        "detail": "pinned env ran (simulated)",
        "patch_applied": True,
    }
    base.update(over)
    return base


def test_pack_advertises_pinned_capability() -> None:
    assert isinstance(get_default_pack(), PinnedEnvCapable)


def test_runner_unavailable_when_env_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_pinned_env, "_resolve_interpreter", lambda: None)
    result = _pinned_env.run_pinned_capture(catalog.anchor(), {"patch": "x"})
    assert result["status"] == "unavailable"
    assert result["attack_exchange"] is None
    assert result["flipped"] is None
    assert result["patch_applied"] is False


def test_runner_reports_no_harness_for_non_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_pinned_env, "_resolve_interpreter", lambda: Path("/bin/true"))
    non_anchor: Finding = {"id": "I-99", "evidence": {"is_loop_anchor": False}}
    result = _pinned_env.run_pinned_capture(non_anchor, {"patch": "x"})
    assert result["status"] == "unavailable"
    assert "harness" in result["detail"]


def test_sanitized_exchange_accepts_a_clean_transcript() -> None:
    assert _pinned_env.sanitized_exchange(dict(_CLEAN_EXCHANGE)) == _CLEAN_EXCHANGE


def _exchange_with(*, request: str | None = None, before: str | None = None) -> dict[str, str]:
    return {
        "request": request if request is not None else _CLEAN_EXCHANGE["request"],
        "before_response": before if before is not None else _CLEAN_EXCHANGE["before_response"],
        "after_response": _CLEAN_EXCHANGE["after_response"],
    }


@pytest.mark.parametrize(
    "bad",
    [
        _exchange_with(request="GET / HTTP/1.1\nAuthorization: Bearer x"),
        _exchange_with(before="HTTP/1.1 200 OK\nSet-Cookie: session=x"),
        _exchange_with(before="HTTP/1.1 404\n```\ninjection"),
        _exchange_with(request="GET /\x00 HTTP/1.1"),
        _exchange_with(request="GET /?token=" + _LEAK + " HTTP/1.1"),
        _exchange_with(request="GET / HTTP/1.1\nHost: testserver\nAccept: */*\n\npassword=" + _LEAK),
        _exchange_with(before='HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"token":"' + _LEAK + '"}'),
        _exchange_with(
            before='HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"access_token":"' + _LEAK + '"}'
        ),
        _exchange_with(
            before='HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"refresh_token":"' + _LEAK + '"}'
        ),
        _exchange_with(
            before='HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"api_key":"' + _LEAK + '"}'
        ),
        _exchange_with(
            before='HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"password":"' + _LEAK + '"}'
        ),
        _exchange_with(
            before='HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"secret":"' + _LEAK + '"}'
        ),
        _exchange_with(
            before='HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"session":"' + _LEAK + '"}'
        ),
        _exchange_with(
            before='HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"cookie":"' + _LEAK + '"}'
        ),
        {"request": "GET / HTTP/1.1"},
        {**_CLEAN_EXCHANGE, "request": "x" * 5000},
    ],
)
def test_runner_and_renderer_reject_unsafe_exchanges(bad: dict[str, Any]) -> None:
    assert _pinned_env.sanitized_exchange(bad) is None
    assert _safe_attack_exchange({"attack_exchange": bad}) is None
    state = run_once(_INITIAL, auto_approve=True)
    change = dict(state.get("prepared_change") or {})
    change["attack_exchange"] = bad
    body = render_pr_body({**state, "prepared_change": change})
    exchange = body[: body.find("## Verification ladder")]
    assert "Exchange not captured by this run." in exchange
    assert "```http" not in exchange
    assert _LEAK not in exchange


@pytest.mark.parametrize(
    ("before", "after", "flipped"),
    [(200, 404, True), (200, 403, True), (200, 200, False), (403, 404, False)],
)
def test_interpret_maps_statuses_to_flip(
    before: int, after: int, flipped: bool
) -> None:
    result = _pinned_env._interpret(
        {"before_status": before, "after_status": after, "attack_exchange": _CLEAN_EXCHANGE}
    )
    assert result["status"] == "success"
    assert result["flipped"] is flipped


def test_interpret_unsafe_exchange_is_not_success() -> None:
    result = _pinned_env._interpret(
        {
            "before_status": 200,
            "after_status": 404,
            "attack_exchange": _exchange_with(
                before='HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"token":"x"}'
            ),
        }
    )
    assert result["status"] == "unsafe_capture"
    assert result["flipped"] is False
    assert result["attack_exchange"] is None


def _simulate_available_env(
    monkeypatch: pytest.MonkeyPatch, result: dict[str, Any]
) -> None:
    monkeypatch.setattr(_pinned_env, "_resolve_interpreter", lambda: Path("/bin/true"))
    monkeypatch.setattr(_pinned_env, "run_pinned_capture", lambda finding, prepared=None: result)


def test_opted_in_run_captures_exchange_and_takes_t1_from_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_available_env(monkeypatch, _canned_result())
    final = run_once({**_INITIAL, "use_pinned_env": True}, auto_approve=True)

    change = dict(final.get("prepared_change") or {})
    assert change.get("attack_exchange") == _CLEAN_EXCHANGE
    pinned = dict(final.get("pinned_exploit") or {})
    assert pinned.get("status") == "success" and pinned.get("flipped") is True
    assert final.get("verification", {}).get("t1_exploit_oracle_flipped") is True
    prepare = next(span for span in final["spans"] if span["phase"] == "prepare")
    assert prepare["attributes"]["pinned_patch_applied"] is True

    body = render_pr_body(final)
    assert "Exchange not captured by this run." not in body
    assert "GET /orders/500 HTTP/1.1" in body


def test_pinned_flip_false_leaves_t1_red(monkeypatch: pytest.MonkeyPatch) -> None:
    _simulate_available_env(
        monkeypatch, _canned_result(flipped=False, after_blocked=False)
    )
    final = run_once({**_INITIAL, "use_pinned_env": True}, auto_approve=True)
    assert final.get("verification", {}).get("t1_exploit_oracle_flipped") is False


@pytest.mark.parametrize(
    "status",
    [
        "unavailable",
        "launch_failed",
        "patch_failed",
        "test_failed",
        "malformed",
        "unsafe_capture",
    ],
)
def test_requested_pinned_failure_leaves_t1_false_and_explicit(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    _simulate_available_env(
        monkeypatch,
        _canned_result(
            status=status,
            flipped=False,
            attack_exchange=None,
            patch_applied=status in {"test_failed", "malformed", "unsafe_capture"},
            detail=f"pinned {status.replace('_', ' ')}",
        ),
    )
    final = run_once({**_INITIAL, "use_pinned_env": True}, auto_approve=True)
    assert final.get("verification", {}).get("t1_exploit_oracle_flipped") is False
    pinned = dict(final.get("pinned_exploit") or {})
    assert pinned.get("status") == status
    prepare = next(span for span in final["spans"] if span["phase"] == "prepare")
    verify = next(span for span in final["spans"] if span["phase"] == "verify")
    assert prepare["attributes"]["pinned_status"] == status
    assert prepare["attributes"]["pinned_patch_applied"] is (
        status in {"test_failed", "malformed", "unsafe_capture"}
    )
    assert verify["attributes"]["t1_runner"] == "pinned"
    assert verify["attributes"]["pinned_status"] == status
    body = render_pr_body(final)
    assert "Exchange not captured by this run." in body
    assert "exploit oracle ran through the pack's harness" not in body
    assert "Pinned execution was requested" in body


def test_default_run_omits_pinned_shape() -> None:
    final = run_once(_INITIAL, auto_approve=True)
    assert "use_pinned_env" not in final
    assert "pinned_exploit" not in final
    assert "attack_exchange" not in dict(final.get("prepared_change") or {})
    prepare = next(span for span in final["spans"] if span["phase"] == "prepare")
    verify = next(span for span in final["spans"] if span["phase"] == "verify")
    assert prepare["attributes"] == {"prepared": True}
    assert verify["attributes"] == {"ladder_green": False, "ready": False}


def test_cli_initial_state_omits_pinned_key_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AVE_PINNED_ENV", raising=False)
    assert "use_pinned_env" not in cli.initial_run_state()
    monkeypatch.setenv("AVE_PINNED_ENV", "1")
    assert cli.initial_run_state()["use_pinned_env"] is True


def test_prepare_fix_patch_applies_to_real_target_file(tmp_path: Path) -> None:
    original = _GET_ORDER.read_text(encoding="utf-8")
    assert "current_user" not in original
    pack = get_default_pack()
    fix = pack.prepare_fix(catalog.anchor())
    patch = str(fix["patch"])
    assert _PATCH_REL in patch
    assert "_skeleton_target.py" not in patch
    dest = tmp_path / _PATCH_REL
    dest.parent.mkdir(parents=True)
    dest.write_text(original, encoding="utf-8")
    patched = _pinned_env.apply_unified_diff(tmp_path, patch)
    text = patched.read_text(encoding="utf-8")
    assert "current_user.id" in text
    assert "db_order.user_id != current_user.id" in text
    assert _GET_ORDER.read_text(encoding="utf-8") == original


def test_harness_executes_current_target_source_not_a_substitute() -> None:
    src = _HARNESS.read_text(encoding="utf-8")
    assert "_fixed_app" not in src
    assert "init_app" in src
    assert src.index("assert exchange is not None") < src.index("json.dump")


def test_run_capture_rejects_nonzero_even_if_file_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        path = Path(kwargs["env"]["AVE_CAPTURE_PATH"])
        path.write_text(
            json.dumps({"status": 200, "attack_exchange": {"request": "GET /", "response": "ok"}}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 1, _LEAK, _LEAK)

    monkeypatch.setattr(_pinned_env.subprocess, "run", fake_run)
    status, payload = _pinned_env._run_capture(Path("/bin/true"), Path("."), "x.py")
    assert status == "test_failed"
    assert payload is None


def test_nonzero_pytest_with_capture_is_test_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_pinned_env, "_resolve_interpreter", lambda: Path("/bin/true"))
    monkeypatch.setattr(_pinned_env, "_run_capture", lambda *args, **kwargs: ("test_failed", None))
    result = _pinned_env.run_pinned_capture(
        catalog.anchor(), {"patch": "--- a/x\n+++ b/x\n"}
    )
    assert result["status"] == "test_failed"
    assert result["flipped"] is None
    assert result["attack_exchange"] is None
    assert _LEAK not in result["detail"]


def test_missing_patch_is_patch_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_pinned_env, "_resolve_interpreter", lambda: Path("/bin/true"))
    result = _pinned_env.run_pinned_capture(catalog.anchor(), {})
    assert result["status"] == "patch_failed"
    assert result["patch_applied"] is False
