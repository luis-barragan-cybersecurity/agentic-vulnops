"""The pinned-env exploit runner and its wiring (ticket 12).

Guards four things without needing the target's Python-3.10 env (which `make check` never
has): the runner's **honest skip** when the env is absent, the **redaction** gate that keeps
secrets and fence-breakouts out of a captured transcript, the **flip interpretation** that
turns two HTTP statuses into a T1 verdict, and the **graph wiring** — that an opted-in run
with a (simulated) available env threads the captured exchange into the PR body and takes T1
from the pinned flip, while a run without the env behaves exactly as the hermetic default.
"""

from __future__ import annotations

from typing import Any

import pytest

from ave.adapters import get_default_pack
from ave.adapters.base import PinnedEnvCapable
from ave.adapters.python_authz import _pinned_env, catalog
from ave.policy import policy_version
from ave.pr import render_pr_body
from ave.runner import run_once
from ave.state import AVEState

_INITIAL: AVEState = {
    "target_ref": "target/dvrestaurant@d32d0997",
    "policy_version": policy_version(),
}

# A clean transcript, shaped like what the harness emits: no secret headers, no fences.
_CLEAN_EXCHANGE = {
    "request": "GET /orders/500 HTTP/1.1\nHost: testserver\nAccept: */*",
    "before_response": (
        'HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"id":500,"user_id":99}'
    ),
    "after_response": (
        'HTTP/1.1 404 Not Found\ncontent-type: application/json\n\n'
        '{"detail":"Order not found"}'
    ),
}


def _canned_result(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ran": True,
        "before_vulnerable": True,
        "after_blocked": True,
        "flipped": True,
        "attack_exchange": dict(_CLEAN_EXCHANGE),
        "detail": "pinned env ran (simulated)",
    }
    base.update(over)
    return base


# --- The pack exposes the optional capability, honestly skipping when the env is absent. ---


def test_pack_advertises_pinned_capability() -> None:
    assert isinstance(get_default_pack(), PinnedEnvCapable)


def test_runner_skips_honestly_when_env_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_pinned_env, "env_available", lambda: False)
    result = _pinned_env.run_pinned_capture(catalog.anchor())
    assert result["ran"] is False
    assert result["attack_exchange"] is None
    assert result["flipped"] is None
    assert "absent" in result["detail"]


def test_runner_reports_no_harness_for_non_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_pinned_env, "env_available", lambda: True)
    non_anchor = {"id": "I-99", "evidence": {"is_loop_anchor": False}}
    result = _pinned_env.run_pinned_capture(non_anchor)  # type: ignore[arg-type]
    assert result["ran"] is False
    assert "no pinned capture harness" in result["detail"]


# --- Redaction: the fail-closed gate on what may reach the public PR body. ---


def test_sanitized_exchange_accepts_a_clean_transcript() -> None:
    assert _pinned_env.sanitized_exchange(dict(_CLEAN_EXCHANGE)) == _CLEAN_EXCHANGE


@pytest.mark.parametrize(
    "bad",
    [
        {**_CLEAN_EXCHANGE, "request": "GET / HTTP/1.1\nAuthorization: Bearer x"},
        {**_CLEAN_EXCHANGE, "before_response": "HTTP/1.1 200 OK\nSet-Cookie: session=x"},
        {**_CLEAN_EXCHANGE, "after_response": "HTTP/1.1 404\n```\ninjection"},
        {"request": "GET / HTTP/1.1"},  # incomplete
        {**_CLEAN_EXCHANGE, "request": "x" * 5000},  # oversize
        {**_CLEAN_EXCHANGE, "request": "GET /\x00 HTTP/1.1"},  # control char
    ],
)
def test_sanitized_exchange_rejects_unsafe(bad: dict[str, Any]) -> None:
    assert _pinned_env.sanitized_exchange(bad) is None


# --- Interpretation: two statuses become a T1 verdict. ---


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
    assert result["ran"] is True
    assert result["flipped"] is flipped


# --- Wiring: an opted-in run with a simulated env captures + drives T1 from the flip. ---


def _simulate_available_env(
    monkeypatch: pytest.MonkeyPatch, result: dict[str, Any]
) -> None:
    monkeypatch.setattr(_pinned_env, "env_available", lambda: True)
    monkeypatch.setattr(_pinned_env, "run_pinned_capture", lambda finding: result)


def test_opted_in_run_captures_exchange_and_takes_t1_from_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _simulate_available_env(monkeypatch, _canned_result())
    final = run_once({**_INITIAL, "use_pinned_env": True}, auto_approve=True)

    change = dict(final.get("prepared_change") or {})
    assert change.get("attack_exchange") == _CLEAN_EXCHANGE
    pinned = dict(final.get("pinned_exploit") or {})
    assert pinned.get("ran") is True and pinned.get("flipped") is True
    assert final.get("verification", {}).get("t1_exploit_oracle_flipped") is True

    body = render_pr_body(final)
    assert "Exchange not captured by this run." not in body
    assert "GET /orders/500 HTTP/1.1" in body


def test_pinned_flip_false_leaves_t1_red(monkeypatch: pytest.MonkeyPatch) -> None:
    _simulate_available_env(
        monkeypatch, _canned_result(flipped=False, after_blocked=False)
    )
    final = run_once({**_INITIAL, "use_pinned_env": True}, auto_approve=True)
    assert final.get("verification", {}).get("t1_exploit_oracle_flipped") is False


def test_opt_in_without_env_falls_back_to_hermetic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Env unavailable even though the run opted in: no capture, T1 from the hermetic oracle.
    monkeypatch.setattr(_pinned_env, "env_available", lambda: False)
    final = run_once({**_INITIAL, "use_pinned_env": True}, auto_approve=True)
    change = dict(final.get("prepared_change") or {})
    assert "attack_exchange" not in change
    assert final.get("pinned_exploit") is None
    assert final.get("verification", {}).get("t1_exploit_oracle_flipped") is True
    assert "Exchange not captured by this run." in render_pr_body(final)


def test_default_run_is_unchanged_by_this_ticket() -> None:
    # No opt-in: identical to before — the golden example run still asserts byte-equality.
    final = run_once(_INITIAL, auto_approve=True)
    assert final.get("pinned_exploit") is None
    assert "attack_exchange" not in dict(final.get("prepared_change") or {})
