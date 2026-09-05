"""Pinned-env exploit runner for `python_authz` — the **second runner shape**.

The pack's `run_exploit` (in `pack.py`) is the *hermetic in-process* oracle: two plain
functions in `_skeleton_target.py`, fast, needing no target environment, driving
`make check`. This module is the other shape: it runs a selected instance's **by-path
exploit oracle inside the target's pinned Poetry environment** (`target/dvrestaurant/`,
Python 3.10 / FastAPI 0.103), so a real fix is verified against the *real* target — real
router, real DB models, real serialization — and the real **attack exchange** (the request
and the actual deny) is captured for the PR body's opener.

That the exploit harness now has two runner shapes is a seam smell, recorded on
`adapters.base.PinnedEnvCapable` for **ticket 14** (seam hardening) to resolve.

Honest by construction. When the pinned env is absent — no `target/dvrestaurant/`, or no
`poetry` on PATH — `run_pinned_capture` returns a `ran=False` result: never a fabricated
pass, never a fabricated transcript. `make check` runs with the env absent (this repo's CI
has no Python-3.10 target env), so the hermetic path stays the default and this module's
real subprocess path is exercised only where the env exists. The capture itself lives in the
target tree at `app/tests/vulns/_ave_capture_bola_order_read.py` (AVE-seeded, invoked by
path, not auto-collected).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # the one subprocess boundary: argv is fixed, never shell
import tempfile
from pathlib import Path
from typing import Any

from ave.adapters.base import PinnedExploitResult
from ave.state import Finding

# src/ave/adapters/python_authz/_pinned_env.py -> repo root is five parents up.
_REPO_ROOT = Path(__file__).resolve().parents[4]
_TARGET_DIR = _REPO_ROOT / "target" / "dvrestaurant"

# The by-path capture harness for the loop anchor (I-04), relative to the target dir. It
# performs the attack against the real app, then the same request against the fix applied as
# the blessed ownership-check pattern, and writes a redacted transcript to $AVE_CAPTURE_PATH.
_ANCHOR_CAPTURE = "app/tests/vulns/_ave_capture_bola_order_read.py"

# Bound the subprocess: a pinned-env pytest run should be seconds, not minutes.
_TIMEOUT_S = 300

# Redaction, mirrored from the renderer's fail-closed validator (`ave.pr`). Two independent
# gates guard the public artifact: the harness redacts at capture, this redacts what the
# harness returned, and the renderer redacts again at the boundary. Matched lower-cased.
_EXCHANGE_FIELDS: tuple[str, ...] = ("request", "before_response", "after_response")
_FORBIDDEN: tuple[str, ...] = (
    "```",
    "authorization:",
    "cookie:",
    "set-cookie:",
    "bearer ",
    "token=",
    "session=",
)
_MAX_FIELD_LEN = 4000


def _not_run(detail: str) -> PinnedExploitResult:
    """The honest skip: the pinned env did not run, so nothing is claimed."""
    return {
        "ran": False,
        "before_vulnerable": None,
        "after_blocked": None,
        "flipped": None,
        "attack_exchange": None,
        "detail": detail,
    }


def env_available() -> bool:
    """True only when the pinned env can actually run: the vendored target is present and
    `poetry` is on PATH. Anything else is the honest skip."""
    return _TARGET_DIR.is_dir() and shutil.which("poetry") is not None


def sanitized_exchange(raw: Any) -> dict[str, str] | None:
    """Return the captured exchange only if safe to carry forward, else None. Fail-closed:
    each of the three fields must be a non-empty string within a length cap, free of control
    characters (beyond CR/LF/TAB) and of any forbidden substring (a fence, or a
    secret-bearing header/token). One failure rejects the whole exchange."""
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
        if any(ord(ch) < 32 and ch not in "\r\n\t" for ch in value):
            return None
        if any(bad in value.lower() for bad in _FORBIDDEN):
            return None
        cleaned[key] = stripped
    return cleaned


def _capture_target(finding: Finding) -> str | None:
    """The by-path capture harness for this instance, or None if the pack has no pinned
    harness for it. v1 ships the anchor's harness only; other instances resolve as the
    frontier advances (find-stage / seam hardening)."""
    is_anchor = bool(
        isinstance(finding.get("evidence"), dict)
        and finding["evidence"].get("is_loop_anchor")
    )
    return _ANCHOR_CAPTURE if is_anchor else None


def _interpret(payload: dict[str, Any]) -> PinnedExploitResult:
    """Turn the harness's JSON payload into a `PinnedExploitResult`. The harness reports the
    two response statuses it observed against the real target; `flipped` is the pinned T1
    signal (attack succeeded before the fix, denied after)."""
    before_status = payload.get("before_status")
    after_status = payload.get("after_status")
    before_vulnerable = before_status == 200
    after_blocked = isinstance(after_status, int) and after_status in (403, 404)
    exchange = sanitized_exchange(payload.get("attack_exchange"))
    detail = (
        f"pinned env ran: before={before_status} after={after_status}; "
        f"exchange={'captured' if exchange else 'withheld (failed redaction gate)'}"
    )
    return {
        "ran": True,
        "before_vulnerable": before_vulnerable,
        "after_blocked": after_blocked,
        "flipped": before_vulnerable and after_blocked,
        "attack_exchange": exchange,
        "detail": detail,
    }


def run_pinned_capture(finding: Finding) -> PinnedExploitResult:
    """Run the finding's by-path capture harness in the target's pinned Poetry env and
    return a structured result. Never raises: env absent, no harness, a non-zero pytest
    exit, a timeout, or unreadable output each yield a `ran=False` result, so the caller can
    trust the `ran` flag and fall back to the hermetic oracle."""
    if not env_available():
        return _not_run(
            "pinned env absent (no target/dvrestaurant or no poetry on PATH); "
            "hermetic in-process oracle used instead"
        )
    capture_rel = _capture_target(finding)
    if capture_rel is None:
        return _not_run(
            f"no pinned capture harness for {finding.get('id')} "
            f"(v1 ships the loop anchor's harness only)"
        )

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "exchange.json"
        env = {**os.environ, "AVE_CAPTURE_PATH": str(out_path)}
        argv = ["poetry", "run", "pytest", capture_rel, "-q", "-p", "no:cacheprovider"]
        try:
            proc = subprocess.run(  # fixed argv, no shell, trusted target dir
                argv,
                cwd=_TARGET_DIR,
                env=env,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return _not_run(f"pinned env failed to launch: {exc}")

        if not out_path.exists():
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
            return _not_run(
                "pinned env ran but wrote no capture "
                f"(pytest exit {proc.returncode}): {' | '.join(tail)}"
            )
        try:
            payload = json.loads(out_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _not_run(f"pinned env wrote an unreadable capture: {exc}")

    if not isinstance(payload, dict):
        return _not_run("pinned env capture was not a JSON object")
    return _interpret(payload)
