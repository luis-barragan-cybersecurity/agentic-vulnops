"""promptfoo custom provider driving the real AVE graph.

promptfoo calls `call_api(prompt, options, context)`; we run the graph and return its
outcome so evals are properties of the *system*, not of a mocked prompt. Scaffold only
(ticket 02) — returns the stub graph's outcome.
"""

from __future__ import annotations

from typing import Any

from ave.runner import run_once
from ave.state import AVEState


def call_api(prompt: str, options: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    initial: AVEState = {"target_ref": "d32d0997", "policy_version": "unset"}
    final = run_once(initial, auto_approve=True)
    return {
        "output": {
            "ready_to_merge": final.get("ready_to_merge"),
            "pr_ref": final.get("pr_ref"),
        }
    }
