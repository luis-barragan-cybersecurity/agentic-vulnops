"""Phase 6 — Execute.

Open (or update) the PR carrying the prepared change and its blast-radius / ring view —
"the PR is the product." Skeleton: assigns the PR ref; the runner materializes the PR
bundle (body + patch) to disk once the run completes, so it can embed the verification
result. No prepared change => no PR.
"""

from __future__ import annotations

from ave.records.store import make_span, now_iso
from ave.state import AVEState


def execute(state: AVEState) -> AVEState:
    started = now_iso()
    has_change = state.get("prepared_change") is not None
    run_id = state.get("run_record_id", "unset")
    pr_ref = f"local:pr/{run_id}" if has_change else None
    return {
        "pr_ref": pr_ref,
        "spans": [make_span("execute", started, {"pr_ref": pr_ref})],
    }
