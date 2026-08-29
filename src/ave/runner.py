"""Drive one AVE run through the HITL gate, and persist its artifacts.

The graph is compiled to interrupt *before* Prepare (the human-approval boundary), so a
run is two steps: run to the gate, then — once approved — resume to completion. `run_once`
encapsulates that so the CLI, the eval provider, and the tests all exercise the same real
flow (a checkpointer is required for the interrupt to pause and resume). `persist_run`
then writes the run's two durable artifacts — the run record and the PR bundle — to disk.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, cast

from langgraph.checkpoint.memory import MemorySaver

from ave.graph import HITL_GATE_BEFORE, build_graph
from ave.pr import render_pr_body
from ave.records.store import build_run_record, write_run_record
from ave.state import AVEState

# Live run records land here; the committed first-run example lives at results/example-run.
DEFAULT_RESULTS_DIR = Path("results/runs")


def run_once(initial: AVEState, *, auto_approve: bool = True) -> AVEState:
    """Run the graph to the HITL gate; if `auto_approve`, approve and resume to the end.

    With `auto_approve=False` the run is left paused at the gate and the partial state is
    returned — this is what a real HITL session sees before a human decides.
    """
    graph = build_graph(checkpointer=MemorySaver())
    config: dict[str, Any] = {"configurable": {"thread_id": uuid.uuid4().hex}}

    graph.invoke(initial, config)  # runs Intake..Decide, then pauses before Prepare

    if not auto_approve:
        return cast(AVEState, dict(graph.get_state(config).values))

    # "The human approves the decision record" — recorded in state, then resume.
    graph.update_state(config, {"human_approved": True})
    return cast(AVEState, dict(graph.invoke(None, config)))


def persist_run(final: AVEState, base_dir: Path = DEFAULT_RESULTS_DIR) -> dict[str, Path]:
    """Write the run's artifacts under `base_dir/<run_id>/`: the run record, and — when a
    PR was opened — the PR bundle (body + patch). Returns the paths written."""
    run_dir = base_dir / str(final.get("run_record_id", "unset"))
    written: dict[str, Path] = {}

    written["run_record"] = write_run_record(build_run_record(final), run_dir)

    if final.get("pr_ref"):
        pr_dir = run_dir / "pr"
        pr_dir.mkdir(parents=True, exist_ok=True)
        body_path = pr_dir / "PR_BODY.md"
        body_path.write_text(render_pr_body(final), encoding="utf-8")
        written["pr_body"] = body_path
        patch = (final.get("prepared_change") or {}).get("patch")
        if patch:
            patch_path = pr_dir / "fix.patch"
            patch_path.write_text(patch, encoding="utf-8")
            written["patch"] = patch_path

    return written


def paused_at_gate(initial: AVEState) -> bool:
    """True if a fresh run halts at the HITL gate (before Prepare). Used to prove the
    boundary is real."""
    graph = build_graph(checkpointer=MemorySaver())
    config: dict[str, Any] = {"configurable": {"thread_id": uuid.uuid4().hex}}
    graph.invoke(initial, config)
    return bool(graph.get_state(config).next == (HITL_GATE_BEFORE,))
