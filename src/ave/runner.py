"""Drive one AVE run through the HITL gate.

The graph is compiled to interrupt *before* Prepare (the human-approval boundary), so a
run is two steps: run to the gate, then — once approved — resume to completion. This
runner encapsulates that so the CLI, the eval provider, and the tests all exercise the
same real flow. A checkpointer is required for the interrupt to pause and resume.
"""

from __future__ import annotations

import uuid
from typing import Any, cast

from langgraph.checkpoint.memory import MemorySaver

from ave.graph import HITL_GATE_BEFORE, build_graph
from ave.state import AVEState


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


def paused_at_gate(initial: AVEState) -> bool:
    """True if a fresh run halts at the HITL gate (before Prepare). Used to prove the
    boundary is real."""
    graph = build_graph(checkpointer=MemorySaver())
    config: dict[str, Any] = {"configurable": {"thread_id": uuid.uuid4().hex}}
    graph.invoke(initial, config)
    return bool(graph.get_state(config).next == (HITL_GATE_BEFORE,))
