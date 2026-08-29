"""The seven-phase AVE state machine, wired as a LangGraph StateGraph.

Intake -> Match -> Assess -> Decide -> [HITL gate] -> Prepare -> Execute -> Verify.

The HITL gate is declared **structurally**: the graph is compiled to interrupt *before*
Prepare, so a human approves the decision record produced in Decide before any change is
prepared. This is a boundary, not a prompt — it is the invariant's first enforcement point
(the second is CI re-validation from the run record).
"""

from __future__ import annotations

from itertools import pairwise
from typing import Any

from langgraph.graph import END, START, StateGraph

from ave import phases
from ave.state import AVEState

# The node that AVE pauses before, for human approval of the decision record.
HITL_GATE_BEFORE = "prepare"

_NODES = {
    "intake": phases.intake,
    "match": phases.match,
    "assess": phases.assess,
    "decide": phases.decide,
    "prepare": phases.prepare,
    "execute": phases.execute,
    "verify": phases.verify,
}


def build_graph(checkpointer: Any | None = None) -> Any:
    """Build and compile the seven-phase graph.

    A `checkpointer` is required for the HITL interrupt to actually pause at runtime;
    without one the graph still compiles and runs straight through (used by smoke tests).
    """
    builder = StateGraph(AVEState)

    for name, fn in _NODES.items():
        builder.add_node(name, fn)

    order = phases.PHASE_ORDER
    builder.add_edge(START, order[0])
    for earlier, later in pairwise(order):
        builder.add_edge(earlier, later)
    builder.add_edge(order[-1], END)

    return builder.compile(
        checkpointer=checkpointer,
        interrupt_before=[HITL_GATE_BEFORE],
    )
