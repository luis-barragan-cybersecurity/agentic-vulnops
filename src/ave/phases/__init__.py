"""The seven phases of the AVE state machine.

Intake -> Match -> Assess -> Decide -> Prepare -> Execute -> Verify.

Each phase is a pure-ish node: it takes the graph state and returns a partial update.
Every node body here is a **stub** — enough structure to wire and smoke-test the loop
(ticket 02); real behavior lands in later tickets (walking skeleton, ticket 03).
"""

from ave.phases.assess import assess
from ave.phases.decide import decide
from ave.phases.execute import execute
from ave.phases.intake import intake
from ave.phases.match import match
from ave.phases.prepare import prepare
from ave.phases.verify import verify

__all__ = [
    "assess",
    "decide",
    "execute",
    "intake",
    "match",
    "prepare",
    "verify",
]

# Canonical phase order — the single source of truth for the graph edges.
PHASE_ORDER: tuple[str, ...] = (
    "intake",
    "match",
    "assess",
    "decide",
    "prepare",
    "execute",
    "verify",
)
