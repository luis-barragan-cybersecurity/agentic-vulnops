"""Run-record schema — the first-ranked compounding export.

OTel-shaped: a run is a trace; each phase is a span. Every phase appends here, and all
six SANS-VulnOps operational metrics, the CI invariant re-check, and live monitoring read
from it. This is a *scaffold* shape (ticket 02); ticket 05 fixes the full schema needed to
compute all six metrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PhaseSpan:
    """One phase's span within the run trace."""

    phase: str
    started_at: str | None = None
    ended_at: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunRecord:
    """The record of a single AVE run. OTel-named (trace/span) on purpose."""

    run_id: str
    target_ref: str
    policy_version: str
    spans: list[PhaseSpan] = field(default_factory=list)
    # Outcome fields the invariant and the scoreboard read.
    ready_to_merge: bool = False
    decision_record_present: bool = False

    def start_phase(self, phase: str) -> PhaseSpan:
        span = PhaseSpan(phase=phase)
        self.spans.append(span)
        return span
