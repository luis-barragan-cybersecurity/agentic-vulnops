"""Run-record schema — the first-ranked compounding export.

OTel-shaped: a run is a trace; each phase is a span. Every phase appends here, and all
six SANS-VulnOps operational metrics, the CI invariant re-check, and live monitoring read
from it.

The load-bearing shape (locked in ticket 05, landed in ticket 08) is the **per-finding
lifecycle**: phase spans alone are per-*run*, but three of the six metrics — observed
exposure hours, triage latency, and absorption — are per-*finding* and cross-run. So a
`RunRecord` carries `findings: list[FindingLifecycle]` and `exceptions:
list[ExceptionRecord]`, and the metrics flat-map `findings` across every run. Names stay
language- and vuln-family-neutral (D3) so a future language pack reuses the schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

FindingOutcome = Literal[
    "verified_fixed",       # ladder greened and held — the thesis outcome
    "failed_verification",  # a fix was attempted but the ladder did not (stay) green
    "false_positive",       # triaged away; not counted as found
    "accepted_exception",   # risk accepted / deferred (feeds exceptions[])
    "open",                 # observed, not yet resolved
]


@dataclass
class PhaseSpan:
    """One phase's span within the run trace."""

    phase: str
    started_at: str | None = None
    ended_at: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class FindingLifecycle:
    """Per-finding sub-record inside a run trace — the key addition over phase spans.

    Carries the finding-grain timestamps and outcome the operational metrics need:
    exposure hours (`first_observed_at` -> `verified_at`), triage latency
    (`first_observed_at` -> `triaged_at`), absorption (found vs. verified counts), and
    change-failure (`ladder_ever_green_then_red`). `first_observed_at` is
    first-observed-in-run: when the flaw first appeared in *any* run record, honest to
    what AVE actually saw — no target-commit archaeology.
    """

    finding_id: str
    first_observed_at: str            # exposure-clock START (first-observed-in-run)
    triaged_at: str | None = None     # decision made (triage-latency END)
    verified_at: str | None = None    # ladder greened (exposure-clock STOP)
    outcome: FindingOutcome = "open"
    ladder_ever_green_then_red: bool = False   # feeds change-failure rate


@dataclass
class ExceptionRecord:
    """An accepted-risk / deferred finding. Feeds exception staleness (metric #6).

    Named `ExceptionRecord`, not `Exception`, so it never shadows the builtin. v1's loop
    always fixes, so this list is empty and `exception_staleness` is structurally null;
    the field stays because it is a real SANS metric a later accept-risk / defer path
    will populate.
    """

    finding_id: str
    accepted_at: str
    review_due_at: str


@dataclass
class RunRecord:
    """The record of a single AVE run. OTel-named (trace/span) on purpose."""

    run_id: str
    target_ref: str
    policy_version: str
    spans: list[PhaseSpan] = field(default_factory=list)
    findings: list[FindingLifecycle] = field(default_factory=list)
    exceptions: list[ExceptionRecord] = field(default_factory=list)
    # Outcome fields the invariant and the scoreboard read.
    ready_to_merge: bool = False
    decision_record_present: bool = False

    def start_phase(self, phase: str) -> PhaseSpan:
        span = PhaseSpan(phase=phase)
        self.spans.append(span)
        return span
