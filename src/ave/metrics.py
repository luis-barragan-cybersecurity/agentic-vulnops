"""The six SANS-VulnOps operational metrics, computed from run records only.

This is the reference implementation that proves the ticket-05 run-record schema is
sufficient: given a list of `RunRecord`s (each carrying per-finding lifecycles and any
accepted exceptions), all six metrics fall out with no other input than an `as_of` clock.
The scoreboard verb and live monitoring build on this; the numbers are always re-derivable
from committed records, never from a prompt.

The metrics are per-*finding* and cross-run, so they flat-map `findings` across every run.
Field names stay language- and vuln-family-neutral (D3).
"""

from __future__ import annotations

from datetime import datetime
from statistics import median
from typing import Any

from ave.records.run_record import RunRecord


def _hours_between(start: str, end: str) -> float:
    return (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() / 3600


def _p90(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[int(0.9 * (len(ordered) - 1))]


def compute_metrics(records: list[RunRecord], *, as_of: str) -> dict[str, Any]:
    """The six operational metrics plus raw counts, from run records alone.

    1. observed exposure hours (median + p90) — first_observed -> verified, per finding
    2. absorption ratio — verified / found
    3. triage latency (median hours) — first_observed -> triaged, per finding
    4. change-failure rate — failed-or-regressed / fixes attempted
    5. verification rate — verified / fixes attempted (the thesis metric)
    6. exception staleness (median hours overdue) — from accepted exceptions
    """
    lifecycles = [f for r in records for f in r.findings]
    exceptions = [e for r in records for e in r.exceptions]

    verified = [f for f in lifecycles if f.outcome == "verified_fixed"]
    found = [f for f in lifecycles if f.outcome != "false_positive"]
    false_positives = [f for f in lifecycles if f.outcome == "false_positive"]

    exposure = [
        _hours_between(f.first_observed_at, f.verified_at)
        for f in verified
        if f.verified_at is not None
    ]
    triage = [
        _hours_between(f.first_observed_at, f.triaged_at)
        for f in lifecycles
        if f.triaged_at is not None
    ]
    now = datetime.fromisoformat(as_of)
    staleness = [
        _hours_between(e.review_due_at, as_of)
        for e in exceptions
        if now > datetime.fromisoformat(e.review_due_at)
    ]

    n_found = len(found)
    n_verified = len(verified)
    n_failed = len([
        f for f in lifecycles
        if f.outcome == "failed_verification" or f.ladder_ever_green_then_red
    ])
    n_fix_attempts = len([
        f for f in lifecycles
        if f.outcome in ("verified_fixed", "failed_verification")
    ])

    return {
        "observed_exposure_hours": {
            "median": round(median(exposure), 2) if exposure else None,
            "p90": round(_p90(exposure), 2) if exposure else None,
        },
        "absorption_ratio": round(n_verified / n_found, 3) if n_found else None,
        "triage_latency_hours_median": round(median(triage), 2) if triage else None,
        "change_failure_rate": round(n_failed / n_fix_attempts, 3) if n_fix_attempts else None,
        "verification_rate": round(n_verified / n_fix_attempts, 3) if n_fix_attempts else None,
        "exception_staleness_hours_median": round(median(staleness), 2) if staleness else None,
        "counts": {
            "found": n_found,
            "fixed": n_verified,
            "verified": n_verified,
            "false_positive": len(false_positives),
        },
    }
