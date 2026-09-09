"""Assemble and persist a run record.

Each phase appends one span to `state["spans"]`; at the end of a run the runner builds a
`RunRecord` from the final state and writes it to disk. This is the walking-skeleton
version of the run-record store — enough to persist one real, if ugly, record per run.
Ticket 05 fixes the full schema (the six SANS metrics) and the durable store the CI
invariant re-check reads from.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ave.records.run_record import FindingLifecycle, PhaseSpan, RunRecord
from ave.state import AVEState


def now_iso() -> str:
    """A UTC timestamp for a span boundary."""
    return datetime.now(UTC).isoformat()


def make_span(phase: str, started_at: str, attributes: dict[str, Any]) -> dict[str, Any]:
    """One phase's span, ready to append to `state["spans"]`."""
    return {
        "phase": phase,
        "started_at": started_at,
        "ended_at": now_iso(),
        "attributes": attributes,
    }


def _span_start(spans: list[dict[str, Any]], phase: str) -> str | None:
    return next((s.get("started_at") for s in spans if s.get("phase") == phase), None)


def _span_end(spans: list[dict[str, Any]], phase: str) -> str | None:
    return next((s.get("ended_at") for s in spans if s.get("phase") == phase), None)


def _finding_lifecycles(state: AVEState) -> list[FindingLifecycle]:
    """Kept findings stay `open` unless the selected head is remediatively triaged.
    Suppressed findings are `false_positive` with `triaged_at` at Match completion."""
    spans = state.get("spans", [])
    first_observed = _span_start(spans, "intake") or _span_start(spans, "match")
    if first_observed is None:
        return []
    selected = state.get("selected_finding")
    findings = list(state.get("findings") or [])
    if selected and all(f.get("id") != selected.get("id") for f in findings):
        findings.append(selected)
    ready = bool(state.get("ready_to_merge"))
    match_completed = _span_end(spans, "match") or _span_start(spans, "match")
    lifecycles: list[FindingLifecycle] = []
    for finding in findings:
        is_head = selected is not None and finding.get("id") == selected.get("id")
        lifecycles.append(
            FindingLifecycle(
                finding_id=str(finding.get("id", "unknown")),
                first_observed_at=first_observed,
                triaged_at=_span_start(spans, "decide") if is_head else None,
                verified_at=_span_start(spans, "verify") if is_head and ready else None,
                outcome="verified_fixed" if is_head and ready else "open",
            )
        )
    for finding in state.get("suppressed_findings") or []:
        lifecycles.append(
            FindingLifecycle(
                finding_id=str(finding.get("id", "unknown")),
                first_observed_at=first_observed,
                triaged_at=match_completed,
                outcome="false_positive",
            )
        )
    return lifecycles


def build_run_record(state: AVEState) -> RunRecord:
    """Assemble the run record from the final graph state."""
    record = RunRecord(
        run_id=state.get("run_record_id", "unset"),
        target_ref=state.get("target_ref", "unset"),
        policy_version=state.get("policy_version", "unset"),
        ready_to_merge=bool(state.get("ready_to_merge")),
        decision_record_present=state.get("decision_record") is not None,
    )
    for span in state.get("spans", []):
        record.spans.append(
            PhaseSpan(
                phase=span["phase"],
                started_at=span.get("started_at"),
                ended_at=span.get("ended_at"),
                attributes=span.get("attributes", {}),
            )
        )
    record.findings.extend(_finding_lifecycles(state))
    # v1's loop always fixes: no accepted-risk / deferred exceptions yet (see run_record).
    return record


def write_run_record(record: RunRecord, run_dir: Path) -> Path:
    """Persist the run record as JSON under `run_dir`; returns the file path."""
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "run-record.json"
    path.write_text(json.dumps(asdict(record), indent=2) + "\n", encoding="utf-8")
    return path
