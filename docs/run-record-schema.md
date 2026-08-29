# Run-record schema (compounding export #1)

The run record is AVE's most reusable export. It is **OTel-shaped**: a run is a *trace*,
each phase is a *span*. Everything downstream reads it — the six operational metrics, the
CI invariant re-check, and future live-monitoring burn-rate — so nothing downstream is
hand-entered.

See [`ave/records/run_record.py`](../src/ave/records/run_record.py) for the scaffold shape
(`RunRecord`, `PhaseSpan`).

## Status

Scaffold only (ticket 02): enough shape to thread through the graph and back the invariant
check. **Ticket 05** fixes the full schema — the fields required to compute all six SANS
VulnOps operational metrics — and the on-disk store CI reads.

## Neutral naming (D3)

The record names phases and outcomes generically (`ready_to_merge`, `decision_record_present`,
per-phase spans) — never `authz` or `fastapi` — so a future language pack reuses it verbatim.
