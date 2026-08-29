"""First-class, reusable record schemas — AVE's top compounding exports.

- `run_record` — the OTel-shaped record every phase appends to; the six operational
  metrics, the CI invariant check, and future live monitoring all read it.
- `decision_record` — the two-part record that justifies a fix and cites the policy
  version.

These are named neutrally (no `authz`/`fastapi`) so a future language pack reuses them.
"""
