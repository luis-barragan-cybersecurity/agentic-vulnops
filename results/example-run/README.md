# Example run — the walking skeleton's first end-to-end pass

This is a committed, verbatim AVE run: one seeded instance walked through all seven phases
(Intake → Match → Assess → Decide → [HITL gate] → Prepare → Execute → Verify) and produced
a PR with a decision record. T1 (exploit oracle flipped) is real. T0, T2, and re-attack
stay unchecked, so the PR is not ready to merge. It is the walking skeleton's first run
record (ticket 03), kept here as evidence — "the loop runs" — not as a scored result.

- [`run-record.json`](run-record.json) — the OTel-shaped run trace: one span per phase.
- [`pr/PR_BODY.md`](pr/PR_BODY.md) — the reviewer-facing PR body ("the PR is the product").
- [`pr/fix.patch`](pr/fix.patch) — the class-level ownership-guard diff.

## What this is *not*

The instance is the `python_authz` pack's single **synthetic** BOLA case, standing in for
the real vendored target until the seeded-instance catalog lands (ticket 04). T1 says the
*loop mechanics* work end to end — the exploit oracle really flips when the fix is
applied — **not** that AVE beats the Semgrep baseline. Those numbers come from scoring
against the real catalog (the README results table stays empty until then).

Live runs write to `results/runs/<id>/` (git-ignored); regenerate with `make run`.
