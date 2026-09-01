# Example run — one committed end-to-end pass

This is a committed, verbatim AVE run: the seeded anchor instance (I-04, the `get_order`
object-ownership gap) walked through all seven phases
(Intake → Match → Assess → Decide → [HITL gate] → Prepare → Execute → Verify) and produced
a PR with a two-part decision record. T1 (exploit oracle flipped) is real. T0, T2, and
re-attack stay unrun — the ladder shows them as honest empties — so the PR is not ready
to merge.

- [`run-record.json`](run-record.json) — the OTel-shaped run trace: one span per phase,
  plus the per-finding lifecycle (ticket 08's schema).
- [`pr/PR_BODY.md`](pr/PR_BODY.md) — the reviewer-facing PR body ("the PR is the
  product"), in the shape ticket 06 locked: attack exchange, ladder table, the four
  blast-radius blocks, decision record collapsed. It doubles as the golden file
  `tests/test_pr_body.py` renders against, so it is provably what the code emits.
- [`pr/fix.patch`](pr/fix.patch) — the class-level ownership diff (the in-process model's
  patch; its caveat in the body says exactly what it stands for).

First committed at ticket 03 as the walking skeleton's first pass (that verbatim record
is in git history); regenerated at ticket 09 with the landed governance schemas
(policy `1.0.0`, per-finding lifecycle) and the locked PR-body template.

## What this is *not*

T1 says the *loop mechanics* work end to end — the exploit oracle really flips when the
fix is applied — **not** that AVE beats the Semgrep baseline. Those numbers come from
scoring real find-stage output against the catalog (the README results table stays empty
until then). The unfilled blast-radius blocks render as honest empties by design; the
find-stage pass fills them.

Live runs write to `results/runs/<id>/` (git-ignored); regenerate with `make run`.
