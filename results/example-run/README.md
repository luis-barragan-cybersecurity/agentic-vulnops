# Example run — one committed end-to-end pass

This is a committed, verbatim AVE run: the seeded anchor instance (I-04, the `get_order`
object-ownership gap) walked through all seven phases
(Intake → Match → Assess → Decide → [HITL gate] → Prepare → Execute → Verify) and produced
a PR with a two-part decision record. T1 (exploit oracle flipped) is real. T0, T2, and
re-attack stay unrun, so the PR is not ready to merge. This default example uses the
hermetic in-process model for T1. It does not execute the generated patch.

- [`run-record.json`](run-record.json) — the OTel-shaped run trace: one span per phase,
  plus the per-finding lifecycle (ticket 08's schema).
- [`pr/PR_BODY.md`](pr/PR_BODY.md) — the reviewer-facing PR body ("the PR is the
  product"), in the shape ticket 06 locked: attack exchange, ladder table, the four
  blast-radius blocks, decision record collapsed. It doubles as the golden file
  `tests/test_pr_body.py` renders against, so it is provably what the code emits.
- [`pr/fix.patch`](pr/fix.patch) — the applicable ownership diff for
  `target/dvrestaurant/app/apis/orders/services/get_order_service.py`.

First committed at ticket 03 as the walking skeleton's first pass (that verbatim record
is in git history); regenerated at ticket 09 with the landed governance schemas
(policy `1.0.0`, per-finding lifecycle) and the locked PR-body template; regenerated again
at ticket 24 with the many-findings run shape — every finding carries `source`, the Match
span records what was ingested and from where, the Assess span records the stated rank
function and why the head was selected, and the PR body says "Selected 1 of N". This run
still ingests exactly **one** finding: the pack claims only the loop anchor, so N is 1 and
the machinery is proven by tests on synthetic multi-source findings.

## What this is *not*

T1 says the *loop mechanics* and the hermetic oracle work end to end. It does not prove
that the generated patch changes the vendored target. Run with `AVE_PINNED_ENV=1` for that
proof. T1 also does not show that AVE beats the Semgrep baseline. Those numbers come from
scoring real find-stage output against the catalog. The README results table stays empty
until then. The unfilled blast-radius blocks render as honest empties by design. The
find-stage pass fills them.

Live runs write to `results/runs/<id>/` (git-ignored); regenerate with `make run`.
