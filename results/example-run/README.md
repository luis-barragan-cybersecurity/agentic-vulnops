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
(policy `1.0.0`, per-finding lifecycle) and the locked PR-body template; regenerated at
ticket 24 with the many-findings run shape; regenerated again at ticket 25 when the **LLM
finder** became the finding source; regenerated at ticket 26 when the **adversarial cull**
reviewed every accepted finding. This run now ingests **many** findings — every ownership
and role gap the model rediscovered from the code-facts store, each `ave:llm-finder` and
citation-validated — keeps all eight after the cull (no suppressions, no fail-open), and
drives the one bound to the loop's hermetic oracle (the anchor, `get_order`). The Match
span carries the coverage denominator (`examined N of M handlers`) and the full per-review
cull report; the Assess span records the stated rank function, the driven finding, and the
ones deferred until a generated exploit binds them (ticket 27); the PR body says
"Selected 1 of N", lists the rest as Still open, and fills Cleared from the selected
finding's validated ruled-out hypotheses. The finder and cull replay recorded transcripts,
so this run needs no model access.

## What this is *not*

T1 says the *loop mechanics* and the hermetic oracle work end to end. It does not prove
that the generated patch changes the vendored target. Run with `AVE_PINNED_ENV=1` for that
proof. T1 also does not show that AVE beats the Semgrep baseline. Those numbers come from
scoring real find-stage output against the catalog. The README results table stays empty
until then. Unfilled blast-radius blocks (the one fact, measured counts) still render as
honest empties. Cleared now comes from the cull's validated ruled-out hypotheses.

Live runs write to `results/runs/<id>/` (git-ignored); regenerate with `make run`.
