# Example run — one committed end-to-end pass

This is a committed, verbatim AVE run: the seeded anchor instance (I-04, the `get_order`
object-ownership gap) walked through all seven phases
(Intake → Match → Assess → Decide → [HITL gate] → Prepare → Execute → Verify) and produced
a PR with a two-part decision record. After HITL, Prepare writes
`results/runs/<id>/bound/_ave_bound.py` and stamps `evidence["oracle"]`. Default T1 is
not green: the unpinned run does not execute that bound pytest or the generated patch.
T0, T2, and re-attack stay unrun, so the PR is not ready to merge.

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
reviewed every accepted finding; regenerated at ticket 28 when the **blast-radius pass**
measured the selected change. This run now ingests **many** findings — every ownership
and role gap the model rediscovered from the code-facts store, each `ave:llm-finder` and
citation-validated — keeps all eight after the cull (no suppressions, no fail-open), and
drives the one finishable finding (`get_order` ownership + handler route). The Match
span carries the coverage denominator (`examined N of M handlers`) and the full per-review
cull report; the Assess span records the stated rank function, the driven finding, and the
ones deferred until a generated exploit binds them (ticket 27); the PR body says
"Selected 1 of N", lists the rest as Still open, and fills Cleared from the selected
finding's validated ruled-out hypotheses. The finder and cull replay recorded transcripts,
so this run needs no model access. Since ticket 28, `find()` measures each kept finding
against the store's identity-aware call graph and records the result under
`evidence["blast_radius_measurement"]`. The Assess span carries the driven finding's
projection (files 1, dependents 0, routes 1), its `ast_resolved` fact at `how_sure: 5`,
and `selection.dependents_measured: 8`. The PR body renders the same counts against the
policy limits 3 / 25 / 15, states the one fact at How sure 5/5, and lists each Still open
row by the reviewer-facing `file:line` from `evidence["review_location"]`.

## What this is *not*

T1 on this default run is an honest empty. It does not prove the generated patch changes
the vendored target. Run with `AVE_PINNED_ENV=1` for that proof (pinned T1 reads capture
JSON: 200 then 403 or 404). T1 also does not show that AVE beats the Semgrep baseline. Those numbers come from
scoring real find-stage output against the catalog. The README results table stays empty
until then. The blast-radius blocks on this run are measured, not empty. A dimension the
call graph cannot bind would still render as the honest `unmeasured`, never as a zero.
Cleared now comes from the cull's validated ruled-out hypotheses.

Live runs write to `results/runs/<id>/` (git-ignored); regenerate with `make run`.
