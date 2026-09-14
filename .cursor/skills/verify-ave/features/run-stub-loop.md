# Run the loop

By default, `ave run` walks the seven-phase graph on the hardcoded target ref `target/dvrestaurant@d32d0997`. It replays finder and cull fixtures, keeps eight findings, suppresses zero, and drives the I-04 finding. After the HITL gate, Prepare writes `results/runs/<id>/bound/_ave_bound.py` and stamps that path on the selected finding. It auto-approves at the HITL gate, writes a local PR bundle under `results/runs/<id>/`, leaves T1 unpainted, and reports that nothing is ready to merge.

## Sub-features

- `run-help` lists the `run` subcommand.
- `run-cli` completes via `ave run` / `python -m ave.cli run`.
- `run-make` completes via `make run`.
- `run-claims-nothing` reports `ready_to_merge = False` and a `local:pr/` ref.
- `run-selection` attributes the driven finding to `ave:llm-finder`, records the stated rank function, and explains why the run selected the I-04 location.
- `run-cull-ledger` records kept, suppressed, fail-open, and oracle-override counts on the Match span.
- `run-lifecycles` persists one open lifecycle per kept finding and a false-positive lifecycle per suppressed finding.
- `run-cleared` fills the PR body's Cleared table from the selected finding's validated ruled-out hypothesis.
- `run-many-contract` covers multi-source attribution, de-duplication, ranking, and unselected open findings.
- `run-blast-radius` measures the selected change's `files`, `dependents`, and `routes` from the code-facts store, records them on the Assess span and in the decision record, and routes the decision to `out_of_policy_change` because a fix predicate fails, not because a dimension is unmeasured.
- `run-pr-body` writes the locked, honest PR-body template and matches the committed example after run-specific values are normalized.
- `run-bound-exploit` writes `results/runs/<id>/bound/_ave_bound.py` after HITL. Before you merge copies that file to `app/tests/_ave_bound.py` and runs it from `target/dvrestaurant`.

## How to get to it (user POV)

- Run `ave run` after `make setup`.
- Run `python -m ave.cli run`.
- Run `make run` from the repo root with the venv on `PATH`.

## Driving it with control-ave

Preconditions:

- `control-ave doctor` succeeded.
- Working tree on `README.md` and `target/` must stay clean. The command writes gitignored files under `results/runs/`.
- `AVE_LLM_LIVE` and `AVE_PINNED_ENV` are unset. This recipe proves the default fixture run.

- **Help.** Run `.cursor/skills/verify-ave/control-ave cli -- --help`. Exit code `0`. Stdout lists `run`, `break`, `eradicate`, `scoreboard`, `inventory`, and `find`.
- **CLI entry.** Run `.cursor/skills/verify-ave/control-ave capture run-stub-loop -- cli -- run`. `artifacts/run-stub-loop/exit_code.txt` is `0`.
- **Gate line.** Stdout contains `run: walking seven phases; HITL gate auto-approves (no pause).` and `run complete.`
- **Outcome.** Stdout contains `human_approved = True`, `ready_to_merge = False`, and a `pr_ref` starting with `local:pr/`.
- **Artifacts.** Stdout contains `run_record`, `pr_body`, and `patch` lines under `results/runs/<id>/`. That directory exists. `git status --porcelain -- README.md target` is empty.
- **Trace.** Stdout contains a JSON object with `"name": "ave.run"` and `"service.name": "ave"`.
- **Selection.** Open the printed `run_record` path. Match records `found: 8`, `ingested: 8`, `sources: ["ave:llm-finder"]`, and `suppressed: 0`. Assess selects `ave-llm-get_order_service-get_order`, records `dependents_measured: 8` with `dependents: 0` on every ranking row, and names the other seven as `deferred_pending_exploit`.
- **Blast radius.** In the same run record, the Assess span's `blast_radius` has `files: 1`, `dependents: 0`, `routes: 1`, and a `fact` with `provenance: "ast_resolved"` and `how_sure: 5`. The Decide span has `hitl_route: "out_of_policy_change"`. The PR body's decision record repeats `1 / 0 / 1`. The run record persists no finding `evidence`, so the per-finding `blast_radius_measurement` and `review_location` keys are proven by the blast-radius contract node below, not by the record. `ave run` stdout never prints these counts.
- **Cull ledger.** In the same Match span, `find_stage.cull` records `reviewed: 8`, `kept: 8`, `suppressed: 0`, `fail_open: 0`, `bound_oracle_overrides: 0`, `client: "fixture"`, both cull prompt versions at `2`, and eight reviews. Each default review has `effective: "keep"` and `basis: "validated"`.
- **Ingestion.** Match merges kept findings into `findings`. Suppressed findings go only to `suppressed_findings`, so Assess cannot rank or drive them.
- **Lifecycles.** The default run record has eight lifecycles, all `outcome: "open"`. Only `ave-llm-get_order_service-get_order` has `triaged_at` set. The rest have `triaged_at: null` and `verified_at: null`.
- **Bound exploit.** The run directory contains `bound/_ave_bound.py`. That file defines `test_authorization_boundary`, consults `AVE_CAPTURE_PATH`, and does not mention `app/tests/vulns/`.
- **PR body.** Open the printed `pr_body` path. Before the attack exchange, it says `Selected 1 of 8 ingested findings`, names `ave:llm-finder`, quotes the rank function, and says `dependents measured for 8 of 8`. The blast-radius table reads `| Files changed | 1 | 3 |`, `| Dependent call sites | 0 | 25 |`, `| Routes affected | 1 | 15 |`. The one fact reads `The AST inventory identifies get_order as the GET /orders/{order_id} route handler.` followed by `How sure: **5/5**` and a proof citing `get_order_service.py:11-20`. The decision record line reads `HITL route fired: **out_of_policy_change**` and `Rule matched: fix_predicates.require_all (a fix predicate failed)`. The Still open table's Where column shows `file:line`, for example `app/apis/menu/services/update_menu_item_service.py:15`, not `file:symbol`. The Cleared table rules out `A post-fetch ownership guard binds db_order to current_user on every path`. Its How cell explains that the handler returns `db_order` with no `user_id` comparison and cites `get_order_service.py:11-20`. Every ladder rung including T1 is `⬜ not green`. `Ready to merge` is `no`. Before you merge copies `results/runs/<id>/bound/_ave_bound.py` to `target/dvrestaurant/app/tests/_ave_bound.py` and runs that node from `target/dvrestaurant`.
- **PR-body contract.** Run `.cursor/skills/verify-ave/control-ave capture pr-body-template -- pytest -- tests/test_pr_body.py -q`. Exit code `0`; stdout reports `24 passed`. This proves the fresh renderer matches `results/example-run/pr/PR_BODY.md` after only run IDs and timestamps are normalized. It also proves that Cleared is pack-projected and that its model-authored table cells are escaped.
- **Binding contract.** Run `.cursor/skills/verify-ave/control-ave capture binding-contract -- pytest -- tests/test_binding.py -q`. Exit code `0`; stdout reports `11 passed`.
- **Many-findings contract.** Run `.cursor/skills/verify-ave/control-ave capture many-findings -- pytest -- tests/test_many_findings.py -q`. Exit code `0`; stdout reports `28 passed`. These tests fold a second source, check one lifecycle per ingested finding, prove the suppressed false-positive lifecycle, and prove that an external winner of a merge inherits the pack's blast-radius measurement. The default fixture run does not prove suppression.
- **Blast-radius contract.** Run `.cursor/skills/verify-ave/control-ave capture blast-radius-tests -- pytest -- tests/test_blast_radius.py -q`. Exit code `0`; stdout reports `11 passed`. These tests pin the anchor's `1 / 0 / 1`, the `how_sure 5` fact, the `Unproven` fallback on an incomplete reach and on a rejected citation, the forged-identity rejection, `patch_paths == changed_paths`, `PatchScopeMismatch` in Prepare, and the agreement between the Assess span, the decision record, and the prepared change.
- **Cull contract.** Run `.cursor/skills/verify-ave/control-ave capture cull-tests -- pytest -- tests/test_cull.py -q`. Exit code `0`; stdout reports `29 passed`. Scripted sessions prove suppression, fail-open keep, one-to-one pairing, and bound-oracle override.
- **Make entry.** Run `.cursor/skills/verify-ave/control-ave make -- run`. Same four summary lines and exit `0`.
- **Proof.** Keep `artifacts/run-stub-loop/stdout.txt` and `exit_code.txt`.

## Gotchas

- The CLI never waits. `auto_approve=True` is hardcoded.
- Bare `make run` without `.venv/bin` on `PATH` uses system `python3` and fails to import `ave`.
- Langgraph prints a `LangChainPendingDeprecationWarning` on stderr. That is not a failure.
- `ready_to_merge = False` because every ladder rung is unpainted on the default path. T1 is an honest skip, not a hermetic flip. Do not treat today's False as the invariant implementation.
- Target ref `target/dvrestaurant@d32d0997` is hardcoded. There is no CLI flag to change it. The driven finding is `ave-llm-get_order_service-get_order` at the catalog I-04 location. The FastAPI tree is vendored; `run` does not start it.
- The default path replays finder and cull fixtures and emits eight kept findings. That is not a live-model proof. `ave find` prints both stage summaries. The cull and many-finding tests prove paths that the default fixtures do not exercise.
- `ave run` stdout does not print cull counts. Read `find_stage.cull` from the Match span.
- `out_of_policy_change` is the measured result, not a fail-closed fallback. A run that reports `unknown_blast_radius` on the fixture means a dimension came back `None`, which is a regression in the measurement, not policy. The synthetic `unknown_blast_radius` case lives in `tests/test_governance.py`.
- The default fixtures suppress zero. Do not report the direct run as proof that the cull removed a false positive.
- The default PR body declares an uncaptured exchange instead of inventing HTTP. Set `AVE_PINNED_ENV=1` only through the separate [Pinned-environment run](./pinned-env-run.md) recipe. The golden comparison masks only the random run ID and timestamps; it does not normalize substantive content.
