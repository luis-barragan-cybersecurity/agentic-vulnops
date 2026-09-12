# Run the loop

By default, `ave run` walks the seven-phase graph on the hardcoded target ref `target/dvrestaurant@d32d0997` with the hermetic I-04 oracle. It replays finder and cull fixtures, keeps eight findings, suppresses zero, and drives the I-04 finding. It auto-approves at the HITL gate, writes a local PR bundle under `results/runs/<id>/`, and reports that nothing is ready to merge.

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
- `run-pr-body` writes the locked, honest PR-body template and matches the committed example after run-specific values are normalized.

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
- **Selection.** Open the printed `run_record` path. Match records `found: 8`, `ingested: 8`, `sources: ["ave:llm-finder"]`, and `suppressed: 0`. Assess selects `ave-llm-get_order_service-get_order`, records `dependents_measured: 0`, and names the other seven as `deferred_pending_exploit`.
- **Cull ledger.** In the same Match span, `find_stage.cull` records `reviewed: 8`, `kept: 8`, `suppressed: 0`, `fail_open: 0`, `bound_oracle_overrides: 0`, `client: "fixture"`, both cull prompt versions at `2`, and eight reviews. Each default review has `effective: "keep"` and `basis: "validated"`.
- **Ingestion.** Match merges kept findings into `findings`. Suppressed findings go only to `suppressed_findings`, so Assess cannot rank or drive them.
- **Lifecycles.** The default run record has eight lifecycles, all `outcome: "open"`. Only `ave-llm-get_order_service-get_order` has `triaged_at` set. The rest have `triaged_at: null` and `verified_at: null`.
- **PR body.** Open the printed `pr_body` path. Before the attack exchange, it says `Selected 1 of 8 ingested findings`, names `ave:llm-finder`, and quotes the rank function. The Cleared table rules out `A post-fetch ownership guard binds db_order to current_user on every path`. Its How cell explains that the handler returns `db_order` with no `user_id` comparison and cites `get_order_service.py:11-20`. Only T1 is green and `Ready to merge` is `no`.
- **PR-body contract.** Run `.cursor/skills/verify-ave/control-ave capture pr-body-template -- pytest -- tests/test_pr_body.py -q`. Exit code `0`; stdout reports `24 passed`. This proves the fresh renderer matches `results/example-run/pr/PR_BODY.md` after only run IDs and timestamps are normalized. It also proves that Cleared is pack-projected and that its model-authored table cells are escaped.
- **Many-findings contract.** Run `.cursor/skills/verify-ave/control-ave capture many-findings -- pytest -- tests/test_many_findings.py -q`. Exit code `0`; stdout reports `26 passed`. These tests fold a second source, check one lifecycle per ingested finding, and prove the suppressed false-positive lifecycle. The default fixture run does not prove suppression.
- **Cull contract.** Run `.cursor/skills/verify-ave/control-ave capture cull-tests -- pytest -- tests/test_cull.py -q`. Exit code `0`; stdout reports `29 passed`. Scripted sessions prove suppression, fail-open keep, one-to-one pairing, and bound-oracle override.
- **Make entry.** Run `.cursor/skills/verify-ave/control-ave make -- run`. Same four summary lines and exit `0`.
- **Proof.** Keep `artifacts/run-stub-loop/stdout.txt` and `exit_code.txt`.

## Gotchas

- The CLI never waits. `auto_approve=True` is hardcoded.
- Bare `make run` without `.venv/bin` on `PATH` uses system `python3` and fails to import `ave`.
- Langgraph prints a `LangChainPendingDeprecationWarning` on stderr. That is not a failure.
- `ready_to_merge = False` because T0/T2/re-attack are stub rungs left false. T1 (oracle flip) is real. Do not treat today's False as the invariant implementation.
- Target ref `target/dvrestaurant@d32d0997` is hardcoded. There is no CLI flag to change it. The driven finding is `ave-llm-get_order_service-get_order` at the catalog I-04 location. The FastAPI tree is vendored; `run` does not start it.
- The default path replays finder and cull fixtures and emits eight kept findings. That is not a live-model proof. `ave find` prints both stage summaries. The cull and many-finding tests prove paths that the default fixtures do not exercise.
- `ave run` stdout does not print cull counts. Read `find_stage.cull` from the Match span.
- The default fixtures suppress zero. Do not report the direct run as proof that the cull removed a false positive.
- The default PR body declares an uncaptured exchange instead of inventing HTTP. Set `AVE_PINNED_ENV=1` only through the separate [Pinned-environment run](./pinned-env-run.md) recipe. The golden comparison masks only the random run ID and timestamps; it does not normalize substantive content.
