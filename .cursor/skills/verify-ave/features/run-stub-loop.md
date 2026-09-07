# Run the loop

By default, `ave run` walks the seven-phase graph on the hardcoded target ref `target/dvrestaurant@d32d0997` with the hermetic I-04 oracle. It auto-approves at the HITL gate, prints a tracing span, writes a local PR bundle under `results/runs/<id>/`, and reports that nothing is ready to merge.

## Sub-features

- `run-help` lists the `run` subcommand.
- `run-cli` completes via `ave run` / `python -m ave.cli run`.
- `run-make` completes via `make run`.
- `run-claims-nothing` reports `ready_to_merge = False` and a `local:pr/` ref.
- `run-selection` attributes I-04 to `ave:pack-anchor`, records the stated rank function, and explains why the run selected it.
- `run-lifecycles` persists one open lifecycle for every finding the run surfaced.
- `run-many-contract` covers multi-source attribution, de-duplication, ranking, and unselected open findings with synthetic inputs.
- `run-pr-body` writes the locked, honest PR-body template and matches the committed example after run-specific values are normalized.

## How to get to it (user POV)

- Run `ave run` after `make setup`.
- Run `python -m ave.cli run`.
- Run `make run` from the repo root with the venv on `PATH`.

## Driving it with control-ave

Preconditions:

- `control-ave doctor` succeeded.
- Working tree on `README.md` and `target/` must stay clean. The command writes gitignored files under `results/runs/`.

- **Help.** Show subcommands. Run `.cursor/skills/verify-ave/control-ave cli -- --help`. Exit code `0`. Stdout lists `run`, `break`, `eradicate`, `scoreboard`.
- **CLI entry.** Run the loop. Run `.cursor/skills/verify-ave/control-ave capture run-stub-loop -- cli -- run`. `artifacts/run-stub-loop/exit_code.txt` is `0`.
- **Gate line.** Stdout contains `run: walking seven phases; HITL gate auto-approves (no pause).` and `run complete.`
- **Outcome.** Stdout contains `human_approved = True`, `ready_to_merge = False`, and a `pr_ref` starting with `local:pr/`.
- **Artifacts.** Stdout contains `run_record`, `pr_body`, and `patch` lines under `results/runs/<id>/`. That directory exists. `git status --porcelain -- README.md target` is empty.
- **Trace.** Stdout contains a JSON object with `"name": "ave.run"` and `"service.name": "ave"`.
- **Selection.** Open the printed `run_record` path. Match records `found: 1`, `ingested: 1`, and `sources: ["ave:pack-anchor"]`. Assess selects I-04, records `dependents_measured: 0`, and says it was the only finding ingested.
- **Lifecycles.** The run record has one I-04 lifecycle with `triaged_at` set, `verified_at: null`, and `outcome: "open"`.
- **PR body.** Open the printed `pr_body` path. Before the attack exchange, it says `Selected 1 of 1 ingested finding`, names `ave:pack-anchor`, and quotes the rank function. It then contains the attack exchange, verification ladder, four blast-radius blocks, and collapsed decision record in that order. Only T1 is green and `Ready to merge` is `no`.
- **PR-body contract.** Run `.cursor/skills/verify-ave/control-ave capture pr-body-template -- pytest -- tests/test_pr_body.py -q`. Exit code `0`; stdout reports `19 passed`. This proves the fresh renderer matches `results/example-run/pr/PR_BODY.md` after only run IDs and timestamps are normalized.
- **Many-findings contract.** Run `.cursor/skills/verify-ave/control-ave capture many-findings -- pytest -- tests/test_many_findings.py -q`. Exit code `0`; stdout reports `22 passed`. These tests use synthetic multi-source findings because the live pack still emits only I-04.
- **Make entry.** Run the Makefile verb. Run `.cursor/skills/verify-ave/control-ave make -- run`. Same four summary lines and exit `0`.
- **Proof.** Keep `artifacts/run-stub-loop/stdout.txt` and `exit_code.txt`. They show the command completed and claimed no merge.

## Gotchas

- The CLI never waits. `auto_approve=True` is hardcoded in `src/ave/cli.py`.
- Bare `make run` without `.venv/bin` on `PATH` uses system `python3` and fails to import `ave`.
- Langgraph prints a `LangChainPendingDeprecationWarning` on stderr. That is not a failure.
- `ready_to_merge = False` because T0/T2/re-attack are stub rungs left false. T1 (oracle flip) is real. Do not treat today's False as the invariant implementation.
- Target ref `target/dvrestaurant@d32d0997` is hardcoded. There is no CLI flag to change it. The loop finding is catalog id `I-04`. The FastAPI tree is vendored; `run` does not start it.
- The live path does not prove that a finder emitted several findings. It proves the one-finding I-04 shape. `tests/test_many_findings.py` proves the multi-source fold and selection contract.
- The default PR body declares an uncaptured exchange instead of inventing HTTP. Set `AVE_PINNED_ENV=1` only through the separate [Pinned-environment run](./pinned-env-run.md) recipe. The golden comparison masks only the random run ID and timestamps; it does not normalize substantive content.
