---
name: verify-ave
description: Drive AVE from the CLI and Makefile. Use when proving ave/make run, inventory, find, adversarial cull, the pinned-environment opt-in, eradicate, scoreboard, baseline, the HITL gate, the generated PR body, or python -m ave.invariant --check against this checkout.
---

# Verify AVE

AVE is a CLI. There is no web UI and no long-running server. A user runs Makefile verbs that call `python -m ave.cli`. The FastAPI fork is vendored under `target/dvrestaurant/` with a catalog at `target/catalog.json`. By default, `ave run` replays finder and adversarial-cull fixtures, drives the I-04 location through the in-process oracle, and writes a local PR bundle under `results/runs/<id>/`. `ave find` prints both fixture stages without walking the graph. `AVE_PINNED_ENV=1` runs the I-04 capture test against the vendored target and an isolated copy with AVE's generated patch applied, both through the target's Poetry interpreter. Neither path starts the target's Docker app or a long-running server. Prove what the command actually does, not what the README opening promises.

The next agent to read this has never seen the app. Commands below are literal.

## Launch

From the repo root:

```bash
python3 -m venv .venv
. .venv/bin/activate
make setup
```

Ready when `.venv/bin/python -m ave.cli --help` prints subcommands `run`, `break`, `eradicate`, `scoreboard`, `inventory`, and `find`. `make setup` is `pip install -e ".[dev]"`. Needs Python 3.11+. CI uses 3.11. This checkout also runs on 3.14.

No port. No seed data. `.env` is unused. LLM keys are not required. `ave find` and `ave run` replay recorded fixtures unless `AVE_LLM_LIVE` is set. OpenTelemetry prints a JSON span to stdout on `run` and `eradicate` because `setup_tracing` always attaches `ConsoleSpanExporter`.

Teardown of Launch is nothing. Leave `.venv` in place. `make clean` only deletes caches (`.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `build`, `dist`, egg-info, coverage). Do not run `make clean` in the middle of a proof.

## Doctor

Run this first whenever anything looks off:

```bash
.cursor/skills/verify-ave/control-ave doctor
```

Stdout must contain `ok` lines for python (the repo `.venv`), `policy_version` (the `version` string from `policy.yaml`; this checkout prints `"1.0.0"`), `hitl_gate_before=prepare`, `policy_path`, `invariant`, the six CLI subcommands, and the repo path. Doctor checks the exact invariant line internally, then prints `ok invariant`. Importing the graph may print a `LangChainPendingDeprecationWarning` on stderr; ignore it. Non-zero means this checkout is not worth driving: install is missing, `policy.yaml` did not load, or the graph constant moved.

Doctor does not start the graph. It does not prove `ready_to_merge`.

## Drive

Put `.cursor/skills/verify-ave` on `PATH` or invoke the script by path. Always go through `control-ave` so proofs use `.venv`, not a random `python3`.

```bash
.cursor/skills/verify-ave/control-ave cli -- run
.cursor/skills/verify-ave/control-ave cli -- break
.cursor/skills/verify-ave/control-ave cli -- eradicate
.cursor/skills/verify-ave/control-ave cli -- scoreboard
.cursor/skills/verify-ave/control-ave cli -- inventory
.cursor/skills/verify-ave/control-ave cli -- find
.cursor/skills/verify-ave/control-ave make -- run
.cursor/skills/verify-ave/control-ave make -- check
.cursor/skills/verify-ave/control-ave make -- baseline
.cursor/skills/verify-ave/control-ave invariant -- --check
.cursor/skills/verify-ave/control-ave pytest -- tests/test_graph_smoke.py::test_run_halts_at_the_hitl_gate_before_approval
.cursor/skills/verify-ave/control-ave pytest -- tests/test_pr_body.py
.cursor/skills/verify-ave/control-ave pytest -- tests/test_many_findings.py
.cursor/skills/verify-ave/control-ave pytest -- tests/test_code_facts.py
.cursor/skills/verify-ave/control-ave pytest -- tests/test_llm_finder.py
.cursor/skills/verify-ave/control-ave pytest -- tests/test_cull.py
.cursor/skills/verify-ave/control-ave pytest -- tests/test_retrieval_tools.py
AVE_PINNED_ENV=1 .cursor/skills/verify-ave/control-ave capture pinned-env-run -- cli -- run
```

`make PYTHON=.venv/bin/python <target>` is the same as `control-ave make -- <target>`. Bare `make run` after `source .venv/bin/activate` is the README path. Without the venv on `PATH`, `PYTHON ?= python3` hits the system interpreter and `ave` is missing.

Stable handles:

- CLI subcommand names: `run`, `break`, `eradicate`, `scoreboard`, `inventory`, `find`
- Inventory summary `inventory: examined 18 of 27 handlers.`
- Inventory screen counts `examine 15, cheap 3, dropped 9`
- Inventory contract node `tests/test_code_facts.py` (21 tests)
- Find summary `find: examined 18 of 27 handlers.`
- Finder summary `finder: 8 accepted, 7 finder-cleared, 0 rejected, 0 exhausted`
- Cull summary `adversarial-cull: 8 reviewed, 8 kept, 0 suppressed, 0 fail-open`
- Finder contract node `tests/test_llm_finder.py` (19 tests)
- Cull contract node `tests/test_cull.py` (29 tests)
- Shared retrieval contract node `tests/test_retrieval_tools.py` (5 tests)
- Summary lines from `ave run`: `human_approved = True`, `ready_to_merge = False`, `pr_ref` starting with `local:pr/`
- Loop finding id `ave-llm-get_order_service-get_order` (catalog location I-04; the CLI does not print I-04)
- HITL node name `prepare` (`HITL_GATE_BEFORE`)
- Invariant line `invariant: OK (no run records to validate yet)` (CLI still does not load `results/runs/`)
- Pause pytest node `tests/test_graph_smoke.py::test_run_halts_at_the_hitl_gate_before_approval`
- Resume pytest node `tests/test_walking_skeleton.py::test_loop_runs_end_to_end_and_produces_a_pr`
- PR-body contract node `tests/test_pr_body.py` (24 tests; golden comparison normalizes only run IDs and timestamps)
- Finding fan-in contract node `tests/test_many_findings.py` (26 tests; synthetic inputs cover attribution, de-duplication, ranking, open lifecycles, and suppressed false positives)
- Pinned-run contract node `tests/test_pinned_env.py` (53 tests)
- Pinned opt-in environment variable `AVE_PINNED_ENV`
- Baseline heading `AVE role-pattern Semgrep baseline — score vs target catalog`
- Baseline class-aware BOLA line `BOLA  recall : 0%  (0/4)`

The CLI always calls `run_once(..., auto_approve=True)`. There is no flag to pause. To prove the gate actually stops, use the pytest node above (or `run_once(..., auto_approve=False)` in that test). Do not treat a stdout string about the HITL gate as proof of a pause. The process does not wait for a human.

Read `.cursor/skills/verify-ave/features/README.md` before picking an entry point. A proof that only runs `ave run` does not cover inventory, find, eradicate, scoreboard, baseline, the gate, or the invariant job.

## Evidence

Write under `.cursor/skills/verify-ave/artifacts/<feature-id>/`. Capture keeps those files when you clean up processes.

```bash
.cursor/skills/verify-ave/control-ave capture run-stub-loop -- cli -- run
```

That writes `command.txt`, `stdout.txt`, `stderr.txt`, `exit_code.txt` in `artifacts/run-stub-loop/`.

Proof standards:

- Drive `ave` / `make` / the pytest node named in the feature file. Do not set `AVEState` fields in a scratch script and call that a user proof.
- Capture the command, stdout, stderr, and exit code. For `run` and `eradicate`, the four summary lines are the user-visible result. The OTel JSON blob is a side effect of tracing, not the product.
- `inventory` parses the allowlisted target application as text, prints one screen per route handler, and writes no code-facts file. Confirm the summary, the 27 handler lines, and a clean `README.md` / `target/`.
- Check side effects, not slogans. `break` prints that the catalog is already seeded and writes nothing under `target/`. `scoreboard` prints a ticket-05 stub and does not edit the README. `run` / `eradicate` write gitignored files under `results/runs/<id>/`. Confirm `git -C <repo> status --porcelain -- README.md target` stays empty.
- The generated PR body is a product artifact. Inspect the path printed by `run`; it says `Selected 1 of 8 ingested findings`, names `ave:llm-finder`, quotes the rank function, keeps only T1 green, and reports readiness `no`. Its Cleared table contains one ruled-out ownership-guard hypothesis and explains the missing `user_id` comparison with a source citation. The default run declares an uncaptured exchange. A successful pinned run renders three `http` blocks. Use `tests/test_pr_body.py` for the locked section order and committed golden comparison.
- The default pack emits eight kept findings from fixture replay. Inspect the run record for Match `found: 8`, `ingested: 8`, `suppressed: 0`, and `sources: ["ave:llm-finder"]`. Under `find_stage.cull`, verify `reviewed: 8`, `kept: 8`, `suppressed: 0`, `fail_open: 0`, and `bound_oracle_overrides: 0`. Assess drives `ave-llm-get_order_service-get_order` and records the other seven as deferred. All eight default lifecycles stay `open`. Only the driven finding has `triaged_at` set. Use `tests/test_many_findings.py` for the suppressed false-positive lifecycle, `tests/test_cull.py` for suppression and fail-open behavior, and `tests/test_llm_finder.py` for fixture recall. Do not report these results as a live-model run.
- An accepted pinned capture has `pinned_status: success`, `pinned_patch_applied: true`, and `attack_exchange_captured: true` in the Prepare span. Verify has `t1_runner: pinned` and `pinned_status: success`. These fields prove that AVE ran the same capture test against the original target and an isolated copy after applying the generated patch. The tracked target remains unchanged.
- A requested pinned failure records its explicit `pinned_status`, leaves T1 red, and keeps `t1_runner: pinned`. It never falls back to the hermetic result. Treat `not_flipped`, `unavailable`, `launch_failed`, `patch_failed`, `test_failed`, `malformed`, and `unsafe_capture` as failed pinned proof.
- `make baseline` is a separate pattern-scanner comparator. It may run live Semgrep and refresh `semgrep-findings.json`, or replay that committed file when Semgrep is unavailable; both paths rewrite `results.json`. `control-ave` keeps Semgrep's log and settings under this skill's ignored artifacts directory so a sandboxed drive does not need write access to `~/.semgrep`. Record the source line and pre-drive status of `evals/baseline/semgrep/`.
- `python -m ave.invariant --check` still prints the vacuous OK even after live runs have written records. Record the exact stdout. Do not report it as "the invariant held over run records."
- `make eval` (promptfoo) is a secondary surface. It is not in the first feature map. Skip it unless you are extending the map. It needs network for `npx`.

Stderr will usually contain `LangChainPendingDeprecationWarning` from langgraph. Ignore it. The exit code and the summary lines are the signal.

## Cleanup

Each Drive already exited. There is nothing to kill.

Do not `pkill -f ave`. Do not delete `.venv`. Do not delete `.cursor/skills/verify-ave/artifacts/`. Do not `make clean` unless you intend to drop caches after the proof is saved.

`git checkout --` is not part of verification cleanup. Tracked files under `README.md` and `target/` should stay clean. If they did not, that is a failed proof, not something to sweep. Live `results/runs/` is gitignored.

Two `ave run` processes can overlap. There is no port and no data directory. Isolation is per-process `MemorySaver` + a random `thread_id`. Do not invent a shared profile, and do not refuse a second CLI run.

## Helpers

`control-ave` is executable. From the repo root:

```bash
chmod +x .cursor/skills/verify-ave/control-ave
.cursor/skills/verify-ave/control-ave doctor
.cursor/skills/verify-ave/control-ave capture run-stub-loop -- cli -- run
```

Subcommands: `doctor`, `cli`, `make`, `pytest`, `invariant`, `capture`. Unknown names exit 1. `capture` rewrites `cli`/`make`/`pytest`/`invariant`/`doctor` to this same script so you do not have to pass the path twice.
