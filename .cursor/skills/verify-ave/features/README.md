# AVE verification map

This directory is the maintained source for verifying AVE's user-facing CLI. Read the index before driving the app, then use the matching feature file as the recipe.

## Baseline preconditions

- Repo root is the checkout that contains `Makefile`, `policy.yaml`, and `src/ave/`.
- `.venv` exists and `make setup` has been run in it.
- `.cursor/skills/verify-ave/control-ave doctor` exited `0` and printed only `ok` lines on stdout. Stderr may contain a `LangChainPendingDeprecationWarning`.
- No FastAPI target needs to be running. `target/dvrestaurant/` is vendored source plus catalog, not a server you start for these proofs.
- Drive through `control-ave` so the interpreter is `.venv/bin/python`.

## Driving conventions

- Start every recipe from this baseline unless its preconditions say otherwise.
- Treat every command as literal. Keep quoted names and flags unchanged.
- Prefer `control-ave cli` and `control-ave make` over a bare `python3`.
- `ave run` and `ave eradicate` auto-approve the HITL gate. Prove a real pause with the pytest node in [HITL gate](./hitl-gate.md), not with the CLI.
- Restore nothing. The AVE demo commands should not mutate tracked files. `make baseline` is the exception: it rewrites tracked scorer artifacts, so record their pre-drive state and report any diff.
- Keep proof artifacts under `.cursor/skills/verify-ave/artifacts/`. Cleanup must not delete them.

## Proof and skip reporting

- Capture the command, stdout, stderr, and exit code, not only the last line.
- CLI proof includes the four summary fields when the command runs the graph (`human_approved`, `ready_to_merge`, `pr_ref`, and `run complete`).
- Mutation proof for `break`, `scoreboard`, `inventory`, and `find` is a clean `git status` on `README.md` and `target/`. `run` writing `results/runs/` is expected and gitignored.
- Record the feature ID and entry point used with every artifact.
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a skipped entry point as verified through a different path.
- Do not score the README results table. `make scoreboard` does not write it.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with control-ave` starts with `Preconditions:` and uses labeled bullets that pair each user action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

Keep implementation details out of the map. Name only user paths, stable handles, required state, commands, and observable proof.

## Features

- [Route inventory](./inventory.md) covers the deterministic route scan, pre-filter screens, coverage denominator, and enforced source allowlist.
- [LLM finder](./find.md) covers `ave find`, both stage summaries, offline fixture replay, and finder-boundary tests.
- [Adversarial cull](./adversarial-cull.md) covers per-finding counter-review, suppression, fail-open behavior, oracle override, and the Cleared projection.
- [Run the loop](./run-stub-loop.md) covers `ave run` / `make run`, finding attribution and head selection, cull persistence, per-finding lifecycles, auto-approve, and the local PR bundle.
- [Pinned-environment run](./pinned-env-run.md) covers the `AVE_PINNED_ENV` opt-in, generated-patch proof, captured exchange, pinned T1, and explicit failure outcomes.
- [Eradicate demo](./eradicate-demo.md) covers `break` then `run` as `ave eradicate` / `make eradicate`.
- [Scoreboard](./scoreboard.md) covers the results-table command and proves it does not edit the README.
- [HITL gate](./hitl-gate.md) covers the pause before Prepare. CLI cannot do this today.
- [Invariant check](./invariant-check.md) covers `python -m ave.invariant --check` as CI runs it.
- [Semgrep baseline](./baseline.md) covers `make baseline`, including live scanning and reproducible frozen replay.
