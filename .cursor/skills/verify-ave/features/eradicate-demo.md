# Eradicate demo

`ave eradicate` prints that the vendored catalog is already seeded, then runs the same auto-approved graph as `ave run`. It does not seed the target, open a hosted PR, or wait for a human.

## Sub-features

- `break-print` prints that the catalog already exists and writes no files under `target/`.
- `eradicate-cli` runs break then run via `ave eradicate`.
- `eradicate-make` runs the same via `make eradicate`.
- `eradicate-outcome` matches `ave run` on `human_approved`, `ready_to_merge`, and `pr_ref`.

## How to get to it (user POV)

- Run `ave break` alone (demo step 1).
- Run `ave eradicate` (break, then run).
- Run `make break` or `make eradicate`.

## Driving it with control-ave

Preconditions:

- `control-ave doctor` succeeded.
- `git status --porcelain -- README.md target` is empty, or you have recorded the dirty files so you can tell new ones apart.

- **Break only.** Seed is a print. Run `.cursor/skills/verify-ave/control-ave capture break-print -- cli -- break`. Exit code `0`. Stdout contains `break: the vendored target already carries the seeded catalog (target/CATALOG.md,` and `8 authorization instances + decoys`. `git status --porcelain -- target` is unchanged. `target/dvrestaurant/` and `target/catalog.json` already exist; break does not add them.
- **Eradicate CLI.** Run the money-shot. Run `.cursor/skills/verify-ave/control-ave capture eradicate-demo -- cli -- eradicate`. Exit code `0`.
- **Order.** Stdout contains the two break lines, then `eradicate: break then run. HITL gate auto-approves (no pause).`, then the same run summary as [Run the loop](./run-stub-loop.md): `human_approved = True`, `ready_to_merge = False`, `pr_ref` starting with `local:pr/`.
- **Run artifacts.** Open the printed `run_record` and `pr_body` paths. Apply the selection, attribution, lifecycle, and honest-readiness checks from [Run the loop](./run-stub-loop.md).
- **Make entry.** Run `.cursor/skills/verify-ave/control-ave make -- eradicate`. Same stdout shape and exit `0`.
- **Proof.** `artifacts/eradicate-demo/stdout.txt` shows break-then-run. `git status --porcelain -- README.md target` still has no new files. New writes, if any, are under `results/runs/`.

## Gotchas

- `eradicate` calls `_break` then `_run`. It does not call a third PR step. `pr_ref` is `local:pr/<run_id>` from Execute.
- Do not prove "HITL approve" from this command. It auto-approves, same as `run`.
- A dirty `target/` from some other branch is not a break side effect. Diff against the pre-command `git status`.
- `make break` only prints. The instance catalog is already in `target/CATALOG.md`. Break does not seed it.
