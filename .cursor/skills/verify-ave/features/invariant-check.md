# Invariant check

CI runs `python -m ave.invariant --check` as its own job. The entrypoint is real. Live runs write `results/runs/`, but `--check` does not load them. It always prints OK and exits 0.

## Sub-features

- `invariant-cli` exits 0 with the vacuous OK line.
- `invariant-ci` is the same command CI uses after `make setup`.
- `invariant-predicate` the in-memory helper rejects ready-without-record. That is tests, not the CLI.

## How to get to it (user POV)

- Run `python -m ave.invariant --check` from a setup venv.
- Push or open a PR. The `invariant` GitHub Actions job runs that command.
- Run `pytest tests/test_invariant.py` for the predicate and for `main(["--check"])`.

## Driving it with control-ave

Preconditions:

- `control-ave doctor` already ran `--check` once. Re-run it as the feature, do not cite doctor output as this proof.

- **CLI as CI.** Run `.cursor/skills/verify-ave/control-ave capture invariant-check -- invariant -- --check`. Exit code `0`. Stdout is exactly `invariant: OK (no run records to validate yet)`.
- **Predicate tests.** Run `.cursor/skills/verify-ave/control-ave pytest -- tests/test_invariant.py -q`. Exit code `0`. Five passed. `test_ready_without_decision_record_violates` is the non-vacuous case.
- **Proof.** Keep `artifacts/invariant-check/stdout.txt`. The line is the vacuous OK. Note in the proof that no records were loaded, even if `results/runs/` has files.

## Gotchas

- `violations` in `main` is a hardcoded empty list. A green job does not re-read a store.
- `invariant_holds` only requires `decision_record_present` when `ready_to_merge` is true. It does not look at the ladder flags in `policy.yaml`.
- `--check` is parsed and ignored beyond "run the check." There is no `--path` to a record file.
- Do not pass `--check` twice in a way that argparse rejects. The capture line is `invariant -- --check` so argparse on control-ave is not involved and `ave.invariant` receives `--check`.
