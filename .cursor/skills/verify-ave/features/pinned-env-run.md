# Pinned-environment run

`AVE_PINNED_ENV=1 ave run` asks the Python authorization pack to prove AVE's generated I-04 patch in `target/dvrestaurant`'s Poetry environment. A successful `200` to `404` or `403` flip supplies T1 and renders the exchange in the local PR body. A failed, unavailable, or non-flipping requested run leaves T1 red.

## Sub-features

- `pinned-opt-in` enables the optional runner through `AVE_PINNED_ENV`.
- `pinned-capture` records the three-part attack exchange in the generated PR body.
- `pinned-patch` proves AVE's generated patch without changing the tracked target.
- `pinned-t1` takes T1 only from a successful pinned result.
- `pinned-failure` leaves T1 red when a requested pinned run cannot complete.

## How to get to it (user POV)

- Run `AVE_PINNED_ENV=1 ave run`.
- Run `AVE_PINNED_ENV=1 python -m ave.cli run`.
- Run `AVE_PINNED_ENV=1 make run`.
- Run `AVE_PINNED_ENV=1 ave eradicate` or `AVE_PINNED_ENV=1 make eradicate`.

## Driving it with control-ave

Preconditions:

- `control-ave doctor` succeeded for AVE's own `.venv`.
- `target/dvrestaurant/` exists.
- `poetry` is on the `PATH`.
- From `target/dvrestaurant/`, `poetry run python --version` reports Python 3.10 and `poetry run pytest app/tests/vulns/_ave_capture_bola_order_read.py -q` can import the target.

- **Pinned CLI entry.** Run `AVE_PINNED_ENV=1 .cursor/skills/verify-ave/control-ave capture pinned-env-run -- cli -- run`. Exit code `0`.
- **Outcome.** Stdout contains the normal four run summary fields. The command still reports `ready_to_merge = False` because only T1 is green.
- **Pinned success.** Open the printed `run_record`. The Prepare span has `pinned_status: success`, `pinned_patch_applied: true`, and `attack_exchange_captured: true`. The Verify span has `t1_runner: pinned` and `pinned_status: success`. These fields prove that AVE accepted the generated patch's `200` to `404` or `403` flip.
- **Pinned PR body.** Open the printed `pr_body`. It carries the selection and attribution header from [Run the loop](./run-stub-loop.md). The opener has three `http` blocks for the request, the `200` response, and the I-04 harness's `404` response. It does not contain `Exchange not captured by this run.`
- **Failure path.** If a pinned prerequisite fails, record it and drive the command anyway. A missing target interpreter produces `pinned_status: unavailable`. An interpreter that cannot run the capture can produce `pinned_status: test_failed`. The Verify span keeps `t1_runner: pinned`, records the same explicit status, and leaves T1 red. The PR body states the failure and does not invent an exchange.
- **Pinned unit contract.** Run `.cursor/skills/verify-ave/control-ave capture pinned-env-tests -- pytest -- tests/test_pinned_env.py -q`. Exit code `0`; stdout reports `53 passed`. These tests lock explicit outcomes, patch proof, redaction, and graph wiring. They do not prove the Poetry path.
- **Proof.** Keep `artifacts/pinned-env-run/` and the printed local PR bundle. Confirm `git status --porcelain -- README.md target` is unchanged from before the drive.

## Gotchas

- The command starts no server. It runs one short-lived target test and returns.
- The presence of `target/dvrestaurant/` and `poetry` does not prove that the target environment can run. Confirm the Python version and imports before treating the path as reachable.
- A requested pinned failure never falls back to the hermetic T1. Read the run record or generated PR body for the failure status because the CLI summary does not print it.
- A successful proof leaves `git status --porcelain -- target` unchanged apart from changes that were present before the command.
- The renderer accepts only a complete exchange that passes its denylist and control-character checks. A rejected exchange falls back to the uncaptured message.
