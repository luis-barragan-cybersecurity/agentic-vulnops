# Pinned-environment run

`AVE_PINNED_ENV=1 ave run` asks the Python authorization pack to run the I-04 capture test in `target/dvrestaurant`'s Poetry environment. The runner captures the original target, applies AVE's generated patch to an isolated copy, and captures that copy. A successful `200` to `404` or `403` flip supplies T1 and renders the exchange in the local PR body. A failed or unavailable requested run leaves T1 red.

## Sub-features

- `pinned-opt-in` enables the optional runner through `AVE_PINNED_ENV`.
- `pinned-capture` records the three-part attack exchange in the generated PR body.
- `pinned-patch` applies AVE's generated patch to an isolated target copy.
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
- **Pinned success.** Open the printed `run_record`. The Prepare span has `pinned_status: success`, `pinned_patch_applied: true`, and `attack_exchange_captured: true`. The Verify span has `t1_runner: pinned` and `pinned_status: success`. These fields prove that AVE applied its generated patch to an isolated copy and accepted the resulting `200` to `404` capture.
- **Pinned PR body.** Open the printed `pr_body`. The opener has three `http` blocks for the request, the `200` response, and the I-04 harness's `404` response. It does not contain `Exchange not captured by this run.`
- **Failure path.** If the target environment is unavailable, record that prerequisite and drive the command anyway. The Prepare span has `pinned_status: unavailable`. The Verify span keeps `t1_runner: pinned`, records the same status, and leaves T1 red. The PR body declares that pinned execution was requested but unavailable.
- **Pinned unit contract.** Run `.cursor/skills/verify-ave/control-ave capture pinned-env-tests -- pytest -- tests/test_pinned_env.py -q`. Exit code `0`; stdout reports `47 passed`. These tests lock explicit outcomes, patch application, redaction, subprocess isolation, and graph wiring with mocks. They do not launch Poetry.
- **Proof.** Keep `artifacts/pinned-env-run/` and the printed local PR bundle. Confirm `git status --porcelain -- README.md target` is unchanged from before the drive.

## Gotchas

- The command starts no server. A Poetry subprocess runs one `pytest` file that uses FastAPI `TestClient`.
- The presence of `target/dvrestaurant/` and `poetry` does not prove that the target environment can run. Confirm the Python version and imports before treating the path as reachable.
- A requested pinned failure never falls back to the hermetic T1. Read the run record or generated PR body for the failure status because the CLI summary does not print it.
- The runner first captures the vendored target, then copies the target, applies the generated patch inside that temporary copy, and runs the same test again. It does not modify the tracked target.
- The renderer accepts only a complete exchange that passes its denylist and control-character checks. A rejected exchange falls back to the uncaptured message.
