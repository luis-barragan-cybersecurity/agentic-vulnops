# Pinned-environment run

`AVE_PINNED_ENV=1 ave run` asks the Python authorization pack to run the I-04 capture test in `target/dvrestaurant`'s Poetry environment. A successful capture supplies T1 and renders the request, vulnerable response, and deny in the local PR body. A failed or unavailable pinned run falls back to the hermetic oracle.

## Sub-features

- `pinned-opt-in` enables the optional runner through `AVE_PINNED_ENV`.
- `pinned-capture` records the three-part attack exchange in the generated PR body.
- `pinned-t1` takes T1 from the pinned result when that result ran.
- `pinned-fallback` takes T1 from the hermetic oracle when the pinned result did not run.

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
- **Pinned success.** Open the printed `run_record`. The Prepare span has `pinned_ran: true` and `attack_exchange_captured: true`. The Verify span has `t1_runner: pinned`. These fields prove that AVE accepted the `200` to `404` capture. They do not prove that the inner pytest process exited `0`.
- **Pinned PR body.** Open the printed `pr_body`. The opener has three `http` blocks for the request, the `200` response, and the I-04 harness's `404` response. It does not contain `Exchange not captured by this run.`
- **Fallback path.** If the target environment is unavailable, record that prerequisite and drive the command anyway. The Prepare span has `pinned_ran: false` or no pinned fields. The Verify span has `t1_runner: hermetic`, and the PR body declares that the exchange was not captured. This proves fallback, not pinned execution.
- **Pinned unit contract.** Run `.cursor/skills/verify-ave/control-ave capture pinned-env-tests -- pytest -- tests/test_pinned_env.py -q`. Exit code `0`; stdout reports `18 passed`. These tests lock skip, redaction, interpretation, and graph wiring with mocks. They do not launch Poetry.
- **Proof.** Keep `artifacts/pinned-env-run/` and the printed local PR bundle. Confirm `git status --porcelain -- README.md target` is unchanged from before the drive.

## Gotchas

- The command starts no server. A Poetry subprocess runs one `pytest` file that uses FastAPI `TestClient`.
- The presence of `target/dvrestaurant/` and `poetry` does not prove that the target environment can run. Confirm the Python version and imports before treating the path as reachable.
- A failed pinned subprocess silently falls back to the hermetic T1. The CLI does not print the pinned failure detail.
- The capture test creates a separate fixed FastAPI route for the after-response. It does not apply the generated `fix.patch` to the vendored target. Prove the captured exchange, not that AVE's prepared patch fixed the shipped route.
- The renderer accepts only a complete exchange that passes its denylist and control-character checks. A rejected exchange falls back to the uncaptured message.
