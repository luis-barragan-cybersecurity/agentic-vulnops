# HITL gate

A fresh graph run stops before the `prepare` node until something sets `human_approved` and resumes. The CLI always auto-approves, so a user cannot see the pause from `ave run`. The observable pause proof today is the smoke test that calls `run_once(..., auto_approve=False)`.

## Sub-features

- `gate-declared` the interrupt is before `prepare`.
- `gate-pauses` a run with `auto_approve=False` has a decision record and no `pr_ref`.
- `gate-cli-skips` `ave run` does not pause for input.

## How to get to it (user POV)

- There is no CLI flag. A user running `ave run` never sits at the gate.
- CI and `make test` run `tests/test_graph_smoke.py::test_run_halts_at_the_hitl_gate_before_approval`.
- `tests/test_walking_skeleton.py::test_loop_runs_end_to_end_and_produces_a_pr` is the auto-approve resume path the CLI uses.

## Driving it with control-ave

Preconditions:

- `control-ave doctor` succeeded.
- You are proving the pause, not the auto-approve path. If you only needed auto-approve, use [Run the loop](./run-stub-loop.md) and do not mark this feature verified.

- **Pause test.** Run `.cursor/skills/verify-ave/control-ave capture hitl-gate -- pytest -- tests/test_graph_smoke.py::test_run_halts_at_the_hitl_gate_before_approval -q`. Exit code `0`. Stdout includes `1 passed`.
- **Resume test.** Run `.cursor/skills/verify-ave/control-ave pytest -- tests/test_walking_skeleton.py::test_loop_runs_end_to_end_and_produces_a_pr -q`. Exit code `0`. `1 passed`.
- **CLI does not pause.** Run `.cursor/skills/verify-ave/control-ave cli -- run`. The process returns without stdin. `human_approved = True` is already set.
- **Proof.** Keep `artifacts/hitl-gate/stdout.txt` showing the pause test passed. Do not file an `ave run` transcript as proof of this feature.

## Gotchas

- `paused_at_gate` and `run_once(auto_approve=False)` need a checkpointer. Tests pass `MemorySaver`. Compiling the graph without one runs straight through. Do not "drive" `build_graph()` with no checkpointer and call that the gate.
- Docs mention a draft PR at the interrupt. `pr_ref` is set in Execute, after Prepare. A paused run has `pr_ref is None`.
- `human_approved` on the paused state is `False` from Decide. Prepare, Execute, and Verify never read that flag. The pause is LangGraph `interrupt_before=["prepare"]`.
- Passing `make test` covers this node plus others. Name the node id in the artifact if you used the full suite, and still do not skip the pause-specific test when this feature is the claim.
- There is no `test_run_completes_after_approval_but_claims_nothing`. That name is dead. Use the walking-skeleton node above.
