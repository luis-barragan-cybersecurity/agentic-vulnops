# Architecture

AVE is a LangGraph state machine of **seven phases**, with one human governance gate.

```
Intake -> Match -> Assess -> Decide -> [ HITL gate ] -> Prepare -> Execute -> Verify
```

| Phase | Responsibility |
|-------|----------------|
| **Intake** | Pin the target ref + policy version; open the run record. |
| **Match** | Surface candidate findings (rule + model findings, fanned in behind the adapter seam). |
| **Assess** | Retrieve-then-reason over findings (avoids caller-graph context overflow); select one to drive. |
| **Decide** | Produce the two-part decision record citing the policy version. |
| **HITL gate** | `interrupt()` before Prepare — a human approves the decision record. Structural, never a prompt. |
| **Prepare** | Build the class-level change and a draft PR. |
| **Execute** | Apply the change; open/update the PR with the blast-radius / ring view. |
| **Verify** | Run the verification ladder (T0 build, T1 flipped exploit oracle, T2 full suite, re-attack); only then mark ready-to-merge. |

## Stable core vs. the language-pack seam (D3)

The **core** — `ave.graph`, `ave.state`, `ave.records`, `ave.policy`, `ave.telemetry` —
is language- and vuln-family-neutral. Nothing in it is named `python`, `fastapi`, or
`authz`. The v1 vertical (Python/FastAPI, BOLA/BFLA) plugs in behind
[`ave.adapters`](../src/ave/adapters/README.md) — the language-pack seam, reserved but
**not designed** until the walking skeleton reveals what is genuinely Python-specific.

## Compounding exports

1. **Run-record schema** (`ave.records.run_record`) — OTel-shaped; every phase appends;
   metrics, the invariant check, and monitoring read it.
2. **`policy.yaml` shape** (`ave.policy`) — governance-as-data.
3. **Language-pack seam** (`ave.adapters`) — named, not designed.

See [`invariant.md`](./invariant.md) and [`run-record-schema.md`](./run-record-schema.md).
