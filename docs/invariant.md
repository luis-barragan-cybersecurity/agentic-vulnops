# The invariant

> **No PR is ready to merge without a green verification ladder (T0 build, T1 flipped
> exploit oracle, T2 full suite, + re-attack) and a two-part decision record citing the
> `policy.yaml` version.**

A **draft** PR may exist earlier — this is how a human first sees the change at the HITL
gate (Option B). It cannot become *ready-to-merge* without the ladder and the record.

## Enforced at two boundaries — never by a prompt

1. **In-graph construction gate.** The mergeable outcome is constructed only from typed
   inputs that require the ladder result and the decision record (see
   [`ave/phases/verify.py`](../src/ave/phases/verify.py)). A model cannot "decide" a PR is
   ready; the type does.
2. **CI re-validation from the run record.** CI independently re-checks the invariant
   against the run record (see [`ave/invariant.py`](../src/ave/invariant.py) and the
   `invariant` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)), so the
   property is re-proven outside the process that produced it.

## The failure it removes

The headline failure mode is the **overconfident false-fix**: a plausible-but-wrong patch
with an unearned "fixed" claim. The invariant removes it structurally — the exploit oracle
is *flipped* (its polarity inverted) and the original attack is *re-run* against the patched
code before anything is claimed.
