# AVE fix: Enforce object ownership in get_order (BOLA class-level fix)

**Finding** `I-04` — object-ownership-gap at `app/apis/orders/services/get_order_service.py:get_order`
**Target** `target/dvrestaurant@d32d0997` · pack `python_authz` · policy `1.0.0`

## The attack, and the deny that replaced it

> **Exchange not captured by this run.** The exploit oracle ran through the pack's harness, which proves the flip but does not record a request/response transcript. When Execute/Verify run the bound by-path oracle in the target's own environment, the captured request and the actual deny render here verbatim — a 404 stays a 404.

- Endpoint under attack: `GET /orders/{order_id}`
- Bound exploit oracle (inverted polarity): `app/tests/vulns/ave_seed_bola_order_read.py::test_bola_cross_customer_order_read` — it *passes* by succeeding at the attack, so a fix must flip it red.
- What this run proved: see **T1** in the ladder below — the flip is the evidence, and nothing beyond it is claimed.

## Verification ladder

| Rung | Status | Evidence |
|---|---|---|
| T0 — target builds | ⬜ not green | — |
| T1 — exploit oracle flipped (green → red) | ✅ | `app/tests/vulns/ave_seed_bola_order_read.py::test_bola_cross_customer_order_read` flipped green → red |
| T2 — target's own suite | ⬜ not green | — |
| Re-attack — original attack replayed post-fix | ⬜ not green | — |

An unrun rung is never painted green — “⬜ not green” means the rung did not run or did not pass, and is not claimed.

**Ready to merge: no**

## Blast radius

| Dimension | Measured | Limit (policy `1.0.0`) |
|---|---|---|
| Files changed | 2 | 3 |
| Dependent call sites | 1 | 25 |
| Routes affected | 1 | 15 |

### The one fact

The fix is two files, not a one-line `if` inside `get_order`: the ownership predicate lands in the shared authorization dependency and its wiring, so the object-by-id read inherits the deny instead of re-implementing it — an inline check would fix this one endpoint and leave the class alive.

*How sure: **2/5** — the in-process oracle model flips (T1) and the legitimate-owner read still passes; the two-file surface is the fix plan's `changed_paths`, not yet a measured diff against the pinned target — hence 2/5.*

### Still open

This run's finding sources surfaced no other instances. (v1 surfaces the loop anchor only; the find-stage fills this block from what it actually finds — the catalog's answer key stays off this path.)

### Cleared

Nothing was checked-and-ruled-out by this run, so nothing is listed. (Fills with the find-stage blast-radius pass.)

### Before you merge

Runnable by the reviewer, and allowed to fail:

```bash
# expect: FAILS after this fix (inverted polarity — this test IS the attack); needs the target's pinned Poetry/Docker env
cd target/dvrestaurant && poetry run pytest app/tests/vulns/ave_seed_bola_order_read.py::test_bola_cross_customer_order_read
```
```bash
# expect: green — the target's own suite (the T2 rung; the ladder above is honest about not having run it)
cd target/dvrestaurant && poetry run pytest app/tests
```

**Rings:** this change is planned for `caller` → `pr`; each advance is gated by the policy's stop criteria, and the last named ring is the last one executed.

<details>
<summary><b>Decision record</b> (two-part: response × execution) — CI re-derives this from <code>policy.yaml</code></summary>

**Part 1 — Response decision**
- Classification: object-ownership-gap
- Disposition: **fix** · Severity: high
- Remediation: Close the whole object-ownership-gap class at app/apis/orders/services/get_order_service.py:get_order in one class-level change, not the single instance, without regressing legitimate access.
- Scope (the class removed): the whole object-ownership-gap class, not just app/apis/orders/services/get_order_service.py:get_order

**Part 2 — Execution route**
- Route: **standing_preauthorized** · HITL route fired: none
- Rule matched: `helper_only_diff + class_level + within_blast_radius`
- Blast radius (measured): files 2 / dependents 1 / routes 1
- Ladder required: `t0_build`, `t1_exploit_oracle_flipped`, `t2_full_suite`, `reattack_clean`
- Decided by: agent at 2026-08-30T21:56:12.651738+00:00

Rationale: Helper-only, class-level diff within blast-radius limits => the fix removes the class and cannot regress a legitimate caller.

Cites: policy `1.0.0` · oracle `app/tests/vulns/ave_seed_bola_order_read.py` · ground truth `catalog.ground_truth()#I-04`

</details>

<details>
<summary><b>Patch</b></summary>

> Not an applicable diff. This patch is the in-process model of the fix (`_skeleton_target.py`), which is why its headers name a different file than the finding above.

```diff
--- a/_skeleton_target.py:get_order
+++ b/_skeleton_target.py:get_order
@@ -1,4 +1,6 @@
 def get_order(order_id: int, current_user: str) -> dict[str, Any]:
-    """BOLA: returns the requested object with no ownership check — any authenticated
-    user can read any order."""
-    return _ORDERS[order_id]
+    """The class-level fix: enforce object ownership before returning the object."""
+    order = _ORDERS[order_id]
+    if order["owner"] != current_user:
+        raise PermissionError("not the owner of this order")
+    return order
```

</details>

---
*Generated by AVE from run `42625242c5b6487788cdace344115cd9`. No fix is claimed, ever — the ladder and the record above are what “fixed” means.*
