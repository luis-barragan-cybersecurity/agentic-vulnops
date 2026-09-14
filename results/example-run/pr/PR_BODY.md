# AVE fix: Enforce object ownership in get_order (BOLA class-level fix)

**Finding** `ave-llm-get_order_service-get_order` — object-ownership-gap at `app/apis/orders/services/get_order_service.py:get_order`
**Target** `target/dvrestaurant@d32d0997` · pack `python_authz` · policy `1.0.0`
**Selected** 1 of 8 ingested findings — highest confidence (0.9 against 0.86 for the runner-up); found by `ave:llm-finder`.
*Rank function: confidence desc → measured dependents asc (unmeasured last) → location asc → ingest order; dependents measured for 8 of 8.*

## The attack, and the deny that replaced it

> **Exchange not captured by this run.** No complete, validated HTTP request and response pair is available. The ladder below shows what this run proved; no transcript is inferred.

- Bound exploit oracle (inverted polarity): `results/runs/f4e75118b52a421d8945675a501c2eeb/bound/_ave_bound.py::test_authorization_boundary` — it *passes* by succeeding at the attack, so a fix must flip it red.
- What this run proved appears in the verification ladder below.

## Verification ladder

| Rung | Status | Evidence |
|---|---|---|
| T0 — target builds | ⬜ not green | — |
| T1 — exploit oracle flipped (green → red) | ⬜ not green | — |
| T2 — target's own suite | ⬜ not green | — |
| Re-attack — original attack replayed post-fix | ⬜ not green | — |

An unrun rung is never painted green — “⬜ not green” means the rung did not run or did not pass, and is not claimed.

**Ready to merge: no**

## Blast radius

| Dimension | Measured | Limit (policy `1.0.0`) |
|---|---|---|
| Files changed | 1 | 3 |
| Dependent call sites | 0 | 25 |
| Routes affected | 1 | 15 |

### The one fact

The AST inventory identifies get_order as the GET /orders/{order_id} route handler. A complete caller-index query found no dependent call sites in the allowlisted tree.

*How sure: **5/5** — The inventory cites target/dvrestaurant/app/apis/orders/services/get_order_service.py:11-20. The recorded reach is complete, and dependent_sites is empty.*

### Still open

| Instance | Where | Found by |
|---|---|---|
| `ave-llm-update_profile_service-update_profile` | `app/apis/auth/services/update_profile_service.py:21` | `ave:llm-finder` |
| `ave-llm-delete_menu_item_service-delete_menu_item` | `app/apis/menu/services/delete_menu_item_service.py:12` | `ave:llm-finder` |
| `ave-llm-update_menu_item_service-update_menu_item` | `app/apis/menu/services/update_menu_item_service.py:15` | `ave:llm-finder` |
| `ave-llm-get_orders_for_delivery_service-get_orders` | `app/apis/orders/services/get_orders_for_delivery_service.py:12` | `ave:llm-finder` |
| `ave-llm-service-get_discount_coupons` | `app/apis/referrals/service.py:84` | `ave:llm-finder` |
| `ave-llm-service-get_referral_code_endpoint` | `app/apis/referrals/service.py:38` | `ave:llm-finder` |
| `ave-llm-update_user_role_service-update_user_role` | `app/apis/users/services/update_user_role_service.py:12` | `ave:llm-finder` |

### Cleared

| Ruled out | How |
|---|---|
| A post-fetch ownership guard binds db_order to current_user on every path | The handler returns db_order after a fetch by order_id with no user_id comparison (target/dvrestaurant/app/apis/orders/services/get_order_service.py:11-20 — return db_order) |

### Before you merge

Runnable by the reviewer, and allowed to fail:

```bash
# expect: FAILS after this fix (inverted polarity — this test IS the attack)
cp results/runs/f4e75118b52a421d8945675a501c2eeb/bound/_ave_bound.py target/dvrestaurant/app/tests/_ave_bound.py && cd target/dvrestaurant && poetry run pytest app/tests/_ave_bound.py::test_authorization_boundary
```
```bash
# expect: green — the target's own suite (the T2 rung; the ladder above is honest about not having run it)
cd target/dvrestaurant && poetry run pytest app/tests
```

**Rings:** planned for `caller` → `pr`. This run does not execute deployment rings or enforce their stop criteria.

<details>
<summary><b>Decision record</b> (two-part: response × execution)</summary>

**Part 1 — Response decision**
- Classification: object-ownership-gap
- Disposition: **fix** · Severity: high
- Remediation: Close the whole object-ownership-gap class at app/apis/orders/services/get_order_service.py:get_order in one class-level change, not the single instance, without regressing legitimate access.
- Scope (the class removed): the whole object-ownership-gap class, not just app/apis/orders/services/get_order_service.py:get_order

**Part 2 — Execution route**
- Route: **hitl_approved** · HITL route fired: **out_of_policy_change**
- Rule matched: `fix_predicates.require_all (a fix predicate failed)`
- Blast radius: files 1 / dependents 0 / routes 1
- Ladder required: `t0_build`, `t1_exploit_oracle_flipped`, `t2_full_suite`, `reattack_clean`
- Decided by: agent at 2026-09-13T23:59:26.091034+00:00

Rationale: Fix falls outside standing preauthorization; a human must rule at the gate.

Cites: policy `1.0.0` · oracle `unknown` · ground truth `catalog.ground_truth()#ave-llm-get_order_service-get_order`

</details>

<details>
<summary><b>Patch</b></summary>

```diff
--- a/target/dvrestaurant/app/apis/orders/services/get_order_service.py
+++ b/target/dvrestaurant/app/apis/orders/services/get_order_service.py
@@ -1,6 +1,6 @@
-from apis.auth.utils import RolesBasedAuthChecker
+from apis.auth.utils import RolesBasedAuthChecker, get_current_user
 from apis.orders import schemas
-from db.models import Order, UserRole
+from db.models import Order, User, UserRole
 from db.session import get_db
 from fastapi import APIRouter, Depends, HTTPException
 from sqlalchemy.orm import Session
@@ -13,8 +13,11 @@
     order_id: int,
     db: Session = Depends(get_db),
     auth=Depends(RolesBasedAuthChecker([UserRole.CUSTOMER])),
+    current_user: User = Depends(get_current_user),
 ):
     db_order = db.query(Order).filter(Order.id == order_id).first()
     if db_order is None:
         raise HTTPException(status_code=404, detail="Order not found")
+    if db_order.user_id != current_user.id:
+        raise HTTPException(status_code=404, detail="Order not found")
     return db_order
```

</details>

---
*Generated by AVE from run `f4e75118b52a421d8945675a501c2eeb`. No fix is claimed, ever — the ladder and the record above are what “fixed” means.*
