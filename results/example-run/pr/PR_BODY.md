# AVE fix: Enforce object ownership in get_order (BOLA class-level fix)

**Finding** `bola-order-owner` — object-ownership-gap (BOLA) at `ave.adapters.python_authz._skeleton_target:get_order_vulnerable`
**Target** `skeleton://python_authz/bola-order-owner` · pack `python_authz` · policy `0`

## Why (decision record)
Class-level ownership guard removes the object-ownership-gap at ave.adapters.python_authz._skeleton_target:get_order_vulnerable (fixes the whole class, not one call site).
_Authorized by:_ helper-only diff within blast-radius limits; verification ladder required

## Blast radius
- changed symbol: `get_order`
- callers: route:GET /orders/{order_id}
- rings: caller, pr

## Patch
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

## Verification ladder
- [x] T0 build
- [x] T1 exploit oracle flipped
- [x] T2 full suite
- [x] re-attack clean

**Ready to merge: yes**
