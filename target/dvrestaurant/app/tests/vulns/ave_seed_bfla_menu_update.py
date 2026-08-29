# AVE-seeded exploit oracle (added 2026-08-29, planning ticket 04).
# Instance I-08 — BFLA on PUT /menu/{item_id} (seeded diff in
# apis/menu/services/update_menu_item_service.py: the [EMPLOYEE, CHEF] role gate
# is commented out, mirroring upstream's native Level 1 defect on DELETE). INVERTED
# POLARITY: PASSES while vulnerable, FAILS once the checker is restored. Not
# auto-collected — invoke by path. See target/CATALOG.md.
from db.models import MenuItem


def test_bfla_customer_can_update_menu_item(test_db, customer_client):
    """
    Note:
        PUT /menu/{item_id} has had its RolesBasedAuthChecker([EMPLOYEE, CHEF])
        dependency commented out, so any authenticated user (including a Customer)
        can edit menu items — the privileged-function gate is missing.

    Possible fix:
        Restore auth=Depends(RolesBasedAuthChecker([EMPLOYEE, CHEF])) on the route,
        as the sibling create/update-with-gate services do.
    """
    item = MenuItem(
        name="Chicken Burrito",
        price=10.99,
        category="",
        description="",
        image_base64="",
    )
    test_db.add(item)
    test_db.commit()

    # caller is the fixture customer (Customer role) — must not be allowed to edit
    response = customer_client.put(
        f"/menu/{item.id}",
        json={"name": "Hacked Burrito", "price": 0.01, "category": ""},
    )
    assert response.status_code == 200  # customer edited a menu item
