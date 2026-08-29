# AVE-seeded exploit oracle (added 2026-08-29, planning ticket 04).
# Instance I-05 — BFLA on GET /delivery/orders (latent in upstream d32d0997: the
# hidden "delivery integration" route has no auth dependency at all). INVERTED
# POLARITY: PASSES while vulnerable, FAILS once an auth/role gate is added. Not
# auto-collected — invoke by path. See target/CATALOG.md.
from db.models import Order, OrderStatus, User, UserRole


def test_bfla_unauthenticated_delivery_orders(test_db, anon_client):
    """
    Note:
        GET /delivery/orders is excluded from the OpenAPI schema
        (include_in_schema=False) but is still routed and carries NO
        authentication or role dependency. An unauthenticated caller who knows the
        path can enumerate every order in the system.

    Possible fix:
        Attach a mandatory auth dependency (e.g. an EMPLOYEE/CHEF role gate, or a
        service credential) at the route or router level.
    """
    victim = User(
        id=99,
        username="victim",
        password="x",
        first_name="Victim",
        last_name="",
        phone_number="999",
        role=UserRole.CUSTOMER,
    )
    order = Order(
        id=501,
        user_id=99,
        status=OrderStatus.PENDING,
        delivery_address="1 Victim St",
        phone_number="999",
        final_price=42.0,
    )
    test_db.add(victim)
    test_db.add(order)
    test_db.commit()

    # no credentials at all
    response = anon_client.get("/delivery/orders")
    assert response.status_code == 200
    assert len(response.json()) >= 1  # anon read the full order feed
