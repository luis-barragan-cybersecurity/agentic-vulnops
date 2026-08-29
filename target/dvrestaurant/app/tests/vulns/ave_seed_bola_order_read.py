# AVE-seeded exploit oracle (added 2026-08-29, planning ticket 04).
# Instance I-04 — BOLA on GET /orders/{order_id} (latent in upstream d32d0997:
# the route carries a [CUSTOMER] role gate but no ownership check). INVERTED
# POLARITY: this test PASSES while the target is vulnerable and FAILS once the
# owner check is added. Not auto-collected — invoke by path. See target/CATALOG.md.
from db.models import Order, OrderStatus, User, UserRole


def test_bola_cross_customer_order_read(test_db, customer_client):
    """
    Note:
        GET /orders/{order_id} checks that the caller has the Customer role, but
        never checks that the order belongs to them. Any customer can read any
        other customer's order by iterating the id — a classic BOLA a role rule
        cannot see (the role check is present and passing).

    Possible fix:
        Bind the query to the caller: filter Order.user_id == current_user.id (or
        404 when the fetched order's user_id differs), as get_order_status.py does.
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
        id=500,
        user_id=99,
        status=OrderStatus.PENDING,
        delivery_address="1 Victim St",
        phone_number="999",
        final_price=42.0,
    )
    test_db.add(victim)
    test_db.add(order)
    test_db.commit()

    # caller is the fixture customer (id=3), reading victim's order (owner id=99)
    response = customer_client.get("/orders/500")
    assert response.status_code == 200
    assert response.json()["user_id"] == 99  # read someone else's order
