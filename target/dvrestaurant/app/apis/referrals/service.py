# --- AVE seeded authorization instances (GPL-3.0 §5: file modified) ---
# Changed 2026-08-29 by the AVE build (planning ticket 04). Two deliberately
# introduced BOLA (object-level) gaps for the AVE benchmark:
#   * get_referral_code_endpoint honours an attacker-supplied `username`   (I-07)
#   * get_discount_coupons honours an attacker-supplied `user_id`          (I-06)
# Both keep a valid role/identity, so a role-pattern scanner stays blind — the
# gap is a missing ownership predicate, not a missing role check. Oracles live in
# app/tests/vulns/ave_seed_*; see target/CATALOG.md. Upstream file at d32d0997
# had neither parameter.
from typing import List, Optional

from apis.auth.schemas import User
from apis.auth.utils import get_current_user
from apis.referrals.schemas import DiscountCouponRead
from apis.referrals.utils import get_referral_code
from db.models import DiscountCoupon
from db.models import User as UserModel
from db.session import get_db
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing_extensions import Annotated

router = APIRouter()

# 20% discount on the first order
# for user applying the referral code
REFERRAL_DISCOUNT_PERCENTAGE = 20


class ReferralCodeResponse(BaseModel):
    code: str


class ApplyReferralRequest(BaseModel):
    referral_code: str


class ApplyReferralResponse(BaseModel):
    message: str
    discount: float


@router.get("/referral-code", response_model=ReferralCodeResponse)
async def get_referral_code_endpoint(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    username: Optional[str] = None,
):
    """Obtains or creates a referral code for the current user."""
    # AVE-seeded BOLA (I-07): when `username` is supplied the lookup targets that
    # user instead of the caller, leaking another user's referral code. The fix is
    # to bind the lookup to `current_user` and ignore the parameter.
    if username is not None:
        db_user = db.query(UserModel).filter(UserModel.username == username).first()
    else:
        db_user = db.query(UserModel).filter(UserModel.id == current_user.id).first()
    code = get_referral_code(db, db_user)

    return ReferralCodeResponse(code=code)


@router.post("/apply-referral", response_model=ApplyReferralResponse)
async def apply_referral_code(
    request: ApplyReferralRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    """Referrals can be applied by users to receive discounts."""
    referrer = (
        db.query(UserModel)
        .filter(UserModel.referral_code == request.referral_code)
        .first()
    )

    if referrer is None:
        return ApplyReferralResponse(message="Invalid referral code", discount=0.0)

    discount_coupon = DiscountCoupon(
        user_id=current_user.id,
        referrer_user_id=referrer.id,
        discount_percentage=REFERRAL_DISCOUNT_PERCENTAGE,
    )
    db.add(discount_coupon)
    db.commit()

    return ApplyReferralResponse(
        message=f"Referral code {request.referral_code} applied successfully",
        discount=REFERRAL_DISCOUNT_PERCENTAGE,
    )


@router.get("/discount-coupons", response_model=List[DiscountCouponRead])
async def get_discount_coupons(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    user_id: Optional[int] = None,
):
    """Retrieve all discount coupons for the current user."""
    # AVE-seeded BOLA (I-06): when `user_id` is supplied the query filters on it
    # instead of the caller, exposing another user's coupons. The fix is to always
    # filter on `current_user.id` and ignore the parameter.
    target_user_id = user_id if user_id is not None else current_user.id
    coupons = (
        db.query(DiscountCoupon).filter(DiscountCoupon.user_id == target_user_id).all()
    )
    return coupons
