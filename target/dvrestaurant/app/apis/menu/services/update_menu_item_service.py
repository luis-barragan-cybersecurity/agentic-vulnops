# --- AVE seeded authorization instance (GPL-3.0 §5: file modified) ---
# Changed 2026-08-29 by the AVE build (planning ticket 04). Deliberately
# introduced BFLA (function-level) gap I-08: the role dependency on the menu
# *update* route is commented out, so any authenticated user (incl. Customer) can
# edit menu items — the same class of defect upstream left on the *delete* route
# (native Level 1). Oracle: app/tests/vulns/ave_seed_bfla_menu_update.py; see
# target/CATALOG.md. Restore the `auth=Depends(...)` line to fix.
from apis.auth.utils import RolesBasedAuthChecker, get_current_user
from apis.menu import schemas, utils
from db.models import User, UserRole
from db.session import get_db
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing_extensions import Annotated

router = APIRouter()


@router.put("/menu/{item_id}", response_model=schemas.MenuItem)
def update_menu_item(
    item_id: int,
    menu_item: schemas.MenuItemCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    # auth=Depends(RolesBasedAuthChecker([UserRole.EMPLOYEE, UserRole.CHEF])),  # AVE-seeded BFLA (I-08): checker disabled
):
    db_item = utils.update_menu_item(db, item_id, menu_item)
    return db_item
