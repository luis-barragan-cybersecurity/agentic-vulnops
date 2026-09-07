# GPL-3.0 §5 notice: this file is not upstream-verbatim. Modified from the pinned
# upstream tree (d32d0997) by the AVE project on 2026-08-29; notice revised 2026-09-06.
# Licensing and provenance: target/README.md.
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
    # auth=Depends(RolesBasedAuthChecker([UserRole.EMPLOYEE, UserRole.CHEF])),
):
    db_item = utils.update_menu_item(db, item_id, menu_item)
    return db_item
