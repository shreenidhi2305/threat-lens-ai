from fastapi import APIRouter, Depends

from app.core.dependencies import CurrentUser, get_current_user
from app.modules.users.schemas import UserProfile
from app.modules.users.service import user_service

router = APIRouter()


@router.get('/me', response_model=UserProfile)
def get_me(current_user: CurrentUser = Depends(get_current_user)) -> UserProfile:
    return user_service.get_me(current_user.user_id)
