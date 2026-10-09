from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.dependencies import CurrentUser, get_current_user
from app.modules.audit.service import audit_service
from app.modules.users.schemas import UpdateProfileRequest, UserProfile
from app.modules.users.service import user_service

router = APIRouter()


@router.get('/me', response_model=UserProfile)
def get_me(current_user: CurrentUser = Depends(get_current_user)) -> UserProfile:
    return user_service.get_me(current_user.user_id, current_user.roles)


@router.patch('/me', response_model=UserProfile)
def update_me(
    payload: UpdateProfileRequest,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
) -> UserProfile:
    try:
        profile = user_service.update_me(current_user.user_id, current_user.roles, payload.display_name)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit_service.record_request(
        request, 'user.profile_update', user=current_user, target=current_user.user_id
    )
    return profile
