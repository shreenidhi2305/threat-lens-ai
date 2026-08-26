from fastapi import APIRouter

from app.modules.auth.schemas import LoginRequest, TokenResponse
from app.modules.auth.service import auth_service

router = APIRouter()


@router.post('/login', response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    return auth_service.login(payload.email, payload.password)
