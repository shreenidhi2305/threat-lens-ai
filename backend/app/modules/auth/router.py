from fastapi import APIRouter, HTTPException, status

from app.modules.auth.schemas import LoginRequest, TokenResponse
from app.modules.auth.service import auth_service

router = APIRouter()


@router.post('/login', response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    try:
        return auth_service.login(payload.email, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials') from exc