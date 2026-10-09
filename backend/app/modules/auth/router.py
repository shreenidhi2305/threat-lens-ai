import logging

from fastapi import APIRouter, HTTPException, Request, status

from app.modules.audit.service import audit_service
from app.modules.auth.schemas import LoginRequest, TokenResponse
from app.modules.auth.service import AuthNotConfiguredError, auth_service

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post('/login', response_model=TokenResponse)
def login(payload: LoginRequest, request: Request) -> TokenResponse:
    try:
        token = auth_service.login(payload.email, payload.password)
    except AuthNotConfiguredError as exc:
        audit_service.record_request(
            request, 'auth.login_failed', actor=payload.email, status='failure',
            detail='authentication not configured',
        )
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    except ValueError as exc:
        audit_service.record_request(
            request, 'auth.login_failed', actor=payload.email, status='failure',
            detail='invalid credentials',
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'Invalid credentials') from exc
    except Exception as exc:  # noqa: BLE001 - identity provider errors must not leak details
        logger.exception('Sign-in failed unexpectedly')
        audit_service.record_request(
            request, 'auth.login_failed', actor=payload.email, status='failure',
            detail='identity provider error',
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'Invalid credentials') from exc
    audit_service.record_request(request, 'auth.login', actor=payload.email.strip().lower())
    return token
