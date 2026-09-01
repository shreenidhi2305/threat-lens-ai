from datetime import datetime, timedelta, timezone

from jose import jwt

from app.core.config import settings


def create_access_token(
    subject: str,
    roles: list[str] | None = None,
    expires_minutes: int | None = None,
) -> str:
    expires_delta = expires_minutes or settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
    payload = {'sub': subject, 'roles': roles or [], 'exp': expire}
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
