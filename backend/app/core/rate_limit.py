"""API gateway rate limiting (sliding window, per principal).

Authenticated requests are limited per user; anonymous ones per client IP. Sign-in
attempts have their own, stricter per-IP budget to slow credential guessing.
State is in-process, which matches the single-worker deployment this project ships;
swap ``SlidingWindowLimiter`` for a Redis-backed one to share limits across workers.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from fastapi import Request
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.runtime_settings import runtime_settings

_EXEMPT_PATHS = ('/health', '/docs', '/redoc', '/openapi.json')


class SlidingWindowLimiter:
    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._calls = 0

    def check(self, key: str, limit: int, now: float | None = None) -> tuple[bool, int, int]:
        """Record a hit. Returns ``(allowed, remaining, retry_after_seconds)``."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._calls += 1
            if self._calls % 2000 == 0:
                self._prune(now)
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= limit:
                retry = max(1, int(self.window - (now - hits[0])) + 1)
                return False, 0, retry
            hits.append(now)
            return True, limit - len(hits), 0

    def _prune(self, now: float) -> None:
        for key in [k for k, h in self._hits.items() if not h or now - h[-1] >= self.window]:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def client_ip(request: Request) -> str:
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get('x-forwarded-for', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
    return request.client.host if request.client else 'unknown'


def _principal(request: Request) -> str:
    auth = request.headers.get('authorization', '')
    if auth.lower().startswith('bearer '):
        try:
            payload = jwt.decode(
                auth[7:], settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
            )
            subject = payload.get('sub')
            if subject:
                return f'user:{subject}'
        except JWTError:
            pass
    return f'ip:{client_ip(request)}'


limiter = SlidingWindowLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if (
            not settings.RATE_LIMIT_ENABLED
            or request.method == 'OPTIONS'
            or path in _EXEMPT_PATHS
            or not path.startswith(settings.API_PREFIX)  # static UI files are not rate limited
        ):
            return await call_next(request)

        if request.method == 'POST' and path.endswith('/auth/login'):
            key = f'login:{client_ip(request)}'
            limit = int(runtime_settings.get('LOGIN_RATE_LIMIT_PER_MINUTE'))
        else:
            key = _principal(request)
            limit = int(runtime_settings.get('RATE_LIMIT_PER_MINUTE'))

        allowed, remaining, retry_after = limiter.check(key, limit)
        if not allowed:
            return JSONResponse(
                {'detail': 'Rate limit exceeded. Slow down and retry shortly.'},
                status_code=429,
                headers={
                    'Retry-After': str(retry_after),
                    'X-RateLimit-Limit': str(limit),
                    'X-RateLimit-Remaining': '0',
                },
            )
        response = await call_next(request)
        response.headers['X-RateLimit-Limit'] = str(limit)
        response.headers['X-RateLimit-Remaining'] = str(remaining)
        return response
