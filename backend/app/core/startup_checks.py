"""Startup safety checks. In production, unsafe configuration stops the app from booting."""

from __future__ import annotations

import logging

from app.core.config import Settings
from app.core.config import settings as default_settings

logger = logging.getLogger(__name__)

_UNSAFE_SECRETS = {'', 'change-me', 'changeme', 'secret'}


def find_problems(cfg: Settings) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)`` for the given settings."""
    errors: list[str] = []
    warnings: list[str] = []

    weak_secret = (
        cfg.JWT_SECRET_KEY.strip().lower() in _UNSAFE_SECRETS or len(cfg.JWT_SECRET_KEY) < 32
    )
    if weak_secret:
        (errors if cfg.is_production else warnings).append(
            'JWT_SECRET_KEY is the default or shorter than 32 characters; '
            'anyone could forge sign-in tokens.'
        )
    if not cfg.supabase_configured:
        if cfg.dev_login_enabled and cfg.dev_login_password_required:
            if cfg.is_production and len(cfg.DEV_LOGIN_PASSWORD) < 12:
                errors.append('DEV_LOGIN_PASSWORD must be at least 12 characters.')
            warnings.append(
                'Demo mode: no identity provider is configured, so everyone signs in with the shared '
                'DEV_LOGIN_PASSWORD. Do not use this with real data.'
            )
        elif cfg.dev_login_enabled:
            (errors if cfg.is_production else warnings).append(
                'No identity provider is configured, so the dev login '
                '(any email, any password) is active.'
                + (' Set DEV_LOGIN_PASSWORD to gate a demo deployment.' if cfg.is_production else '')
            )
        else:
            errors.append(
                'No identity provider is configured (set SUPABASE_URL and SUPABASE_SERVICE_KEY); '
                'nobody would be able to sign in.'
            )
    if cfg.is_production:
        origins = cfg.cors_origins
        # Behind the bundled nginx proxy the UI and API share one origin, so CORS is irrelevant.
        if not cfg.TRUST_PROXY_HEADERS and (
            not origins or all('localhost' in o or '127.0.0.1' in o for o in origins)
        ):
            warnings.append(
                'CORS_ALLOW_ORIGINS only lists localhost; the deployed frontend will be blocked.'
            )
        if not cfg.RATE_LIMIT_ENABLED:
            warnings.append('Rate limiting is disabled.')
    return errors, warnings


def validate_settings(cfg: Settings | None = None) -> None:
    cfg = cfg or default_settings
    errors, warnings = find_problems(cfg)
    for message in warnings:
        logger.warning('Config warning: %s', message)
    if errors:
        for message in errors:
            logger.error('Config error: %s', message)
        raise RuntimeError(
            'Refusing to start in production with unsafe configuration: ' + ' | '.join(errors)
        )
