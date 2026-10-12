"""Serve the built React app from the API process.

Used for single-container deployments (one image, one port), where there is no separate web
server. Only active when ``SERVE_FRONTEND_DIR`` points at a build containing ``index.html``.
Real API routes, ``/health`` and ``/docs`` are registered first and always win; this catch-all
only answers what is left (static files, and ``index.html`` for client-side routes).
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from app.core.config import settings

logger = logging.getLogger(__name__)

_CSP = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors {ancestors}"
)


def security_headers() -> dict[str, str]:
    ancestors = settings.FRAME_ANCESTORS.strip() or "'none'"
    headers = {
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Content-Security-Policy': _CSP.format(ancestors=ancestors),
    }
    if ancestors == "'none'":
        headers['X-Frame-Options'] = 'DENY'
    return headers


def mount_frontend(app: FastAPI) -> bool:
    """Add the static-file / SPA catch-all. Returns True if the UI is being served."""
    if not settings.SERVE_FRONTEND_DIR:
        return False
    root = Path(settings.SERVE_FRONTEND_DIR).resolve()
    index = root / 'index.html'
    if not index.is_file():
        logger.warning('SERVE_FRONTEND_DIR=%s has no index.html; not serving the UI', root)
        return False

    headers = security_headers()

    @app.get('/{full_path:path}', include_in_schema=False)
    def spa(full_path: str) -> FileResponse:
        if full_path == 'api' or full_path.startswith('api/'):
            raise HTTPException(404, 'Not Found')
        if full_path:
            target = (root / full_path).resolve()
            if root in target.parents and target.is_file():
                hashed = full_path.startswith('assets/')
                cache = 'public, max-age=31536000, immutable' if hashed else 'no-cache'
                return FileResponse(target, headers={**headers, 'Cache-Control': cache})
        # client-side routes (/alerts, /admin, ...) fall back to the app shell
        return FileResponse(index, headers={**headers, 'Cache-Control': 'no-cache'})

    logger.info('Serving the UI from %s', root)
    return True
