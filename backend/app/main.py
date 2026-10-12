import logging
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.demo_seed import seed_demo_data
from app.core.frontend import mount_frontend
from app.core.logging import configure_logging
from app.core.metrics import metrics
from app.core.rate_limit import RateLimitMiddleware
from app.core.startup_checks import validate_settings

logger = logging.getLogger(__name__)


def _warm_up() -> None:
    """Load the ML models and compile YARA rules now instead of on the first scan."""
    try:
        from app.ml.models.registry import get_classifier, get_detector
        from app.modules.file_analysis.analyzers.yara import _compiled_rules

        get_detector()
        get_classifier()
        _compiled_rules()
    except Exception:  # noqa: BLE001 - warm-up is an optimisation, never a startup blocker
        logger.exception('Warm-up failed; models/rules will load lazily')


@asynccontextmanager
async def lifespan(_app: FastAPI):
    validate_settings()
    started = time.perf_counter()
    _warm_up()
    logger.info('Warm-up finished in %.2fs', time.perf_counter() - started)
    if settings.SEED_DEMO_DATA:
        threading.Thread(target=seed_demo_data, name='demo-seed', daemon=True).start()
    yield


def create_application() -> FastAPI:
    configure_logging()
    app = FastAPI(title=settings.PROJECT_NAME, version=settings.API_VERSION, lifespan=lifespan)

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=['*'],
        allow_headers=['*'],
    )

    @app.middleware('http')
    async def timing(request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - started
        response.headers['X-Process-Time'] = f'{elapsed:.3f}'
        slow = elapsed >= settings.SLOW_REQUEST_SECONDS
        metrics.record(response.status_code, elapsed, slow=slow)
        if slow:
            logger.warning('Slow request %s %s took %.2fs', request.method, request.url.path, elapsed)
        return response

    app.include_router(api_router, prefix=settings.API_PREFIX)

    @app.get('/health', tags=['health'])
    def health_check() -> dict[str, str]:
        return {'status': 'ok'}

    # Last, so the real routes above always win over the static-file catch-all.
    mount_frontend(app)

    return app


app = create_application()
