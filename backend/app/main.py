from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging


def create_application() -> FastAPI:
    configure_logging()
    app = FastAPI(title=settings.PROJECT_NAME, version=settings.API_VERSION)
    app.include_router(api_router, prefix=settings.API_PREFIX)

    @app.get('/health', tags=['health'])
    def health_check() -> dict[str, str]:
        return {'status': 'ok'}

    return app


app = create_application()
