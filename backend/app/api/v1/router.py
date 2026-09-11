from fastapi import APIRouter

from app.modules.alerts.router import router as alerts_router
from app.modules.analytics.router import router as analytics_router
from app.modules.auth.router import router as auth_router
from app.modules.file_analysis.router import router as file_analysis_router
from app.modules.malware_classification.router import router as malware_router
from app.modules.reports.router import router as reports_router
from app.modules.threat_monitoring.router import router as threats_router
from app.modules.users.router import router as users_router

api_router = APIRouter()

api_router.include_router(auth_router, prefix='/auth', tags=['auth'])
api_router.include_router(users_router, prefix='/users', tags=['users'])
api_router.include_router(file_analysis_router, prefix='/files', tags=['files'])
api_router.include_router(file_analysis_router, prefix='/analysis', tags=['analysis'])
api_router.include_router(malware_router, prefix='/malware', tags=['malware'])
api_router.include_router(threats_router, prefix='/threats', tags=['threats'])
api_router.include_router(alerts_router, prefix='/alerts', tags=['alerts'])
api_router.include_router(analytics_router, prefix='/analytics', tags=['analytics'])
api_router.include_router(reports_router, prefix='/reports', tags=['reports'])
