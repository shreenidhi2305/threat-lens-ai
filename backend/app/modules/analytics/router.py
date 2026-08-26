from fastapi import APIRouter

from app.modules.analytics.schemas import AnalyticsSummary
from app.modules.analytics.service import analytics_service

router = APIRouter()


@router.get('/summary', response_model=AnalyticsSummary)
def get_summary() -> AnalyticsSummary:
    return analytics_service.summary()
