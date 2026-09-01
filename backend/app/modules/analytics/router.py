from fastapi import APIRouter, Depends

from app.core.dependencies import CurrentUser, require_roles
from app.modules.analytics.schemas import AnalyticsSummary
from app.modules.analytics.service import analytics_service

router = APIRouter()


@router.get('/summary', response_model=AnalyticsSummary)
def get_summary(
    _user: CurrentUser = Depends(
        require_roles('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')
    ),
) -> AnalyticsSummary:
    return analytics_service.summary()
