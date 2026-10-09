from fastapi import APIRouter, Depends, Query

from app.core.dependencies import CurrentUser, require_roles
from app.modules.analytics.schemas import AnalyticsSummary
from app.modules.analytics.service import analytics_service
from app.modules.threat_monitoring.schemas import TimelineBucket
from app.modules.threat_monitoring.service import threat_monitoring_service

router = APIRouter()

# The analytics dashboard is a read-only rollup, so it is open to every role
# that can reach it in the nav (including Researcher, unlike the raw
# /threats endpoints which are analyst/SOC/admin only).
_ANALYTICS_ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')


@router.get('/summary', response_model=AnalyticsSummary)
def get_summary(
    _user: CurrentUser = Depends(require_roles(*_ANALYTICS_ROLES)),
) -> AnalyticsSummary:
    return analytics_service.summary()


@router.get('/timeline', response_model=list[TimelineBucket])
def get_timeline(
    _user: CurrentUser = Depends(require_roles(*_ANALYTICS_ROLES)),
    window: str = Query('7d', pattern='^(24h|7d|30d)$'),
) -> list[TimelineBucket]:
    return [TimelineBucket(**b) for b in threat_monitoring_service.get_timeline(window=window)]