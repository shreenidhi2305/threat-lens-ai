from fastapi import APIRouter, Depends, Query

from app.core.dependencies import CurrentUser, require_roles
from app.modules.alerts.service import alerts_service
from app.modules.threat_monitoring.schemas import Detection, ThreatSnapshot
from app.modules.threat_monitoring.service import threat_monitoring_service

router = APIRouter()

_VIEW_ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator')


@router.get('/snapshot', response_model=ThreatSnapshot)
def snapshot(_user: CurrentUser = Depends(require_roles(*_VIEW_ROLES))) -> ThreatSnapshot:
    open_alerts = len(alerts_service.list_alerts(status='open'))
    return threat_monitoring_service.get_snapshot(open_alerts=open_alerts)


@router.get('/detections', response_model=list[Detection])
def detections(
    _user: CurrentUser = Depends(require_roles(*_VIEW_ROLES)),
    limit: int = Query(100, le=500),
    level: str | None = Query(None, pattern='^(low|medium|high)$'),
) -> list[Detection]:
    return threat_monitoring_service.list_detections(limit=limit, level=level)
