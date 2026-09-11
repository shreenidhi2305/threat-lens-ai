from fastapi import APIRouter, Depends, Query

from app.core.dependencies import CurrentUser, require_roles
from app.modules.alerts.service import alerts_service
from app.modules.threat_monitoring.schemas import Detection, ThreatSnapshot, ThreatStats, TimelineBucket
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
    verdict: str | None = Query(None, pattern='^(malicious|suspicious|benign)$'),
    family: str | None = Query(None, max_length=120),
    q: str | None = Query(None, max_length=200),
) -> list[Detection]:
    # Rakshitha's logging preserved; filters are additive and optional.
    return threat_monitoring_service.list_detections(
        limit=limit, level=level, verdict=verdict, family=family, q=q
    )


@router.get('/timeline', response_model=list[TimelineBucket])
def timeline(
    _user: CurrentUser = Depends(require_roles(*_VIEW_ROLES)),
    window: str = Query('24h', pattern='^(24h|7d|30d)$'),
) -> list[TimelineBucket]:
    return [TimelineBucket(**b) for b in threat_monitoring_service.get_timeline(window=window)]


@router.get('/stats', response_model=ThreatStats)
def stats(_user: CurrentUser = Depends(require_roles(*_VIEW_ROLES))) -> ThreatStats:
    open_alerts = len(alerts_service.list_alerts(status='open'))
    return ThreatStats(**threat_monitoring_service.get_stats(open_alerts=open_alerts))


@router.get('/families', response_model=list[str])
def families(
    _user: CurrentUser = Depends(require_roles(*_VIEW_ROLES)),
) -> list[str]:
    return threat_monitoring_service.distinct_families()
