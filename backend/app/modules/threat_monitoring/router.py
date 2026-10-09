from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from app.core.dependencies import CurrentUser, require_roles
from app.modules.alerts.service import alerts_service
from app.modules.reports.threat_pdf import render_threat_monitoring_pdf
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


def _filter_notes(
    *,
    threats_only: bool,
    level: str | None,
    verdict: str | None,
    family: str | None,
    q: str | None,
) -> list[str]:
    notes: list[str] = []
    if threats_only:
        notes.append('Threats only (benign excluded)')
    if level:
        notes.append(f'Risk level: {level}')
    if verdict:
        notes.append(f'Verdict: {verdict}')
    if family:
        notes.append(f'Family: {family}')
    if q and q.strip():
        notes.append(f'Search: {q.strip()[:80]}')
    return notes or ['None — full detection log']


@router.get('/report')
def download_monitoring_report(
    user: CurrentUser = Depends(require_roles(*_VIEW_ROLES)),
    window: str = Query('24h', pattern='^(24h|7d|30d)$'),
    level: str | None = Query(None, pattern='^(low|medium|high)$'),
    verdict: str | None = Query(None, pattern='^(malicious|suspicious|benign)$'),
    family: str | None = Query(None, max_length=120),
    q: str | None = Query(None, max_length=200),
    threats_only: bool = Query(False),
) -> Response:
    """Full monitoring snapshot, plus detections matching the Threat Monitor filters."""
    open_alerts = len(alerts_service.list_alerts(status='open'))
    stats = ThreatStats(**threat_monitoring_service.get_stats(open_alerts=open_alerts))
    timeline = [TimelineBucket(**bucket) for bucket in threat_monitoring_service.get_timeline(window=window)]
    matched = threat_monitoring_service.list_detections(
        limit=500, level=level, verdict=verdict, family=family, q=q,
    )
    if threats_only:
        matched = [item for item in matched if item.verdict_label != 'benign']
    role = user.roles[0] if user.roles else 'Unknown'
    pdf = render_threat_monitoring_pdf(
        stats=stats,
        timeline=timeline,
        detections=matched,
        window=window,
        filter_notes=_filter_notes(
            threats_only=threats_only, level=level, verdict=verdict, family=family, q=q,
        ),
        prepared_by=user.user_id,
        role=role,
        matched_count=len(matched),
    )
    return Response(
        content=pdf,
        media_type='application/pdf',
        headers={'Content-Disposition': 'attachment; filename="threat-monitor-report.pdf"'},
    )
