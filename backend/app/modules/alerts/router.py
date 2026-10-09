from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.dependencies import CurrentUser, require_roles
from app.modules.alerts.schemas import (
    Alert,
    AlertActionRequest,
    AlertStats,
    CreateIncidentRequest,
    Incident,
    UpdateIncidentRequest,
)
from app.modules.alerts.service import alerts_service
from app.modules.audit.service import audit_service

router = APIRouter()

_VIEW_ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator')
_ACT_ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator')


@router.get('/', response_model=list[Alert])
def list_alerts(
    _user: CurrentUser = Depends(require_roles(*_VIEW_ROLES)),
    status_filter: str | None = Query(None, alias='status', pattern='^(open|acknowledged|resolved)$'),
) -> list[Alert]:
    return alerts_service.list_alerts(status=status_filter)


@router.get('/stats', response_model=AlertStats)
def alert_stats(_user: CurrentUser = Depends(require_roles(*_VIEW_ROLES))) -> AlertStats:
    return alerts_service.stats()


@router.get('/incidents', response_model=list[Incident])
def list_incidents(_user: CurrentUser = Depends(require_roles(*_VIEW_ROLES))) -> list[Incident]:
    return alerts_service.list_incidents()


@router.post('/incidents', response_model=Incident, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: CreateIncidentRequest,
    request: Request,
    user: CurrentUser = Depends(require_roles(*_ACT_ROLES)),
) -> Incident:
    incident = alerts_service.create_incident(payload.alert_ids, payload.title)
    if incident is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'No valid alert ids')
    audit_service.record_request(
        request, 'incident.create', user=user, target=incident.id,
        detail=f'{len(incident.alert_ids)} alert(s): {incident.title}',
    )
    return incident


@router.patch('/incidents/{incident_id}', response_model=Incident)
def update_incident(
    incident_id: str,
    payload: UpdateIncidentRequest,
    request: Request,
    user: CurrentUser = Depends(require_roles(*_ACT_ROLES)),
) -> Incident:
    incident = alerts_service.update_incident(incident_id, payload.status)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'Incident not found')
    audit_service.record_request(
        request, 'incident.update', user=user, target=incident.id, detail=f'status -> {payload.status}'
    )
    return incident


@router.post('/{alert_id}/acknowledge', response_model=Alert)
def acknowledge(
    alert_id: str,
    request: Request,
    payload: AlertActionRequest | None = None,
    user: CurrentUser = Depends(require_roles(*_ACT_ROLES)),
) -> Alert:
    alert = alerts_service.set_status(alert_id, 'acknowledged', payload.note if payload else None)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'Alert not found')
    audit_service.record_request(request, 'alert.acknowledge', user=user, target=alert.id, detail=alert.sample_name)
    return alert


@router.post('/{alert_id}/resolve', response_model=Alert)
def resolve(
    alert_id: str,
    request: Request,
    payload: AlertActionRequest | None = None,
    user: CurrentUser = Depends(require_roles(*_ACT_ROLES)),
) -> Alert:
    alert = alerts_service.set_status(alert_id, 'resolved', payload.note if payload else None)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'Alert not found')
    audit_service.record_request(request, 'alert.resolve', user=user, target=alert.id, detail=alert.sample_name)
    return alert
