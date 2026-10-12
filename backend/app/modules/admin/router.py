"""Administrator-only endpoints (the Administrator role in the spec).

Manage users and roles, configure platform settings and security policies, manage
integrations, monitor platform activity, and manage the deployed ML models.
"""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response

from app.core.dependencies import CurrentUser, require_roles
from app.core.runtime_settings import runtime_settings
from app.ml.models.registry import registry_status, reload_models
from app.modules.admin.schemas import (
    IntegrationStatus,
    IntegrationTestResult,
    PlatformOverview,
    SettingsUpdateRequest,
)
from app.modules.admin.service import admin_service
from app.modules.alerts.notifications import send_test_email
from app.modules.audit.schemas import AuditEvent
from app.modules.audit.service import audit_service
from app.modules.integrations.siem import siem_forwarder
from app.modules.model_management.schemas import FeedbackSummary
from app.modules.model_management.service import feedback_service
from app.modules.users.schemas import ManagedUser, RoleChangeRequest
from app.modules.users.service import LastAdministratorError, UserNotFoundError, user_service

router = APIRouter()

_ADMIN = require_roles('Administrator')


# --- platform monitor ----------------------------------------------------------
@router.get('/overview', response_model=PlatformOverview)
def overview(_user: CurrentUser = Depends(_ADMIN)) -> PlatformOverview:
    return admin_service.overview()


# --- users and roles -----------------------------------------------------------
@router.get('/users', response_model=list[ManagedUser])
def list_users(_user: CurrentUser = Depends(_ADMIN)) -> list[ManagedUser]:
    return user_service.list_users()


@router.patch('/users/{user_id}/role', response_model=ManagedUser)
def change_role(
    user_id: str,
    payload: RoleChangeRequest,
    request: Request,
    user: CurrentUser = Depends(_ADMIN),
) -> ManagedUser:
    if user_id.lower() == user.user_id.lower():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'You cannot change your own role')
    previous = next((u.role for u in user_service.list_users() if u.id == user_id), None)
    try:
        updated = user_service.set_role(user_id, payload.role)
    except UserNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'User not found') from exc
    except LastAdministratorError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit_service.record_request(
        request, 'user.role_change', user=user, target=updated.email,
        detail=f'{previous} -> {updated.role}',
    )
    return updated


# --- settings and security policies --------------------------------------------
@router.get('/settings')
def get_settings(_user: CurrentUser = Depends(_ADMIN)) -> dict:
    return {'fields': runtime_settings.describe()}


@router.put('/settings')
def update_settings(
    payload: SettingsUpdateRequest,
    request: Request,
    user: CurrentUser = Depends(_ADMIN),
) -> dict:
    try:
        applied = runtime_settings.update(payload.values)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if applied:
        audit_service.record_request(
            request, 'settings.update', user=user,
            detail=', '.join(f'{k}={v}' for k, v in applied.items()),
        )
    return {'applied': applied, 'fields': runtime_settings.describe()}


@router.post('/settings/reset')
def reset_settings(request: Request, user: CurrentUser = Depends(_ADMIN)) -> dict:
    runtime_settings.reset()
    audit_service.record_request(request, 'settings.reset', user=user)
    return {'fields': runtime_settings.describe()}


# --- integrations --------------------------------------------------------------
@router.get('/integrations', response_model=list[IntegrationStatus])
def integrations(_user: CurrentUser = Depends(_ADMIN)) -> list[IntegrationStatus]:
    return admin_service.integrations()


@router.post('/integrations/{integration_id}/test', response_model=IntegrationTestResult)
def test_integration(
    integration_id: str,
    request: Request,
    user: CurrentUser = Depends(_ADMIN),
) -> IntegrationTestResult:
    if integration_id == 'siem':
        outcome = siem_forwarder.send_test()
    elif integration_id == 'email':
        ok, error = send_test_email()
        outcome = {'ok': ok, 'error': error}
    else:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'This integration cannot be tested')
    audit_service.record_request(
        request, 'integration.test', user=user, target=integration_id,
        status='success' if outcome['ok'] else 'failure', detail=outcome['error'],
    )
    return IntegrationTestResult(**outcome)


# --- activity log --------------------------------------------------------------
@router.get('/audit', response_model=list[AuditEvent])
def audit_log(
    _user: CurrentUser = Depends(_ADMIN),
    limit: int = Query(100, ge=1, le=1000),
    action: str | None = Query(None, max_length=60),
    actor: str | None = Query(None, max_length=120),
    q: str | None = Query(None, max_length=120),
) -> list[AuditEvent]:
    return audit_service.list_events(limit=limit, action=action, actor=actor, q=q)


@router.get('/audit/export.csv')
def export_audit(request: Request, user: CurrentUser = Depends(_ADMIN)) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(['at', 'actor', 'role', 'action', 'target', 'detail', 'status', 'ip'])
    for e in audit_service.list_events(limit=5000):
        writer.writerow([e.at.isoformat(), e.actor or '', e.role or '', e.action, e.target or '',
                         e.detail or '', e.status, e.ip or ''])
    audit_service.record_request(request, 'audit.export', user=user)
    return Response(
        content=buffer.getvalue(),
        media_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename="audit-log.csv"'},
    )


# --- ML model management -------------------------------------------------------
@router.get('/models')
def models(_user: CurrentUser = Depends(_ADMIN)) -> dict:
    summary: FeedbackSummary = feedback_service.summary()
    return {'registry': registry_status(), 'feedback': summary.model_dump()}


@router.post('/models/reload')
def reload_model_registry(request: Request, user: CurrentUser = Depends(_ADMIN)) -> dict:
    """Hot-swap the model artifacts on disk without restarting the API."""
    reload_models()
    status_after = registry_status()
    audit_service.record_request(
        request, 'model.reload', user=user,
        detail=(status_after.get('detector') or {}).get('version') or 'no detector loaded',
    )
    return {'registry': status_after}
