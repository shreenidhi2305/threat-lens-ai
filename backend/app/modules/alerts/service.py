"""Alert Service: alert generation, notifications, and incident creation.

In-memory store for now (process lifetime). Persistent schema lives in
``supabase/migrations/003_detections_and_alerts.sql``.
"""

from __future__ import annotations

import uuid
from collections import OrderedDict
from datetime import datetime, timezone

from app.core.config import settings
from app.modules.alerts.notifications import send_email
from app.modules.alerts.schemas import Alert, AlertStats, Incident
from app.modules.file_analysis.schemas import AnalysisResult
from app.modules.notifications.service import notifications_service

_LEVEL_RANK = {'low': 0, 'medium': 1, 'high': 2}
_MAX_ALERTS = 1000


class AlertsService:
    def __init__(self) -> None:
        self._alerts: OrderedDict[str, Alert] = OrderedDict()
        self._incidents: OrderedDict[str, Incident] = OrderedDict()

    # --- generation --------------------------------------------------------
    def evaluate(
        self, result: AnalysisResult, detection_id: str | None = None, actor: str | None = None
    ) -> Alert | None:
        verdict = result.verdict
        if verdict is None:
            return None

        min_rank = _LEVEL_RANK.get(settings.ALERT_MIN_LEVEL, 2)
        if _LEVEL_RANK.get(verdict.level, 0) < min_rank:
            return None

        sha = result.hashes.sha256
        for existing in self._alerts.values():
            if existing.sample_sha256 == sha and existing.status != 'resolved':
                return existing  # dedupe: one live alert per sample

        severity = 'critical' if (verdict.score >= 85 or result.signature_match.matched) else 'high'
        alert = Alert(
            id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            severity=severity,
            status='open',
            title=f'{verdict.classification}',
            sample_sha256=sha,
            sample_name=result.object_path.split('/')[-1] or result.object_path,
            verdict_label=verdict.label,
            verdict_score=verdict.score,
            category=verdict.family,
            agreement=verdict.agreement,
            detection_id=detection_id,
            created_by=actor,
        )
        alert.notified = send_email(alert)
        self._alerts[alert.id] = alert
        while len(self._alerts) > _MAX_ALERTS:
            self._alerts.popitem(last=False)
        notifications_service.notify(
            category='alert',
            severity=severity,
            title=f'{severity.capitalize()} alert: {alert.title}',
            message=f'{alert.sample_name} — verdict {alert.verdict_label} ({alert.verdict_score}/100)',
            alert_id=alert.id,
            email_sent=alert.notified,
        )
        return alert

    # --- queries ----------------------------------------------------------
    def list_alerts(self, status: str | None = None) -> list[Alert]:
        items = list(reversed(self._alerts.values()))
        if status:
            items = [a for a in items if a.status == status]
        return items

    def get(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def stats(self) -> AlertStats:
        vals = list(self._alerts.values())
        return AlertStats(
            open=sum(1 for a in vals if a.status == 'open'),
            acknowledged=sum(1 for a in vals if a.status == 'acknowledged'),
            resolved=sum(1 for a in vals if a.status == 'resolved'),
            critical_open=sum(1 for a in vals if a.status == 'open' and a.severity == 'critical'),
            notifications_enabled=settings.smtp_configured,
        )

    # --- transitions ----------------------------------------------------
    def set_status(self, alert_id: str, status: str, note: str | None = None) -> Alert | None:
        alert = self._alerts.get(alert_id)
        if alert is None:
            return None
        alert.status = status
        if note:
            alert.note = note
        notifications_service.notify(
            category='status',
            severity='info',
            title=f'Alert {status}',
            message=f'{alert.title} ({alert.sample_name}) marked {status}' + (f' — {note}' if note else ''),
            alert_id=alert.id,
        )
        return alert

    # --- incidents ------------------------------------------------------
    def create_incident(self, alert_ids: list[str], title: str | None) -> Incident | None:
        linked = [self._alerts[a] for a in alert_ids if a in self._alerts]
        if not linked:
            return None
        severity = 'critical' if any(a.severity == 'critical' for a in linked) else 'high'
        incident = Incident(
            id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            title=title or linked[0].title,
            status='open',
            severity=severity,
            alert_ids=[a.id for a in linked],
        )
        self._incidents[incident.id] = incident
        for a in linked:
            a.incident_id = incident.id
            if a.status == 'open':
                a.status = 'acknowledged'
        notifications_service.notify(
            category='incident',
            severity=incident.severity,
            title=f'Incident opened: {incident.title}',
            message=f'{len(linked)} alert(s) grouped into this incident',
            incident_id=incident.id,
        )
        return incident

    def list_incidents(self) -> list[Incident]:
        return list(reversed(self._incidents.values()))


alerts_service = AlertsService()
