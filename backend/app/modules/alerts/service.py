"""Alert Service: alert generation, notifications, incident tracking and SIEM forwarding.

Alerts and incidents are held in memory for fast access and, when Supabase is
configured, written through to the ``alerts`` / ``incidents`` tables and reloaded on
first use after a restart (schema: ``supabase/migrations/003`` and ``006``).
Persistence is best-effort: a database failure never blocks alerting.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import OrderedDict
from datetime import datetime, timezone

from app.core.config import settings
from app.core.runtime_settings import runtime_settings
from app.db.repositories.alerts import AlertRepository, IncidentRepository
from app.modules.alerts.notifications import send_email
from app.modules.alerts.schemas import Alert, AlertStats, Incident
from app.modules.file_analysis.schemas import AnalysisResult
from app.modules.integrations.siem import siem_forwarder
from app.modules.notifications.service import notifications_service

logger = logging.getLogger(__name__)

_LEVEL_RANK = {'low': 0, 'medium': 1, 'high': 2}
_MAX_ALERTS = 1000


def _alert_event(alert: Alert) -> dict:
    return {
        'alert_id': alert.id,
        'status': alert.status,
        'title': alert.title,
        'sample_name': alert.sample_name,
        'sample_sha256': alert.sample_sha256,
        'verdict': alert.verdict_label,
        'score': alert.verdict_score,
        'category': alert.category,
        'engine_agreement': alert.agreement,
        'incident_id': alert.incident_id,
    }


class AlertsService:
    def __init__(self) -> None:
        self._alerts: OrderedDict[str, Alert] = OrderedDict()
        self._incidents: OrderedDict[str, Incident] = OrderedDict()
        # Scans run on worker threads, so the dedupe-then-insert below must be atomic.
        self._lock = threading.RLock()
        self._alert_repo = AlertRepository()
        self._incident_repo = IncidentRepository()
        self._hydrated = False

    # --- persistence -------------------------------------------------------
    def _ensure_loaded(self) -> None:
        """Load alerts/incidents saved by a previous run (once, when Supabase is configured)."""
        if self._hydrated or not settings.supabase_configured:
            return
        with self._lock:
            if self._hydrated:
                return
            self._hydrated = True
            try:
                alert_rows = list(reversed(self._alert_repo.list(_MAX_ALERTS)))
                incident_rows = list(reversed(self._incident_repo.list()))
            except Exception:  # noqa: BLE001
                logger.exception('Could not load saved alerts; continuing with in-memory state')
                return
            for row in alert_rows:
                row = dict(row)
                if row['id'] in self._alerts:
                    continue
                try:
                    self._alerts[row['id']] = Alert.model_validate(
                        {k: v for k, v in row.items() if k in Alert.model_fields}
                    )
                except Exception:  # noqa: BLE001
                    logger.warning('Skipping unreadable saved alert %s', row.get('id'))
            for row in incident_rows:
                row = dict(row)
                if row['id'] in self._incidents:
                    continue
                try:
                    incident = Incident.model_validate(
                        {k: v for k, v in row.items() if k in Incident.model_fields}
                    )
                    incident.alert_ids = [a.id for a in self._alerts.values() if a.incident_id == incident.id]
                    self._incidents[incident.id] = incident
                except Exception:  # noqa: BLE001
                    logger.warning('Skipping unreadable saved incident %s', row.get('id'))

    def _persist_alert(self, alert: Alert) -> None:
        if not settings.supabase_configured:
            return
        row = {
            'id': alert.id,
            'detection_id': alert.detection_id,
            'incident_id': alert.incident_id,
            'severity': alert.severity,
            'status': alert.status,
            'title': alert.title,
            'sample_sha256': alert.sample_sha256,
            'sample_name': alert.sample_name,
            'verdict_label': alert.verdict_label,
            'verdict_score': alert.verdict_score,
            'category': alert.category,
            'agreement': alert.agreement,
            'notified': alert.notified,
            'note': alert.note,
            'created_by': alert.created_by,
            'created_at': alert.created_at.isoformat(),
            'resolved_at': datetime.now(timezone.utc).isoformat() if alert.status == 'resolved' else None,
        }
        try:
            self._alert_repo.upsert(row)
        except Exception:  # noqa: BLE001 - e.g. detection row missing; retry without the link
            try:
                self._alert_repo.upsert({**row, 'detection_id': None, 'created_by': None})
            except Exception:  # noqa: BLE001
                logger.warning('Could not persist alert %s; kept in memory', alert.id)

    def _persist_incident(self, incident: Incident) -> None:
        if not settings.supabase_configured:
            return
        try:
            self._incident_repo.upsert({
                'id': incident.id,
                'title': incident.title,
                'status': incident.status,
                'severity': incident.severity,
                'created_at': incident.created_at.isoformat(),
                'closed_at': incident.closed_at.isoformat() if incident.closed_at else None,
            })
        except Exception:  # noqa: BLE001
            logger.warning('Could not persist incident %s; kept in memory', incident.id)

    # --- generation --------------------------------------------------------
    def evaluate(
        self, result: AnalysisResult, detection_id: str | None = None, actor: str | None = None
    ) -> Alert | None:
        verdict = result.verdict
        if verdict is None:
            return None

        self._ensure_loaded()
        min_rank = _LEVEL_RANK.get(str(runtime_settings.get('ALERT_MIN_LEVEL')), 2)
        if _LEVEL_RANK.get(verdict.level, 0) < min_rank:
            return None

        sha = result.hashes.sha256
        severity = 'critical' if (verdict.score >= 85 or result.signature_match.matched) else 'high'
        with self._lock:
            for existing in self._alerts.values():
                if existing.sample_sha256 == sha and existing.status != 'resolved':
                    return existing  # dedupe: one live alert per sample

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
            self._alerts[alert.id] = alert
            while len(self._alerts) > _MAX_ALERTS:
                self._alerts.popitem(last=False)
        # SMTP / database / SIEM are network I/O: do them outside the lock.
        alert.notified = send_email(alert)
        self._persist_alert(alert)
        notifications_service.notify(
            category='alert',
            severity=severity,
            title=f'{severity.capitalize()} alert: {alert.title}',
            message=f'{alert.sample_name} — verdict {alert.verdict_label} ({alert.verdict_score}/100)',
            alert_id=alert.id,
            email_sent=alert.notified,
        )
        siem_forwarder.forward('alert.created', _alert_event(alert), severity=severity)
        return alert

    # --- queries ----------------------------------------------------------
    def list_alerts(self, status: str | None = None) -> list[Alert]:
        self._ensure_loaded()
        items = list(reversed(self._alerts.values()))
        if status:
            items = [a for a in items if a.status == status]
        return items

    def get(self, alert_id: str) -> Alert | None:
        self._ensure_loaded()
        return self._alerts.get(alert_id)

    def stats(self) -> AlertStats:
        self._ensure_loaded()
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
        self._ensure_loaded()
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                return None
            alert.status = status
            if note:
                alert.note = note
        self._persist_alert(alert)
        notifications_service.notify(
            category='status',
            severity='info',
            title=f'Alert {status}',
            message=f'{alert.title} ({alert.sample_name}) marked {status}' + (f' — {note}' if note else ''),
            alert_id=alert.id,
        )
        siem_forwarder.forward('alert.status_changed', _alert_event(alert), severity=alert.severity)
        return alert

    # --- incidents ------------------------------------------------------
    def create_incident(self, alert_ids: list[str], title: str | None) -> Incident | None:
        self._ensure_loaded()
        with self._lock:
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
        self._persist_incident(incident)
        for a in linked:
            self._persist_alert(a)
        notifications_service.notify(
            category='incident',
            severity=incident.severity,
            title=f'Incident opened: {incident.title}',
            message=f'{len(linked)} alert(s) grouped into this incident',
            incident_id=incident.id,
        )
        siem_forwarder.forward(
            'incident.created',
            {'incident_id': incident.id, 'title': incident.title, 'status': incident.status,
             'alert_ids': incident.alert_ids},
            severity=incident.severity,
        )
        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        self._ensure_loaded()
        return self._incidents.get(incident_id)

    def update_incident(self, incident_id: str, status: str) -> Incident | None:
        """Move an incident through open -> contained -> closed."""
        self._ensure_loaded()
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None:
                return None
            incident.status = status
            incident.closed_at = datetime.now(timezone.utc) if status == 'closed' else None
        self._persist_incident(incident)
        notifications_service.notify(
            category='incident',
            severity='info',
            title=f'Incident {status}',
            message=f'{incident.title} is now {status}',
            incident_id=incident.id,
        )
        siem_forwarder.forward(
            'incident.updated',
            {'incident_id': incident.id, 'title': incident.title, 'status': incident.status},
            severity=incident.severity,
        )
        return incident

    def list_incidents(self) -> list[Incident]:
        self._ensure_loaded()
        return list(reversed(self._incidents.values()))


alerts_service = AlertsService()
