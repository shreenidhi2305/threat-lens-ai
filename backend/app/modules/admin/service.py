"""Administrator console: platform monitor, integrations, settings and model management."""

from __future__ import annotations

from urllib.parse import urlparse

from app.core.config import settings
from app.core.metrics import metrics
from app.core.startup_checks import find_problems
from app.ml.models.registry import registry_status
from app.modules.admin.schemas import IntegrationStatus, PlatformOverview
from app.modules.alerts.service import alerts_service
from app.modules.audit.service import audit_service
from app.modules.integrations.siem import siem_forwarder
from app.modules.notifications.service import notifications_service
from app.modules.reports.service import reports_service
from app.modules.threat_monitoring.service import threat_monitoring_service
from app.modules.users.service import user_service


def _host(url: str) -> str | None:
    try:
        return urlparse(url).netloc or None
    except ValueError:
        return None


class AdminService:
    def overview(self) -> PlatformOverview:
        errors, warnings = find_problems(settings)
        snapshot = threat_monitoring_service.get_snapshot(open_alerts=len(alerts_service.list_alerts('open')))
        return PlatformOverview(
            version=settings.API_VERSION,
            environment=settings.APP_ENV,
            uptime_seconds=metrics.snapshot()['uptime_seconds'],
            persistence='supabase' if settings.supabase_configured else 'in-memory',
            auth_mode='supabase' if settings.supabase_configured else 'dev-login',
            requests=metrics.snapshot(),
            totals={
                'users': len(user_service.list_users()),
                'detections': snapshot.total_detections,
                'malicious': snapshot.malicious,
                'open_alerts': snapshot.open_alerts,
                'incidents': len(alerts_service.list_incidents()),
                'reports': len(reports_service.list_report_history(limit=1000)),
                'unread_notifications': notifications_service.counts().unread,
            },
            models=registry_status(),
            audit_actions=audit_service.counts_by_action(),
            warnings=errors + warnings,
        )

    def integrations(self) -> list[IntegrationStatus]:
        siem = siem_forwarder.status()
        return [
            IntegrationStatus(
                id='virustotal',
                name='VirusTotal',
                description='Threat-intelligence hash lookups on every scan (the file is never uploaded).',
                configured=settings.virustotal_configured,
                destination='virustotal.com' if settings.virustotal_configured else None,
                detail=None if settings.virustotal_configured else 'Set VIRUSTOTAL_API_KEY to enable.',
            ),
            IntegrationStatus(
                id='email',
                name='Email (SMTP)',
                description='Emails alert details to the SOC distribution address.',
                configured=settings.smtp_configured,
                destination=_host(f'//{settings.SMTP_HOST}') if settings.smtp_configured else None,
                detail=None if settings.smtp_configured else 'Set SMTP_HOST and ALERT_EMAIL_TO to enable.',
                testable=True,
            ),
            IntegrationStatus(
                id='siem',
                name='SIEM / SOAR webhook',
                description='Forwards alerts and incidents as signed JSON events to a SIEM or SOAR playbook.',
                configured=siem['configured'],
                healthy=None if not siem['configured'] else (siem['last_error'] is None),
                destination=_host(settings.SIEM_WEBHOOK_URL) if siem['configured'] else None,
                detail=siem['last_error'] if siem['configured'] else 'Set SIEM_WEBHOOK_URL to enable.',
                testable=True,
                stats={k: siem[k] for k in ('sent', 'failed', 'last_status', 'last_event_at', 'signed')},
            ),
            IntegrationStatus(
                id='supabase',
                name='Supabase (PostgreSQL + Storage)',
                description='Users, roles, detections, alerts, reports, audit log and uploaded samples.',
                configured=settings.supabase_configured,
                destination=_host(settings.SUPABASE_URL) if settings.supabase_configured else None,
                detail=None if settings.supabase_configured
                else 'Not configured: running with in-memory data and the local dev login.',
            ),
        ]


admin_service = AdminService()
