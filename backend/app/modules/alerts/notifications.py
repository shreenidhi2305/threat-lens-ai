"""Alert notification channels. Email is best-effort and never raises."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from app.core.config import settings
from app.modules.alerts.schemas import Alert

logger = logging.getLogger(__name__)


def _build_message(alert: Alert) -> EmailMessage:
    msg = EmailMessage()
    msg['Subject'] = f'[ThreatLens] {alert.severity.upper()} - {alert.title}'
    msg['From'] = settings.ALERT_EMAIL_FROM
    msg['To'] = settings.ALERT_EMAIL_TO
    msg.set_content(
        f'A {alert.severity} alert was raised by ThreatLens AI.\n\n'
        f'Sample    : {alert.sample_name}\n'
        f'SHA-256   : {alert.sample_sha256}\n'
        f'Verdict   : {alert.verdict_label} (score {alert.verdict_score}/100)\n'
        f'Category  : {alert.category or "n/a"}\n'
        f'Engines   : {alert.agreement or "n/a"}\n'
        f'Alert ID  : {alert.id}\n'
        f'Raised at : {alert.created_at.isoformat()}\n\n'
        f'Review it in the ThreatLens console.\n'
    )
    return msg


def send_email(alert: Alert) -> bool:
    """Return True if the email was handed to the SMTP server."""
    if not settings.smtp_configured:
        return False
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            if settings.SMTP_USERNAME:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(_build_message(alert))
        logger.info('Alert %s emailed to %s', alert.id, settings.ALERT_EMAIL_TO)
        return True
    except Exception:  # noqa: BLE001 - notification failure must not break alerting
        logger.exception('Failed to send alert email for %s', alert.id)
        return False
