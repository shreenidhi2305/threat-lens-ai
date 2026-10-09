"""In-app notification feed.

Every alert, alert-status change, incident, and generated report raised
elsewhere in the platform is mirrored here as a persisted, readable/
dismissible notification. Supabase-backed when configured, with an
in-memory ring buffer as the local-dev store and fallback, matching the
pattern used by ``ThreatMonitoringService``.
"""

from __future__ import annotations

import uuid
from collections import deque
from datetime import datetime, timezone

from app.core.config import settings
from app.db.repositories.notifications import NotificationRepository
from app.modules.notifications.schemas import Notification, NotificationCounts

_MAX_LOG = 1000


class NotificationsService:
    def __init__(self) -> None:
        self._log: deque[Notification] = deque(maxlen=_MAX_LOG)
        self._repository = NotificationRepository()

    def notify(
        self,
        *,
        category: str,
        severity: str,
        title: str,
        message: str,
        alert_id: str | None = None,
        incident_id: str | None = None,
        report_id: str | None = None,
        email_sent: bool = False,
    ) -> Notification:
        notification = Notification(
            id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            category=category,
            severity=severity,
            title=title,
            message=message,
            alert_id=alert_id,
            incident_id=incident_id,
            report_id=report_id,
            email_sent=email_sent,
        )
        self._log.appendleft(notification)
        self._persist(notification)
        return notification

    def _persist(self, notification: Notification) -> None:
        if not settings.supabase_configured:
            return
        try:
            self._repository.create({
                'id': notification.id,
                'category': notification.category,
                'severity': notification.severity,
                'title': notification.title,
                'message': notification.message,
                'alert_id': notification.alert_id,
                'incident_id': notification.incident_id,
                'report_id': notification.report_id,
                'read': notification.read,
                'email_sent': notification.email_sent,
                'created_at': notification.created_at,
            })
        except Exception:
            # Keep the notification in memory if Supabase is unavailable.
            pass

    def _all(self) -> list[Notification]:
        if settings.supabase_configured:
            try:
                rows = self._repository.list(limit=_MAX_LOG)
                return [Notification.model_validate(dict(row)) for row in rows]
            except Exception:
                pass  # fall back to the in-memory log below
        return list(self._log)

    def list_notifications(self, unread_only: bool = False, limit: int = 100) -> list[Notification]:
        items = self._all()
        if unread_only:
            items = [n for n in items if not n.read]
        return items[:limit]

    def counts(self) -> NotificationCounts:
        items = self._all()
        return NotificationCounts(unread=sum(1 for n in items if not n.read), total=len(items))

    def mark_read(self, notification_id: str) -> Notification | None:
        for notification in self._log:
            if notification.id == notification_id:
                notification.read = True
                break
        else:
            return None
        if settings.supabase_configured:
            try:
                self._repository.mark_read(notification_id)
            except Exception:
                pass
        return notification

    def mark_all_read(self) -> int:
        marked = sum(1 for n in self._log if not n.read)
        for notification in self._log:
            notification.read = True
        if settings.supabase_configured:
            try:
                self._repository.mark_all_read()
            except Exception:
                pass
        return marked


notifications_service = NotificationsService()
