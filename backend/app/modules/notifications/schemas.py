from datetime import datetime

from pydantic import BaseModel

NotificationCategory = str  # alert | status | incident | report
NotificationSeverity = str  # info | low | medium | high | critical


class Notification(BaseModel):
    id: str
    created_at: datetime
    category: NotificationCategory
    severity: NotificationSeverity
    title: str
    message: str
    alert_id: str | None = None
    incident_id: str | None = None
    report_id: str | None = None
    read: bool = False
    email_sent: bool = False


class NotificationCounts(BaseModel):
    unread: int
    total: int
