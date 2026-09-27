from datetime import datetime

from pydantic import BaseModel, Field

AlertStatus = str  # open | acknowledged | resolved
IncidentStatus = str  # open | contained | closed


class Alert(BaseModel):
    id: str
    created_at: datetime
    severity: str = Field(description="high | critical")
    status: AlertStatus = 'open'
    title: str
    sample_sha256: str
    sample_name: str
    verdict_label: str
    verdict_score: int
    category: str | None = None
    agreement: str | None = None
    detection_id: str | None = None
    incident_id: str | None = None
    notified: bool = False
    created_by: str | None = None
    note: str | None = None


class Incident(BaseModel):
    id: str
    created_at: datetime
    title: str
    status: IncidentStatus = 'open'
    severity: str
    alert_ids: list[str] = []


class AlertActionRequest(BaseModel):
    note: str | None = None


class CreateIncidentRequest(BaseModel):
    alert_ids: list[str]
    title: str | None = None


class AlertStats(BaseModel):
    open: int
    acknowledged: int
    resolved: int
    critical_open: int
    notifications_enabled: bool
