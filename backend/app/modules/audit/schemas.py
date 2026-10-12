from datetime import datetime

from pydantic import BaseModel


class AuditEvent(BaseModel):
    id: str
    at: datetime
    actor: str | None = None
    role: str | None = None
    action: str
    target: str | None = None
    detail: str | None = None
    status: str = 'success'  # success | failure | denied
    ip: str | None = None
