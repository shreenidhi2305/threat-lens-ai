from datetime import datetime

from pydantic import BaseModel


class ReportResponse(BaseModel):
    report_id: str
    status: str
    sample_id: str | None = None
    file_hash: str | None = None
    predicted_class: str | None = None
    confidence: float | None = None
    is_malicious: bool | None = None
    risk_score: int | None = None
    severity: str | None = None
    static_indicators: list[str] = []
    recommendation: str | None = None
    timestamp: datetime | None = None


ReportStatus = ReportResponse
