from pydantic import BaseModel


class ReportStatus(BaseModel):
    report_id: str
    status: str
