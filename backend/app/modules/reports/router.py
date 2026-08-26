from fastapi import APIRouter

from app.modules.reports.schemas import ReportStatus
from app.modules.reports.service import reports_service

router = APIRouter()


@router.get('/{report_id}', response_model=ReportStatus)
def get_report_status(report_id: str) -> ReportStatus:
    return reports_service.get_report_status(report_id)
