from fastapi import APIRouter, Depends

from app.core.dependencies import CurrentUser, require_roles
from app.modules.reports.schemas import ReportStatus
from app.modules.reports.service import reports_service

router = APIRouter()


@router.get('/{report_id}', response_model=ReportStatus)
def get_report_status(
    report_id: str,
    _user: CurrentUser = Depends(
        require_roles('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')
    ),
) -> ReportStatus:
    return reports_service.get_report_status(report_id)
