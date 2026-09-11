from fastapi import APIRouter, Depends
from fastapi.responses import Response

from app.core.dependencies import CurrentUser, require_roles
from app.modules.reports.schemas import ReportResponse
from app.modules.file_analysis.schemas import AnalysisResult
from app.modules.reports.pdf import render_analysis_pdf
from app.modules.reports.service import reports_service

router = APIRouter()

_REPORT_ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')


@router.post('/pdf')
def download_pdf(
    result: AnalysisResult,
    _user: CurrentUser = Depends(require_roles(*_REPORT_ROLES)),
) -> Response:
    """Render the client-held analysis result without reading the uploaded sample."""
    filename = result.object_path.replace('\\', '/').rsplit('/', 1)[-1] or 'analysis'
    safe_name = ''.join(char if char.isalnum() or char in '._-' else '_' for char in filename)
    return Response(
        content=render_analysis_pdf(result),
        media_type='application/pdf',
        headers={'Content-Disposition': f'attachment; filename="{safe_name}-report.pdf"'},
    )


@router.get('/{report_id}', response_model=ReportResponse)
def get_report_status(
    report_id: str,
    _user: CurrentUser = Depends(
        require_roles('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')
    ),
) -> ReportResponse:
    return reports_service.get_report_status(report_id)
