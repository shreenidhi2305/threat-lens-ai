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

@router.get('', response_model=list[ReportResponse])
def list_reports(
    _user: CurrentUser = Depends(
        require_roles('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')
    ),
) -> list[ReportResponse]:
    return reports_service.list_reports()

@router.get('/{report_id}', response_model=ReportResponse)
def get_report_status(
    report_id: str,
    _user: CurrentUser = Depends(
        require_roles('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')
    ),
) -> ReportResponse:
    return reports_service.get_report_status(report_id)
@router.get('/{report_id}/pdf')
def download_previous_pdf(
    report_id: str,
    _user: CurrentUser = Depends(
        require_roles(
            'Security Analyst',
            'SOC Team Member',
            'Administrator',
            'Researcher',
        )
    ),
) -> Response:
    """Download the PDF for a previously generated report."""
    analysis = reports_service.get_analysis(report_id)

    if analysis is None:
        return Response(
            content='Report analysis not found',
            status_code=404,
            media_type='text/plain',
        )

    filename = (
        getattr(analysis, 'object_path', 'analysis')
        .replace('\\', '/')
        .rsplit('/', 1)[-1]
        or 'analysis'
    )

    safe_name = ''.join(
        char if char.isalnum() or char in '._-' else '_'
        for char in filename
    )

    return Response(
        content=render_analysis_pdf(analysis),
        media_type='application/pdf',
        headers={
            'Content-Disposition': (
                f'attachment; filename="{safe_name}-report.pdf"'
            )
        },
    )