from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from app.core.dependencies import CurrentUser, require_roles
from app.modules.reports.schemas import ReportRecord, ReportResponse
from app.modules.file_analysis.schemas import AnalysisResult
from app.modules.reports.pdf import render_analysis_pdf, render_summary_pdf
from app.modules.reports.service import reports_service
from app.modules.threat_monitoring.service import threat_monitoring_service

router = APIRouter()

_REPORT_ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')


@router.post('/pdf')
def download_pdf(
    result: AnalysisResult,
    user: CurrentUser = Depends(require_roles(*_REPORT_ROLES)),
) -> Response:
    """Render the client-held analysis result without reading the uploaded sample."""
    filename = result.object_path.replace('\\', '/').rsplit('/', 1)[-1] or 'analysis'
    safe_name = ''.join(char if char.isalnum() or char in '._-' else '_' for char in filename)
    reports_service.log_report(
        report_type='investigation',
        title=f'Investigation Report — {safe_name}',
        created_by=user.user_id,
        sha256=result.hashes.sha256,
        filename=safe_name,
        verdict_label=result.verdict.label if result.verdict else None,
        risk_score=result.verdict.score if result.verdict else result.risk.score,
    )
    return Response(
        content=render_analysis_pdf(result),
        media_type='application/pdf',
        headers={'Content-Disposition': f'attachment; filename="{safe_name}-report.pdf"'},
    )


@router.post('/summary')
def download_summary_pdf(
    user: CurrentUser = Depends(require_roles(*_REPORT_ROLES)),
    window: str = Query('7d', pattern='^(24h|7d|30d)$'),
) -> Response:
    """Generate an aggregate threat-monitoring / operational report for the given window."""
    stats = threat_monitoring_service.get_stats()
    timeline = threat_monitoring_service.get_timeline(window)
    reports_service.log_report(
        report_type='summary',
        title=f'Threat Summary Report — {window}',
        created_by=user.user_id,
        window=window,
    )
    return Response(
        content=render_summary_pdf(stats, timeline, window, generated_by=user.user_id),
        media_type='application/pdf',
        headers={'Content-Disposition': f'attachment; filename="threat-summary-{window}.pdf"'},
    )


@router.get('/history', response_model=list[ReportRecord])
def list_report_history(
    _user: CurrentUser = Depends(require_roles(*_REPORT_ROLES)),
    limit: int = Query(100, ge=1, le=500),
) -> list[ReportRecord]:
    return reports_service.list_report_history(limit=limit)


@router.get('/{report_id}', response_model=ReportResponse)
def get_report_status(
    report_id: str,
    _user: CurrentUser = Depends(
        require_roles('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')
    ),
) -> ReportResponse:
    return reports_service.get_report_status(report_id)
