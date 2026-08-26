from app.modules.reports.schemas import ReportStatus


class ReportsService:
    def get_report_status(self, report_id: str) -> ReportStatus:
        return ReportStatus(report_id=report_id, status='pending')


reports_service = ReportsService()
