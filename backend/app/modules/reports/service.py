from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.modules.reports.schemas import ReportStatus


class ReportsService:
    def __init__(self) -> None:
        self._reports: dict[str, ReportStatus] = {}

    def create_report(self, classification: Any, analysis: Any = None) -> ReportStatus:
        if isinstance(analysis, dict):
            file_hash = analysis.get('sha256') or analysis.get('hashes', {}).get('sha256')
            indicators = analysis.get('suspicious_indicators', [])
        else:
            file_hash = getattr(analysis, 'sha256', None)
            indicators = getattr(analysis, 'suspicious_indicators', []) if analysis else []

        report = ReportStatus(
            report_id=str(uuid4()),
            status=classification.status,
            sample_id=classification.sample_id,
            file_hash=file_hash,
            predicted_class=classification.predicted_class,
            confidence=classification.confidence,
            is_malicious=classification.is_malicious,
            risk_score=classification.risk_score,
            severity=classification.severity,
            static_indicators=indicators,
            recommendation=classification.recommendation,
            timestamp=datetime.now(timezone.utc),
        )
        self._reports[report.report_id] = report
        return report

    def get_report_status(self, report_id: str) -> ReportStatus:
        return self._reports.get(report_id, ReportStatus(report_id=report_id, status='pending'))


reports_service = ReportsService()
