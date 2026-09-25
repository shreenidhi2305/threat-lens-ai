from collections import deque
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.core.config import settings
from app.db.repositories.reports import ReportRepository
from app.modules.reports.schemas import ReportRecord, ReportStatus

_MAX_HISTORY = 1000


class ReportsService:
    def __init__(self) -> None:
        self._reports: dict[str, ReportStatus] = {}
        self._history: deque[ReportRecord] = deque(maxlen=_MAX_HISTORY)
        self._repository = ReportRepository()

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

    # --- report history (investigation + summary PDFs) ---------------------
    def log_report(
        self,
        *,
        report_type: str,
        title: str,
        created_by: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        verdict_label: str | None = None,
        risk_score: int | None = None,
        window: str | None = None,
    ) -> ReportRecord:
        record = ReportRecord(
            id=str(uuid4()),
            created_at=datetime.now(timezone.utc),
            report_type=report_type,
            title=title,
            created_by=created_by,
            sha256=sha256,
            filename=filename,
            verdict_label=verdict_label,
            risk_score=risk_score,
            window=window,
        )
        self._history.appendleft(record)
        self._persist(record)
        return record

    def _persist(self, record: ReportRecord) -> None:
        if not settings.supabase_configured:
            return
        try:
            self._repository.create({
                'id': record.id,
                'report_type': record.report_type,
                'format': record.format,
                'title': record.title,
                'created_by': record.created_by,
                'sha256': record.sha256,
                'filename': record.filename,
                'verdict_label': record.verdict_label,
                'risk_score': record.risk_score,
                'window': record.window,
                'created_at': record.created_at,
            })
        except Exception:
            # Keep the record in memory if Supabase is unavailable.
            pass

    def list_report_history(self, limit: int = 100) -> list[ReportRecord]:
        if settings.supabase_configured:
            try:
                rows = self._repository.list(limit=limit)
                return [ReportRecord.model_validate(dict(row)) for row in rows]
            except Exception:
                pass  # fall back to the in-memory history below
        return list(self._history)[:limit]


reports_service = ReportsService()
