from collections import deque
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.core.config import settings
from app.db.repositories.reports import AnalysisReportRepository, ReportRepository
from app.modules.reports.schemas import ReportRecord, ReportStatus

_MAX_HISTORY = 1000


class ReportsService:
    def __init__(self) -> None:
        self._reports: dict[str, ReportStatus] = {}
        self._analyses: dict[str, Any] = {}
        self._history: deque[ReportRecord] = deque(maxlen=_MAX_HISTORY)
        self._repository = ReportRepository()
        self._analysis_repository = AnalysisReportRepository()

    def create_report(self, classification: Any, analysis: Any = None) -> ReportStatus:
        """Create and persist a per-scan report from a classification + its analysis.

        Stores the full analysis alongside the report (in-memory, and in
        Supabase when configured) so it can be retrieved and re-rendered later
        via ``get_analysis`` / ``get_report_status`` without the caller
        holding any state.
        """
        if isinstance(analysis, dict):
            file_hash = analysis.get('sha256') or analysis.get('hashes', {}).get('sha256')
            indicators = analysis.get('suspicious_indicators', [])
            object_path = analysis.get('object_path', '')
        else:
            file_hash = getattr(analysis, 'sha256', None)
            indicators = getattr(analysis, 'suspicious_indicators', []) if analysis else []
            object_path = getattr(analysis, 'object_path', '') if analysis else ''

        filename = object_path.replace('\\', '/').rsplit('/', 1)[-1] if object_path else None

        report = ReportStatus(
            report_id=str(uuid4()),
            status=classification.status,
            filename=filename,
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
        if analysis is not None:
            self._analyses[report.report_id] = analysis
        self._persist_analysis_report(report, analysis)
        return report

    def create_threat_prediction_report(self, analysis: Any) -> ReportStatus:
        """Create a report directly from a completed pipeline scan's verdict."""
        verdict = getattr(analysis, 'verdict', None)
        if verdict is None:
            raise ValueError('Cannot create a threat prediction report without a final verdict')

        class _Classification:
            status = 'completed'
            sample_id = None
            predicted_class = verdict.classification
            confidence = verdict.confidence
            is_malicious = verdict.label == 'malicious'
            risk_score = verdict.score
            severity = verdict.level
            recommendation = verdict.recommended_action

        return self.create_report(_Classification(), analysis)

    def _persist_analysis_report(self, report: ReportStatus, analysis: Any) -> None:
        if not settings.supabase_configured:
            return
        try:
            analysis_data = None
            if analysis is not None:
                if hasattr(analysis, 'model_dump'):
                    analysis_data = analysis.model_dump(mode='json')
                elif isinstance(analysis, dict):
                    analysis_data = analysis
            self._analysis_repository.create({
                'id': report.report_id,
                'sample_id': report.sample_id,
                'filename': report.filename,
                'status': report.status,
                'file_hash': report.file_hash,
                'predicted_class': report.predicted_class,
                'confidence': report.confidence,
                'is_malicious': report.is_malicious,
                'risk_score': report.risk_score,
                'severity': report.severity,
                'static_indicators': report.static_indicators,
                'recommendation': report.recommendation,
                'analysis_data': analysis_data,
                'created_at': report.timestamp,
            })
        except Exception:
            # Keep the report in memory if Supabase is unavailable.
            pass

    def list_reports(self) -> list[ReportStatus]:
        """All per-scan threat-prediction reports, newest first."""
        if settings.supabase_configured:
            try:
                rows = self._analysis_repository.list()
                return [self._row_to_report(row) for row in rows]
            except Exception:
                pass  # fall back to the in-memory store below
        return sorted(
            self._reports.values(),
            key=lambda r: r.timestamp or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

    @staticmethod
    def _row_to_report(row: dict) -> ReportStatus:
        return ReportStatus(
            report_id=str(row['id']),
            status=row.get('status', 'completed'),
            filename=row.get('filename'),
            sample_id=row.get('sample_id'),
            file_hash=row.get('file_hash'),
            predicted_class=row.get('predicted_class'),
            confidence=row.get('confidence'),
            is_malicious=row.get('is_malicious'),
            risk_score=row.get('risk_score'),
            severity=row.get('severity'),
            static_indicators=row.get('static_indicators', []),
            recommendation=row.get('recommendation'),
            timestamp=row.get('created_at'),
        )

    def get_report_status(self, report_id: str) -> ReportStatus:
        if report_id in self._reports:
            return self._reports[report_id]
        if settings.supabase_configured:
            try:
                row = self._analysis_repository.get(report_id)
                if row is not None:
                    return self._row_to_report(row)
            except Exception:
                pass
        return ReportStatus(report_id=report_id, status='pending')

    def get_analysis(self, report_id: str) -> Any | None:
        """The full stored analysis for a past report, for PDF re-rendering."""
        if report_id in self._analyses:
            return self._analyses[report_id]
        if settings.supabase_configured:
            try:
                row = self._analysis_repository.get(report_id)
                if row and row.get('analysis_data'):
                    from app.modules.file_analysis.schemas import AnalysisResult

                    return AnalysisResult.model_validate(row['analysis_data'])
            except Exception:
                pass
        return None

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
