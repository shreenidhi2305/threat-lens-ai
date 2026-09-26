from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.core.config import settings
from app.modules.reports.schemas import ReportStatus
from app.db.repositories.reports import ReportRepository


class ReportsService:
    def __init__(self) -> None:
        self._reports: dict[str, ReportStatus] = {}
        self._analyses: dict[str, Any] = {}
        self.repository = ReportRepository()

    def create_report(
        self,
        classification: Any,
        analysis: Any = None,
    ) -> ReportStatus:

        # Get file hash and indicators from analysis
        if isinstance(analysis, dict):
            file_hash = analysis.get("sha256") or analysis.get(
                "hashes", {}
            ).get("sha256")
            indicators = analysis.get("suspicious_indicators", [])
            object_path = analysis.get("object_path", "")
        else:
            file_hash = getattr(analysis, "sha256", None)

            if file_hash is None and analysis is not None:
                hashes = getattr(analysis, "hashes", None)
                if hashes is not None:
                    if isinstance(hashes, dict):
                        file_hash = hashes.get("sha256")
                    else:
                        file_hash = getattr(hashes, "sha256", None)

            indicators = (
                getattr(analysis, "suspicious_indicators", [])
                if analysis
                else []
            )
            object_path = (
                getattr(analysis, "object_path", "")
                if analysis
                else ""
            )

        filename = (
            object_path.replace("\\", "/").rsplit("/", 1)[-1]
            if object_path
            else None
        )

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

        # Keep local in-memory copy
        self._reports[report.report_id] = report

        if analysis is not None:
            self._analyses[report.report_id] = analysis

        # Save to Supabase when configured
        if settings.supabase_configured:
            analysis_data = None

            if analysis is not None:
                if hasattr(analysis, "model_dump"):
                    analysis_data = analysis.model_dump(mode="json")
                elif isinstance(analysis, dict):
                    analysis_data = analysis

            db_report = {
                "id": report.report_id,
                "sample_id": report.sample_id,
                "filename": report.filename,
                "status": report.status,
                "file_hash": report.file_hash,
                "predicted_class": report.predicted_class,
                "confidence": report.confidence,
                "is_malicious": report.is_malicious,
                "risk_score": report.risk_score,
                "severity": report.severity,
                "static_indicators": report.static_indicators,
                "recommendation": report.recommendation,
                "analysis_data": analysis_data,
            }

            self.repository.create(db_report)

        return report
    def create_threat_prediction_report(
        self,
        analysis: Any,
    ) -> ReportStatus:
        """Create a report directly from the final pipeline analysis."""

        verdict = getattr(analysis, "verdict", None)

        if verdict is None:
            raise ValueError("Cannot create report without a final verdict")

        class ReportClassification:
            status = "completed"
            sample_id = None
            predicted_class = verdict.classification
            confidence = verdict.confidence
            is_malicious = verdict.label == "malicious"
            risk_score = verdict.score
            severity = verdict.level
            recommendation = verdict.recommended_action

        return self.create_report(
            ReportClassification(),
            analysis,
        )

    def list_reports(self) -> list[ReportStatus]:
        """Return all generated reports, newest first."""

        if settings.supabase_configured:
            rows = self.repository.list()

            reports = []

            for row in rows:
                reports.append(
                    ReportStatus(
                        report_id=str(row["id"]),
                        status=row.get("status", "completed"),
                        filename=row.get("filename"),
                        sample_id=row.get("sample_id"),
                        file_hash=row.get("file_hash"),
                        predicted_class=row.get("predicted_class"),
                        confidence=row.get("confidence"),
                        is_malicious=row.get("is_malicious"),
                        risk_score=row.get("risk_score"),
                        severity=row.get("severity"),
                        static_indicators=row.get(
                            "static_indicators", []
                        ),
                        recommendation=row.get("recommendation"),
                        timestamp=row.get("created_at"),
                    )
                )

            return reports

        return sorted(
            self._reports.values(),
            key=lambda report: report.timestamp
            or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

    def get_report_status(self, report_id: str) -> ReportStatus:

        if settings.supabase_configured:
            row = self.repository.get(report_id)

            if row is not None:
                return ReportStatus(
                    report_id=str(row["id"]),
                    status=row.get("status", "completed"),
                    filename=row.get("filename"),
                    sample_id=row.get("sample_id"),
                    file_hash=row.get("file_hash"),
                    predicted_class=row.get("predicted_class"),
                    confidence=row.get("confidence"),
                    is_malicious=row.get("is_malicious"),
                    risk_score=row.get("risk_score"),
                    severity=row.get("severity"),
                    static_indicators=row.get(
                        "static_indicators", []
                    ),
                    recommendation=row.get("recommendation"),
                    timestamp=row.get("created_at"),
                )

        return self._reports.get(
            report_id,
            ReportStatus(
                report_id=report_id,
                status="pending",
            ),
        )

    def get_analysis(self, report_id: str) -> Any | None:
        """Return the analysis associated with a generated report."""

        if settings.supabase_configured:
            row = self.repository.get(report_id)

            if row is None:
                return None

            analysis_data = row.get("analysis_data")

            if analysis_data is None:
                return None

            from app.modules.file_analysis.schemas import AnalysisResult

            return AnalysisResult.model_validate(analysis_data)

        return self._analyses.get(report_id)


reports_service = ReportsService()